// SPDX-License-Identifier: Apache-2.0
// BLACKBOX ACV CP10 experimental durable-egress gate for OpenShell.
// Target: NVIDIA/OpenShell@484f0768fc6a0d93e0a2be295c1679aed24e18a9

use crate::opa::{OpaEngine, PolicyGenerationGuard};
use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const JOURNAL_ENV: &str = "OPENSHELL_BLACKBOX_EGRESS_JOURNAL";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EgressSurface {
    Connect,
    ForwardHttp,
    TransparentTcp,
}

#[derive(Clone, Debug)]
pub(crate) struct PermitInput<'a> {
    pub(crate) surface: EgressSurface,
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) matched_policy: &'a str,
    pub(crate) binary_path: &'a str,
    pub(crate) binary_pid: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct DurableEgressPermit {
    pub(crate) schema: String,
    pub(crate) operation_id: String,
    pub(crate) sandbox_id: String,
    pub(crate) supervisor_session_id: String,
    pub(crate) supervisor_session_epoch: u64,
    pub(crate) policy_generation: u64,
    pub(crate) surface: EgressSurface,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) matched_policy: String,
    pub(crate) binary_path: String,
    pub(crate) binary_pid: Option<u32>,
    pub(crate) intent_sha256: String,
    pub(crate) committed_unix_ns: u64,
    pub(crate) record_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DispatchLease {
    pub(crate) dispatch_sequence: u64,
    pub(crate) supervisor_session_epoch: u64,
    pub(crate) policy_generation: u64,
}

#[derive(Debug, Default)]
struct SessionState {
    id: Option<String>,
    epoch: u64,
}

/// Cross-component logical dispatch fence.
///
/// Session publication acquires `session`; policy reload already serializes on
/// `OpaEngine::engine`. `linearize_dispatch` acquires the policy lock first via
/// `with_current_generation`, then this session lock. Thus either a revocation
/// linearizes first and dispatch is rejected, or dispatch linearizes first and
/// the operation is legitimately in-flight.
#[derive(Debug, Default)]
pub struct DispatchAuthorityFence {
    session: Mutex<SessionState>,
    dispatch_sequence: AtomicU64,
}

impl DispatchAuthorityFence {
    pub fn publish_session(&self, next: Option<String>) {
        let mut state = self.session.lock().expect("BLACKBOX session fence poisoned");
        state.id = next;
        state.epoch = state.epoch.wrapping_add(1);
    }

    fn active_session(&self) -> Result<(String, u64)> {
        let state = self
            .session
            .lock()
            .map_err(|_| miette::miette!("BLACKBOX session fence poisoned"))?;
        let id = state
            .id
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| miette::miette!("BLACKBOX egress has no accepted supervisor session"))?;
        Ok((id, state.epoch))
    }

    fn linearize_dispatch(
        &self,
        opa: &OpaEngine,
        expected_generation: u64,
        expected_session: &str,
        expected_session_epoch: u64,
    ) -> Result<DispatchLease> {
        let nested = opa.with_current_generation(expected_generation, |_| {
            let state = self
                .session
                .lock()
                .map_err(|_| miette::miette!("BLACKBOX session fence poisoned"))?;
            if state.id.as_deref() != Some(expected_session) || state.epoch != expected_session_epoch {
                return Err(miette::miette!(
                    "BLACKBOX supervisor session changed before dispatch \
                     [expected_session:{expected_session} expected_epoch:{expected_session_epoch} \
                     current_session:{:?} current_epoch:{}]",
                    state.id,
                    state.epoch,
                ));
            }
            Ok(DispatchLease {
                dispatch_sequence: self.dispatch_sequence.fetch_add(1, Ordering::AcqRel) + 1,
                supervisor_session_epoch: state.epoch,
                policy_generation: expected_generation,
            })
        })?;

        nested.ok_or_else(|| {
            miette::miette!(
                "BLACKBOX policy generation changed before dispatch [expected_generation:{expected_generation}]"
            )
        })?
    }
}

static GLOBAL_DISPATCH_FENCE: LazyLock<Arc<DispatchAuthorityFence>> =
    LazyLock::new(|| Arc::new(DispatchAuthorityFence::default()));

pub fn publish_supervisor_session(session: Option<String>) {
    GLOBAL_DISPATCH_FENCE.publish_session(session);
}

#[derive(Debug)]
struct PermitStore {
    path: PathBuf,
    file: Mutex<File>,
}

impl PermitStore {
    fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    fn append_and_sync(&self, permit: &DurableEgressPermit) -> io::Result<()> {
        let mut line = serde_json::to_vec(permit).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("BLACKBOX permit journal lock poisoned"))?;
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(())
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone)]
pub(crate) struct DurableEgressPermitGate {
    sandbox_id: Arc<str>,
    authority: Arc<DispatchAuthorityFence>,
    store: Arc<PermitStore>,
}

impl DurableEgressPermitGate {
    pub(crate) fn new(
        sandbox_id: impl Into<String>,
        authority: Arc<DispatchAuthorityFence>,
        journal_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let sandbox_id = sandbox_id.into();
        if sandbox_id.is_empty() {
            return Err(miette::miette!("BLACKBOX durable egress gate requires sandbox_id"));
        }
        Ok(Self {
            sandbox_id: Arc::<str>::from(sandbox_id),
            authority,
            store: Arc::new(PermitStore::open(journal_path).into_diagnostic()?),
        })
    }

    pub(crate) async fn commit_before_effect(
        &self,
        generation_guard: &PolicyGenerationGuard,
        input: PermitInput<'_>,
    ) -> Result<DurableEgressPermit> {
        generation_guard.ensure_current()?;
        let (session_id, session_epoch) = self.authority.active_session()?;
        let generation = generation_guard.captured_generation();
        let host = input.host.trim_end_matches('.').to_ascii_lowercase();
        let committed_unix_ns = unix_ns();
        let operation_id = Uuid::new_v4().to_string();

        let intent = serde_json::json!({
            "surface": input.surface,
            "host": host,
            "port": input.port,
            "matched_policy": input.matched_policy,
            "binary_path": input.binary_path,
            "binary_pid": input.binary_pid,
        });
        let intent_sha256 = sha256_hex(&serde_json::to_vec(&intent).into_diagnostic()?);
        let record = serde_json::json!({
            "schema": "blackbox.openshell.durable-egress-permit.v2",
            "operation_id": &operation_id,
            "sandbox_id": &*self.sandbox_id,
            "supervisor_session_id": session_id,
            "supervisor_session_epoch": session_epoch,
            "policy_generation": generation,
            "surface": input.surface,
            "host": host,
            "port": input.port,
            "matched_policy": input.matched_policy,
            "binary_path": input.binary_path,
            "binary_pid": input.binary_pid,
            "intent_sha256": intent_sha256,
            "committed_unix_ns": committed_unix_ns,
        });
        let record_sha256 = sha256_hex(&serde_json::to_vec(&record).into_diagnostic()?);

        let permit = DurableEgressPermit {
            schema: "blackbox.openshell.durable-egress-permit.v2".to_string(),
            operation_id,
            sandbox_id: self.sandbox_id.to_string(),
            supervisor_session_id: record["supervisor_session_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            supervisor_session_epoch: session_epoch,
            policy_generation: generation,
            surface: input.surface,
            host: record["host"].as_str().unwrap_or_default().to_string(),
            port: input.port,
            matched_policy: input.matched_policy.to_string(),
            binary_path: input.binary_path.to_string(),
            binary_pid: input.binary_pid,
            intent_sha256: record["intent_sha256"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            committed_unix_ns,
            record_sha256,
        };

        let store = Arc::clone(&self.store);
        let copy = permit.clone();
        tokio::task::spawn_blocking(move || store.append_and_sync(&copy))
            .await
            .map_err(|error| miette::miette!("BLACKBOX durable writer task failed: {error}"))?
            .into_diagnostic()?;

        generation_guard.ensure_current()?;
        Ok(permit)
    }

    pub(crate) fn linearize_dispatch(
        &self,
        opa: &OpaEngine,
        generation_guard: &PolicyGenerationGuard,
        permit: &DurableEgressPermit,
    ) -> Result<DispatchLease> {
        if permit.policy_generation != generation_guard.captured_generation() {
            return Err(miette::miette!("BLACKBOX permit generation does not match dispatch guard"));
        }
        self.authority.linearize_dispatch(
            opa,
            permit.policy_generation,
            &permit.supervisor_session_id,
            permit.supervisor_session_epoch,
        )
    }
}

pub(crate) fn gate_from_env(sandbox_id: Option<&str>) -> Result<Option<Arc<DurableEgressPermitGate>>> {
    let Some(sandbox_id) = sandbox_id else {
        return Ok(None);
    };
    let Some(path) = std::env::var_os(JOURNAL_ENV) else {
        return Ok(None);
    };
    Ok(Some(Arc::new(DurableEgressPermitGate::new(
        sandbox_id,
        Arc::clone(&GLOBAL_DISPATCH_FENCE),
        PathBuf::from(path),
    )?)))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn unix_ns() -> u64 {
    let ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    u64::try_from(ns).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = include_str!("../data/sandbox-policy.rego");

    #[test]
    fn dispatch_fence_rejects_session_aba() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let fence = DispatchAuthorityFence::default();
        fence.publish_session(Some("a".into()));
        let (session, epoch) = fence.active_session().unwrap();
        fence.publish_session(Some("b".into()));
        fence.publish_session(Some("a".into()));
        assert!(
            fence
                .linearize_dispatch(&engine, engine.current_generation(), &session, epoch)
                .is_err()
        );
    }

    #[test]
    fn dispatch_fence_rejects_stale_policy_generation() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let fence = DispatchAuthorityFence::default();
        fence.publish_session(Some("a".into()));
        let (session, epoch) = fence.active_session().unwrap();
        let old = engine.current_generation();
        engine.enter_fail_closed("test").unwrap();
        assert!(fence.linearize_dispatch(&engine, old, &session, epoch).is_err());
    }

    #[test]
    fn permit_store_path_is_retained() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permits.jsonl");
        let store = PermitStore::open(&path).unwrap();
        assert_eq!(store.path(), path);
    }

    fn test_input<'a>() -> PermitInput<'a> {
        PermitInput {
            surface: EgressSurface::ForwardHttp,
            host: "LOCALHOST.",
            port: 8080,
            matched_policy: "test-policy",
            binary_path: "/bin/test-agent",
            binary_pid: Some(42),
        }
    }

    #[tokio::test]
    async fn permit_requires_active_supervisor_session_and_writes_nothing_on_rejection() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let gate = DurableEgressPermitGate::new("sandbox-a", authority, &journal).unwrap();

        assert!(gate.commit_before_effect(&guard, test_input()).await.is_err());
        assert_eq!(std::fs::read(&journal).unwrap_or_default(), b"");
    }

    #[tokio::test]
    async fn durable_permit_is_synced_before_receiver_observes_effect() {
        use tokio::net::{TcpListener, TcpStream};

        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let permit = gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("durable permit");
        let lease = gate
            .linearize_dispatch(&engine, &guard, &permit)
            .expect("dispatch lease");
        assert!(lease.dispatch_sequence > 0);

        let journal_before_dial = std::fs::read_to_string(&journal).unwrap();
        assert!(
            journal_before_dial.contains(&permit.operation_id),
            "durable journal must contain operation before dial"
        );

        let receiver = tokio::spawn(async move {
            let (_socket, _peer) = listener.accept().await.unwrap();
            unix_ns()
        });
        let _client = TcpStream::connect(address).await.unwrap();
        let received_ns = receiver.await.unwrap();

        assert!(
            permit.committed_unix_ns <= received_ns,
            "permit commit timestamp must not follow receiver observation"
        );
        let records: Vec<&str> = journal_before_dial.lines().collect();
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn session_replacement_after_permit_blocks_dispatch() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));
        let dir = tempfile::tempdir().unwrap();
        let gate = DurableEgressPermitGate::new(
            "sandbox-a",
            Arc::clone(&authority),
            dir.path().join("permits.jsonl"),
        )
        .unwrap();

        let permit = gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("permit before replacement");
        authority.publish_session(Some("session-b".into()));

        assert!(gate.linearize_dispatch(&engine, &guard, &permit).is_err());
    }

    #[tokio::test]
    async fn policy_change_after_permit_blocks_dispatch() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));
        let dir = tempfile::tempdir().unwrap();
        let gate = DurableEgressPermitGate::new(
            "sandbox-a",
            authority,
            dir.path().join("permits.jsonl"),
        )
        .unwrap();

        let permit = gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("permit before policy change");
        engine.enter_fail_closed("revoked before dial").unwrap();

        assert!(gate.linearize_dispatch(&engine, &guard, &permit).is_err());
    }

    async fn assert_receiver_silent(listener: tokio::net::TcpListener) {
        let observed = tokio::time::timeout(
            std::time::Duration::from_millis(80),
            listener.accept(),
        )
        .await;
        assert!(
            observed.is_err(),
            "receiver unexpectedly observed a network effect before dial"
        );
    }

    #[tokio::test]
    async fn crash_matrix_after_permit_before_dispatch_persists_without_effect() {
        use tokio::net::TcpListener;

        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();

        let permit = gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("durable permit before simulated crash");

        drop(gate);

        let recovered = std::fs::read_to_string(&journal).unwrap();
        assert!(recovered.contains(&permit.operation_id));
        assert_eq!(recovered.lines().count(), 1);
        assert_receiver_silent(listener).await;
    }

    #[tokio::test]
    async fn crash_matrix_after_dispatch_before_dial_persists_without_effect() {
        use tokio::net::TcpListener;

        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();

        let permit = gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("durable permit");
        let lease = gate
            .linearize_dispatch(&engine, &guard, &permit)
            .expect("dispatch linearization");
        assert!(lease.dispatch_sequence > 0);

        drop(gate);

        let recovered = std::fs::read_to_string(&journal).unwrap();
        assert!(recovered.contains(&permit.operation_id));
        assert_receiver_silent(listener).await;
    }

    #[tokio::test]
    async fn crash_matrix_after_dial_before_outcome_preserves_permit_and_effect() {
        use tokio::net::{TcpListener, TcpStream};

        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();

        let permit = gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("durable permit");
        gate.linearize_dispatch(&engine, &guard, &permit)
            .expect("dispatch linearization");

        let receiver = tokio::spawn(async move {
            let (_stream, _peer) = listener.accept().await.unwrap();
            unix_ns()
        });

        let client = TcpStream::connect(address).await.unwrap();
        drop(client);
        drop(gate);

        let observed_ns = receiver.await.unwrap();
        let recovered = std::fs::read_to_string(&journal).unwrap();
        assert!(recovered.contains(&permit.operation_id));
        assert!(permit.committed_unix_ns <= observed_ns);
    }

    #[tokio::test]
    async fn restart_reopens_existing_journal_without_losing_permit() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("session-a".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");

        let permit = {
            let gate = DurableEgressPermitGate::new(
                "sandbox-a",
                Arc::clone(&authority),
                &journal,
            )
            .unwrap();
            gate.commit_before_effect(&guard, test_input())
                .await
                .expect("permit before restart")
        };

        let reopened =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();
        drop(reopened);

        let recovered = std::fs::read_to_string(&journal).unwrap();
        assert_eq!(recovered.lines().count(), 1);
        assert!(recovered.contains(&permit.operation_id));
    }

    fn cp12_write_marker(path: &Path, value: &str) {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .expect("create CP12 marker");
        file.write_all(value.as_bytes()).expect("write CP12 marker");
        file.sync_all().expect("sync CP12 marker");
    }

    fn cp12_wait_forever() -> ! {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    #[test]
    fn cp12_child_worker() {
        let Ok(stage) = std::env::var("BLACKBOX_CP12_STAGE") else {
            return;
        };

        let journal = PathBuf::from(
            std::env::var("BLACKBOX_CP12_JOURNAL").expect("CP12 journal path"),
        );
        let marker = PathBuf::from(
            std::env::var("BLACKBOX_CP12_MARKER").expect("CP12 marker path"),
        );
        let receiver = std::env::var("BLACKBOX_CP12_RECEIVER").ok();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("CP12 runtime");

        runtime.block_on(async move {
            let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
            let guard = engine
                .generation_guard(engine.current_generation())
                .expect("current generation guard");
            let authority = Arc::new(DispatchAuthorityFence::default());
            authority.publish_session(Some("cp12-session".into()));
            let gate =
                DurableEgressPermitGate::new("cp12-sandbox", Arc::clone(&authority), &journal)
                    .unwrap();

            if stage == "before_permit" {
                cp12_write_marker(&marker, "before_permit");
                cp12_wait_forever();
            }

            let permit = gate
                .commit_before_effect(&guard, test_input())
                .await
                .expect("CP12 durable permit");

            if stage == "after_permit" {
                cp12_write_marker(&marker, &permit.operation_id);
                cp12_wait_forever();
            }

            let lease = gate
                .linearize_dispatch(&engine, &guard, &permit)
                .expect("CP12 dispatch lease");
            assert!(lease.dispatch_sequence > 0);

            if stage == "after_dispatch" {
                cp12_write_marker(&marker, &permit.operation_id);
                cp12_wait_forever();
            }

            if stage == "after_dial" {
                let receiver = receiver.expect("CP12 receiver address");
                let _stream = tokio::net::TcpStream::connect(receiver)
                    .await
                    .expect("CP12 dial");
                cp12_write_marker(&marker, &permit.operation_id);
                cp12_wait_forever();
            }

            panic!("unknown CP12 child stage: {stage}");
        });
    }

    #[cfg(unix)]
    fn cp12_wait_for_marker(path: &Path) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Ok(value) = std::fs::read_to_string(path)
                && !value.is_empty()
            {
                return value;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for CP12 marker at {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    fn cp12_spawn_child(
        stage: &str,
        journal: &Path,
        marker: &Path,
        receiver: Option<std::net::SocketAddr>,
    ) -> std::process::Child {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .arg("--exact")
            .arg("durable_egress::tests::cp12_child_worker")
            .arg("--nocapture")
            .env("BLACKBOX_CP12_STAGE", stage)
            .env("BLACKBOX_CP12_JOURNAL", journal)
            .env("BLACKBOX_CP12_MARKER", marker)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(receiver) = receiver {
            command.env("BLACKBOX_CP12_RECEIVER", receiver.to_string());
        }
        command.spawn().expect("spawn CP12 child")
    }

    #[cfg(unix)]
    fn cp12_sigkill(child: &mut std::process::Child) {
        use std::os::unix::process::ExitStatusExt;

        child.kill().expect("SIGKILL CP12 child");
        let status = child.wait().expect("wait for CP12 child");
        assert_eq!(
            status.signal(),
            Some(9),
            "CP12 child must terminate by SIGKILL"
        );
    }

    #[cfg(unix)]
    fn cp12_reopen_and_read(journal: &Path) -> String {
        let reopened = PermitStore::open(journal).expect("reopen CP12 journal after process death");
        drop(reopened);
        std::fs::read_to_string(journal).unwrap_or_default()
    }

    #[cfg(unix)]
    #[test]
    fn real_sigkill_before_permit_leaves_no_durable_authorization() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let marker = dir.path().join("marker");

        let mut child = cp12_spawn_child("before_permit", &journal, &marker, None);
        assert_eq!(cp12_wait_for_marker(&marker), "before_permit");
        cp12_sigkill(&mut child);

        assert!(
            cp12_reopen_and_read(&journal).is_empty(),
            "SIGKILL before permit must not leave durable authorization"
        );
    }

    #[cfg(unix)]
    #[test]
    fn real_sigkill_after_fsync_preserves_permit_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let marker = dir.path().join("marker");

        let mut child = cp12_spawn_child("after_permit", &journal, &marker, None);
        let operation_id = cp12_wait_for_marker(&marker);
        cp12_sigkill(&mut child);

        let recovered = cp12_reopen_and_read(&journal);
        assert_eq!(recovered.lines().count(), 1);
        assert!(recovered.contains(&operation_id));
    }

    #[cfg(unix)]
    #[test]
    fn real_sigkill_after_dispatch_before_dial_preserves_permit_without_effect() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let marker = dir.path().join("marker");

        let mut child = cp12_spawn_child("after_dispatch", &journal, &marker, None);
        let operation_id = cp12_wait_for_marker(&marker);
        cp12_sigkill(&mut child);

        let recovered = cp12_reopen_and_read(&journal);
        assert_eq!(recovered.lines().count(), 1);
        assert!(recovered.contains(&operation_id));
    }

    #[cfg(unix)]
    #[test]
    fn real_sigkill_after_dial_preserves_permit_and_receiver_observation() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let marker = dir.path().join("marker");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let receiver_addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let receiver = std::thread::spawn(move || {
            let (_stream, _peer) = listener.accept().expect("CP12 receiver accept");
            tx.send(unix_ns()).unwrap();
        });

        let mut child =
            cp12_spawn_child("after_dial", &journal, &marker, Some(receiver_addr));
        let operation_id = cp12_wait_for_marker(&marker);
        cp12_sigkill(&mut child);

        let observed_ns = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("CP12 receiver observation");
        receiver.join().unwrap();

        let recovered = cp12_reopen_and_read(&journal);
        let line = recovered.lines().next().expect("CP12 durable permit record");
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(recovered.lines().count(), 1);
        assert_eq!(record["operation_id"].as_str(), Some(operation_id.as_str()));
        let committed_ns = record["committed_unix_ns"].as_u64().unwrap();
        assert!(
            committed_ns <= observed_ns,
            "durable permit commit must precede receiver observation after real SIGKILL"
        );
    }

}
