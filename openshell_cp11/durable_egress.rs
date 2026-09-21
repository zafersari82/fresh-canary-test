// SPDX-License-Identifier: Apache-2.0
// BLACKBOX ACV CP11 experimental durable-egress gate for OpenShell.
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
    pub(crate) writer_epoch: u64,
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
    writer_epoch: u64,
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn claim_writer_epoch(journal_path: &Path) -> io::Result<u64> {
    let epoch_path = path_with_suffix(journal_path, ".writer-epoch");
    let current = match std::fs::read_to_string(&epoch_path) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error),
    };
    let next = current
        .checked_add(1)
        .ok_or_else(|| io::Error::other("BLACKBOX writer epoch exhausted"))?;
    let temp_path = path_with_suffix(
        &epoch_path,
        &format!(".tmp-{}", Uuid::new_v4()),
    );
    let result = (|| -> io::Result<()> {
        let mut temp = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        writeln!(temp, "{next}")?;
        temp.sync_all()?;
        std::fs::rename(&temp_path, &epoch_path)?;
        sync_parent_directory(&epoch_path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    result?;
    Ok(next)
}

impl PermitStore {
    fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;

        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "BLACKBOX permit journal already has an active writer",
                ));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }

        if !existed {
            file.sync_all()?;
            sync_parent_directory(&path)?;
        }

        let writer_epoch = claim_writer_epoch(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
            writer_epoch,
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
            "schema": "blackbox.openshell.durable-egress-permit.v3",
            "operation_id": &operation_id,
            "sandbox_id": &*self.sandbox_id,
            "supervisor_session_id": session_id,
            "supervisor_session_epoch": session_epoch,
            "policy_generation": generation,
            "writer_epoch": self.store.writer_epoch,
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
            schema: "blackbox.openshell.durable-egress-permit.v3".to_string(),
            operation_id,
            sandbox_id: self.sandbox_id.to_string(),
            supervisor_session_id: record["supervisor_session_id"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            supervisor_session_epoch: session_epoch,
            policy_generation: generation,
            writer_epoch: self.store.writer_epoch,
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
        assert_eq!(store.writer_epoch, 1);
    }

    #[test]
    fn permit_store_fences_concurrent_writer_and_advances_epoch_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permits.jsonl");
        let first = PermitStore::open(&path).unwrap();
        let first_epoch = first.writer_epoch;

        let error = PermitStore::open(&path).expect_err("second writer must be fenced");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        drop(first);
        let successor = PermitStore::open(&path).unwrap();
        assert_eq!(successor.writer_epoch, first_epoch + 1);
    }
}
