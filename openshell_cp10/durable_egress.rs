// SPDX-License-Identifier: Apache-2.0
// BLACKBOX ACV CP10 experimental durable-egress gate for OpenShell.
// Target: NVIDIA/OpenShell@484f0768fc6a0d93e0a2be295c1679aed24e18a9

use crate::opa::{OpaEngine, PolicyGenerationGuard};
use miette::{IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use uuid::Uuid;

pub const JOURNAL_ENV: &str = "OPENSHELL_BLACKBOX_EGRESS_JOURNAL";
pub const WITNESS_ENV: &str = "OPENSHELL_BLACKBOX_EGRESS_WITNESS";
const JOURNAL_RECORD_SCHEMA: &str = "blackbox.openshell.journal-record.v1";
const WITNESS_SCHEMA: &str = "blackbox.openshell.high-water-witness.v1";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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

#[cfg(unix)]
fn file_lock_exclusive(file: &File) -> io::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn file_lock_release(file: &File) -> io::Result<()> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn file_lock_exclusive(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "BLACKBOX cross-process writer fencing requires a Unix flock-capable platform",
    ))
}

#[cfg(not(unix))]
fn file_lock_release(_file: &File) -> io::Result<()> {
    Ok(())
}

fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    let directory = File::open(parent)?;
    directory.sync_all()
}

fn lock_path_for(journal: &Path) -> PathBuf {
    let mut value = journal.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn read_writer_token(file: &mut File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut value = String::new();
    file.read_to_string(&mut value)?;
    let token = value.trim();
    if token.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BLACKBOX writer fence token is empty",
        ));
    }
    Ok(token.to_string())
}

fn validate_permit_record(permit: &DurableEgressPermit) -> io::Result<()> {
    if permit.schema != "blackbox.openshell.durable-egress-permit.v2" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BLACKBOX journal contains an unsupported permit schema",
        ));
    }

    let intent = serde_json::json!({
        "surface": permit.surface,
        "host": permit.host,
        "port": permit.port,
        "matched_policy": permit.matched_policy,
        "binary_path": permit.binary_path,
        "binary_pid": permit.binary_pid,
    });
    let intent_sha256 = sha256_hex(&serde_json::to_vec(&intent).map_err(io::Error::other)?);
    if intent_sha256 != permit.intent_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BLACKBOX journal intent commitment mismatch",
        ));
    }

    let record = serde_json::json!({
        "schema": permit.schema,
        "operation_id": permit.operation_id,
        "sandbox_id": permit.sandbox_id,
        "supervisor_session_id": permit.supervisor_session_id,
        "supervisor_session_epoch": permit.supervisor_session_epoch,
        "policy_generation": permit.policy_generation,
        "surface": permit.surface,
        "host": permit.host,
        "port": permit.port,
        "matched_policy": permit.matched_policy,
        "binary_path": permit.binary_path,
        "binary_pid": permit.binary_pid,
        "intent_sha256": permit.intent_sha256,
        "committed_unix_ns": permit.committed_unix_ns,
    });
    let record_sha256 = sha256_hex(&serde_json::to_vec(&record).map_err(io::Error::other)?);
    if record_sha256 != permit.record_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BLACKBOX journal record commitment mismatch",
        ));
    }
    Ok(())
}


#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct JournalRecord {
    journal_schema: String,
    sequence: u64,
    prev_record_sha256: String,
    #[serde(flatten)]
    permit: DurableEgressPermit,
    journal_record_sha256: String,
}

#[derive(Serialize)]
struct JournalRecordCommitment<'a> {
    journal_schema: &'static str,
    sequence: u64,
    prev_record_sha256: &'a str,
    permit: &'a DurableEgressPermit,
}

fn compute_journal_record_sha256(
    sequence: u64,
    prev_record_sha256: &str,
    permit: &DurableEgressPermit,
) -> io::Result<String> {
    let commitment = JournalRecordCommitment {
        journal_schema: JOURNAL_RECORD_SCHEMA,
        sequence,
        prev_record_sha256,
        permit,
    };
    Ok(sha256_hex(
        &serde_json::to_vec(&commitment).map_err(io::Error::other)?,
    ))
}

impl JournalRecord {
    fn new(sequence: u64, prev_record_sha256: String, permit: DurableEgressPermit) -> io::Result<Self> {
        let journal_record_sha256 =
            compute_journal_record_sha256(sequence, &prev_record_sha256, &permit)?;
        Ok(Self {
            journal_schema: JOURNAL_RECORD_SCHEMA.to_string(),
            sequence,
            prev_record_sha256,
            permit,
            journal_record_sha256,
        })
    }

    fn validate(&self, expected_sequence: u64, expected_prev: &str) -> io::Result<()> {
        if self.journal_schema != JOURNAL_RECORD_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX journal record schema mismatch",
            ));
        }
        if self.sequence != expected_sequence {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "BLACKBOX journal sequence gap [expected:{expected_sequence} actual:{}]",
                    self.sequence
                ),
            ));
        }
        if self.prev_record_sha256 != expected_prev {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX journal hash-chain predecessor mismatch",
            ));
        }
        validate_permit_record(&self.permit)?;
        let expected_hash = compute_journal_record_sha256(
            self.sequence,
            &self.prev_record_sha256,
            &self.permit,
        )?;
        if expected_hash != self.journal_record_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX journal record hash mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct HighWaterWitness {
    schema: String,
    sequence: u64,
    head_record_sha256: String,
    updated_unix_ns: u64,
    witness_sha256: String,
}

#[derive(Serialize)]
struct WitnessCommitment<'a> {
    schema: &'static str,
    sequence: u64,
    head_record_sha256: &'a str,
    updated_unix_ns: u64,
}

fn compute_witness_sha256(
    sequence: u64,
    head_record_sha256: &str,
    updated_unix_ns: u64,
) -> io::Result<String> {
    let commitment = WitnessCommitment {
        schema: WITNESS_SCHEMA,
        sequence,
        head_record_sha256,
        updated_unix_ns,
    };
    Ok(sha256_hex(
        &serde_json::to_vec(&commitment).map_err(io::Error::other)?,
    ))
}

impl HighWaterWitness {
    fn new(sequence: u64, head_record_sha256: String) -> io::Result<Self> {
        let updated_unix_ns = unix_ns();
        let witness_sha256 =
            compute_witness_sha256(sequence, &head_record_sha256, updated_unix_ns)?;
        Ok(Self {
            schema: WITNESS_SCHEMA.to_string(),
            sequence,
            head_record_sha256,
            updated_unix_ns,
            witness_sha256,
        })
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema != WITNESS_SCHEMA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX high-water witness schema mismatch",
            ));
        }
        if self.sequence == 0 && self.head_record_sha256 != GENESIS_HASH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX genesis witness hash mismatch",
            ));
        }
        let expected = compute_witness_sha256(
            self.sequence,
            &self.head_record_sha256,
            self.updated_unix_ns,
        )?;
        if expected != self.witness_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX high-water witness commitment mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JournalHead {
    sequence: u64,
    record_sha256: String,
}

impl JournalHead {
    fn genesis() -> Self {
        Self {
            sequence: 0,
            record_sha256: GENESIS_HASH.to_string(),
        }
    }
}

#[derive(Debug)]
struct StoreState {
    head: JournalHead,
    poisoned: bool,
}

struct JournalRecovery {
    head: JournalHead,
    valid_len: usize,
    total_len: usize,
}

fn witness_path_for(journal: &Path) -> PathBuf {
    let mut value = journal.as_os_str().to_os_string();
    value.push(".witness");
    PathBuf::from(value)
}

fn read_high_water_witness(path: &Path) -> io::Result<HighWaterWitness> {
    let bytes = std::fs::read(path)?;
    let witness: HighWaterWitness = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    witness.validate()?;
    Ok(witness)
}

fn write_high_water_witness(path: &Path, head: &JournalHead) -> io::Result<HighWaterWitness> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let witness = HighWaterWitness::new(head.sequence, head.record_sha256.clone())?;
    let mut bytes = serde_json::to_vec(&witness).map_err(io::Error::other)?;
    bytes.push(b'\n');

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("blackbox-witness");
    let temp_path = parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4()));

    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        sync_parent_directory(parent)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }
    write_result?;
    Ok(witness)
}

fn recover_and_validate_journal(
    file: &mut File,
    witness: Option<&HighWaterWitness>,
) -> io::Result<JournalRecovery> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    let valid_len = if bytes.ends_with(b"\n") {
        bytes.len()
    } else {
        bytes.iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1)
    };

    let mut head = JournalHead::genesis();
    let mut start = 0usize;
    let mut witness_matched = witness.is_some_and(|value| value.sequence == 0);

    while start < valid_len {
        let relative_end = bytes[start..valid_len]
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "BLACKBOX journal framing error"))?;
        let end = start + relative_end;
        if end == start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX journal contains an empty interior record",
            ));
        }

        let record: JournalRecord =
            serde_json::from_slice(&bytes[start..end]).map_err(io::Error::other)?;
        let expected_sequence = head.sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "BLACKBOX journal sequence overflow")
        })?;
        record.validate(expected_sequence, &head.record_sha256)?;

        if let Some(witness) = witness
            && record.sequence == witness.sequence
        {
            if record.journal_record_sha256 != witness.head_record_sha256 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "BLACKBOX journal disagrees with preserved high-water witness",
                ));
            }
            witness_matched = true;
        }

        head = JournalHead {
            sequence: record.sequence,
            record_sha256: record.journal_record_sha256,
        };
        start = end + 1;
    }

    if let Some(witness) = witness {
        if witness.sequence > head.sequence {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "BLACKBOX journal rollback detected [witness_sequence:{} journal_sequence:{}]",
                    witness.sequence, head.sequence
                ),
            ));
        }
        if !witness_matched {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX journal does not contain preserved witness head",
            ));
        }
    }

    Ok(JournalRecovery {
        head,
        valid_len,
        total_len: bytes.len(),
    })
}

#[derive(Debug)]
struct PermitStore {
    path: PathBuf,
    witness_path: PathBuf,
    file: Mutex<File>,
    fence_file: Mutex<File>,
    state: Mutex<StoreState>,
    writer_token: String,
}

impl PermitStore {
    fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let witness_path = witness_path_for(&path);
        Self::open_with_witness(path, witness_path)
    }

    fn open_with_witness(
        path: impl AsRef<Path>,
        witness_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let witness_path = witness_path.as_ref().to_path_buf();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;

        let lock_path = lock_path_for(&path);
        let journal_existed = path.exists();
        let lock_existed = lock_path.exists();
        let witness_existed = witness_path.exists();

        if !journal_existed && witness_existed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX journal missing while high-water witness exists",
            ));
        }
        if journal_existed && !witness_existed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX high-water witness missing for existing journal",
            ));
        }

        let mut fence_file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        file_lock_exclusive(&fence_file)?;

        let writer_token = Uuid::new_v4().to_string();
        let setup_result = (|| -> io::Result<(File, JournalHead)> {
            fence_file.set_len(0)?;
            fence_file.seek(SeekFrom::Start(0))?;
            fence_file.write_all(writer_token.as_bytes())?;
            fence_file.write_all(b"\n")?;
            fence_file.sync_all()?;

            let witness = if witness_existed {
                Some(read_high_water_witness(&witness_path)?)
            } else {
                None
            };

            let mut journal = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .write(true)
                .open(&path)?;

            let recovery = recover_and_validate_journal(&mut journal, witness.as_ref())?;

            if recovery.valid_len < recovery.total_len {
                journal.set_len(u64::try_from(recovery.valid_len).map_err(io::Error::other)?)?;
                journal.sync_all()?;
            }
            journal.seek(SeekFrom::End(0))?;

            match witness {
                None => {
                    if recovery.head.sequence != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "BLACKBOX non-empty journal has no high-water witness",
                        ));
                    }
                    write_high_water_witness(&witness_path, &recovery.head)?;
                }
                Some(existing) if recovery.head.sequence > existing.sequence => {
                    write_high_water_witness(&witness_path, &recovery.head)?;
                }
                Some(_) => {}
            }

            if !journal_existed || !lock_existed {
                sync_parent_directory(parent)?;
            }

            Ok((journal, recovery.head))
        })();

        let unlock_result = file_lock_release(&fence_file);
        let (file, head) = setup_result?;
        unlock_result?;

        Ok(Self {
            path,
            witness_path,
            file: Mutex::new(file),
            fence_file: Mutex::new(fence_file),
            state: Mutex::new(StoreState {
                head,
                poisoned: false,
            }),
            writer_token,
        })
    }

    fn append_and_sync(&self, permit: &DurableEgressPermit) -> io::Result<()> {
        let mut fence_file = self
            .fence_file
            .lock()
            .map_err(|_| io::Error::other("BLACKBOX writer fence lock poisoned"))?;
        file_lock_exclusive(&fence_file)?;

        let result = (|| -> io::Result<()> {
            let current_token = read_writer_token(&mut fence_file)?;
            if current_token != self.writer_token {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "BLACKBOX stale journal writer fenced by a newer store instance",
                ));
            }

            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("BLACKBOX journal state lock poisoned"))?;
            if state.poisoned {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "BLACKBOX journal store requires restart reconciliation",
                ));
            }

            let next_sequence = state.head.sequence.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "BLACKBOX journal sequence overflow")
            })?;
            let record = JournalRecord::new(
                next_sequence,
                state.head.record_sha256.clone(),
                permit.clone(),
            )?;
            let mut line = serde_json::to_vec(&record).map_err(io::Error::other)?;
            line.push(b'\n');

            let mut file = self
                .file
                .lock()
                .map_err(|_| io::Error::other("BLACKBOX permit journal lock poisoned"))?;

            if let Err(error) = file.write_all(&line).and_then(|_| file.sync_all()) {
                state.poisoned = true;
                return Err(error);
            }

            let next_head = JournalHead {
                sequence: record.sequence,
                record_sha256: record.journal_record_sha256.clone(),
            };
            if let Err(error) = write_high_water_witness(&self.witness_path, &next_head) {
                state.poisoned = true;
                return Err(error);
            }

            state.head = next_head;
            Ok(())
        })();

        let unlock_result = file_lock_release(&fence_file);
        result?;
        unlock_result
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    fn witness_path(&self) -> &Path {
        &self.witness_path
    }

    #[cfg(test)]
    fn writer_token(&self) -> &str {
        &self.writer_token
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
        let journal_path = journal_path.as_ref().to_path_buf();
        let witness_path = witness_path_for(&journal_path);
        Self::new_with_witness(sandbox_id, authority, journal_path, witness_path)
    }

    pub(crate) fn new_with_witness(
        sandbox_id: impl Into<String>,
        authority: Arc<DispatchAuthorityFence>,
        journal_path: impl AsRef<Path>,
        witness_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let sandbox_id = sandbox_id.into();
        if sandbox_id.is_empty() {
            return Err(miette::miette!("BLACKBOX durable egress gate requires sandbox_id"));
        }
        Ok(Self {
            sandbox_id: Arc::<str>::from(sandbox_id),
            authority,
            store: Arc::new(
                PermitStore::open_with_witness(journal_path, witness_path).into_diagnostic()?,
            ),
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
    let journal_path = PathBuf::from(path);
    let witness_path = std::env::var_os(WITNESS_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| witness_path_for(&journal_path));
    Ok(Some(Arc::new(DurableEgressPermitGate::new_with_witness(
        sandbox_id,
        Arc::clone(&GLOBAL_DISPATCH_FENCE),
        journal_path,
        witness_path,
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


    #[tokio::test]
    async fn newer_store_instance_fences_older_writer_without_killing_it() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp13-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");

        let old_gate = DurableEgressPermitGate::new(
            "sandbox-old",
            Arc::clone(&authority),
            &journal,
        )
        .unwrap();
        let old_token = old_gate.store.writer_token().to_string();

        let new_gate = DurableEgressPermitGate::new(
            "sandbox-new",
            Arc::clone(&authority),
            &journal,
        )
        .unwrap();
        let new_token = new_gate.store.writer_token().to_string();
        assert_ne!(old_token, new_token);

        let stale_result = old_gate.commit_before_effect(&guard, test_input()).await;
        assert!(stale_result.is_err(), "superseded writer must fail closed");

        let permit = new_gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("newest writer must append");
        let recovered = std::fs::read_to_string(&journal).unwrap();
        assert_eq!(recovered.lines().count(), 1);
        assert!(recovered.contains(&permit.operation_id));
    }

    #[tokio::test]
    async fn torn_tail_is_truncated_to_last_verified_record() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp13-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let gate = DurableEgressPermitGate::new(
            "sandbox-a",
            Arc::clone(&authority),
            &journal,
        )
        .unwrap();
        let permit = gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("baseline permit");
        drop(gate);

        {
            let mut file = OpenOptions::new().append(true).open(&journal).unwrap();
            file.write_all(br#"{"schema":"torn"#).unwrap();
            file.sync_all().unwrap();
        }

        let reopened = DurableEgressPermitGate::new(
            "sandbox-b",
            Arc::clone(&authority),
            &journal,
        )
        .expect("torn final fragment should be recovered");
        drop(reopened);

        let recovered = std::fs::read_to_string(&journal).unwrap();
        assert_eq!(recovered.lines().count(), 1);
        assert!(recovered.ends_with('\n'));
        assert!(recovered.contains(&permit.operation_id));
        assert!(!recovered.contains("torn"));
    }

    #[tokio::test]
    async fn complete_corrupt_record_fails_closed_and_fences_previous_writer() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp13-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let old_gate = DurableEgressPermitGate::new(
            "sandbox-old",
            Arc::clone(&authority),
            &journal,
        )
        .unwrap();
        old_gate
            .commit_before_effect(&guard, test_input())
            .await
            .expect("baseline permit");

        {
            let mut file = OpenOptions::new().append(true).open(&journal).unwrap();
            file.write_all(b"{\"complete_but_corrupt\":true}\n").unwrap();
            file.sync_all().unwrap();
        }

        let reopen = DurableEgressPermitGate::new(
            "sandbox-new",
            Arc::clone(&authority),
            &journal,
        );
        assert!(reopen.is_err(), "complete corrupt record must fail closed");

        let stale_result = old_gate.commit_before_effect(&guard, test_input()).await;
        assert!(
            stale_result.is_err(),
            "failed recovery attempt must still fence the previously active writer"
        );
    }

    #[test]
    fn new_store_durably_creates_journal_and_fence_files() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let journal = nested.join("permits.jsonl");
        let lock_path = lock_path_for(&journal);

        let store = PermitStore::open(&journal).unwrap();
        assert!(journal.exists());
        assert!(lock_path.exists());
        assert!(!store.writer_token().is_empty());
        sync_parent_directory(&nested).unwrap();
    }

    #[test]
    fn cp13_stale_writer_child() {
        if std::env::var_os("BLACKBOX_CP13_CHILD").is_none() {
            return;
        }

        let journal = PathBuf::from(std::env::var("BLACKBOX_CP13_JOURNAL").unwrap());
        let marker = PathBuf::from(std::env::var("BLACKBOX_CP13_MARKER").unwrap());
        let command = PathBuf::from(std::env::var("BLACKBOX_CP13_COMMAND").unwrap());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async move {
            let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
            let guard = engine
                .generation_guard(engine.current_generation())
                .expect("current generation guard");
            let authority = Arc::new(DispatchAuthorityFence::default());
            authority.publish_session(Some("cp13-child-session".into()));
            let gate =
                DurableEgressPermitGate::new("cp13-child", authority, &journal).unwrap();

            cp12_write_marker(&marker, "opened");

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            while !command.exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "CP13 child timed out waiting for command"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }

            match gate.commit_before_effect(&guard, test_input()).await {
                Ok(_) => cp12_write_marker(&marker, "unexpected_success"),
                Err(_) => cp12_write_marker(&marker, "stale_rejected"),
            }
        });
    }

    #[cfg(unix)]
    fn cp13_wait_for_marker_value(path: &Path, expected: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Ok(value) = std::fs::read_to_string(path)
                && value == expected
            {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for CP13 marker value {expected}"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[test]
    fn live_old_process_is_fenced_by_newer_writer_process() {
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let marker = dir.path().join("marker");
        let command = dir.path().join("command");

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("durable_egress::tests::cp13_stale_writer_child")
            .arg("--nocapture")
            .env("BLACKBOX_CP13_CHILD", "1")
            .env("BLACKBOX_CP13_JOURNAL", &journal)
            .env("BLACKBOX_CP13_MARKER", &marker)
            .env("BLACKBOX_CP13_COMMAND", &command)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn CP13 stale writer child");

        cp13_wait_for_marker_value(&marker, "opened");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let parent_operation = runtime.block_on(async {
            let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
            let guard = engine
                .generation_guard(engine.current_generation())
                .expect("current generation guard");
            let authority = Arc::new(DispatchAuthorityFence::default());
            authority.publish_session(Some("cp13-parent-session".into()));
            let gate =
                DurableEgressPermitGate::new("cp13-parent", authority, &journal).unwrap();
            gate.commit_before_effect(&guard, test_input())
                .await
                .expect("newer process writer permit")
                .operation_id
        });

        cp12_write_marker(&command, "go");
        cp13_wait_for_marker_value(&marker, "stale_rejected");

        let status = child.wait().expect("wait CP13 stale writer child");
        assert!(status.success());

        let recovered = std::fs::read_to_string(&journal).unwrap();
        assert_eq!(recovered.lines().count(), 1);
        assert!(recovered.contains(&parent_operation));
    }


    fn cp14_read_records(path: &Path) -> Vec<JournalRecord> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<JournalRecord>(line).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn hash_chain_links_records_and_witness_matches_head() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp14-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();

        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();

        let records = cp14_read_records(&journal);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sequence, 1);
        assert_eq!(records[0].prev_record_sha256, GENESIS_HASH);
        assert_eq!(records[1].sequence, 2);
        assert_eq!(
            records[1].prev_record_sha256,
            records[0].journal_record_sha256
        );

        let witness = read_high_water_witness(gate.store.witness_path()).unwrap();
        assert_eq!(witness.sequence, 2);
        assert_eq!(
            witness.head_record_sha256,
            records[1].journal_record_sha256
        );
    }

    #[tokio::test]
    async fn preserved_witness_detects_deleted_valid_tail_record() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp14-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        let records = cp14_read_records(&journal);
        let first_line = serde_json::to_string(&records[0]).unwrap() + "\n";
        drop(gate);

        std::fs::write(&journal, first_line).unwrap();

        let reopened =
            DurableEgressPermitGate::new("sandbox-b", Arc::clone(&authority), &journal);
        assert!(
            reopened.is_err(),
            "preserved high-water witness must detect deletion of a valid journal tail"
        );
    }

    #[tokio::test]
    async fn hash_chain_detects_deleted_middle_record() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp14-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        let records = cp14_read_records(&journal);
        drop(gate);

        let forged_prefix = format!(
            "{}\n{}\n",
            serde_json::to_string(&records[0]).unwrap(),
            serde_json::to_string(&records[2]).unwrap()
        );
        std::fs::write(&journal, forged_prefix).unwrap();

        let reopened =
            DurableEgressPermitGate::new("sandbox-b", Arc::clone(&authority), &journal);
        assert!(
            reopened.is_err(),
            "sequence/hash-chain validation must detect a deleted interior record"
        );
    }

    #[tokio::test]
    async fn missing_witness_for_existing_journal_fails_closed() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp14-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let witness = witness_path_for(&journal);
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        drop(gate);

        std::fs::remove_file(&witness).unwrap();

        let reopened =
            DurableEgressPermitGate::new("sandbox-b", Arc::clone(&authority), &journal);
        assert!(reopened.is_err());
    }

    #[tokio::test]
    async fn corrupt_witness_commitment_fails_closed() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp14-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let witness_path = witness_path_for(&journal);
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        drop(gate);

        let mut witness = read_high_water_witness(&witness_path).unwrap();
        witness.head_record_sha256 = GENESIS_HASH.to_string();
        std::fs::write(
            &witness_path,
            serde_json::to_vec(&witness).unwrap(),
        )
        .unwrap();

        let reopened =
            DurableEgressPermitGate::new("sandbox-b", Arc::clone(&authority), &journal);
        assert!(reopened.is_err());
    }

    #[tokio::test]
    async fn valid_journal_ahead_of_witness_fast_forwards_witness() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp14-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("permits.jsonl");
        let witness_path = witness_path_for(&journal);
        let gate =
            DurableEgressPermitGate::new("sandbox-a", Arc::clone(&authority), &journal).unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        let records = cp14_read_records(&journal);
        drop(gate);

        let older_head = JournalHead {
            sequence: records[0].sequence,
            record_sha256: records[0].journal_record_sha256.clone(),
        };
        write_high_water_witness(&witness_path, &older_head).unwrap();

        let reopened =
            DurableEgressPermitGate::new("sandbox-b", Arc::clone(&authority), &journal)
                .expect("valid journal extension beyond witness should reconcile forward");
        drop(reopened);

        let witness = read_high_water_witness(&witness_path).unwrap();
        assert_eq!(witness.sequence, records[1].sequence);
        assert_eq!(
            witness.head_record_sha256,
            records[1].journal_record_sha256
        );
    }

    #[tokio::test]
    async fn separately_configured_witness_path_detects_journal_rollback() {
        let engine = OpaEngine::from_strings(POLICY, "network_policies: {}\n").unwrap();
        let guard = engine
            .generation_guard(engine.current_generation())
            .expect("current generation guard");
        let authority = Arc::new(DispatchAuthorityFence::default());
        authority.publish_session(Some("cp14-session".into()));

        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("journal").join("permits.jsonl");
        let witness = dir.path().join("witness-store").join("head.json");

        let gate = DurableEgressPermitGate::new_with_witness(
            "sandbox-a",
            Arc::clone(&authority),
            &journal,
            &witness,
        )
        .unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        gate.commit_before_effect(&guard, test_input()).await.unwrap();
        let records = cp14_read_records(&journal);
        drop(gate);

        std::fs::write(
            &journal,
            serde_json::to_string(&records[0]).unwrap() + "\n",
        )
        .unwrap();

        let reopened = DurableEgressPermitGate::new_with_witness(
            "sandbox-b",
            Arc::clone(&authority),
            &journal,
            &witness,
        );
        assert!(reopened.is_err());
    }

}
