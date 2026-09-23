#!/usr/bin/env python3
"""Apply CP16 then add CP17 authenticated remote witness semantics."""
from pathlib import Path
import subprocess
import sys

PIN = "484f0768fc6a0d93e0a2be295c1679aed24e18a9"
HERE = Path(__file__).resolve().parent


def rep(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_cp17.py /path/to/pinned/OpenShell")
    root = Path(sys.argv[1]).resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != PIN:
        raise SystemExit(f"CP17 refuses source drift: {head}")
    if subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain"], text=True
    ).strip():
        raise SystemExit("CP17 requires an unmodified source checkout")

    subprocess.run(
        [sys.executable, str(HERE.parent / "openshell_cp16" / "apply_cp16.py"), str(root)],
        check=True,
    )

    # Remote witness module and crypto dependency.
    target = root / "crates/openshell-supervisor-network/src/remote_witness.rs"
    target.write_text((HERE / "remote_witness.rs").read_text())

    p = root / "crates/openshell-supervisor-network/src/lib.rs"
    s = p.read_text()
    s = rep(
        s,
        "pub mod durable_egress;\n",
        "pub mod durable_egress;\npub mod remote_witness;\n",
        "remote witness module",
    )
    p.write_text(s)

    p = root / "crates/openshell-supervisor-network/Cargo.toml"
    s = p.read_text()
    s = rep(
        s,
        "async-trait = \"0.1\"\n\n",
        "async-trait = \"0.1\"\naws-lc-rs = { workspace = true }\n\n",
        "remote witness crypto dependency",
    )
    p.write_text(s)

    p = root / "crates/openshell-supervisor-network/src/durable_egress.rs"
    s = p.read_text()

    s = rep(
        s,
        "use crate::opa::{OpaEngine, PolicyGenerationGuard};\n",
        "use crate::opa::{OpaEngine, PolicyGenerationGuard};\n"
        "use crate::remote_witness::{RemoteWitnessClient, RemoteWitnessState};\n",
        "remote witness import",
    )

    s = rep(
        s,
        """struct JournalRecovery {
    head: JournalHead,
    valid_len: usize,
    total_len: usize,
}""",
        """struct JournalRecovery {
    head: JournalHead,
    heads: Vec<JournalHead>,
    valid_len: usize,
    total_len: usize,
}""",
        "journal recovery heads",
    )

    s = rep(
        s,
        """    let mut head = JournalHead::genesis();
    let mut start = 0usize;""",
        """    let mut head = JournalHead::genesis();
    let mut heads = vec![head.clone()];
    let mut start = 0usize;""",
        "recovery head vector init",
    )

    s = rep(
        s,
        """        head = JournalHead {
            sequence: record.sequence,
            record_sha256: record.journal_record_sha256,
        };
        start = end + 1;""",
        """        head = JournalHead {
            sequence: record.sequence,
            record_sha256: record.journal_record_sha256,
        };
        heads.push(head.clone());
        start = end + 1;""",
        "recovery head vector append",
    )

    s = rep(
        s,
        """    Ok(JournalRecovery {
        head,
        valid_len,
        total_len: bytes.len(),
    })
}""",
        """    Ok(JournalRecovery {
        head,
        heads,
        valid_len,
        total_len: bytes.len(),
    })
}

fn reconcile_remote_witness(
    client: &RemoteWitnessClient,
    recovery: &JournalRecovery,
) -> io::Result<RemoteWitnessState> {
    let mut remote = client.current()?;
    if remote.sequence > recovery.head.sequence {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "BLACKBOX joint rollback detected by authenticated remote witness \
                 [remote_sequence:{} local_sequence:{}]",
                remote.sequence, recovery.head.sequence
            ),
        ));
    }

    let remote_index = usize::try_from(remote.sequence).map_err(io::Error::other)?;
    let local_at_remote = recovery.heads.get(remote_index).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "BLACKBOX remote witness sequence is outside the validated local chain",
        )
    })?;
    if local_at_remote.record_sha256 != remote.head_record_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BLACKBOX authenticated remote witness disagrees with local chain",
        ));
    }

    while remote.sequence < recovery.head.sequence {
        let next_sequence = remote.sequence.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX remote witness sequence overflow during reconciliation",
            )
        })?;
        let next_index = usize::try_from(next_sequence).map_err(io::Error::other)?;
        let local_next = recovery.heads.get(next_index).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "BLACKBOX local recovery chain omitted a remote reconciliation head",
            )
        })?;
        let next = RemoteWitnessState {
            sequence: local_next.sequence,
            head_record_sha256: local_next.record_sha256.clone(),
        };
        remote = client.advance(&remote, &next)?;
    }

    Ok(remote)
}""",
        "remote witness reconciliation helper",
    )

    s = rep(
        s,
        """struct StoreState {
    head: JournalHead,
    poisoned: bool,
}""",
        """struct StoreState {
    head: JournalHead,
    remote_head: Option<RemoteWitnessState>,
    poisoned: bool,
}""",
        "store remote state",
    )

    s = rep(
        s,
        """struct PermitStore {
    path: PathBuf,
    witness_path: PathBuf,
    file: Mutex<File>,
    fence_file: Mutex<File>,
    state: Mutex<StoreState>,
    writer_token: String,
}""",
        """struct PermitStore {
    path: PathBuf,
    witness_path: PathBuf,
    file: Mutex<File>,
    fence_file: Mutex<File>,
    state: Mutex<StoreState>,
    writer_token: String,
    remote_witness: Option<RemoteWitnessClient>,
}""",
        "store remote client",
    )

    old = """    fn open_with_witness(
        path: impl AsRef<Path>,
        witness_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();"""
    new = """    fn open_with_witness(
        path: impl AsRef<Path>,
        witness_path: impl AsRef<Path>,
    ) -> io::Result<Self> {
        Self::open_with_remote_witness(path, witness_path, None)
    }

    fn open_with_remote_witness(
        path: impl AsRef<Path>,
        witness_path: impl AsRef<Path>,
        remote_witness: Option<RemoteWitnessClient>,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();"""
    s = rep(s, old, new, "remote-aware store open")

    s = rep(
        s,
        "let setup_result = (|| -> io::Result<(File, JournalHead)> {",
        "let setup_result = (|| -> io::Result<(File, JournalHead, Option<RemoteWitnessState>)> {",
        "remote-aware setup result type",
    )

    s = rep(
        s,
        """            Ok((journal, recovery.head))
        })();

        let unlock_result = file_lock_release(&fence_file);
        let (file, head) = setup_result?;""",
        """            let remote_head = remote_witness
                .as_ref()
                .map(|client| reconcile_remote_witness(client, &recovery))
                .transpose()?;

            Ok((journal, recovery.head, remote_head))
        })();

        let unlock_result = file_lock_release(&fence_file);
        let (file, head, remote_head) = setup_result?;""",
        "startup remote reconciliation",
    )

    s = rep(
        s,
        """            state: Mutex::new(StoreState {
                head,
                poisoned: false,
            }),
            writer_token,
        })""",
        """            state: Mutex::new(StoreState {
                head,
                remote_head,
                poisoned: false,
            }),
            writer_token,
            remote_witness,
        })""",
        "store remote fields construction",
    )

    s = rep(
        s,
        """            if let Err(error) = write_high_water_witness(&self.witness_path, &next_head) {
                state.poisoned = true;
                return Err(error);
            }

            state.head = next_head;
            Ok(())""",
        """            if let Err(error) = write_high_water_witness(&self.witness_path, &next_head) {
                state.poisoned = true;
                return Err(error);
            }

            if let Some(client) = &self.remote_witness {
                let current_remote = state.remote_head.clone().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "BLACKBOX authenticated remote witness state is unavailable",
                    )
                })?;
                if current_remote.sequence != state.head.sequence
                    || current_remote.head_record_sha256 != state.head.record_sha256
                {
                    state.poisoned = true;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "BLACKBOX authenticated remote witness is not aligned with local pre-append head",
                    ));
                }
                let next_remote = RemoteWitnessState {
                    sequence: next_head.sequence,
                    head_record_sha256: next_head.record_sha256.clone(),
                };
                match client.advance(&current_remote, &next_remote) {
                    Ok(confirmed) => state.remote_head = Some(confirmed),
                    Err(error) => {
                        state.poisoned = true;
                        return Err(error);
                    }
                }
            }

            state.head = next_head;
            Ok(())""",
        "remote witness before append completion",
    )

    s = rep(
        s,
        """        Ok(Self {
            sandbox_id: Arc::<str>::from(sandbox_id),
            authority,
            store: Arc::new(
                PermitStore::open_with_witness(journal_path, witness_path).into_diagnostic()?,
            ),
        })""",
        """        let remote_witness =
            RemoteWitnessClient::from_env(&sandbox_id).into_diagnostic()?;
        Ok(Self {
            sandbox_id: Arc::<str>::from(sandbox_id),
            authority,
            store: Arc::new(
                PermitStore::open_with_remote_witness(
                    journal_path,
                    witness_path,
                    remote_witness,
                )
                .into_diagnostic()?,
            ),
        })""",
        "gate remote witness construction",
    )

    p.write_text(s)
    print(
        "CP17 applied: Ed25519-authenticated, nonce-fresh remote witness gates durable dispatch"
    )


if __name__ == "__main__":
    main()
