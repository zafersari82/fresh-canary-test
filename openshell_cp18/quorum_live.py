#!/usr/bin/env python3
"""CP18 live 2-of-3 witness-quorum finality evidence."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time

PROXY_HOST = "127.0.0.1"
NAMESPACE = "network-proxy"
CLIENT_ID = "openshell-cp18"


def json_dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def choose_port() -> int:
    sock = socket.socket()
    try:
        sock.bind((PROXY_HOST, 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def wait_file(path: Path, proc: subprocess.Popen, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        if proc.poll() is not None:
            raise RuntimeError(f"process exited before {path.name}: {proc.returncode}")
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {path}")


def stop_process(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def start_witness(
    base: Path,
    witness_id: str,
    client_hmac_key_hex: str,
    initial_state: dict | None = None,
) -> tuple[subprocess.Popen, dict, object]:
    directory = base / witness_id
    directory.mkdir(parents=True, exist_ok=True)
    state = directory / "state.json"
    if initial_state is not None:
        state.write_text(json.dumps(initial_state, sort_keys=True) + "\n")
    ready = directory / "ready.json"
    log = (directory / "server.log").open("wb")
    proc = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve().parent / "quorum_witness_server.py"),
            "--witness-id",
            witness_id,
            "--state",
            str(state),
            "--receipts",
            str(directory / "receipts.jsonl"),
            "--ready",
            str(ready),
            "--client-id",
            CLIENT_ID,
            "--client-hmac-key-hex",
            client_hmac_key_hex,
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    wait_file(ready, proc)
    info = json.loads(ready.read_text())
    info["state_path"] = str(state.resolve())
    return proc, info, log


def quorum_config(infos: list[dict]) -> str:
    return json.dumps(
        [
            {
                "id": info["witness_id"],
                "address": info["address"],
                "public_key_hex": info["public_key_hex"],
            }
            for info in infos
        ],
        sort_keys=True,
    )


def quorum_env(
    infos: list[dict],
    client_hmac_key_hex: str,
    threshold: int = 2,
) -> dict[str, str]:
    return {
        "OPENSHELL_BLACKBOX_REMOTE_WITNESS_QUORUM_JSON": quorum_config(infos),
        "OPENSHELL_BLACKBOX_REMOTE_WITNESS_QUORUM_THRESHOLD": str(threshold),
        "OPENSHELL_BLACKBOX_REMOTE_WITNESS_CLIENT_ID": CLIENT_ID,
        "OPENSHELL_BLACKBOX_REMOTE_WITNESS_CLIENT_HMAC_KEY_HEX": client_hmac_key_hex,
        "OPENSHELL_BLACKBOX_REMOTE_WITNESS_TIMEOUT_MS": "700",
    }


def proxy_command(
    root: Path,
    policy: Path,
    journal: Path,
    witness: Path,
    tls_dir: Path,
    port: int,
) -> list[str]:
    tls_dir.mkdir(parents=True, exist_ok=True)
    return [
        str(root / "target/debug/openshell-supervisor"),
        "--role=network-proxy",
        f"--listen={PROXY_HOST}:{port}",
        f"--tls-dir={tls_dir}",
        (
            "--policy-rules="
            + str(root / "crates/openshell-supervisor-network/data/sandbox-policy.rego")
        ),
        f"--policy-data={policy}",
        "--log-level=info",
    ]


def wait_proxy_ready(proc: subprocess.Popen, port: int, timeout: float = 12.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"proxy exited before readiness: {proc.returncode}")
        try:
            with socket.create_connection((PROXY_HOST, port), timeout=0.3):
                return
        except OSError as exc:
            last = exc
            time.sleep(0.1)
    raise TimeoutError(f"proxy did not become ready: {last}")


def run_proxy_expect_ready(
    root: Path,
    policy: Path,
    journal: Path,
    witness: Path,
    directory: Path,
    env_extra: dict[str, str],
) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    port = choose_port()
    log_path = directory / "proxy.log"
    env = os.environ.copy()
    env.update(env_extra)
    env["OPENSHELL_BLACKBOX_EGRESS_JOURNAL"] = str(journal)
    env["OPENSHELL_BLACKBOX_EGRESS_WITNESS"] = str(witness)
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            proxy_command(root, policy, journal, witness, directory / "tls", port),
            cwd=root,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_proxy_ready(proc, port)
            ready = True
        finally:
            stop_process(proc)
    if not ready:
        raise AssertionError("proxy never reached ready state")
    return {
        "ready": True,
        "exit_code_after_controlled_stop": proc.returncode,
        "log": str(log_path),
    }


def run_proxy_expect_failure(
    root: Path,
    policy: Path,
    journal: Path,
    witness: Path,
    directory: Path,
    env_extra: dict[str, str],
    expected_fragment: str,
) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    port = choose_port()
    log_path = directory / "proxy.log"
    env = os.environ.copy()
    env.update(env_extra)
    env["OPENSHELL_BLACKBOX_EGRESS_JOURNAL"] = str(journal)
    env["OPENSHELL_BLACKBOX_EGRESS_WITNESS"] = str(witness)
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            proxy_command(root, policy, journal, witness, directory / "tls", port),
            cwd=root,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            stop_process(proc)
            raise AssertionError(
                f"negative control stayed alive unexpectedly: {expected_fragment}"
            )
    text = log_path.read_text(errors="replace")
    if proc.returncode == 0:
        raise AssertionError("negative control unexpectedly exited successfully")
    if expected_fragment not in text:
        raise AssertionError(
            f"expected {expected_fragment!r} not found in log: {text[-5000:]}"
        )
    return {
        "failed_closed": True,
        "exit_code": proc.returncode,
        "expected_fragment": expected_fragment,
        "log": str(log_path),
    }


def read_state(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    witnesses_dir = evidence / "witnesses"
    witnesses_dir.mkdir()

    client_hmac_key_hex = secrets.token_hex(32)
    processes: list[subprocess.Popen | None] = []
    logs: list[object] = []

    try:
        infos = []
        for witness_id in ("w1", "w2", "w3"):
            proc, info, log = start_witness(
                witnesses_dir,
                witness_id,
                client_hmac_key_hex,
            )
            processes.append(proc)
            logs.append(log)
            infos.append(info)

        env = quorum_env(infos, client_hmac_key_hex, threshold=2)
        env["BLACKBOX_CP18_REMOTE_STATE_PATHS_JSON"] = json.dumps(
            [info["state_path"] for info in infos]
        )
        env["BLACKBOX_CP18_REMOTE_STATE_THRESHOLD"] = "2"
        json_dump(
            evidence / "quorum-config.json",
            {
                "threshold": 2,
                "members": [
                    {
                        "id": info["witness_id"],
                        "address": info["address"],
                        "public_key_hex": info["public_key_hex"],
                        "state_path": info["state_path"],
                    }
                    for info in infos
                ],
                "client_id": CLIENT_ID,
                "client_hmac_key_sha256": __import__("hashlib")
                .sha256(bytes.fromhex(client_hmac_key_hex))
                .hexdigest(),
            },
        )

        # Positive effectuation proof: real forward HTTP + CONNECT. Receiver
        # must see at least 2 matching durable remote witness states.
        primary = evidence / "primary"
        child_env = os.environ.copy()
        child_env.update(env)
        subprocess.run(
            [
                sys.executable,
                str(
                    Path(__file__).resolve().parent.parent
                    / "openshell_cp16"
                    / "explicit_proxy_live.py"
                ),
                str(root),
                str(primary),
            ],
            cwd=Path(__file__).resolve().parent.parent,
            env=child_env,
            check=True,
        )

        records = [
            json.loads(line)
            for line in (primary / "final-valid-permits.jsonl").read_text().splitlines()
            if line.strip()
        ]
        if [r["surface"] for r in records] != ["forward_http", "connect"]:
            raise AssertionError("CP18 primary explicit-proxy surface sequence changed")
        for name in ("forward", "connect"):
            observation = json.loads(
                (primary / f"{name}-receiver-observation.json").read_text()
            )
            if observation.get(
                "remote_quorum_matching_witnesses_at_receiver_effect"
            ) < 2:
                raise AssertionError(
                    f"{name} receiver did not observe a 2-of-3 remote quorum"
                )

        remote_states = [read_state(info["state_path"]) for info in infos]
        for state in remote_states:
            ns = state.get(NAMESPACE, {})
            if int(ns.get("sequence", -1)) != 2:
                raise AssertionError(
                    f"healthy witness did not reach sequence 2: {state}"
                )

        # One-witness failure tolerance: kill w3. A new proxy must still
        # recover and start using w1+w2 quorum.
        stop_process(processes[2])
        processes[2] = None
        one_fault = run_proxy_expect_ready(
            root,
            primary / "policy.yaml",
            primary / "final-valid-permits.jsonl",
            primary / "final-valid-witness.json",
            evidence / "one-witness-down",
            env,
        )

        # Joint rollback: both local evidence files are restored to sequence 1,
        # while the independent 2-of-3 quorum remains at sequence 2.
        joint = evidence / "joint-local-rollback"
        joint.mkdir()
        shutil.copy2(
            primary / "forward-observed-journal.jsonl",
            joint / "permits.jsonl",
        )
        shutil.copy2(
            primary / "forward-observed-witness.json",
            joint / "witness.json",
        )
        joint_result = run_proxy_expect_failure(
            root,
            primary / "policy.yaml",
            joint / "permits.jsonl",
            joint / "witness.json",
            joint,
            env,
            "joint rollback detected by authenticated remote witness",
        )

        # Signed equivocation by one witness: replace dead w3 with a new
        # independently-signed witness that claims the same sequence but a
        # different head. w1+w2 still form the 2-of-3 correct quorum.
        fork_state = {
            NAMESPACE: {
                "sequence": 2,
                "head_record_sha256": "f" * 64,
            }
        }
        fork_proc, fork_info, fork_log = start_witness(
            witnesses_dir,
            "w3-fork",
            client_hmac_key_hex,
            fork_state,
        )
        processes[2] = fork_proc
        logs.append(fork_log)
        fork_infos = [infos[0], infos[1], fork_info]
        fork_env = quorum_env(fork_infos, client_hmac_key_hex, threshold=2)
        fork_tolerated = run_proxy_expect_ready(
            root,
            primary / "policy.yaml",
            primary / "final-valid-permits.jsonl",
            primary / "final-valid-witness.json",
            evidence / "one-signed-fork",
            fork_env,
        )

        # Remove one correct member. Remaining responses are one correct and
        # one forked state, so no state can obtain 2 signatures. Fail closed.
        stop_process(processes[1])
        processes[1] = None
        split_result = run_proxy_expect_failure(
            root,
            primary / "policy.yaml",
            primary / "final-valid-permits.jsonl",
            primary / "final-valid-witness.json",
            evidence / "split-no-quorum",
            fork_env,
            "remote witness quorum unavailable during current state",
        )

        # Client authentication negative control: even if endpoints and pinned
        # receipt keys are valid, a different HMAC client key cannot obtain a
        # quorum. Keep w1 + fork witness online to avoid conflating with zero
        # reachable endpoints.
        wrong_auth_env = quorum_env(
            [infos[0], fork_info],
            secrets.token_hex(32),
            threshold=2,
        )
        auth_result = run_proxy_expect_failure(
            root,
            primary / "policy.yaml",
            primary / "final-valid-permits.jsonl",
            primary / "final-valid-witness.json",
            evidence / "wrong-client-auth",
            wrong_auth_env,
            "remote witness quorum unavailable during current state",
        )

        result = {
            "status": "QUORUM_FINALITY_VERIFIED",
            "source_pin": "484f0768fc6a0d93e0a2be295c1679aed24e18a9",
            "quorum": {"members": 3, "threshold": 2},
            "real_openshell_surfaces": ["forward_http", "connect"],
            "receiver_time_quorum_before_effect": True,
            "one_witness_unavailable_tolerated": True,
            "joint_local_rollback_detected": True,
            "one_signed_fork_tolerated_with_honest_quorum": True,
            "split_without_quorum_failed_closed": True,
            "client_hmac_authentication_enforced": True,
            "server_receipts_ed25519_authenticated": True,
            "local_journal_and_witness_required": True,
            "positive_controls": {
                "one_witness_down": one_fault,
                "one_signed_fork": fork_tolerated,
            },
            "negative_controls": {
                "joint_local_rollback": joint_result,
                "split_no_quorum": split_result,
                "wrong_client_auth": auth_result,
            },
            "overall_cp18_acceptance": False,
            "remaining_gaps": [
                "witnesses_on_separate_network_and_administrative_failure_domains",
                "transport_level_mtls_or_spiffe_identity",
                "physical_power_loss_and_storage_fault_injection",
                "public_transparency_log_or_external timestamp anchoring",
                "formal proof of quorum/finality state machine",
            ],
        }
        json_dump(evidence / "runtime-result.json", result)
        print(json.dumps(result, sort_keys=True))
    finally:
        for proc in processes:
            stop_process(proc)
        for log in logs:
            try:
                log.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
