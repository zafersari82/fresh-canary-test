#!/usr/bin/env python3
"""CP17 live authenticated-remote-witness evidence."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time


def json_dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def choose_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
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


def run_proxy_expect_failure(
    root: Path,
    policy: Path,
    journal: Path,
    witness: Path,
    tls_dir: Path,
    log_path: Path,
    env_extra: dict[str, str],
    expected_log_fragment: str,
) -> dict:
    tls_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(env_extra)
    env["OPENSHELL_BLACKBOX_EGRESS_JOURNAL"] = str(journal)
    env["OPENSHELL_BLACKBOX_EGRESS_WITNESS"] = str(witness)
    port = choose_port()
    command = [
        str(root / "target/debug/openshell-supervisor"),
        "--role=network-proxy",
        f"--listen=127.0.0.1:{port}",
        f"--tls-dir={tls_dir}",
        (
            "--policy-rules="
            + str(root / "crates/openshell-supervisor-network/data/sandbox-policy.rego")
        ),
        f"--policy-data={policy}",
        "--log-level=info",
    ]
    with log_path.open("wb") as log:
        proc = subprocess.Popen(
            command,
            cwd=root,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            raise AssertionError(
                f"negative control stayed alive unexpectedly: {expected_log_fragment}"
            )
    text = log_path.read_text(errors="replace")
    if proc.returncode == 0:
        raise AssertionError("negative control unexpectedly exited successfully")
    if expected_log_fragment not in text:
        raise AssertionError(
            f"negative control did not expose expected reason {expected_log_fragment!r}: {text[-4000:]}"
        )
    return {
        "exit_code": proc.returncode,
        "expected_log_fragment": expected_log_fragment,
        "matched": True,
        "log": str(log_path),
    }


class FakeReceiptServer:
    def __init__(self, receipt: dict, mode: str):
        self.receipt = dict(receipt)
        self.mode = mode
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.address = f"127.0.0.1:{self.listener.getsockname()[1]}"
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            conn, _ = self.listener.accept()
            with conn:
                f = conn.makefile("rwb", buffering=0)
                request = json.loads(f.readline(65537))
                reply_receipt = dict(self.receipt)
                if self.mode == "replay":
                    # Keep the original signed nonce: signature is genuine but
                    # stale for this new request.
                    pass
                elif self.mode == "forged":
                    # Echo the request nonce but retain the old signature, so
                    # the receipt shape is fresh-looking but cryptographically false.
                    reply_receipt["nonce"] = request["nonce"]
                else:
                    raise ValueError(f"unsupported fake mode {self.mode}")
                response = {"ok": True, "receipt": reply_receipt}
                f.write((json.dumps(response, sort_keys=True) + "\n").encode())
        except BaseException as exc:
            self.error = exc
        finally:
            self.listener.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)

    witness_dir = evidence / "remote-witness"
    witness_dir.mkdir()
    ready = witness_dir / "ready.json"
    server_log = (witness_dir / "server.log").open("wb")
    server = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve().parent / "witness_server.py"),
            "--state",
            str(witness_dir / "state.json"),
            "--receipts",
            str(witness_dir / "receipts.jsonl"),
            "--ready",
            str(ready),
        ],
        stdout=server_log,
        stderr=subprocess.STDOUT,
    )

    try:
        wait_file(ready, server)
        witness_info = json.loads(ready.read_text())
        remote_env = {
            "OPENSHELL_BLACKBOX_REMOTE_WITNESS_ADDR": witness_info["address"],
            "OPENSHELL_BLACKBOX_REMOTE_WITNESS_PUBLIC_KEY_HEX": witness_info[
                "public_key_hex"
            ],
            "OPENSHELL_BLACKBOX_REMOTE_WITNESS_TIMEOUT_MS": "1500",
        }
        json_dump(evidence / "remote-witness-config.json", witness_info)

        # Reuse CP16's real forward-HTTP + CONNECT exercise. Its child proxy
        # inherits our remote-witness environment, so both receiver-visible
        # operations are now gated by local durability AND signed remote receipts.
        primary = evidence / "primary"
        env = os.environ.copy()
        env.update(remote_env)
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent.parent / "openshell_cp16" / "explicit_proxy_live.py"),
                str(root),
                str(primary),
            ],
            cwd=Path(__file__).resolve().parent.parent,
            env=env,
            check=True,
        )

        remote_state = json.loads((witness_dir / "state.json").read_text())
        state = remote_state.get("network-proxy")
        if not state or int(state["sequence"]) != 2:
            raise AssertionError(f"remote witness did not reach sequence 2: {remote_state}")
        final_records = [
            json.loads(line)
            for line in (primary / "final-valid-permits.jsonl").read_text().splitlines()
            if line.strip()
        ]
        if [record["surface"] for record in final_records] != [
            "forward_http",
            "connect",
        ]:
            raise AssertionError("primary explicit-proxy surface evidence changed")

        # Joint rollback: local journal AND local witness are both restored to
        # sequence 1. The independent signed witness remains at sequence 2.
        joint = evidence / "joint-rollback"
        joint.mkdir()
        shutil.copy2(primary / "forward-observed-journal.jsonl", joint / "permits.jsonl")
        shutil.copy2(primary / "forward-observed-witness.json", joint / "witness.json")
        joint_result = run_proxy_expect_failure(
            root,
            primary / "policy.yaml",
            joint / "permits.jsonl",
            joint / "witness.json",
            joint / "tls",
            joint / "proxy.log",
            remote_env,
            "joint rollback detected by authenticated remote witness",
        )

        receipts = [
            json.loads(line)
            for line in (witness_dir / "receipts.jsonl").read_text().splitlines()
            if line.strip()
        ]
        signed_seq2 = next(
            receipt
            for receipt in reversed(receipts)
            if int(receipt["sequence"]) == 2
            and receipt["namespace"] == "network-proxy"
        )

        # Replay: a genuine old signed receipt is returned for a new nonce.
        replay = evidence / "replay-control"
        replay.mkdir()
        replay_server = FakeReceiptServer(signed_seq2, "replay")
        replay_server.start()
        replay_env = dict(remote_env)
        replay_env["OPENSHELL_BLACKBOX_REMOTE_WITNESS_ADDR"] = replay_server.address
        replay_result = run_proxy_expect_failure(
            root,
            primary / "policy.yaml",
            primary / "final-valid-permits.jsonl",
            primary / "final-valid-witness.json",
            replay / "tls",
            replay / "proxy.log",
            replay_env,
            "receipt nonce mismatch (replay rejected)",
        )
        replay_server.thread.join(timeout=5)
        if replay_server.error:
            raise replay_server.error

        # Forgery: nonce is current, but signature belongs to a different
        # message. Pinned Ed25519 verification must reject it.
        forged = evidence / "forged-signature-control"
        forged.mkdir()
        forged_server = FakeReceiptServer(signed_seq2, "forged")
        forged_server.start()
        forged_env = dict(remote_env)
        forged_env["OPENSHELL_BLACKBOX_REMOTE_WITNESS_ADDR"] = forged_server.address
        forged_result = run_proxy_expect_failure(
            root,
            primary / "policy.yaml",
            primary / "final-valid-permits.jsonl",
            primary / "final-valid-witness.json",
            forged / "tls",
            forged / "proxy.log",
            forged_env,
            "Ed25519 signature verification failed",
        )
        forged_server.thread.join(timeout=5)
        if forged_server.error:
            raise forged_server.error

        result = {
            "status": "AUTHENTICATED_REMOTE_WITNESS_VERIFIED",
            "source_pin": "484f0768fc6a0d93e0a2be295c1679aed24e18a9",
            "real_openshell_surfaces": ["forward_http", "connect"],
            "remote_witness_sequence": 2,
            "remote_receipts_ed25519_authenticated": True,
            "receipt_freshness_nonce_bound": True,
            "joint_local_rollback_detected": True,
            "replayed_signed_receipt_rejected": True,
            "forged_receipt_rejected": True,
            "dispatch_requires_remote_receipt_before_effect": True,
            "negative_controls": {
                "joint_rollback": joint_result,
                "replay": replay_result,
                "forged_signature": forged_result,
            },
            "overall_cp17_acceptance": False,
            "remaining_gaps": [
                "witness_on_separate_failure_domain",
                "witness_client_authentication_or_mtls",
                "physical_power_loss",
                "multi_witness_quorum_or_transparency_log",
            ],
        }
        json_dump(evidence / "runtime-result.json", result)
        print(json.dumps(result, sort_keys=True))
    finally:
        if server.poll() is None:
            server.send_signal(signal.SIGTERM)
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        server_log.close()


if __name__ == "__main__":
    main()
