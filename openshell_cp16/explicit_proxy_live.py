#!/usr/bin/env python3
"""CP16 live standalone OpenShell explicit-proxy evidence test."""
from __future__ import annotations

import hashlib
import ipaddress
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
import uuid

PROXY_HOST = "127.0.0.1"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def receiver_host() -> str:
    """Return the runner's ordinary routed IPv4 address, never loopback."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect selects an interface without sending application data.
        probe.connect(("8.8.8.8", 53))
        host = probe.getsockname()[0]
    finally:
        probe.close()
    ip = ipaddress.ip_address(host)
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        raise RuntimeError(f"receiver host is not externally mediable: {host}")
    return host


def choose_port(host: str = PROXY_HOST) -> int:
    s = socket.socket()
    try:
        s.bind((host, 0))
        return s.getsockname()[1]
    finally:
        s.close()


def recv_until(sock: socket.socket, marker: bytes, limit: int = 1 << 20) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise RuntimeError("bounded receive exceeded")
    return bytes(data)


def durable_observation(
    journal: Path,
    witness: Path,
    surface: str,
    port: int,
    evidence: Path,
    prefix: str,
) -> dict:
    journal_bytes = journal.read_bytes()
    witness_bytes = witness.read_bytes()
    records = [json.loads(line) for line in journal_bytes.splitlines() if line.strip()]
    matches = [
        record
        for record in records
        if record.get("surface") == surface and record.get("port") == port
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"receiver observed {len(matches)} durable records for {surface}:{port}"
        )
    record = matches[0]
    witness_obj = json.loads(witness_bytes)
    witness_matches = (
        witness_obj.get("sequence") == record.get("sequence")
        and witness_obj.get("head_record_sha256")
        == record.get("journal_record_sha256")
    )
    (evidence / f"{prefix}-observed-journal.jsonl").write_bytes(journal_bytes)
    (evidence / f"{prefix}-observed-witness.json").write_bytes(witness_bytes)
    result = {
        "surface": surface,
        "port": port,
        "observed_unix_ns": time.time_ns(),
        "journal_present_before_receiver_effect": True,
        "witness_head_matches_record_at_receiver_effect": witness_matches,
        "sequence": record.get("sequence"),
        "operation_id": record.get("operation_id"),
        "journal_record_sha256": record.get("journal_record_sha256"),
        "journal_snapshot_sha256": sha256(journal_bytes),
        "witness_snapshot_sha256": sha256(witness_bytes),
    }
    if not witness_matches:
        raise AssertionError(
            f"witness did not match {surface} record at receiver observation"
        )
    json_dump(evidence / f"{prefix}-receiver-observation.json", result)
    return result


class Receiver:
    def __init__(
        self,
        kind: str,
        journal: Path,
        witness: Path,
        evidence: Path,
        host: str,
    ):
        self.kind = kind
        self.host = host
        self.journal = journal
        self.witness = witness
        self.evidence = evidence
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.challenge = f"cp16-{kind}-{uuid.uuid4()}"
        self.error: BaseException | None = None
        self.observation: dict | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def join(self) -> None:
        self.thread.join(timeout=20)
        if self.thread.is_alive():
            raise TimeoutError(f"{self.kind} receiver did not finish")
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        try:
            conn, peer = self.sock.accept()
            with conn:
                conn.settimeout(10)
                surface = "forward_http" if self.kind == "forward" else "connect"

                # This executes immediately after the receiver can observe the
                # upstream TCP side effect. The journal and high-water witness
                # therefore must already be durable/readable at this point.
                self.observation = durable_observation(
                    self.journal,
                    self.witness,
                    surface,
                    self.port,
                    self.evidence,
                    self.kind,
                )

                if self.kind == "forward":
                    raw = recv_until(conn, b"\r\n\r\n")
                    text = raw.decode("latin1")
                    expected = f"X-CP16-Challenge: {self.challenge}".lower()
                    if expected not in text.lower():
                        raise AssertionError(f"forward challenge missing: {text!r}")
                    body = (self.challenge + "\n").encode()
                    response = (
                        b"HTTP/1.1 200 OK\r\n"
                        + f"Content-Length: {len(body)}\r\n".encode()
                        + b"Connection: close\r\n\r\n"
                        + body
                    )
                    conn.sendall(response)
                else:
                    line = recv_until(conn, b"\n")
                    if line.decode().strip() != self.challenge:
                        raise AssertionError(f"CONNECT payload mismatch: {line!r}")
                    conn.sendall((self.challenge + "\n").encode())

                json_dump(
                    self.evidence / f"{self.kind}-receiver-result.json",
                    {
                        "kind": self.kind,
                        "peer": str(peer),
                        "challenge": self.challenge,
                        "observation": self.observation,
                    },
                )
        except BaseException as exc:
            self.error = exc
        finally:
            self.sock.close()


def wait_proxy_ready(proc: subprocess.Popen, port: int) -> None:
    deadline = time.time() + 25
    last = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"proxy exited before readiness with code {proc.returncode}"
            )
        try:
            with socket.create_connection((PROXY_HOST, port), timeout=0.5):
                return
        except OSError as exc:
            last = exc
            time.sleep(0.2)
    raise TimeoutError(f"proxy did not become ready: {last}")


def forward_request(proxy_port: int, receiver: Receiver) -> bytes:
    with socket.create_connection((PROXY_HOST, proxy_port), timeout=10) as s:
        s.settimeout(10)
        authority = f"{receiver.host}:{receiver.port}"
        req = (
            f"GET http://{authority}/cp16-forward HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"X-CP16-Challenge: {receiver.challenge}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req)
        response = bytearray()
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    if b"200 OK" not in response or receiver.challenge.encode() not in response:
        raise AssertionError(
            f"forward proxy response invalid: {bytes(response)!r}"
        )
    return bytes(response)


def connect_request(proxy_port: int, receiver: Receiver) -> bytes:
    with socket.create_connection((PROXY_HOST, proxy_port), timeout=10) as s:
        s.settimeout(10)
        authority = f"{receiver.host}:{receiver.port}"
        s.sendall(
            (
                f"CONNECT {authority} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                "\r\n"
            ).encode()
        )
        headers = recv_until(s, b"\r\n\r\n")
        if b"200" not in headers.split(b"\r\n", 1)[0]:
            raise AssertionError(f"CONNECT was not established: {headers!r}")
        s.sendall((receiver.challenge + "\n").encode())
        echoed = recv_until(s, b"\n")
        if receiver.challenge.encode() not in echoed:
            raise AssertionError(f"CONNECT echo mismatch: {echoed!r}")
        return headers + echoed


def start_proxy(
    root: Path,
    policy: Path,
    tls_dir: Path,
    journal: Path,
    witness: Path,
    proxy_port: int,
    log_path: Path,
) -> tuple[subprocess.Popen, object]:
    tls_dir.mkdir(parents=True, exist_ok=True)
    log = log_path.open("wb")
    env = os.environ.copy()
    env["OPENSHELL_BLACKBOX_EGRESS_JOURNAL"] = str(journal)
    env["OPENSHELL_BLACKBOX_EGRESS_WITNESS"] = str(witness)
    cmd = [
        str(root / "target/debug/openshell-supervisor"),
        "--role=network-proxy",
        f"--listen={PROXY_HOST}:{proxy_port}",
        f"--tls-dir={tls_dir}",
        (
            "--policy-rules="
            + str(root / "crates/openshell-supervisor-network/data/sandbox-policy.rego")
        ),
        f"--policy-data={policy}",
        "--log-level=info",
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=root,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    return proc, log


def stop_proxy(proc: subprocess.Popen, log) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    log.close()


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: explicit_proxy_live.py /path/to/OpenShell /path/to/evidence"
        )

    root = Path(sys.argv[1]).resolve()
    evidence = Path(sys.argv[2]).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    journal = evidence / "permits.jsonl"
    witness = evidence / "witness.json"

    upstream_host = receiver_host()
    json_dump(
        evidence / "runner-network.json",
        {"proxy_host": PROXY_HOST, "receiver_host": upstream_host},
    )

    forward = Receiver("forward", journal, witness, evidence, upstream_host)
    connect = Receiver("connect", journal, witness, evidence, upstream_host)
    forward.start()
    connect.start()

    # Literal non-loopback runner IPs intentionally use OpenShell's
    # ImplicitIpLiteral destination mode. Loopback remains always blocked and
    # is never weakened for this test.
    policy = evidence / "policy.yaml"
    policy.write_text(
        f"""network_policies:
  cp16_explicit_proxy:
    name: cp16_explicit_proxy
    endpoints:
      - host: "{upstream_host}"
        port: {forward.port}
        tls: skip
      - host: "{upstream_host}"
        port: {connect.port}
        tls: skip
    binaries:
      - path: "/**"
"""
    )

    proxy_port = choose_port(PROXY_HOST)
    proc, log = start_proxy(
        root,
        policy,
        evidence / "tls",
        journal,
        witness,
        proxy_port,
        evidence / "proxy.log",
    )
    try:
        wait_proxy_ready(proc, proxy_port)
        fwd_response = forward_request(proxy_port, forward)
        forward.join()
        conn_response = connect_request(proxy_port, connect)
        connect.join()
        (evidence / "forward-client-response.bin").write_bytes(fwd_response)
        (evidence / "connect-client-response.bin").write_bytes(conn_response)
    finally:
        stop_proxy(proc, log)

    if proc.returncode not in (0, -signal.SIGTERM):
        raise AssertionError(
            f"primary proxy terminated unexpectedly: {proc.returncode}"
        )

    # Preserve valid final state before destructive negative controls.
    shutil.copy2(journal, evidence / "final-valid-permits.jsonl")
    shutil.copy2(witness, evidence / "final-valid-witness.json")

    records = [
        json.loads(line)
        for line in journal.read_text().splitlines()
        if line.strip()
    ]
    surfaces = [r.get("surface") for r in records]
    if surfaces != ["forward_http", "connect"]:
        raise AssertionError(f"unexpected durable surface sequence: {surfaces}")

    # Roll back only the journal while retaining the high-water witness.
    # A new durable proxy must fail closed during gate construction.
    rollback = evidence / "rollback-control"
    rollback.mkdir()
    rolled_journal = rollback / "permits.jsonl"
    rolled_witness = rollback / "witness.json"
    rolled_journal.write_text(json.dumps(records[0], sort_keys=True) + "\n")
    shutil.copy2(witness, rolled_witness)

    rollback_port = choose_port(PROXY_HOST)
    rollback_proc, rollback_log = start_proxy(
        root,
        policy,
        rollback / "tls",
        rolled_journal,
        rolled_witness,
        rollback_port,
        rollback / "proxy.log",
    )
    try:
        deadline = time.time() + 15
        while rollback_proc.poll() is None and time.time() < deadline:
            time.sleep(0.2)
        if rollback_proc.poll() is None:
            raise AssertionError(
                "journal-only rollback was not rejected at startup"
            )
        if rollback_proc.returncode == 0:
            raise AssertionError(
                "rollback control unexpectedly exited successfully"
            )
    finally:
        stop_proxy(rollback_proc, rollback_log)

    observations = [forward.observation, connect.observation]
    if not all(
        observation
        and observation["journal_present_before_receiver_effect"]
        and observation["witness_head_matches_record_at_receiver_effect"]
        for observation in observations
    ):
        raise AssertionError("receiver-time durable observation failed")

    result = {
        "status": "EXPLICIT_PROXY_SURFACES_VERIFIED",
        "source_pin": "484f0768fc6a0d93e0a2be295c1679aed24e18a9",
        "scope": "standalone_network_proxy",
        "verified_surfaces": ["forward_http", "connect"],
        "cp15_carried_surface": "transparent_tcp",
        "receiver_operations": 2,
        "causal_durable_before_receiver_observation_proven": True,
        "journal_only_rollback_detected": True,
        "overall_cp16_acceptance": False,
        "remaining_gaps": [
            "authenticated_remote_witness",
            "joint_journal_and_witness_rollback",
            "physical_power_loss",
        ],
    }
    json_dump(evidence / "runtime-result.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
