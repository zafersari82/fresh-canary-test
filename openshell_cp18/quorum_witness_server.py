#!/usr/bin/env python3
"""CP18 authenticated quorum witness service.

Each process owns:
- its own durable state file,
- an independent Ed25519 receipt-signing key,
- a shared or per-deployment HMAC key used to authenticate OpenShell requests.

The private Ed25519 key never leaves the witness process.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RECEIPT_SCHEMA = "blackbox.remote-witness.receipt.v1"
REQUEST_AUTH_SCHEMA = "blackbox.remote-witness.request-auth.v1"
GENESIS = "0" * 64


def receipt_bytes(namespace: str, sequence: int, head: str, nonce: str) -> bytes:
    return (
        RECEIPT_SCHEMA.encode()
        + b"\0"
        + namespace.encode()
        + b"\0"
        + str(sequence).encode()
        + b"\0"
        + head.encode()
        + b"\0"
        + nonce.encode()
    )


def request_auth_bytes(request: dict) -> bytes:
    fields = [
        REQUEST_AUTH_SCHEMA,
        str(request.get("client_id", "")),
        str(request.get("op", "")),
        str(request.get("namespace", "")),
        str(request.get("nonce", "")),
        "" if request.get("previous_sequence") is None else str(request["previous_sequence"]),
        str(request.get("previous_head_record_sha256") or ""),
        "" if request.get("sequence") is None else str(request["sequence"]),
        str(request.get("head_record_sha256") or ""),
    ]
    return "\0".join(fields).encode()


class DurableState:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict[str, dict[str, object]] = {}
        if path.exists():
            self.data = json.loads(path.read_text())

    def current(self, namespace: str) -> dict[str, object]:
        value = self.data.get(namespace)
        if value is None:
            return {"sequence": 0, "head_record_sha256": GENESIS}
        return {
            "sequence": int(value["sequence"]),
            "head_record_sha256": str(value["head_record_sha256"]),
        }

    def advance(
        self,
        namespace: str,
        previous_sequence: int,
        previous_head: str,
        sequence: int,
        head: str,
    ) -> dict[str, object]:
        with self.lock:
            current = self.current(namespace)

            # Idempotent retry: if this witness already durably committed the
            # exact requested state, acknowledge it again without forking.
            if sequence == current["sequence"] and head == current["head_record_sha256"]:
                return current

            if previous_sequence != current["sequence"]:
                raise ValueError(
                    f"previous sequence mismatch: expected {current['sequence']} got {previous_sequence}"
                )
            if previous_head != current["head_record_sha256"]:
                raise ValueError("previous head mismatch")
            if sequence != previous_sequence + 1:
                raise ValueError("advance must be exactly one sequence")
            if len(head) != 64 or any(c not in "0123456789abcdefABCDEF" for c in head):
                raise ValueError("head hash malformed")

            self.data[namespace] = {
                "sequence": sequence,
                "head_record_sha256": head.lower(),
            }
            self._persist()
            return self.current(namespace)

    def force_state(self, namespace: str, sequence: int, head: str) -> None:
        with self.lock:
            self.data[namespace] = {
                "sequence": sequence,
                "head_record_sha256": head,
            }
            self._persist()

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.{time.time_ns()}.tmp"
        )
        payload = (json.dumps(self.data, sort_keys=True) + "\n").encode()
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=True) as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, self.path)
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if temp.exists():
                temp.unlink()


class Witness:
    def __init__(
        self,
        witness_id: str,
        state: DurableState,
        receipts: Path,
        client_id: str,
        client_hmac_key: bytes,
    ):
        self.witness_id = witness_id
        self.state = state
        self.receipts = receipts
        self.client_id = client_id
        self.client_hmac_key = client_hmac_key
        self.key = Ed25519PrivateKey.generate()
        self.public_key_hex = (
            self.key.public_key()
            .public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            .hex()
        )
        self.receipt_lock = threading.Lock()

    def verify_client(self, request: dict) -> None:
        if request.get("client_id") != self.client_id:
            raise PermissionError("client identity mismatch")
        supplied = str(request.get("auth_hex") or "")
        expected = hmac.new(
            self.client_hmac_key,
            request_auth_bytes(request),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise PermissionError("client HMAC authentication failed")

    def handle(self, request: dict) -> dict:
        self.verify_client(request)

        op = request.get("op")
        namespace = str(request.get("namespace", ""))
        nonce = str(request.get("nonce", ""))
        if not namespace or not nonce:
            raise ValueError("namespace and nonce are required")

        if op == "get":
            state = self.state.current(namespace)
        elif op == "advance":
            state = self.state.advance(
                namespace,
                int(request["previous_sequence"]),
                str(request["previous_head_record_sha256"]),
                int(request["sequence"]),
                str(request["head_record_sha256"]),
            )
        else:
            raise ValueError(f"unsupported operation: {op!r}")

        receipt = {
            "schema": RECEIPT_SCHEMA,
            "witness_id": self.witness_id,
            "namespace": namespace,
            "sequence": int(state["sequence"]),
            "head_record_sha256": str(state["head_record_sha256"]),
            "nonce": nonce,
        }
        receipt["signature_hex"] = self.key.sign(
            receipt_bytes(
                receipt["namespace"],
                receipt["sequence"],
                receipt["head_record_sha256"],
                receipt["nonce"],
            )
        ).hex()
        self._record_receipt(receipt)
        return {"ok": True, "receipt": receipt}

    def _record_receipt(self, receipt: dict) -> None:
        self.receipts.parent.mkdir(parents=True, exist_ok=True)
        line = (json.dumps(receipt, sort_keys=True) + "\n").encode()
        with self.receipt_lock:
            fd = os.open(
                self.receipts,
                os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                0o600,
            )
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)


def handle_connection(conn: socket.socket, witness: Witness) -> None:
    with conn:
        conn.settimeout(5)
        f = conn.makefile("rwb", buffering=0)
        try:
            line = f.readline(65537)
            if not line:
                return
            if len(line) > 65536:
                raise ValueError("request exceeded 64 KiB")
            request = json.loads(line)
            response = witness.handle(request)
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}
        f.write((json.dumps(response, sort_keys=True) + "\n").encode())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness-id", required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--client-hmac-key-hex", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    hmac_key = bytes.fromhex(args.client_hmac_key_hex)
    if len(hmac_key) < 32:
        raise SystemExit("client HMAC key must be at least 32 bytes")

    state = DurableState(args.state)
    witness = Witness(
        args.witness_id,
        state,
        args.receipts,
        args.client_id,
        hmac_key,
    )

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(64)
    host, port = listener.getsockname()

    args.ready.parent.mkdir(parents=True, exist_ok=True)
    ready = {
        "witness_id": args.witness_id,
        "address": f"{host}:{port}",
        "public_key_hex": witness.public_key_hex,
        "pid": os.getpid(),
        "state_path": str(args.state.resolve()),
    }
    args.ready.write_text(json.dumps(ready, sort_keys=True) + "\n")
    print(json.dumps(ready, sort_keys=True), flush=True)

    try:
        while True:
            conn, _peer = listener.accept()
            thread = threading.Thread(
                target=handle_connection,
                args=(conn, witness),
                daemon=True,
            )
            thread.start()
    finally:
        listener.close()


if __name__ == "__main__":
    main()
