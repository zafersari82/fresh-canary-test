// SPDX-License-Identifier: Apache-2.0
//! BLACKBOX ACV CP15 live Docker lifecycle test.
//!
//! Exercises three real OpenShell egress dial families through a live gateway,
//! supervisor container, sandbox and receiver fixtures, then reads the durable
//! evidence from the still-running supervisor before sandbox cleanup.

#![cfg(feature = "e2e-docker")]

use std::collections::BTreeSet;
use std::io::Write;
use std::process::Command;

use openshell_e2e::harness::container::SupportContainer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tempfile::NamedTempFile;

const HTTP_HOST: &str = "cp15-forward.openshell.test";
const HTTP_PORT: u16 = 8000;
const CONNECT_HOST: &str = "cp15-connect.openshell.test";
const CONNECT_PORT: u16 = 9443;
const TCP_HOST: &str = "cp15-tcp.openshell.test";
const TCP_PORT: u16 = 5432;

const PRIVATE_ALLOWED_IPS: &str = r#"        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7""#;

fn write_policy() -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|e| format!("create policy: {e}"))?;
    let policy = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only:
    - /usr
    - /lib
    - /proc
    - /dev/urandom
    - /app
    - /etc
    - /var/log
  read_write:
    - /sandbox
    - /tmp
    - /dev/null

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  cp15_runtime:
    name: cp15_runtime
    endpoints:
      - host: {HTTP_HOST}
        port: {HTTP_PORT}
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /allowed
{PRIVATE_ALLOWED_IPS}
      - host: {CONNECT_HOST}
        port: {CONNECT_PORT}
        tls: skip
{PRIVATE_ALLOWED_IPS}
      - host: {TCP_HOST}
        port: {TCP_PORT}
        protocol: tcp
{PRIVATE_ALLOWED_IPS}
    binaries:
      - path: "/**"
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|e| format!("write policy: {e}"))?;
    file.flush().map_err(|e| format!("flush policy: {e}"))?;
    Ok(file)
}

fn supervisor_container_id(sandbox_name: &str) -> Result<String, String> {
    let name_filter = format!("label=openshell.ai/sandbox-name={sandbox_name}");
    let output = Command::new("docker")
        .args([
            "ps",
            "--filter",
            &name_filter,
            "--filter",
            "label=openshell.ai/isolation-role=supervisor",
            "--format",
            "{{.ID}}",
        ])
        .output()
        .map_err(|e| format!("run docker ps: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker ps failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let ids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if ids.len() != 1 {
        return Err(format!(
            "expected exactly one supervisor container for {sandbox_name}, found {ids:?}"
        ));
    }
    Ok(ids[0].clone())
}

fn docker_cat(container: &str, path: &str) -> Result<String, String> {
    let output = Command::new("docker")
        .args(["exec", container, "cat", path])
        .output()
        .map_err(|e| format!("docker exec cat {path}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker exec cat {path} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn verify_evidence(journal: &str, witness: &str) {
    let records = journal
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("parse journal record"))
        .collect::<Vec<_>>();
    assert!(
        records.len() >= 3,
        "expected at least three live runtime permits, got {}: {journal}",
        records.len()
    );

    let surfaces = records
        .iter()
        .filter_map(|record| record.get("surface").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    for expected in ["connect", "forward_http", "transparent_tcp"] {
        assert!(
            surfaces.contains(expected),
            "missing CP15 surface {expected}; observed {surfaces:?}; journal={journal}"
        );
    }

    let mut previous_hash =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    for (index, record) in records.iter().enumerate() {
        let sequence = record["sequence"].as_u64().expect("record sequence");
        assert_eq!(sequence, (index + 1) as u64, "journal sequence must be contiguous");
        assert_eq!(
            record["prev_record_sha256"].as_str(),
            Some(previous_hash.as_str()),
            "journal predecessor hash mismatch at sequence {sequence}"
        );
        previous_hash = record["journal_record_sha256"]
            .as_str()
            .expect("journal record hash")
            .to_string();
    }

    let witness: Value = serde_json::from_str(witness.trim()).expect("parse high-water witness");
    assert_eq!(
        witness["sequence"].as_u64(),
        Some(records.len() as u64),
        "witness sequence must match live journal head"
    );
    assert_eq!(
        witness["head_record_sha256"].as_str(),
        Some(previous_hash.as_str()),
        "witness head hash must match live journal head"
    );
}

#[tokio::test]
async fn live_supervisor_lifecycle_emits_all_three_durable_surfaces() {
    assert_eq!(
        std::env::var("OPENSHELL_E2E_DRIVER").as_deref(),
        Ok("docker"),
        "CP15 requires the Docker e2e driver"
    );

    const HTTP_SERVER: &str = r#"
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/allowed":
            self.send_response(404)
            self.end_headers()
            return
        body = b"cp15-forward-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, format, *args):
        pass
HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

    const CONNECT_ECHO: &str = r#"
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9443))
s.listen()
while True:
    c, _ = s.accept()
    try:
        data = c.recv(4096)
        if data:
            c.sendall(data)
    finally:
        c.close()
"#;

    const TCP_ECHO: &str = r#"
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 5432))
s.listen()
while True:
    c, _ = s.accept()
    try:
        data = c.recv(4096)
        if data:
            c.sendall(b"cp15-tcp-ok:" + data)
    finally:
        c.close()
"#;

    let _http = SupportContainer::start_python(HTTP_HOST, HTTP_SERVER, HTTP_PORT)
        .await
        .expect("start CP15 forward HTTP fixture");
    let _connect = SupportContainer::start_python(CONNECT_HOST, CONNECT_ECHO, CONNECT_PORT)
        .await
        .expect("start CP15 CONNECT fixture");
    let _tcp = SupportContainer::start_python(TCP_HOST, TCP_ECHO, TCP_PORT)
        .await
        .expect("start CP15 transparent TCP fixture");

    let policy = write_policy().expect("write CP15 policy");
    let policy_path = policy.path().to_string_lossy().into_owned();
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path, "--no-tty"],
        &["sh", "-c", "echo Ready; sleep 2147483647"],
        "Ready",
    )
    .await
    .expect("create live CP15 sandbox");

    let forward_script = format!(
        r#"
import urllib.request
body = urllib.request.urlopen("http://{HTTP_HOST}:{HTTP_PORT}/allowed", timeout=15).read()
assert body == b"cp15-forward-ok", body
print("CP15_FORWARD_OK")
"#
    );
    let forward = sandbox
        .exec(&["python3", "-c", &forward_script])
        .await
        .expect("exercise live forward HTTP path");
    assert!(forward.contains("CP15_FORWARD_OK"), "{forward}");

    let connect_script = format!(
        r#"
import os, socket
from urllib.parse import urlparse

proxy = (
    os.environ.get("HTTPS_PROXY")
    or os.environ.get("https_proxy")
    or os.environ.get("HTTP_PROXY")
    or os.environ.get("http_proxy")
)
if not proxy:
    raise RuntimeError("OpenShell proxy environment is absent")
if "://" not in proxy:
    proxy = "http://" + proxy
parsed = urlparse(proxy)
port = parsed.port or 80
with socket.create_connection((parsed.hostname, port), timeout=15) as sock:
    target = "{CONNECT_HOST}:{CONNECT_PORT}"
    request = (
        f"CONNECT {{target}} HTTP/1.1\r\n"
        f"Host: {{target}}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    ).encode()
    sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    if b" 200 " not in response.split(b"\r\n", 1)[0]:
        raise RuntimeError(f"CONNECT failed: {{response!r}}")
    payload = b"cp15-connect"
    sock.sendall(payload)
    echoed = sock.recv(len(payload))
    if echoed != payload:
        raise RuntimeError(f"CONNECT echo mismatch: {{echoed!r}}")
print("CP15_CONNECT_OK")
"#
    );
    let connect = sandbox
        .exec(&["python3", "-c", &connect_script])
        .await
        .expect("exercise live explicit CONNECT path");
    assert!(connect.contains("CP15_CONNECT_OK"), "{connect}");

    let transparent_script = format!(
        r#"
import os, socket
for key in ("ALL_PROXY","HTTP_PROXY","HTTPS_PROXY","all_proxy","http_proxy","https_proxy"):
    os.environ.pop(key, None)
with socket.create_connection(("{TCP_HOST}", {TCP_PORT}), timeout=15) as sock:
    sock.sendall(b"raw-tcp")
    data = sock.recv(4096)
    assert data == b"cp15-tcp-ok:raw-tcp", data
print("CP15_TRANSPARENT_TCP_OK")
"#
    );
    let transparent = sandbox
        .exec(&["python3", "-c", &transparent_script])
        .await
        .expect("exercise live transparent TCP path");
    assert!(
        transparent.contains("CP15_TRANSPARENT_TCP_OK"),
        "{transparent}"
    );

    let supervisor = supervisor_container_id(&sandbox.name).expect("locate live supervisor");
    let journal = docker_cat(&supervisor, "/tmp/blackbox/permits.jsonl")
        .expect("read live durable journal");
    let witness = docker_cat(&supervisor, "/tmp/blackbox/witness.json")
        .expect("read live high-water witness");
    verify_evidence(&journal, &witness);

    sandbox.cleanup().await;
}
