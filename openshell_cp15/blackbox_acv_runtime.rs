// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "e2e")]

use std::io::Write;
use std::process::Command;

use openshell_e2e::harness::container::is_e2e_driver;
use openshell_e2e::harness::host_process::HostPythonFixture;
use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use serial_test::serial;
use tempfile::NamedTempFile;

const POLICY_HOST: &str = "host.openshell.internal";
const JOURNAL_PATH: &str = "/var/log/blackbox-acv/permits.jsonl";
const WITNESS_PATH: &str = "/var/log/blackbox-acv/witness.json";
const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

fn write_policy(port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let policy = format!(
        r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock: {{ compatibility: best_effort }}
process: {{ run_as_user: sandbox, run_as_group: sandbox }}
network_policies:
  cp15_runtime:
    name: cp15_runtime
    endpoints:
      - host: {POLICY_HOST}
        ports: [{port}]
        protocol: tcp
        allowed_ips: ["10.0.0.0/8", "127.0.0.0/8", "172.0.0.0/8", "192.168.0.0/16"]
    binaries:
      - path: "/**"
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

fn docker_stdout(args: &[&str]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .map_err(|error| format!("run docker {}: {error}", args.join(" ")))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(format!(
            "docker {} failed (exit {:?}):\n{combined}",
            args.join(" "),
            output.status.code()
        ))
    }
}

fn supervisor_container(sandbox_name: &str) -> Result<String, String> {
    let name_filter = format!("label=openshell.ai/sandbox-name={sandbox_name}");
    let id = docker_stdout(&[
        "ps",
        "-q",
        "--filter",
        &name_filter,
        "--filter",
        "label=openshell.ai/isolation-role=supervisor",
    ])?;
    let ids = id.lines().filter(|line| !line.trim().is_empty()).collect::<Vec<_>>();
    match ids.as_slice() {
        [only] => Ok((*only).to_string()),
        _ => Err(format!(
            "expected exactly one live supervisor companion for {sandbox_name}, got {ids:?}"
        )),
    }
}

fn read_companion_file(container: &str, path: &str) -> Result<String, String> {
    docker_stdout(&["exec", container, "cat", path])
}

fn parse_records(journal: &str) -> Vec<Value> {
    journal
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("valid BLACKBOX journal JSON"))
        .collect()
}

fn validate_chain_and_witness(records: &[Value], witness: &Value) {
    assert!(!records.is_empty(), "BLACKBOX journal must contain at least one record");

    let mut previous = GENESIS_HASH.to_string();
    for (index, record) in records.iter().enumerate() {
        let expected_sequence = u64::try_from(index + 1).expect("sequence fits u64");
        assert_eq!(
            record["sequence"].as_u64(),
            Some(expected_sequence),
            "journal sequence must be contiguous"
        );
        assert_eq!(
            record["prev_record_sha256"].as_str(),
            Some(previous.as_str()),
            "journal predecessor hash must link to prior record"
        );
        previous = record["journal_record_sha256"]
            .as_str()
            .expect("journal record hash")
            .to_string();
    }

    assert_eq!(
        witness["sequence"].as_u64(),
        records.last().and_then(|record| record["sequence"].as_u64()),
        "high-water witness sequence must match journal head"
    );
    assert_eq!(
        witness["head_record_sha256"].as_str(),
        records
            .last()
            .and_then(|record| record["journal_record_sha256"].as_str()),
        "high-water witness hash must match journal head"
    );
}

#[tokio::test]
#[serial(cp15_blackbox_runtime)]
async fn docker_full_sandbox_lifecycle_emits_durable_transparent_tcp_evidence() {
    if !is_e2e_driver("docker") {
        return;
    }

    let fixture_port = find_free_port();
    let fixture_script = format!(
        r#"import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {fixture_port}))
s.listen()
while True:
    c, _ = s.accept()
    data = c.recv(4096)
    if data == b"cp15-runtime-probe":
        observed = time.time_ns()
        print(f"OBSERVED_NS={{observed}}", flush=True)
        c.sendall(b"cp15-runtime-ok")
    c.close()
"#
    );
    let fixture = HostPythonFixture::start(&fixture_script, fixture_port)
        .await
        .expect("start CP15 host receiver");

    let policy = write_policy(fixture_port).expect("write CP15 policy");
    let policy_path = policy.path().to_string_lossy().into_owned();
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create full Docker sandbox lifecycle");

    let script = format!(
        r#"import os, socket
for key in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "http_proxy", "https_proxy"):
    os.environ.pop(key, None)
with socket.create_connection(({host:?}, {port}), timeout=15) as conn:
    conn.sendall(b"cp15-runtime-probe")
    result = conn.recv(4096)
    assert result == b"cp15-runtime-ok", result
print("CP15_RUNTIME_TCP_OK")
"#,
        host = POLICY_HOST,
        port = fixture_port,
    );
    let output = sandbox
        .exec(&["python3", "-c", &script])
        .await
        .expect("exercise real sandbox transparent TCP path");
    assert!(output.contains("CP15_RUNTIME_TCP_OK"), "{output}");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let observed_ns = loop {
        let logs = fixture.logs().expect("read CP15 receiver log");
        if let Some(value) = logs
            .lines()
            .find_map(|line| line.strip_prefix("OBSERVED_NS="))
            .and_then(|value| value.trim().parse::<u64>().ok())
        {
            break value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "receiver never logged CP15 observation; logs={logs}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };

    let companion = supervisor_container(&sandbox.name).expect("find supervisor companion");
    let journal = read_companion_file(&companion, JOURNAL_PATH).expect("read BLACKBOX journal");
    let witness_text =
        read_companion_file(&companion, WITNESS_PATH).expect("read BLACKBOX high-water witness");
    let witness: Value = serde_json::from_str(witness_text.trim()).expect("valid witness JSON");
    let records = parse_records(&journal);
    validate_chain_and_witness(&records, &witness);

    let matching = records
        .iter()
        .filter(|record| {
            record["surface"].as_str() == Some("transparent_tcp")
                && record["host"].as_str() == Some(POLICY_HOST)
                && record["port"].as_u64() == Some(u64::from(fixture_port))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "expected exactly one BLACKBOX transparent_tcp permit for receiver; journal={journal}"
    );
    let committed_ns = matching[0]["committed_unix_ns"]
        .as_u64()
        .expect("permit commit timestamp");
    assert!(
        committed_ns <= observed_ns,
        "durable permit commit must precede real receiver observation: commit={committed_ns} observed={observed_ns}"
    );

    sandbox.cleanup().await;
}
