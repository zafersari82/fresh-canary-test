// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "e2e")]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_healthy};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::host_process::HostPythonFixture;
use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Value, json};
use tempfile::NamedTempFile;

const HOST: &str = "host.openshell.internal";
const STATE: &str = "/var/lib/blackbox-acv";
const SURFACES: [&str; 2] = ["native_http", "native_raw_tcp"];

fn docker(args: &[&str]) -> String {
    let out = Command::new("docker").args(args).output().expect("Docker command");
    assert!(out.status.success(), "docker {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).expect("UTF-8 Docker output").trim().to_string()
}

fn supervisor_logs(id: &str) -> String {
    let out = Command::new("docker").args(["logs", id]).output().unwrap();
    assert!(out.status.success(), "read supervisor logs: {}", String::from_utf8_lossy(&out.stderr));
    format!("{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

fn session_failures(log: &str) -> usize {
    log.lines().filter(|line| line.contains("supervisor session failed, reconnecting")).count()
}

fn gateway_port_from_args() -> u16 {
    let args_file = PathBuf::from(
        std::env::var("OPENSHELL_E2E_GATEWAY_ARGS_FILE")
            .expect("owned gateway args file required"),
    );
    let raw = fs::read(&args_file).expect("read gateway args file");
    let args: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8(arg.to_vec()).expect("gateway args must be UTF-8"))
        .collect();
    let index = args
        .iter()
        .position(|arg| arg == "--port")
        .expect("gateway --port argument required");
    args.get(index + 1)
        .expect("gateway --port value required")
        .parse::<u16>()
        .expect("gateway port must be numeric")
}

fn gateway_sockets(port: u16) -> String {
    let filter = format!("sport = :{port}");
    let out = Command::new("ss")
        .args(["-tnp", "state", "established", &filter])
        .output()
        .expect("inspect gateway TCP sockets");
    assert!(
        out.status.success(),
        "ss gateway socket inspection failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn reset_gateway_transports(port: u16) -> String {
    let filter = format!("sport = :{port}");
    let out = Command::new("sudo")
        .args(["ss", "-K", "state", "established", &filter])
        .output()
        .expect("reset gateway TCP transports");
    assert!(
        out.status.success(),
        "ss -K gateway transport reset failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn companion(name: &str) -> Value {
    let filter = format!("label=openshell.ai/sandbox-name={name}");
    let ids = docker(&["ps", "-q", "--filter", &filter, "--filter", "label=openshell.ai/isolation-role=supervisor"]);
    assert_eq!(ids.lines().count(), 1, "one live supervisor: {ids}");
    let data: Value = serde_json::from_str(&docker(&["inspect", &ids])).unwrap();
    data[0].clone()
}

fn evidence_mount(info: &Value) -> String {
    let mounts = info["Mounts"].as_array().expect("supervisor mounts");
    let mount = mounts.iter().find(|m| m["Destination"] == STATE).expect("persistent evidence mount required; tmpfs is insufficient");
    assert_eq!(mount["Type"], "volume");
    assert_eq!(mount["RW"], true);
    mount["Name"].as_str().unwrap().to_string()
}

fn snapshot(info: &Value, phase: &str, output: &Path) -> Value {
    let dir = output.join(phase);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("supervisor.json"), serde_json::to_vec_pretty(&json!({
        "Id": info["Id"], "Image": info["Image"], "Mounts": info["Mounts"],
        "sandbox_id": info["Config"]["Labels"]["openshell.ai/sandbox-id"],
        "network_mode": info["HostConfig"]["NetworkMode"],
    })).unwrap()).unwrap();
    let id = info["Id"].as_str().unwrap();
    for file in ["permits.jsonl", "witness.json", "permits.jsonl.lock"] {
        let source = format!("{id}:{STATE}/{file}");
        docker(&["cp", &source, dir.join(file).to_str().unwrap()]);
    }
    let expected_id = info["Config"]["Labels"]["openshell.ai/sandbox-id"].as_str().unwrap();
    let result = Command::new("python3")
        .arg(std::env::var("CP15_VERIFIER").expect("independent verifier required"))
        .arg("--journal").arg(dir.join("permits.jsonl"))
        .arg("--witness").arg(dir.join("witness.json"))
        .arg("--sandbox-id").arg(expected_id).output().unwrap();
    assert!(result.status.success(), "raw verification failed: {}", String::from_utf8_lossy(&result.stderr));
    let validated: Value = serde_json::from_slice(&result.stdout).unwrap();
    fs::write(dir.join("verification.json"), &result.stdout).unwrap();
    validated
}

fn preserves_prefix(before: &Value, after: &Value) {
    let old = before["records"].as_array().unwrap();
    let new = after["records"].as_array().unwrap();
    assert!(new.len() >= old.len(), "durable history shrank");
    assert_eq!(old.as_slice(), &new[..old.len()], "durable prefix changed");
}

fn receiver_script(port: u16, http: bool) -> String {
    format!(r#"import socket, json, time
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',{port}))
s.listen()
while True:
 c,_=s.accept()
 print(json.dumps({{'kind':'accept','port':{port},'monotonic_ns':time.monotonic_ns()}}),flush=True)
 c.settimeout(10)
 try:
  data=b''
  stop=b'\r\n\r\n' if {http} else b'\n'
  while stop not in data:
   piece=c.recv(4096)
   if not piece: break
   data+=piece
  if not data: continue
  if {http}:
   fields=data.decode('ascii').split('\r\n')
   token=next(v.split(':',1)[1].strip() for v in fields if v.lower().startswith('x-cp15-challenge:'))
  else: token=data.decode('ascii').strip()
  print(json.dumps({{'kind':'receipt','challenge':token,'port':{port},'monotonic_ns':time.monotonic_ns()}}),flush=True)
  body=token.encode()+b'\n'
  if {http}: c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
  else: c.sendall(body)
 except Exception as e:
  print(json.dumps({{'kind':'error','error':str(e)}}),flush=True)
 finally: c.close()
"#, http=if http { "True" } else { "False" })
}

fn client_script(surface: &str, port: u16, challenge: &str) -> String {
    format!(r#"import os,socket
surface={surface:?}
token={challenge:?}
host={HOST:?}
port={port}
for key in ('ALL_PROXY','HTTP_PROXY','HTTPS_PROXY','all_proxy','http_proxy','https_proxy'):
 assert key not in os.environ, 'native runtime must have no proxy environment'
with socket.create_connection((host,port),timeout=10) as s:
 s.settimeout(10)
 if surface=='native_http':
  request='GET /allowed HTTP/1.1\r\nHost: '+host+':'+str(port)+'\r\nX-CP15-Challenge: '+token+'\r\nConnection: close\r\n\r\n'
  s.sendall(request.encode())
 else: s.sendall(token.encode()+b'\n')
 response=b''
 while (token+'\n').encode() not in response:
  part=s.recv(4096)
  assert part, response
  response+=part
 assert (token+'\n').encode() in response, response
print('CP15_CLIENT_OK')
"#)
}

fn receiver_events(fixture: &HostPythonFixture) -> Vec<Value> {
    fixture.logs().unwrap().lines().map(|line| serde_json::from_str(line).expect("receiver JSONL")).collect()
}

async fn ready(sandbox: &SandboxGuard) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if sandbox.exec(&["python3", "-c", "print('CP15_READY')"]).await.is_ok() { return; }
        assert!(tokio::time::Instant::now() < deadline, "sandbox failed to become ready");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn lifecycle(action: &str, sandbox: &SandboxGuard) {
    let (out, code) = tokio::time::timeout(Duration::from_secs(150), run_cli(&["sandbox", action, &sandbox.name])).await.expect("lifecycle command deadline");
    assert_eq!(code, 0, "sandbox {action}: {out}");
}

async fn exercise(sandbox: &SandboxGuard, fixtures: &[HostPythonFixture], phase: &str, output: &Path, previous: Option<&Value>) -> Value {
    let old_count = previous.map_or(0, |v| v["count"].as_u64().unwrap() as usize);
    let mut receipts = Vec::new();
    for (index, surface) in SURFACES.iter().enumerate() {
        let fixture = &fixtures[index];
        let challenge = format!("{}-{phase}-{surface}", sandbox.name);
        let before_accepts = receiver_events(fixture).iter().filter(|v| v["kind"] == "accept").count();
        let result = sandbox.exec(&["python3", "-c", &client_script(surface, fixture.port, &challenge)]).await.expect("real runtime egress");
        assert!(result.contains("CP15_CLIENT_OK"), "{result}");
        let events = receiver_events(fixture);
        assert_eq!(events.iter().filter(|v| v["kind"] == "accept").count(), before_accepts+1, "unexpected upstream dial count");
        let matches: Vec<_> = events.iter().filter(|v| v["challenge"] == challenge).collect();
        assert_eq!(matches.len(), 1, "exact receiver receipt for {challenge}");
        receipts.push(json!({"surface":surface,"port":fixture.port,"challenge":challenge,"receipt":matches[0]}));
        fs::write(output.join(format!("receiver-{surface}.jsonl")), fixture.logs().unwrap()).unwrap();
    }
    let state = snapshot(&companion(&sandbox.name), phase, output);
    if let Some(old) = previous { preserves_prefix(old, &state); }
    let records = state["records"].as_array().unwrap();
    assert_eq!(records.len(), old_count+SURFACES.len(), "one distinct admission per bounded runtime operation");
    for (index, receipt) in receipts.iter_mut().enumerate() {
        let record = &records[old_count+index];
        assert_eq!(record["surface"], "transparent_tcp", "native clients share the mediated entrypoint");
        receipt["enforcement_surface"] = json!("transparent_tcp");
        assert_eq!(record["port"], receipt["port"]);
        assert_eq!(record["host"], HOST);
        receipt["operation_id"] = record["operation_id"].clone();
        receipt["binding"] = json!("one isolated request per unique port and journal delta; ID is not carried on wire");
    }
    fs::write(output.join(phase).join("receipts.json"), serde_json::to_vec_pretty(&receipts).unwrap()).unwrap();
    println!("CP15_NATIVE_PHASE {phase}: two native clients and raw commitments verified; full CP15 acceptance remains false");
    state
}

fn session(state: &Value) -> &Value { &state["records"].as_array().unwrap().last().unwrap()["supervisor_session_id"] }

#[tokio::test]
async fn native_supervisor_sandbox_lifecycle_preserves_durable_evidence() {
    assert_eq!(std::env::var("OPENSHELL_E2E_DRIVER").as_deref(), Ok("docker"), "CP15 must never silently skip");
    assert_eq!(std::env::var("OPENSHELL_CP15_DURABLE_EVIDENCE").as_deref(), Ok("1"));
    let output = PathBuf::from(std::env::var("CP15_EVIDENCE_DIR").expect("evidence output required"));
    fs::create_dir_all(&output).unwrap();
    let mut fixtures = Vec::new();
    for index in 0..SURFACES.len() {
        let port = find_free_port();
        fixtures.push(HostPythonFixture::start(&receiver_script(port, index==0), port).await.unwrap());
    }
    let mut policy = NamedTempFile::new().unwrap();
    write!(policy, r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock: {{ compatibility: best_effort }}
process: {{ run_as_user: sandbox, run_as_group: sandbox }}
network_policies:
  cp15:
    name: cp15
    endpoints:
      - host: {HOST}
        port: {http}
        protocol: rest
        access: full
        allowed_ips: ["127.0.0.0/8"]
      - host: {HOST}
        port: {tcp}
        protocol: tcp
        allowed_ips: ["127.0.0.0/8"]
    binaries:
      - path: "/**"
"#, http=fixtures[0].port, tcp=fixtures[1].port).unwrap();
    policy.flush().unwrap();
    let mut sandbox = SandboxGuard::create_keep_with_args(&["--policy", policy.path().to_str().unwrap()], &["sh","-c","echo Ready; sleep infinity"], "Ready").await.expect("full gateway/supervisor/sandbox creation");
    let initial_info = companion(&sandbox.name);
    let volume = evidence_mount(&initial_info);
    let filter = format!("label=openshell.ai/sandbox-name={}", sandbox.name);
    let workload_id = docker(&["ps","-q","--filter", &filter,"--filter","label=openshell.ai/isolation-role=sandbox"]);
    let workload: Value = serde_json::from_str(&docker(&["inspect", &workload_id])).unwrap();
    assert_eq!(workload[0]["HostConfig"]["NetworkMode"], "none");
    assert!(workload[0]["Mounts"].as_array().unwrap().iter().all(|m| m["Name"] != volume && m["Destination"] != STATE), "workload must not mount evidence");
    let initial = exercise(&sandbox, &fixtures, "initial", &output, None).await;

    let _gateway = ManagedGateway::from_env().unwrap().expect("owned gateway required for reconnect test");
    // SIGSTOP only stalls an established TCP session; it does not make the
    // supervisor observe a transport failure. Keep the exact same gateway
    // process alive and destroy only its established TCP sockets instead.
    // This produces a real connection reset while preserving gateway process
    // identity, supervisor container identity, and the durable evidence volume.
    let gateway_pid_file = PathBuf::from(std::env::var("OPENSHELL_E2E_GATEWAY_PID_FILE").unwrap());
    let gateway_pid = fs::read_to_string(&gateway_pid_file).unwrap();
    let gateway_pid = gateway_pid.trim().parse::<u32>().expect("owned gateway PID");
    assert!(gateway_pid > 1, "owned gateway PID required");
    let gateway_port = gateway_port_from_args();
    let supervisor_id = initial_info["Id"].as_str().unwrap();
    let before_logs = supervisor_logs(supervisor_id);
    let before_failures = session_failures(&before_logs);
    let reconnect_dir = output.join("gateway_reconnect");
    fs::create_dir_all(&reconnect_dir).unwrap();
    fs::write(reconnect_dir.join("before-reset.log"), &before_logs).unwrap();
    let sockets_before = gateway_sockets(gateway_port);
    fs::write(reconnect_dir.join("sockets-before.txt"), &sockets_before).unwrap();
    assert!(
        sockets_before.lines().skip(1).any(|line| !line.trim().is_empty()),
        "no established gateway transport found before reset: {sockets_before}"
    );
    let reset_output = reset_gateway_transports(gateway_port);
    fs::write(reconnect_dir.join("transport-reset.txt"), &reset_output).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let reset_failures = loop {
        let log = supervisor_logs(supervisor_id);
        let count = session_failures(&log);
        fs::write(reconnect_dir.join("after-reset.log"), &log).unwrap();
        if count > before_failures { break count; }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no observed supervisor transport failure after TCP reset"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    wait_for_healthy(Duration::from_secs(120)).await.unwrap();
    ready(&sandbox).await;
    let reconnected = exercise(&sandbox, &fixtures, "gateway_reconnect", &output, Some(&initial)).await;
    assert_ne!(session(&initial), session(&reconnected), "new accepted session required");
    assert_eq!(initial_info["Id"], companion(&sandbox.name)["Id"], "gateway reconnect must preserve supervisor process");
    assert_eq!(evidence_mount(&companion(&sandbox.name)), volume);
    assert_eq!(fs::read(output.join("initial/permits.jsonl.lock")).unwrap(), fs::read(reconnect_dir.join("permits.jsonl.lock")).unwrap(), "transport reconnect must preserve the writer token");
    fs::write(reconnect_dir.join("transport-transition.json"), serde_json::to_vec_pretty(&json!({
        "gateway_pid":gateway_pid, "gateway_port":gateway_port,
        "fault_injection":"tcp_socket_reset_via_ss_kill",
        "session_failures_before":before_failures, "session_failures_after_reset":reset_failures,
        "supervisor_id":supervisor_id, "supervisor_replaced":false,
        "writer_replaced":false, "accepted_session_changed":true,
    })).unwrap()).unwrap();

    let before = companion(&sandbox.name);
    lifecycle("stop", &sandbox).await;
    lifecycle("start", &sandbox).await;
    ready(&sandbox).await;
    let after = companion(&sandbox.name);
    assert_ne!(before["Id"], after["Id"], "supervisor must be replaced");
    assert_eq!(evidence_mount(&after), volume, "same persisted evidence volume required");
    let restarted = exercise(&sandbox, &fixtures, "sandbox_restart", &output, Some(&reconnected)).await;
    assert_ne!(session(&reconnected), session(&restarted));
    assert_ne!(fs::read(output.join("gateway_reconnect/permits.jsonl.lock")).unwrap(), fs::read(output.join("sandbox_restart/permits.jsonl.lock")).unwrap(), "replacement must claim a new writer token");

    // An unplanned supervisor death is terminal in the upstream Docker driver.
    // Freeze it before a native stop: Docker must kill the unresponsive process,
    // while the gateway owns the stopping transition and can safely start again.
    docker(&["kill", "--signal", "STOP", after["Id"].as_str().unwrap()]);
    lifecycle("stop", &sandbox).await;
    lifecycle("start", &sandbox).await;
    ready(&sandbox).await;
    let recovered_info = companion(&sandbox.name);
    assert_ne!(after["Id"], recovered_info["Id"], "forced stop/start must replace the supervisor");
    assert_eq!(evidence_mount(&recovered_info), volume, "forced stop/start must retain the evidence volume");
    let recovered = exercise(&sandbox, &fixtures, "forced_stop_start", &output, Some(&restarted)).await;
    assert_ne!(session(&restarted), session(&recovered));
    assert_ne!(fs::read(output.join("sandbox_restart/permits.jsonl.lock")).unwrap(), fs::read(output.join("forced_stop_start/permits.jsonl.lock")).unwrap());

    fs::write(output.join("runtime-result.json"), serde_json::to_vec_pretty(&json!({
        "status":"NATIVE_LIFECYCLE_VERIFIED", "supervisor_storage":"persistent_docker_volume",
        "overall_cp15_acceptance":false,
        "unexercised_entrypoints":["explicit_connect","forward_http"],
        "enforcement_surface":"transparent_tcp",
        "phases":["initial","gateway_reconnect","sandbox_restart","forced_stop_start"],
        "client_paths":SURFACES, "receiver_operations":8, "raw_commitments_verified":true,
        "volume":volume, "coverage":"NOT_ESTABLISHED", "outcome":"OUTCOME_UNKNOWN",
        "causal_fsync_before_receiver_observation_proven":false,
        "unplanned_supervisor_crash_auto_recovery_proven":false,
        "joint_rollback_detected":false, "authenticated_remote_witness":false,
        "physical_power_loss_tested":false
    })).unwrap()).unwrap();
    sandbox.cleanup().await;
    docker(&["volume", "rm", &volume]);
}
