#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(sys.argv[1]).resolve()
HERE = Path(__file__).resolve().parent
REPO = HERE.parent

subprocess.run(
    [sys.executable, str(REPO / "openshell_cp10" / "apply_cp10.py"), str(ROOT)],
    check=True,
)

driver = ROOT / "crates/openshell-driver-docker/src/lib.rs"
source = driver.read_text()
anchor = '''        format!(
            "{}={}",
            openshell_core::sandbox_env::TELEMETRY_ENABLED,
            openshell_core::telemetry::enabled_env_value()
        ),
    ];
    if config.guest_tls.is_some() {'''
replacement = '''        format!(
            "{}={}",
            openshell_core::sandbox_env::TELEMETRY_ENABLED,
            openshell_core::telemetry::enabled_env_value()
        ),
    ];

    // BLACKBOX CP15: operator-owned E2E instrumentation only. The sandbox
    // workload cannot set this driver-process environment variable. Keeping
    // the hook opt-in avoids changing ordinary supervisor environments.
    if std::env::var_os("OPENSHELL_BLACKBOX_E2E_EVIDENCE").is_some() {
        environment.extend([
            "OPENSHELL_BLACKBOX_EGRESS_JOURNAL=/tmp/blackbox/permits.jsonl".to_string(),
            "OPENSHELL_BLACKBOX_EGRESS_WITNESS=/tmp/blackbox/witness.json".to_string(),
        ]);
    }

    if config.guest_tls.is_some() {'''
count = source.count(anchor)
if count != 1:
    raise SystemExit(f"CP15 Docker supervisor env anchor count={count}")
driver.write_text(source.replace(anchor, replacement, 1))

target = ROOT / "e2e/rust/tests/cp15_blackbox_runtime.rs"
target.write_text((HERE / "cp15_blackbox_runtime.rs").read_text())
print("CP15 live-runtime patch applied")
