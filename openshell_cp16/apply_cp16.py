#!/usr/bin/env python3
"""Apply CP15, then enable durable evidence for the real standalone explicit proxy."""
from pathlib import Path
import subprocess
import sys

PIN = "484f0768fc6a0d93e0a2be295c1679aed24e18a9"
HERE = Path(__file__).resolve().parent


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_cp16.py /path/to/pinned/OpenShell")
    root = Path(sys.argv[1]).resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != PIN:
        raise SystemExit(f"CP16 refuses source drift: {head}")
    if subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain"], text=True
    ).strip():
        raise SystemExit("CP16 requires an unmodified source checkout")

    subprocess.run(
        [sys.executable, str(HERE.parent / "openshell_cp15" / "apply_cp15.py"), str(root)],
        check=True,
    )

    # CP15 deliberately demonstrated the stale-dispatch failure before
    # applying this second-stage fix. CP16 inherits the fixed state, not the
    # red negative-control state.
    subprocess.run(
        [
            sys.executable,
            str(HERE.parent / "openshell_cp15" / "apply_writer_dispatch_fix.py"),
            str(root),
        ],
        check=True,
    )

    path = root / "crates/openshell-supervisor/src/lib.rs"
    source = path.read_text()

    old = '''    let (_, workspace_rx) = tokio::sync::watch::channel(String::new());
    let tls_dir = prepare_network_proxy_tls_dir(tls_dir)?;
    let mut networking = openshell_supervisor_network::run::run_networking(
'''
    new = '''    let (_, workspace_rx) = tokio::sync::watch::channel(String::new());
    // CP16: the standalone explicit proxy has no gateway/sandbox session, but
    // durable authorization still needs a process-lifetime dispatch authority.
    // Publish an explicit network-proxy scope only when the experimental
    // durable journal is enabled. This is not presented as a sandbox identity.
    let blackbox_durable_enabled = std::env::var_os(
        openshell_supervisor_network::durable_egress::JOURNAL_ENV,
    )
    .is_some();
    if blackbox_durable_enabled {
        openshell_supervisor_network::durable_egress::publish_supervisor_session(Some(format!(
            "network-proxy:{}:{}",
            std::process::id(),
            listen
        )));
    }

    let tls_dir = prepare_network_proxy_tls_dir(tls_dir)?;
    let mut networking = openshell_supervisor_network::run::run_networking(
'''
    source = replace_once(source, old, new, "network-proxy durable authority")

    old = '''        &provider_credentials,
        None,
        Some("network-proxy"),
        None,
'''
    new = '''        &provider_credentials,
        blackbox_durable_enabled.then_some("network-proxy"),
        Some("network-proxy"),
        None,
'''
    source = replace_once(source, old, new, "network-proxy durable gate scope")

    old = '''    tokio::select! {
        _ = exited => Err(miette::miette!("network-proxy accept loop exited unexpectedly")),
        () = wait_for_control_shutdown_signal() => {
            drop(networking);
            Ok(0)
        }
    }
}
'''
    new = '''    let outcome = tokio::select! {
        _ = exited => Err(miette::miette!("network-proxy accept loop exited unexpectedly")),
        () = wait_for_control_shutdown_signal() => {
            drop(networking);
            Ok(0)
        }
    };
    if blackbox_durable_enabled {
        openshell_supervisor_network::durable_egress::publish_supervisor_session(None);
    }
    outcome
}
'''
    source = replace_once(source, old, new, "network-proxy authority cleanup")
    path.write_text(source)
    print("CP16 applied: standalone CONNECT/forward HTTP durable gate enabled at exact source pin")


if __name__ == "__main__":
    main()
