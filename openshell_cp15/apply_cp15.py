#!/usr/bin/env python3
"""Apply CP14 plus the opt-in CP15 Docker lifecycle integration to its exact pin."""
from pathlib import Path
import subprocess
import sys

PIN = '484f0768fc6a0d93e0a2be295c1679aed24e18a9'
HERE = Path(__file__).resolve().parent


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f'CP15 source anchor mismatch: {old[:90]!r}')
    return text.replace(old, new, 1)


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: apply_cp15.py /path/to/pinned/OpenShell')
    root = Path(sys.argv[1]).resolve()
    head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    if head != PIN:
        raise SystemExit(f'CP15 refuses source drift: {head}')
    if subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True).strip():
        raise SystemExit('CP15 requires an unmodified source checkout')
    subprocess.run([sys.executable, str(HERE.parent/'openshell_cp10/apply_cp10.py'), str(root)], check=True)

    p = root/'crates/openshell-supervisor-network/src/durable_egress.rs'
    s = p.read_text().rstrip()
    if not s.endswith('}'):
        raise SystemExit('CP15 test module boundary mismatch')
    p.write_text(s[:-1]+'\n'+(HERE/'stale_dispatch_test.rs').read_text()+'\n}\n')

    # Seccomp-mediated raw TCP also enters the unified mediated handler. Retain
    # its origin instead of labelling its synthesized CONNECT as explicit CONNECT.
    p = root/'crates/openshell-supervisor-network/src/proxy.rs'
    s = p.read_text()
    if 'let blackbox_transparent = transparent_open.is_some();' not in s or 'if blackbox_transparent { EgressSurface::TransparentTcp } else { EgressSurface::Connect }' not in s:
        raise SystemExit('CP15 requires the actual CP14 CI source with transparent origin binding')

    # This is an explicitly enabled experimental Docker lane, not a change to
    # every supervisor's default environment. The workload never gets this mount.
    p = root/'crates/openshell-driver-docker/src/lib.rs'
    s = p.read_text()
    marker = '    if config.guest_tls.is_some() {\n        environment.extend(['
    s = replace_once(s, marker, '''    let blackbox_enabled = std::env::var("OPENSHELL_CP15_DURABLE_EVIDENCE").as_deref() == Ok("1");
    if blackbox_enabled {
        environment.extend([
            "OPENSHELL_BLACKBOX_EGRESS_JOURNAL=/var/lib/blackbox-acv/permits.jsonl".to_string(),
            "OPENSHELL_BLACKBOX_EGRESS_WITNESS=/var/lib/blackbox-acv/witness.json".to_string(),
        ]);
    }
'''+marker)
    marker = '    if let Some(socket) = config.provider_spiffe_workload_api_socket.as_ref() {\n        let parent = socket.parent().ok_or_else(|| {'
    s = replace_once(s, marker, '''    if blackbox_enabled {
        supervisor_mounts.push(Mount {
            target: Some("/var/lib/blackbox-acv".to_string()),
            source: Some(format!("{}-blackbox-evidence", docker_supervisor_volume_name(sandbox, config))),
            typ: Some(MountTypeEnum::VOLUME),
            read_only: Some(false),
            // Populate the empty volume from the image's 65534-owned directory.
            volume_options: Some(MountVolumeOptions { no_copy: Some(false), ..Default::default() }),
            ..Default::default()
        });
    }
'''+marker)
    p.write_text(s)
    directory = root/'deploy/docker/.build/prebuilt-binaries/blackbox-state'
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'CP15_STORAGE').write_text('Experimental durable supervisor evidence. Not a remote witness.\n')
    p = root/'deploy/docker/Dockerfile.supervisor'
    s = replace_once(p.read_text(), 'ENTRYPOINT ["/openshell-supervisor"]',
                    'COPY --chown=65534:65534 --chmod=0700 deploy/docker/.build/prebuilt-binaries/blackbox-state/ /var/lib/blackbox-acv/\n'
                    '# CP15 uses a native GNU CI build, whose unwind runtime is not in base-nossl.\n'
                    'COPY --chmod=0555 deploy/docker/.build/prebuilt-binaries/${TARGETARCH}/libgcc_s.so.1 /lib/libgcc_s.so.1\n\n'
                    'ENTRYPOINT ["/openshell-supervisor"]')
    p.write_text(s)
    (root/'e2e/rust/tests/blackbox_lifecycle.rs').write_text((HERE/'blackbox_lifecycle.rs').read_text())
    if (HERE/'blackbox_native_lifecycle.rs').exists():
        (root/'e2e/rust/tests/blackbox_native_lifecycle.rs').write_text((HERE/'blackbox_native_lifecycle.rs').read_text())
    print('CP15 applied to exact source pin; live validation still required')


if __name__ == '__main__':
    main()
