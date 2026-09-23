#!/usr/bin/env python3
"""Apply CP17 then replace single remote witness with CP18 quorum finality."""
from pathlib import Path
import subprocess
import sys

PIN = "484f0768fc6a0d93e0a2be295c1679aed24e18a9"
HERE = Path(__file__).resolve().parent


def rep(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_cp18.py /path/to/pinned/OpenShell")
    root = Path(sys.argv[1]).resolve()
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
    ).strip()
    if head != PIN:
        raise SystemExit(f"CP18 refuses source drift: {head}")
    if subprocess.check_output(
        ["git", "-C", str(root), "status", "--porcelain"], text=True
    ).strip():
        raise SystemExit("CP18 requires an unmodified source checkout")

    subprocess.run(
        [sys.executable, str(HERE.parent / "openshell_cp17" / "apply_cp17.py"), str(root)],
        check=True,
    )

    # Replace CP17's single-witness client with quorum-capable CP18.
    target = root / "crates/openshell-supervisor-network/src/remote_witness.rs"
    target.write_text((HERE / "remote_witness.rs").read_text())

    # HMAC-SHA256 authenticates OpenShell -> witness requests in quorum mode.
    p = root / "crates/openshell-supervisor-network/Cargo.toml"
    s = p.read_text()
    if 'hmac = "0.12"' not in s:
        s = rep(
            s,
            'aws-lc-rs = { workspace = true }\n',
            'aws-lc-rs = { workspace = true }\nhmac = "0.12"\n',
            "CP18 hmac dependency",
        )
    p.write_text(s)

    print(
        "CP18 applied: 2-of-N authenticated witness quorum gates effectuation"
    )


if __name__ == "__main__":
    main()
