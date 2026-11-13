#!/usr/bin/python3
"""Non-privileged dry-run and installed-layout verifier for FK0957 supervisor."""
from __future__ import annotations

import argparse
import grp
import os
from pathlib import Path
import stat
import sys

from phk2_fk0957_remote_topology_endpoint import REMOTE_SOURCE_PATHS

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "ops/phk2/fk0957-supervisor.service"
SOURCE = ROOT / "tools/phk2_host/fk0957_supervisor.py"
INSTALLS = {
    "/usr/local/bin/fk0957-safe-launcher": ("root", "root", 0o755),
    "/usr/local/lib/sidecar/fk0957": ("root", "root", 0o755),
    "/usr/local/lib/sidecar/fk0957/tools": ("root", "root", 0o755),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host": ("root", "root", 0o755),
    "/usr/local/lib/sidecar/fk0957/ops": ("root", "root", 0o755),
    "/usr/local/lib/sidecar/fk0957/ops/phk2": ("root", "root", 0o755),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/fk0957_supervisor.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/fk0957_supervisor_client.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/fk0957_safe_bootstrap.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/fk0957_safe_launcher.c": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/build_fk0957_safe_launcher.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/phk2_fk0957_topology_transport.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/phk2_fk0957_topology_discovery.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/phk2_fk0957_idcode_gate.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/phk2_fk0957_remote_orchestrator.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/tools/phk2_host/phk2_fk0957_remote_topology_endpoint.py": ("root", "root", 0o644),
    "/usr/local/lib/sidecar/fk0957/ops/phk2/fk0957-supervisor.service": ("root", "root", 0o644),
    "/etc/systemd/system/fk0957-supervisor.service": ("root", "root", 0o644),
    "/etc/udev/rules.d/90-sidecar-fk0957-supervised.rules": ("root", "root", 0o644),
    "/etc/udev/rules.d": ("root", "root", 0o755),
    "/etc/sidecar/fk0957": ("root", "root", 0o750),
    "/run/sidecar": ("root", "sidecar-acquire", 0o750),
    "/var/lib/sidecar/fk0957/supervisor": ("root", "root", 0o700),
    "/var/lib/sidecar/fk0957/consumed-release-authorizations": ("root", "root", 0o700),
}

# Install the entire source closure the remote endpoint verifies and imports.
# Keep the repository-relative layout below the immutable release root so its
# signed source manifest paths have one unambiguous mapping.
for relative in REMOTE_SOURCE_PATHS:
    INSTALLS.setdefault(
        f"/usr/local/lib/sidecar/fk0957/{relative}", ("root", "root", 0o644))


def verify_source_package() -> None:
    if not SOURCE.is_file() or not UNIT.is_file():
        raise ValueError("supervisor package source or unit is missing")
    missing = [relative for relative in REMOTE_SOURCE_PATHS
               if not (ROOT / relative).is_file()]
    if missing:
        raise ValueError("remote source closure is incomplete")
    text = UNIT.read_text(encoding="utf-8")
    supervisor_text = SOURCE.read_text(encoding="utf-8")
    if ("Restart=no" not in text or "User=root" not in text or
            'LAUNCHER = "/usr/local/bin/fk0957-safe-launcher"' not in supervisor_text or
            "ExecStart=/usr/local/bin/fk0957-safe-launcher --supervisor" not in text):
        raise ValueError("service security policy is incomplete")


def verify_installed() -> list[str]:
    errors = []
    for raw, (_owner, group, mode) in INSTALLS.items():
        path = Path(raw)
        try:
            info = path.lstat()
        except OSError:
            errors.append(f"MISSING {raw}")
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(f"SYMLINK {raw}")
        if stat.S_IMODE(info.st_mode) != mode:
            errors.append(f"MODE {raw} expected {mode:04o}")
        if info.st_uid != 0:
            errors.append(f"OWNER {raw} expected root")
        try:
            expected_gid = grp.getgrnam(group).gr_gid
        except KeyError:
            errors.append(f"GROUP {raw} missing group {group}")
        else:
            if info.st_gid != expected_gid:
                errors.append(f"GROUP {raw} expected {group}")
    return errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        verify_source_package()
        if args.apply:
            print("REFUSED: privileged installation is deliberately not implemented")
            return 2
        if args.verify:
            errors = verify_installed()
            if errors:
                print("FK0957_SUPERVISOR_INSTALL=FAIL")
                for error in errors:
                    print(error)
                return 1
            print("FK0957_SUPERVISOR_INSTALL=PASS")
            return 0
        for path, (owner, group, mode_value) in INSTALLS.items():
            print(f"{path} owner={owner}:{group} mode={mode_value:04o}")
        print("SERVICE=ops/phk2/fk0957-supervisor.service")
        print("INSTALL=DRY_RUN_ONLY")
        return 0
    except (OSError, ValueError) as exc:
        print(f"FK0957_SUPERVISOR_PACKAGE=FAIL ({type(exc).__name__})")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
