#!/usr/bin/python3
"""Non-privileged dry-run and installed-layout verifier for FK0957 supervisor."""
from __future__ import annotations

import argparse
import grp
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
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
    "/etc/sidecar/fk0957/remote-trust.json": ("root", "root", 0o400),
    "/etc/sidecar/fk0957/runtime-release-manifest.json": ("root", "root", 0o400),
    "/etc/sidecar/fk0957/remote-trust.json": ("root", "root", 0o400),
    "/run/sidecar": ("root", "sidecar-acquire", 0o750),
    "/var/lib/sidecar/fk0957/supervisor": ("root", "root", 0o700),
    "/var/lib/sidecar/fk0957/consumed-release-authorizations": ("root", "root", 0o700),
}
FILE_SOURCES = {
    "/etc/sidecar/fk0957/remote-trust.json": ROOT / "ops/phk2/FK0957_REMOTE_TRUST_TEMPLATE.json",
    "/etc/sidecar/fk0957/runtime-release-manifest.json":
        ROOT / "ops/phk2/FK0957_RUNTIME_MANIFEST.template.json",
    "/etc/systemd/system/fk0957-supervisor.service": UNIT,
    "/etc/udev/rules.d/90-sidecar-fk0957-supervised.rules":
        ROOT / "ops/phk2/90-sidecar-fk0957-supervised.rules",
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
    missing = []
    for relative in REMOTE_SOURCE_PATHS:
        path = ROOT / relative
        try:
            info = path.lstat()
        except OSError:
            missing.append(relative)
            continue
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
            missing.append(relative)
    if missing:
        raise ValueError("remote source closure is incomplete")
    text = UNIT.read_text(encoding="utf-8")
    supervisor_text = SOURCE.read_text(encoding="utf-8")
    if ("Restart=no" not in text or "User=root" not in text or
            'LAUNCHER = "/usr/local/bin/fk0957-safe-launcher"' not in supervisor_text or
            "ExecStart=/usr/local/bin/fk0957-safe-launcher --supervisor" not in text):
        raise ValueError("service security policy is incomplete")
    template = (ROOT / "ops/phk2/FK0957_REMOTE_TRUST_TEMPLATE.json").read_bytes()
    from phk2_fk0957_remote_topology_endpoint import TRUST_CONFIG_SHA256
    if hashlib.sha256(template).hexdigest() != TRUST_CONFIG_SHA256:
        raise ValueError("pinned trust template digest does not match source")


def _source_for_install_path(raw: str) -> Path | None:
    if raw in FILE_SOURCES:
        return FILE_SOURCES[raw]
    prefix = "/usr/local/lib/sidecar/fk0957/"
    if raw.startswith(prefix):
        relative = raw[len(prefix):]
        candidate = ROOT / relative
        if candidate.is_file():
            return candidate
    return None


def stage_package(root: Path) -> None:
    """Stage a complete non-privileged install tree for package verification."""
    verify_source_package()
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for raw, (_owner, _group, mode) in INSTALLS.items():
        destination = root / raw.lstrip("/")
        source = _source_for_install_path(raw)
        if source is None and raw == "/usr/local/bin/fk0957-safe-launcher":
            continue
        if source is None:
            destination.mkdir(parents=True, exist_ok=True)
            destination.chmod(mode)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, destination, follow_symlinks=False)
            destination.chmod(mode)
    staged_bootstrap = root / "usr/local/lib/sidecar/fk0957/tools/phk2_host/fk0957_safe_bootstrap.py"
    staged_manifest = root / "etc/sidecar/fk0957/runtime-release-manifest.json"
    launcher = root / "usr/local/bin/fk0957-safe-launcher"
    build_script = ROOT / "tools/phk2_host/build_fk0957_safe_launcher.py"
    subprocess.run([
        sys.executable, str(build_script), "--output", str(launcher),
        "--bootstrap-path", "/usr/local/lib/sidecar/fk0957/tools/phk2_host/fk0957_safe_bootstrap.py",
        "--bootstrap-bytes", str(staged_bootstrap),
        "--manifest-path", "/etc/sidecar/fk0957/runtime-release-manifest.json",
        "--manifest-bytes", str(staged_manifest),
        "--trust-config-path", "/etc/sidecar/fk0957/remote-trust.json",
        "--trust-config-bytes", str(root / "etc/sidecar/fk0957/remote-trust.json"),
    ], check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    launcher.chmod(0o755)
    # Preserve the intended deployment permissions in the staged tree.
    for raw, (_owner, _group, mode) in INSTALLS.items():
        destination = root / raw.lstrip("/")
        if destination.exists() and not destination.is_symlink():
            destination.chmod(mode)


def verify_staged_package(root: Path) -> list[str]:
    errors = []
    root = root.resolve()
    for raw, (_owner, _group, mode) in INSTALLS.items():
        path = root / raw.lstrip("/")
        try:
            info = path.lstat()
        except OSError:
            errors.append(f"MISSING {raw}")
            continue
        if stat.S_ISLNK(info.st_mode):
            errors.append(f"SYMLINK {raw}")
            continue
        if stat.S_IMODE(info.st_mode) != mode:
            errors.append(f"MODE {raw} expected {mode:04o}")
        source = _source_for_install_path(raw)
        if source is not None:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                errors.append(f"FILE_IDENTITY {raw}")
            elif hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
                errors.append(f"CONTENT {raw}")
    launcher = root / "usr/local/bin/fk0957-safe-launcher"
    if launcher.exists():
        try:
            headers = subprocess.run(["/usr/bin/readelf", "-l", str(launcher)], check=True,
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={"PATH": "/usr/bin:/bin", "LANG": "C"}).stdout
            if "INTERP" in headers:
                errors.append("LAUNCHER_DYNAMIC_INTERPRETER")
        except (OSError, subprocess.SubprocessError):
            errors.append("LAUNCHER_NOT_STATIC_ELF")
    return errors


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
    parser.add_argument("--stage-root", type=Path,
                        help="stage and verify the package beneath a disposable filesystem root")
    args = parser.parse_args(argv)
    try:
        verify_source_package()
        if args.apply:
            print("REFUSED: privileged installation is deliberately not implemented")
            return 2
        if args.stage_root is not None:
            stage_package(args.stage_root)
            errors = verify_staged_package(args.stage_root)
            if errors:
                print("FK0957_SUPERVISOR_STAGE=FAIL")
                for error in errors:
                    print(error)
                return 1
            print("FK0957_SUPERVISOR_STAGE=PASS")
            print("INSTALL=DISPOSABLE_ROOT_ONLY")
            return 0
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
