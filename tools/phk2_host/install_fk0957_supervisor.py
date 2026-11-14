#!/usr/bin/python3
"""Non-privileged dry-run and installed-layout verifier for FK0957 supervisor."""
from __future__ import annotations

import argparse
import errno
import json
import grp
import hashlib
import os
from pathlib import Path
import pwd
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
    "/usr/lib/sysusers.d": ("root", "root", 0o755),
    "/usr/lib/sysusers.d/90-sidecar-fk0957.conf": ("root", "root", 0o644),
    "/etc/udev/rules.d/90-sidecar-fk0957-supervised.rules": ("root", "root", 0o644),
    "/etc/udev/rules.d": ("root", "root", 0o755),
    "/etc/sidecar/fk0957": ("root", "root", 0o750),
    "/etc/sidecar/fk0957/remote-trust.json": ("root", "root", 0o400),
    "/etc/sidecar/fk0957/release-issuer.pub": ("root", "root", 0o400),
    "/etc/sidecar/fk0957/handoff-issuer.pub": ("root", "root", 0o400),
    "/etc/sidecar/fk0957/runtime-release-manifest.json": ("root", "root", 0o400),
    "/etc/sidecar/fk0957/deployment-ownership.json": ("root", "root", 0o400),
    "/run/sidecar": ("root", "sidecar-acquire", 0o750),
    "/var/lib/sidecar/fk0957/supervisor": ("root", "root", 0o700),
    "/var/lib/sidecar/fk0957/consumed-release-authorizations": ("root", "root", 0o700),
}
FILE_SOURCES = {
    "/etc/sidecar/fk0957/remote-trust.json": ROOT / "ops/phk2/FK0957_REMOTE_TRUST_TEMPLATE.json",
    "/etc/sidecar/fk0957/runtime-release-manifest.json":
        ROOT / "ops/phk2/FK0957_RUNTIME_MANIFEST.template.json",
    "/etc/systemd/system/fk0957-supervisor.service": UNIT,
    "/usr/lib/sysusers.d/90-sidecar-fk0957.conf": ROOT / "ops/phk2/fk0957.sysusers.conf",
    "/etc/sidecar/fk0957/deployment-ownership.json": ROOT / "ops/phk2/FK0957_DEPLOYMENT_OWNERSHIP.json",
    "/etc/udev/rules.d/90-sidecar-fk0957-supervised.rules":
        ROOT / "ops/phk2/90-sidecar-fk0957-supervised.rules",
}

OWNER_IDS = {"root": 0, "sidecar-acquire": 970, "sidecar-fk0957-runner": 971}
GROUP_IDS = {"root": 0, "sidecar-acquire": 970, "sidecar-fk0957-runner": 971,
             "fk0957-device": 972}
RUNTIME_OWNERSHIP_ROWS = [
    {"path": "/run/sidecar/fk0957-supervisor.sock", "owner": "root", "owner_uid": 0,
     "group": "sidecar-acquire", "group_gid": 970, "mode": "0660",
     "lifecycle": "created_by_supervisor"},
]


def ownership_payload() -> dict:
    rows = []
    for path, (owner, group, mode) in sorted(INSTALLS.items()):
        rows.append({"path": path, "owner": owner, "owner_uid": OWNER_IDS[owner],
                     "group": group, "group_gid": GROUP_IDS[group],
                     "mode": f"{mode:04o}", "lifecycle": "installed"})
    rows.extend(RUNTIME_OWNERSHIP_ROWS)
    return {
        "schema": "fk0957-deployment-ownership-v1", "version": 1,
        "service": {"name": "fk0957-supervisor.service", "uid": 0,
                    "user": "root", "gid": 970, "group": "sidecar-acquire"},
        "principals": [
            {"name": "root", "uid": 0, "primary_group": "root", "primary_gid": 0,
             "role": "supervisor"},
            {"name": "sidecar-acquire", "uid": 970, "primary_group": "sidecar-acquire",
             "primary_gid": 970, "role": "ordinary_ipc_client"},
            {"name": "sidecar-fk0957-runner", "uid": 971,
             "primary_group": "sidecar-fk0957-runner", "primary_gid": 971,
             "supplementary_groups": ["fk0957-device"], "role": "one_shot_child"},
            {"name": "fk0957-device", "gid": 972, "role": "exact_usb_access_group"},
        ],
        "paths": rows,
        "authority_policy": {
            "state_and_ledger_owner_uid": 0, "state_and_ledger_mode": "0700",
            "ordinary_client_uid": 970, "ordinary_client_may_write_state": False,
            "ordinary_client_may_write_ledger": False,
            "ordinary_client_may_connect_socket": True,
            "runner_may_write_supervisor_state": False,
            "protected_state_acl_write_grants": False,
        },
    }


def _canonical_json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode()


def _mode_grants_write(mode: int, owner_uid: int, owner_gid: int,
                       uid: int, groups: set[int]) -> bool:
    if uid == owner_uid:
        return bool(mode & stat.S_IWUSR)
    if owner_gid in groups:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)

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
    ownership_path = ROOT / "ops/phk2/FK0957_DEPLOYMENT_OWNERSHIP.json"
    if ownership_path.read_bytes() != _canonical_json(ownership_payload()):
        raise ValueError("deployment ownership manifest does not match install policy")
    sysusers = (ROOT / "ops/phk2/fk0957.sysusers.conf").read_text(encoding="utf-8")
    if not all(token in sysusers for token in (
            "sidecar-acquire 970", "sidecar-fk0957-runner 971:971", "fk0957-device 972")):
        raise ValueError("dedicated service identity policy is incomplete")


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
        if source is None and raw in {
                "/etc/sidecar/fk0957/release-issuer.pub",
                "/etc/sidecar/fk0957/handoff-issuer.pub"}:
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            destination.write_bytes(b"")  # Provisioning slot; empty keys are rejected.
            destination.chmod(mode)
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
        elif raw in {"/etc/sidecar/fk0957/release-issuer.pub",
                     "/etc/sidecar/fk0957/handoff-issuer.pub"}:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 0:
                errors.append(f"UNPROVISIONED_KEY_SLOT {raw}")
    ownership_path = root / "etc/sidecar/fk0957/deployment-ownership.json"
    try:
        staged_ownership = json.loads(ownership_path.read_bytes())
    except (OSError, ValueError):
        errors.append("OWNERSHIP_MANIFEST_INVALID")
    else:
        expected_ownership = ownership_payload()
        if staged_ownership != expected_ownership:
            errors.append("OWNERSHIP_MANIFEST_POLICY_MISMATCH")
        policy = staged_ownership.get("authority_policy", {})
        protected = {row["path"]: row for row in staged_ownership.get("paths", [])
                     if isinstance(row, dict) and "path" in row}
        for protected_path in ("/var/lib/sidecar/fk0957/supervisor",
                               "/var/lib/sidecar/fk0957/consumed-release-authorizations"):
            row = protected.get(protected_path, {})
            mode = int(row.get("mode", "0000"), 8)
            owner_gid = row.get("group_gid", -1)
            ordinary_can_write = _mode_grants_write(mode, row.get("owner_uid", -1),
                                                    owner_gid, 970, {970})
            runner_can_write = _mode_grants_write(mode, row.get("owner_uid", -1),
                                                  owner_gid, 971, {971, 972})
            if (row.get("owner_uid") != 0 or row.get("group_gid") != 0 or
                    row.get("mode") != "0700" or ordinary_can_write or runner_can_write or
                    policy.get("ordinary_client_may_write_state") is not False or
                    policy.get("ordinary_client_may_write_ledger") is not False):
                errors.append(f"ORDINARY_APP_WRITE_POLICY {protected_path}")
        socket_row = protected.get("/run/sidecar/fk0957-supervisor.sock", {})
        if (socket_row.get("owner_uid") != 0 or socket_row.get("group_gid") != 970 or
                socket_row.get("mode") != "0660"):
            errors.append("SUPERVISOR_SOCKET_POLICY")
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
    expected_users = {"sidecar-acquire": (970, 970),
                      "sidecar-fk0957-runner": (971, 971)}
    for name, (uid, gid) in expected_users.items():
        try:
            user = pwd.getpwnam(name)
        except KeyError:
            errors.append(f"USER {name} missing")
            continue
        if (user.pw_uid, user.pw_gid) != (uid, gid):
            errors.append(f"USER {name} expected uid/gid {uid}/{gid}")
        if user.pw_shell not in {"/usr/sbin/nologin", "/bin/false"} or user.pw_dir != "/nonexistent":
            errors.append(f"USER {name} must be non-login")
    for name, gid in {"sidecar-acquire": 970, "fk0957-device": 972}.items():
        try:
            group = grp.getgrnam(name)
        except KeyError:
            errors.append(f"GROUP {name} missing")
        else:
            if group.gr_gid != gid:
                errors.append(f"GROUP {name} expected gid {gid}")
    try:
        runner_name = "sidecar-fk0957-runner"
        device_group = grp.getgrnam("fk0957-device")
        runner = pwd.getpwnam(runner_name)
        members = set(device_group.gr_mem)
        primary = {user.pw_name for user in pwd.getpwall() if user.pw_gid == device_group.gr_gid}
        if (members | primary) != {runner_name}:
            errors.append("DEVICE_GROUP_MEMBERSHIP must be limited to the runner")
    except KeyError:
        pass
    for protected in (Path("/var/lib/sidecar/fk0957/supervisor"),
                      Path("/var/lib/sidecar/fk0957/consumed-release-authorizations")):
        cursor = protected
        while cursor != Path("/"):
            for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
                try:
                    os.getxattr(cursor, attribute, follow_symlinks=False)
                except OSError as exc:
                    if exc.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
                        errors.append(f"ACL_INSPECTION {cursor}")
                else:
                    errors.append(f"ACL_PRESENT {cursor}")
            cursor = cursor.parent
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
