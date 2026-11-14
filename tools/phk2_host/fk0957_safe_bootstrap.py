"""Trusted post-launch bootstrap for the FK0957 CLI (invoked with -I -S)."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

_EXPECTED_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "FK0957_TRUSTED_LAUNCHER": "1",
}


def _refuse() -> int:
    sys.stdout.write('{"status":"REFUSED","phase":"PRELIVE_VALIDATION",'
                     '"code":"TRUSTED_LAUNCHER_REQUIRED"}\n')
    return 2


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _read_launcher_manifest(args: list[str]) -> tuple[list[str], dict | None, bytes | None]:
    if len(args) < 4:
        raise ValueError("manifest capability missing")
    def read_pinned_json(fd_arg: str, sha_arg: str, prefix: str, limit: int) -> tuple[dict, bytes, str]:
        fd_match = re.fullmatch(rf"--trusted-{prefix}-fd=([0-9]{{1,4}})", fd_arg)
        sha_match = re.fullmatch(rf"--trusted-{prefix}-sha256=([0-9a-f]{{64}})", sha_arg)
        if fd_match is None or sha_match is None:
            raise ValueError("trusted file capability malformed")
        fd = int(fd_match.group(1))
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400 or
                info.st_size <= 0 or info.st_size > limit):
            raise ValueError("trusted file identity invalid")
        raw = os.pread(fd, info.st_size + 1, 0)
        after = os.fstat(fd)
        if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != sha_match.group(1)):
            raise ValueError("trusted file hash invalid")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        if canonical != raw or type(value) is not dict:
            raise ValueError("trusted JSON is not canonical")
        return value, raw, sha_match.group(1)

    manifest_value, _manifest_raw, manifest_sha = read_pinned_json(
        args[0], args[1], "manifest", 16 * 1024 * 1024)
    _trust_value, trust_raw, trust_sha = read_pinned_json(
        args[2], args[3], "trust-config", 64 * 1024)
    return args[4:], {"sha256": manifest_sha, "document": manifest_value}, trust_raw


def _verify_release_manifest(manifest: dict, trust_config_raw: bytes) -> None:
    bootstrap = Path(__file__).resolve()
    repo_root = bootstrap.parents[2]
    host_tools = repo_root / "tools" / "phk2_host"
    if not host_tools.is_dir():
        raise ValueError("trusted source root missing")
    sys.path.insert(0, str(host_tools))
    import phk2_fk0957_remote_topology_endpoint as endpoint
    transport = __import__("phk2_fk0957_topology_transport")
    issuers = endpoint._load_trust_config(raw_override=trust_config_raw)
    payload, _payload_bytes, _digest = endpoint._verify_signed(
        manifest["document"], expected_issuer="FK0957_RELEASE_AUTHORITY",
        public_key_raw=issuers["release"], payload_fields=endpoint.MANIFEST_FIELDS,
        schema="fk0957-runtime-source-manifest-v1")
    endpoint._verify_runtime_manifest(payload, endpoint._profile_hash())
    transport._bind_verified_remote_release_head(payload["production_head"])


def main(argv: list[str] | None = None) -> int:
    if (sys.flags.isolated != 1 or sys.flags.no_site != 1 or
            dict(os.environ) != _EXPECTED_ENV):
        return _refuse()
    try:
        args, manifest, trust_config_raw = _read_launcher_manifest(
            list(sys.argv[1:] if argv is None else argv))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return _refuse()
    if manifest is None or trust_config_raw is None:
        return _refuse()
    if args == ["--launcher-self-test"]:
        sys.stdout.write(json.dumps({
            "isolated": sys.flags.isolated,
            "no_site": sys.flags.no_site,
            "environment_keys": sorted(os.environ),
            "sitecustomize_loaded": "sitecustomize" in sys.modules,
            "usercustomize_loaded": "usercustomize" in sys.modules,
            "manifest_sha256": manifest["sha256"],
        }, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    try:
        _verify_release_manifest(manifest, trust_config_raw)
    except BaseException:
        return _refuse()
    if args == ["--verify-runtime-manifest"]:
        sys.stdout.write("RUNTIME_MANIFEST=VERIFIED\n")
        sys.stdout.write(f"PRODUCTION_HEAD={manifest['document']['payload']['production_head']}\n")
        sys.stdout.write(f"SOURCE_COUNT={len(manifest['document']['payload']['source_hashes'])}\n")
        return 0
    if args == ["--supervisor"]:
        if os.geteuid() != 0:
            return _refuse()
        repo_root = Path(__file__).resolve().parents[2]
        host_tools = repo_root / "tools" / "phk2_host"
        if not host_tools.is_dir():
            return _refuse()
        sys.path.insert(0, str(host_tools))
        try:
            import fk0957_supervisor as supervisor
        except Exception:
            return _refuse()
        return int(supervisor.main())
    if args and args[0] == "--supervisor-client":
        repo_root = Path(__file__).resolve().parents[2]
        host_tools = repo_root / "tools" / "phk2_host"
        if not host_tools.is_dir():
            return _refuse()
        sys.path.insert(0, str(host_tools))
        try:
            import fk0957_supervisor_client as client
        except Exception:
            return _refuse()
        return int(client.main(args[1:]))
    if args == ["--supervisor-remote-endpoint"]:
        # The root supervisor passes an inherited Unix socket created while
        # privileged. SO_PEERCRED is kernel-derived; an environment value or
        # caller-created Python object cannot forge it.
        try:
            capability = socket.socket(fileno=os.dup(3))
            try:
                if capability.family != socket.AF_UNIX or not hasattr(socket, "SO_PEERCRED"):
                    return _refuse()
                _pid, peer_uid, _gid = struct.unpack(
                    "3i", capability.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if peer_uid != 0:
                    return _refuse()
            finally:
                capability.close()
        except (OSError, ValueError, struct.error):
            return _refuse()
        repo_root = Path(__file__).resolve().parents[2]
        host_tools = repo_root / "tools" / "phk2_host"
        if not host_tools.is_dir():
            return _refuse()
        system_packages = Path("/usr/lib/python3/dist-packages")
        try:
            info = system_packages.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                return _refuse()
        except OSError:
            return _refuse()
        sys.path[:] = [entry for entry in sys.path
                       if entry and "site-packages" not in entry]
        sys.path.append(str(system_packages))
        sys.path.insert(0, str(host_tools))
        try:
            import phk2_fk0957_remote_topology_endpoint as remote_endpoint
        except Exception:
            return _refuse()
        return int(remote_endpoint.main())
    bootstrap = Path(__file__).resolve()
    repo_root = bootstrap.parents[2]
    host_tools = repo_root / "tools" / "phk2_host"
    if not host_tools.is_dir():
        return _refuse()
    # -S prevents .pth processing. Add only the root-owned system package
    # directory needed for the reviewed Ed25519 dependency.
    system_packages = Path("/usr/lib/python3/dist-packages")
    try:
        info = system_packages.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            return _refuse()
    except OSError:
        return _refuse()
    sys.path[:] = [sysconfig_path for sysconfig_path in sys.path
                   if sysconfig_path and "site-packages" not in sysconfig_path]
    sys.path.append(str(system_packages))
    sys.path.insert(0, str(host_tools))
    try:
        import phk2_fk0957_topology_rgb_cli as live_cli
    except Exception:
        return _refuse()
    return int(live_cli.main(args))


if __name__ == "__main__":
    raise SystemExit(main())
