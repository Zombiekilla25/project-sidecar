"""One-shot unsigned FK0957 topology acquisition endpoint for the testbench.

The endpoint has no signing key, signing import, arbitrary scan parameters, or
retry path. Trust-key pins are deliberately unset until an approved
maintenance/release authority provisions them; production therefore fails
closed before opening a device until that authority is installed.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
from typing import Any

import phk2_fk0957_topology_discovery as topology
import phk2_fk0957_topology_transport as transport

SCHEMA = "fk0957-remote-topology-request-v1"
MAX_REQUEST_BYTES = 512 * 1024
MAX_RECORD_BYTES = 512 * 1024
EXPECTED_TARGET = {
    "card_id": "FK0957", "adapter_serial": "153300000957A",
    "usb_descriptor_serial": "153300000957", "vid": "0403", "pid": "6010",
    "interface": "A",
}
TRUST_CONFIG = Path("/etc/sidecar/fk0957/remote-trust.json")
# Pin the canonical deployment template, whose issuer key slots are empty.
# Production issuer keys require a separately reviewed administrator
# provisioning commit that replaces the template and updates this pin.
TRUST_CONFIG_SHA256 = "64ced3c5dafb6d585d3ffa10c022599722dd85e2313bb68bb4bcae6f57a22dc1"
CONSUMED_AUTHORIZATION_DIR = Path("/var/lib/sidecar/fk0957/consumed-release-authorizations")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")

REQUEST_FIELDS = {
    "schema", "version", "operation_id", "descriptor_evidence_b64",
    "descriptor_evidence_sha256", "handoff", "release_authorization",
    "runtime_manifest",
}
SIGNED_FIELDS = {"payload", "payload_sha256", "signature_algorithm", "signature_hex", "issuer"}
HANDOFF_FIELDS = {
    "schema", "version", "handoff_id", "operation_id", "authorization_id",
    "permit_sha256", "target", "bridge_executable_sha256", "bridge_config_sha256",
    "expected_clients", "expected_lanes", "bridge_release_state", "usbfs_ownership",
    "production_head", "manifest_sha256", "transaction_profile_sha256",
    "issued_at", "expires_at",
}
AUTH_FIELDS = {
    "schema", "version", "authorization_id", "operation_id", "permit_sha256",
    "handoff_sha256", "target", "production_head", "manifest_sha256",
    "transaction_profile_sha256", "issued_at", "expires_at", "nonce",
}
MANIFEST_FIELDS = {
    "schema", "version", "production_head", "worktree_clean", "source_hashes",
    "source_inventory", "native_runtime_hashes", "runtime_inventory", "trust_config_sha256",
    "transaction_profile_sha256", "issued_at",
}
RELEASE_SOURCE_PATHS = {
    "tools/phk2_host/fk0957_safe_launcher.c",
    "tools/phk2_host/build_fk0957_safe_launcher.py",
    "tools/phk2_host/fk0957_safe_bootstrap.py",
    "tools/phk2_host/fk0957_supervisor.py",
    "tools/phk2_host/fk0957_supervisor_client.py",
    "tools/phk2_host/install_fk0957_supervisor.py",
    "ops/phk2/fk0957-supervisor.service",
    "ops/phk2/90-sidecar-fk0957-supervised.rules",
    "tools/phk2_host/phk2_fk0957_remote_orchestrator.py",
    "tools/phk2_host/phk2_fk0957_identity_observer.py",
    "tools/phk2_host/phk2_fk0957_remote_topology_endpoint.py",
    "tools/phk2_host/phk2_fk0957_topology_transport.py",
    "tools/phk2_host/phk2_fk0957_topology_discovery.py",
    "tools/phk2_host/phk2_fk0957_idcode_gate.py",
    "tools/phk2_host/phk2_fk0957_topology_live_cli.py",
    "tools/phk2_host/phk2_fk0957_topology_rgb_cli.py",
    "tools/phk2_host/phk2_fk0957_topology_rgb_orchestrator.py",
    "tools/phk2_host/phk2_fk0957_topology_signing.py",
    "tools/phk2_host/phk2_fk0957_readonly_backend.py",
    "tools/phk2_host/phk2_fk0957_remote_collector.py",
    "tools/phk2_host/fk0957_remote_cleanup_protocol.py",
    "tools/phk2_host/fk0957_remote_receipts.py",
    "tools/phk2_host/verify_fk0957_runtime_manifest.py",
    "ops/phk2/PHK2_FK0957_EVIDENCE_SCHEMA.json",
    "ops/phk2/FK0957_REFUSAL_ENVELOPE.schema.json",
    "ops/phk2/FK0957_REMOTE_TRUST_TEMPLATE.json",
    "ops/phk2/FK0957_TOPOLOGY_TRANSACTION_PROFILE.json",
    "ops/phk2/FK0957_AUTHORITY_PROVISIONING.md",
    "ops/phk2/FK0957_RUNTIME_MANIFEST.template.json",
    "ops/phk2/FK0957_DEPLOYMENT_OWNERSHIP.json",
    "ops/phk2/fk0957.sysusers.conf",
}
REMOTE_SOURCE_PATHS = {
    "tools/phk2_host/fk0957_safe_launcher.c",
    "tools/phk2_host/fk0957_safe_bootstrap.py",
    "tools/phk2_host/fk0957_supervisor.py",
    "tools/phk2_host/fk0957_supervisor_client.py",
    "ops/phk2/fk0957-supervisor.service",
    "ops/phk2/90-sidecar-fk0957-supervised.rules",
    "tools/phk2_host/phk2_fk0957_remote_topology_endpoint.py",
    "tools/phk2_host/phk2_fk0957_topology_transport.py",
    "tools/phk2_host/phk2_fk0957_topology_discovery.py",
    "tools/phk2_host/phk2_fk0957_idcode_gate.py",
    "tools/phk2_host/phk2_fk0957_remote_orchestrator.py",
    "tools/phk2_host/phk2_fk0957_topology_live_cli.py",
    "tools/phk2_host/fk0957_remote_cleanup_protocol.py",
    "tools/phk2_host/fk0957_remote_receipts.py",
    "tools/phk2_host/verify_fk0957_runtime_manifest.py",
    "tools/phk2_host/phk2_fk0957_readonly_backend.py",
    "tools/phk2_host/phk2_fk0957_remote_collector.py",
    "ops/phk2/FK0957_REMOTE_TRUST_TEMPLATE.json",
    "ops/phk2/FK0957_TOPOLOGY_TRANSACTION_PROFILE.json",
    "ops/phk2/FK0957_REFUSAL_ENVELOPE.schema.json",
    "ops/phk2/FK0957_AUTHORITY_PROVISIONING.md",
    "ops/phk2/FK0957_RUNTIME_MANIFEST.template.json",
    "ops/phk2/FK0957_DEPLOYMENT_OWNERSHIP.json",
    "ops/phk2/fk0957.sysusers.conf",
}
_SUPERVISOR_ISSUERS: dict[str, bytes] | None = None


class Refusal(ValueError):
    def __init__(self, code: str, phase: str = "PRELIVE_VALIDATION"):
        super().__init__(code)
        self.code = code
        self.phase = phase

    def envelope(self) -> dict[str, Any]:
        return {"schema": "fk0957-remote-acquisition-v1", "status": "REFUSED",
                "phase": self.phase, "code": self.code}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _parse_canonical(raw: bytes, limit: int) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise Refusal("REQUEST_SIZE_INVALID")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant")))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise Refusal("REQUEST_JSON_INVALID") from None
    if type(value) is not dict or canonical(value) != raw:
        raise Refusal("REQUEST_NOT_CANONICAL")
    return value


def _strict_hex(value: Any, pattern: re.Pattern[str]) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _load_trust_config(*, raw_override: bytes | None = None) -> dict[str, bytes]:
    """Load immutable issuer keys; hashes are source-pinned, not CLI/env inputs."""
    global _SUPERVISOR_ISSUERS
    if supervisor_capability_valid():
        if _SUPERVISOR_ISSUERS is not None:
            return dict(_SUPERVISOR_ISSUERS)
        try:
            channel = socket.socket(fileno=os.dup(3))
            try:
                header = _recv_exact(channel, 4)
                length = int.from_bytes(header, "big")
                if not 1 <= length <= 64 * 1024:
                    raise ValueError("issuer frame size invalid")
                raw = _recv_exact(channel, length)
                value = _parse_canonical(raw, 64 * 1024)
            finally:
                channel.close()
            if set(value) != {"release", "handoff"}:
                raise ValueError("issuer frame schema invalid")
            keys = {name: base64.b64decode(value[name], validate=True)
                    for name in ("release", "handoff")}
            if any(type(key) is not bytes or len(key) != 32 for key in keys.values()):
                raise ValueError("issuer key length invalid")
            _SUPERVISOR_ISSUERS = keys
            return dict(keys)
        except BaseException:
            raise Refusal("SUPERVISOR_ISSUER_HANDOFF_INVALID") from None
    if not _strict_hex(TRUST_CONFIG_SHA256, HEX64):
        raise Refusal("ISSUER_PINS_NOT_PROVISIONED")
    raw = (raw_override if raw_override is not None else
           _read_protected_file(TRUST_CONFIG, owner=0, mode=0o400,
                                limit=64 * 1024, failure="ISSUER_CONFIG"))
    if hashlib.sha256(raw).hexdigest() != TRUST_CONFIG_SHA256:
        raise Refusal("ISSUER_CONFIG_PIN_MISMATCH")
    value = _parse_canonical(raw, 64 * 1024)
    expected_config_fields = {
        "schema", "version", "release_issuer", "release_public_key_path",
        "release_public_key_sha256", "handoff_issuer", "handoff_public_key_path",
        "handoff_public_key_sha256", "authorization_ledger", "authorization_policy",
        "max_authorization_lifetime_seconds", "manifest_max_age_seconds",
    }
    if (set(value) != expected_config_fields or
            value["schema"] != "fk0957-remote-trust-config-v1" or
            type(value["version"]) is not int or value["version"] != 1 or
            value["release_issuer"] != "FK0957_RELEASE_AUTHORITY" or
            value["handoff_issuer"] != "FK0957_MAINTENANCE_AUTHORITY" or
            value["release_public_key_path"] != "/etc/sidecar/fk0957/release-issuer.pub" or
            value["handoff_public_key_path"] != "/etc/sidecar/fk0957/handoff-issuer.pub" or
            value["authorization_ledger"] != str(CONSUMED_AUTHORIZATION_DIR) or
            value["authorization_policy"] != {
                "operation_bound": True, "single_use": True, "target_card_id": "FK0957"} or
            type(value["max_authorization_lifetime_seconds"]) is not int or
            value["max_authorization_lifetime_seconds"] != 120 or
            type(value["manifest_max_age_seconds"]) is not int or
            value["manifest_max_age_seconds"] != 86400):
        raise Refusal("ISSUER_CONFIG_SCHEMA_INVALID")
    keys = {}
    for name in ("release", "handoff"):
        expected_sha = value[f"{name}_public_key_sha256"]
        if not _strict_hex(expected_sha, HEX64):
            raise Refusal("ISSUER_KEYS_NOT_PROVISIONED")
        key_path = Path(value[f"{name}_public_key_path"])
        raw_key = _read_protected_file(key_path, owner=0, mode=0o400,
                                       limit=32, failure="ISSUER_PUBLIC_KEY")
        if len(raw_key) != 32 or hashlib.sha256(raw_key).hexdigest() != expected_sha:
            raise Refusal("ISSUER_CONFIG_KEY_INVALID")
        keys[name] = raw_key
    return keys


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    out = bytearray()
    while len(out) < count:
        block = sock.recv(count - len(out))
        if not block:
            raise ValueError("issuer handoff truncated")
        out.extend(block)
    return bytes(out)


def _open_absolute_parent(path: Path) -> tuple[int, str]:
    if not path.is_absolute() or ".." in path.parts:
        raise Refusal("PROTECTED_PATH_INVALID")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or
                    info.st_mode & 0o022):
                os.close(child)
                raise Refusal("PROTECTED_PATH_PARENT_UNSAFE")
            os.close(fd)
            fd = child
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _read_protected_file(path: Path, *, owner: int, mode: int, limit: int,
                         failure: str) -> bytes:
    try:
        parent_fd, name = _open_absolute_parent(path)
        try:
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or
                        before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != mode or
                        before.st_size < 1 or before.st_size > limit):
                    raise Refusal(f"{failure}_UNSAFE")
                chunks = bytearray()
                while len(chunks) <= limit:
                    block = os.read(fd, min(65536, limit + 1 - len(chunks)))
                    if not block:
                        break
                    chunks.extend(block)
                after = os.fstat(fd)
                if (len(chunks) > limit or
                        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                    raise Refusal(f"{failure}_CHANGED_DURING_READ")
                return bytes(chunks)
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
    except Refusal:
        raise
    except OSError:
        raise Refusal(f"{failure}_UNAVAILABLE") from None


def _verify_signed(envelope: Any, *, expected_issuer: str, public_key_raw: bytes,
                   payload_fields: set[str], schema: str) -> tuple[dict[str, Any], bytes, bytes]:
    if type(envelope) is not dict or set(envelope) != SIGNED_FIELDS:
        raise Refusal("SIGNED_RECORD_SCHEMA_INVALID")
    payload = envelope["payload"]
    if type(payload) is not dict or set(payload) != payload_fields or \
            payload.get("schema") != schema or type(payload.get("version")) is not int or payload["version"] != 1:
        raise Refusal("SIGNED_RECORD_PAYLOAD_INVALID")
    if envelope["issuer"] != expected_issuer or envelope["signature_algorithm"] != "Ed25519":
        raise Refusal("SIGNED_RECORD_ISSUER_INVALID")
    payload_bytes = canonical(payload)
    payload_sha = hashlib.sha256(payload_bytes).hexdigest()
    if envelope["payload_sha256"] != payload_sha or not _strict_hex(envelope["signature_hex"], re.compile(r"[0-9a-f]{128}\Z")):
        raise Refusal("SIGNED_RECORD_DIGEST_INVALID")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(bytes.fromhex(envelope["signature_hex"]), payload_bytes)
    except Exception:
        raise Refusal("SIGNED_RECORD_SIGNATURE_INVALID") from None
    return payload, payload_bytes, bytes.fromhex(payload_sha)


def _parse_time(value: Any) -> datetime:
    if type(value) is not str:
        raise Refusal("AUTHORIZATION_TIME_INVALID")
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise Refusal("AUTHORIZATION_TIME_INVALID") from None
    if result.tzinfo is None:
        raise Refusal("AUTHORIZATION_TIME_INVALID")
    return result.astimezone(timezone.utc)


def _valid_window(issued: Any, expires: Any, *, now: datetime, max_age: int = 120) -> None:
    start, end = _parse_time(issued), _parse_time(expires)
    if end <= start or end - start > __import__("datetime").timedelta(seconds=max_age) or \
            now.astimezone(timezone.utc) < start or now.astimezone(timezone.utc) >= end:
        raise Refusal("AUTHORIZATION_EXPIRED_OR_STALE")


def _profile_hash() -> str:
    plan = topology.build_plan()
    profile = {"schema": "fk0957-fixed-reset-default-dr-profile-v1", "scan_a_sha256": plan.scan_a_commands and topology.scan_transaction_sha256(plan.scan_a_commands),
               "scan_b_sha256": topology.scan_transaction_sha256(plan.scan_b_commands),
               "scan_a_tck_count": 591, "scan_b_tck_count": 586, "total_tck_count": 1177,
               "ir_update": False}
    if (plan.scan_a_tck_count, plan.scan_b_tck_count, plan.tck_count) != (591, 586, 1177):
        raise Refusal("TRANSACTION_PROFILE_MISMATCH", "PRELIVE_VALIDATION")
    return hashlib.sha256(canonical(profile)).hexdigest()


def _runtime_inventory() -> list[dict[str, str]]:
    """Return verified path/hash/build-id/package rows for the pinned runtime."""
    repo = Path(transport.__file__).resolve().parents[2]
    launcher = (repo / "tools/phk2_host/fk0957_safe_launcher.c").read_text(encoding="utf-8")
    pins: dict[str, tuple[str, str, str]] = {}
    for path, sha256, build_id in re.findall(
            r'PIN\("([^\"]+)",\s*"([0-9a-f]{64})",\s*"([0-9a-f]{40,128})"\)', launcher):
        pins[path] = (sha256, build_id, Path(path).name)
    for pin in transport.LIBRARY_PINS:
        value = (pin.sha256, pin.build_id, pin.name)
        prior = pins.get(str(pin.path))
        if prior is not None and prior[:2] != value[:2]:
            raise Refusal("RUNTIME_PIN_SOURCES_DISAGREE")
        pins[str(pin.path)] = value
    if len(pins) < 7:
        raise Refusal("RUNTIME_PIN_SET_INCOMPLETE")

    rows = []
    for path, (expected_sha, expected_build, logical_name) in sorted(pins.items()):
        try:
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                    info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or
                    os.path.realpath(path) != path):
                raise Refusal("RUNTIME_PIN_FILE_UNSAFE")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_CLOEXEC", 0))
            try:
                before = os.fstat(fd)
                actual_sha = transport._hash_fd(fd)
                actual_build = transport._build_id_fd(fd)
                after = os.fstat(fd)
                if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                        actual_sha != expected_sha or actual_build != expected_build):
                    raise Refusal("RUNTIME_PIN_MISMATCH")
            finally:
                os.close(fd)
            owner = subprocess.run(["/usr/bin/dpkg-query", "-S", path], check=False,
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            package_line = owner.stdout.splitlines()[0] if owner.returncode == 0 and owner.stdout else ""
            package = package_line.partition(": ")[0]
            if not package:
                raise Refusal("RUNTIME_PACKAGE_PROVENANCE_UNAVAILABLE")
            version_result = subprocess.run(
                ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package], check=False,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            package_version = version_result.stdout.strip()
            if version_result.returncode != 0 or not package_version or "\n" in package_version:
                raise Refusal("RUNTIME_PACKAGE_PROVENANCE_UNAVAILABLE")
        except Refusal:
            raise
        except (OSError, subprocess.SubprocessError):
            raise Refusal("RUNTIME_INVENTORY_UNAVAILABLE") from None
        rows.append({"logical_name": logical_name, "path": path,
                     "sha256": actual_sha, "build_id": actual_build,
                     "package": package, "package_version": package_version})
    return rows


def build_unsigned_runtime_manifest(repo: Path | None = None) -> dict[str, Any]:
    """Create the complete release-manifest payload for signing by the pinned authority."""
    root = repo or Path(__file__).resolve().parents[2]
    head, clean = transport._production_git_state(root)
    if not clean:
        raise Refusal("RUNTIME_GIT_STATE_MISMATCH")
    hashes = {}
    source_inventory = []
    for relative in sorted(RELEASE_SOURCE_PATHS):
        try:
            info = (root / relative).lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
                raise Refusal("RUNTIME_SOURCE_UNSAFE")
            digest = hashlib.sha256((root / relative).read_bytes()).hexdigest()
            hashes[relative] = digest
            source_inventory.append({
                "relative_path": relative,
                "absolute_install_path": f"/usr/local/lib/sidecar/fk0957/{relative}",
                "sha256": digest,
            })
        except Refusal:
            raise
        except OSError:
            raise Refusal("RUNTIME_SOURCE_UNAVAILABLE") from None
    runtime_inventory = _runtime_inventory()
    return {
        "schema": "fk0957-runtime-source-manifest-v1", "version": 1,
        "production_head": head, "worktree_clean": True, "source_hashes": hashes,
        "source_inventory": source_inventory,
        "native_runtime_hashes": {row["logical_name"]: row["sha256"]
                                  for row in runtime_inventory},
        "runtime_inventory": runtime_inventory,
        "trust_config_sha256": TRUST_CONFIG_SHA256,
        "transaction_profile_sha256": _profile_hash(),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


def _verify_runtime_manifest(manifest: dict[str, Any], profile_sha: str) -> None:
    repo = Path(__file__).resolve().parents[2]
    if set(manifest["source_hashes"]) != RELEASE_SOURCE_PATHS:
        raise Refusal("RUNTIME_SOURCE_SET_INVALID")
    inventory = manifest.get("source_inventory")
    if type(inventory) is not list or len(inventory) != len(RELEASE_SOURCE_PATHS):
        raise Refusal("RUNTIME_SOURCE_INVENTORY_INVALID")
    expected_inventory = [
        {"relative_path": relative,
         "absolute_install_path": f"/usr/local/lib/sidecar/fk0957/{relative}",
         "sha256": manifest["source_hashes"].get(relative)}
        for relative in sorted(RELEASE_SOURCE_PATHS)
    ]
    if inventory != expected_inventory:
        raise Refusal("RUNTIME_SOURCE_INVENTORY_INVALID")
    local_checkout = (repo / ".git").exists()
    check_sources = RELEASE_SOURCE_PATHS if local_checkout else REMOTE_SOURCE_PATHS
    for relative in sorted(check_sources):
        path = repo / relative
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
                raise Refusal("RUNTIME_SOURCE_UNSAFE")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except Refusal:
            raise
        except OSError:
            raise Refusal("RUNTIME_SOURCE_UNAVAILABLE") from None
        if digest != manifest["source_hashes"][relative]:
            raise Refusal("RUNTIME_SOURCE_HASH_MISMATCH")
    if local_checkout:
        head, clean = transport._production_git_state(repo)
        if not clean or head != manifest["production_head"]:
            raise Refusal("RUNTIME_GIT_STATE_MISMATCH")
    else:
        try:
            transport._bind_verified_remote_release_head(manifest["production_head"])
        except transport.Refusal:
            raise Refusal("RUNTIME_GIT_STATE_MISMATCH") from None
    expected_native = {row["logical_name"]: row["sha256"]
                       for row in _runtime_inventory()}
    if manifest["native_runtime_hashes"] != expected_native:
        raise Refusal("NATIVE_RUNTIME_MANIFEST_MISMATCH")
    if manifest["runtime_inventory"] != _runtime_inventory():
        raise Refusal("RUNTIME_INVENTORY_MISMATCH")
    if manifest["trust_config_sha256"] != TRUST_CONFIG_SHA256:
        raise Refusal("TRUST_CONFIG_MANIFEST_MISMATCH")
    if manifest["transaction_profile_sha256"] != profile_sha:
        raise Refusal("TRANSACTION_PROFILE_MISMATCH")


def _validate_request(raw: bytes, issuers: dict[str, bytes], *, now: datetime | None = None) -> tuple[dict[str, Any], bytes, str]:
    request = _parse_canonical(raw, MAX_REQUEST_BYTES)
    if set(request) != REQUEST_FIELDS or request.get("schema") != SCHEMA or type(request.get("version")) is not int or request["version"] != 1:
        raise Refusal("REQUEST_SCHEMA_INVALID")
    operation_id = request["operation_id"]
    if not _strict_hex(operation_id, OPERATION_ID):
        raise Refusal("OPERATION_ID_INVALID")
    try:
        descriptor = base64.b64decode(request["descriptor_evidence_b64"], validate=True)
    except (TypeError, ValueError, base64.binascii.Error):
        raise Refusal("DESCRIPTOR_ENCODING_INVALID") from None
    descriptor_sha = hashlib.sha256(descriptor).hexdigest()
    if not descriptor or request["descriptor_evidence_sha256"] != descriptor_sha:
        raise Refusal("DESCRIPTOR_DIGEST_INVALID")
    if set(issuers) != {"release", "handoff"} or any(type(issuers[k]) is not bytes or len(issuers[k]) != 32 for k in issuers):
        raise Refusal("ISSUER_PINS_NOT_PROVISIONED")
    current = now or datetime.now(timezone.utc)
    auth, auth_bytes, auth_sha_raw = _verify_signed(
        request["release_authorization"], expected_issuer="FK0957_RELEASE_AUTHORITY",
        public_key_raw=issuers["release"], payload_fields=AUTH_FIELDS,
        schema="fk0957-release-authorization-v1")
    handoff, handoff_bytes, handoff_sha_raw = _verify_signed(
        request["handoff"], expected_issuer="FK0957_MAINTENANCE_AUTHORITY",
        public_key_raw=issuers["handoff"], payload_fields=HANDOFF_FIELDS,
        schema="fk0957-maintenance-handoff-v1")
    manifest, _manifest_bytes, _ = _verify_signed(
        request["runtime_manifest"], expected_issuer="FK0957_RELEASE_AUTHORITY",
        public_key_raw=issuers["release"], payload_fields=MANIFEST_FIELDS,
        schema="fk0957-runtime-source-manifest-v1")
    profile_sha = _profile_hash()
    if (manifest["worktree_clean"] is not True or not _strict_hex(manifest["production_head"], HEX40) or
            type(manifest["source_hashes"]) is not dict or type(manifest["native_runtime_hashes"]) is not dict or
            manifest["transaction_profile_sha256"] != profile_sha):
        raise Refusal("RUNTIME_MANIFEST_INVALID")
    manifest_issued = _parse_time(manifest["issued_at"])
    if (current.astimezone(timezone.utc) < manifest_issued or
            (current.astimezone(timezone.utc) - manifest_issued).total_seconds() > 86400):
        raise Refusal("RUNTIME_MANIFEST_STALE")
    for mapping in (manifest["source_hashes"], manifest["native_runtime_hashes"]):
        if not mapping or any(type(k) is not str or not k or not _strict_hex(v, HEX64) for k, v in mapping.items()):
            raise Refusal("RUNTIME_MANIFEST_INVALID")
    _verify_runtime_manifest(manifest, profile_sha)
    _valid_window(auth.get("issued_at"), auth.get("expires_at"), now=current)
    _valid_window(handoff.get("issued_at"), handoff.get("expires_at"), now=current)
    target = {**EXPECTED_TARGET}
    expected_handoff = {
        "operation_id": operation_id, "authorization_id": auth["authorization_id"],
        "permit_sha256": descriptor_sha, "target": target,
        "production_head": manifest["production_head"], "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
        "transaction_profile_sha256": profile_sha,
    }
    expected_auth = {
        "operation_id": operation_id, "permit_sha256": descriptor_sha,
        "handoff_sha256": hashlib.sha256(canonical(handoff)).hexdigest(), "target": target,
        "production_head": manifest["production_head"], "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
        "transaction_profile_sha256": profile_sha,
    }
    if any(handoff.get(k) != v for k, v in expected_handoff.items()) or \
            any(auth.get(k) != v for k, v in expected_auth.items()):
        raise Refusal("AUTHORIZATION_BINDING_MISMATCH")
    clients, lanes = handoff["expected_clients"], handoff["expected_lanes"]
    if (handoff["bridge_release_state"] != "RELEASED" or
            handoff["usbfs_ownership"] != "EXCLUSIVE" or
            type(clients) is not list or not clients or
            any(type(item) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item) for item in clients) or
            type(lanes) is not list or not lanes or
            any(type(item) is not str or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", item) for item in lanes) or
            len(set(clients)) != len(clients) or len(set(lanes)) != len(lanes) or
            not _strict_hex(handoff["handoff_id"], HEX64) or
            not _strict_hex(handoff["bridge_executable_sha256"], HEX64) or
            not _strict_hex(handoff["bridge_config_sha256"], HEX64)):
        raise Refusal("HANDOFF_OWNERSHIP_UNKNOWN")
    auth_id = auth["authorization_id"]
    nonce = auth["nonce"]
    if not _strict_hex(auth_id, HEX64) or not _strict_hex(nonce, HEX64):
        raise Refusal("AUTHORIZATION_ID_INVALID")
    return {"operation_id": operation_id, "descriptor": descriptor,
            "descriptor_sha256": descriptor_sha, "authorization_id": auth_id,
            "authorization_sha256": auth_sha_raw.hex(), "handoff_sha256": hashlib.sha256(canonical(handoff)).hexdigest(),
            "manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
            "production_head": manifest["production_head"], "transaction_profile_sha256": profile_sha,
            "permit_nonce": nonce, "expires_at": auth["expires_at"]}, auth_bytes, auth_id


def _consume_authorization(auth_id: str, authorization_bytes: bytes) -> None:
    """Durably consume before permit creation/device open; O_EXCL serializes races."""
    root = CONSUMED_AUTHORIZATION_DIR
    dir_fd = -1
    try:
        if not root.is_absolute() or ".." in root.parts:
            raise Refusal("AUTHORIZATION_LEDGER_UNSAFE")
        dir_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        for index, part in enumerate(root.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
            info = os.fstat(child)
            final = index == len(root.parts[1:]) - 1
            if (not stat.S_ISDIR(info.st_mode) or
                    (final and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700)) or
                    (not final and (info.st_uid not in (0, os.getuid()) or
                                    (info.st_mode & 0o022 and
                                     not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))))):
                os.close(child)
                raise Refusal("AUTHORIZATION_LEDGER_UNSAFE")
            os.close(dir_fd)
            dir_fd = child
    except Refusal:
        if dir_fd >= 0:
            os.close(dir_fd)
        raise
    except OSError:
        if dir_fd >= 0:
            os.close(dir_fd)
        raise Refusal("AUTHORIZATION_LEDGER_UNAVAILABLE") from None
    name = auth_id + ".consumed"
    try:
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=dir_fd)
        except FileExistsError:
            raise Refusal("AUTHORIZATION_REPLAY") from None
        try:
            digest = hashlib.sha256(authorization_bytes).hexdigest().encode("ascii") + b"\n"
            offset = 0
            while offset < len(digest):
                offset += os.write(fd, digest[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dir_fd)
    finally:
        if dir_fd >= 0:
            os.close(dir_fd)


def _unsigned_record(context: dict[str, Any], permit: Any,
                     result: transport.TransportObservation, parsed: Any) -> dict[str, Any]:
    if (permit.authorization_id != context.get("authorization_id") or
            permit.authorization_sha256 != context.get("authorization_sha256") or
            permit.operation_id != context.get("operation_id") or
            result.authorization_id != context.get("authorization_id") or
            result.authorization_sha256 != context.get("authorization_sha256") or
            result.operation_id != context.get("operation_id") or
            permit.nonce != context.get("permit_nonce") or
            result.permit_nonce != context.get("permit_nonce")):
        raise Refusal("AUTHORIZATION_IDENTITY_MISMATCH", "LOCAL_VALIDATION")
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema": "fk0957-unsigned-topology-acquisition-v1", "status": "ACQUIRED",
        "operation_id": context["operation_id"], "authorization_id": context["authorization_id"],
        "authorization_sha256": context["authorization_sha256"], "handoff_sha256": context["handoff_sha256"],
        "manifest_sha256": context["manifest_sha256"], "production_head": context["production_head"],
        "transaction_profile_sha256": context["transaction_profile_sha256"],
        "card_id": result.card_id, "adapter_serial": result.adapter_serial,
        "usb_descriptor_serial": result.usb_descriptor_serial, "physical_interface": result.physical_interface,
        "descriptor_evidence_sha256": result.descriptor_evidence_sha256,
        "authorization_id": result.authorization_id,
        "authorization_sha256": result.authorization_sha256,
        "operation_id": result.operation_id, "permit_nonce": result.permit_nonce,
        "trusted_signer_fingerprint": permit.trusted_signer_fingerprint,
        "observation_timestamp": now, "transport_source_sha256": result.transport_source_sha256,
        "worktree_clean": result.worktree_clean,
        "runtime_library_provenance": [
            {"logical_name": row[0], "approved_path": row[1], "expected_sha256": row[2],
             "expected_build_id": row[3], "soname": row[4], "loaded_object_realpath": row[7]}
            for row in result.runtime_library_provenance],
        "scan_a_transaction_sha256": result.scan_a_transaction_sha256,
        "scan_a_tck_count": result.scan_a_tck_count, "scan_a_raw_tdo_hex": result.scan_a_raw_tdo.hex(),
        "scan_b_transaction_sha256": result.scan_b_transaction_sha256,
        "scan_b_tck_count": result.scan_b_tck_count, "scan_b_raw_tdo_hex": result.scan_b_raw_tdo.hex(),
        "total_tck_count": result.total_tck_count, "matched_device_count": result.matched_device_count,
        "opened_device_count": result.opened_device_count, "second_device_opened": result.second_device_opened,
        "aggregate_dr_length": parsed.aggregate_dr_length, "observed_taps_tdo_to_tdi": parsed.taps_tdo_to_tdi,
        "raw_tdo_scan_a_bits_lsb_first": parsed.raw_tdo_scan_a_bits,
        "raw_tdo_scan_b_bits_lsb_first": parsed.raw_tdo_scan_b_bits,
        "write_count": result.write_count, "reset_count": result.reset_count,
        "program_count": result.program_count, "jtag_operation_count": 1,
        "topology_discovery_only": True, "idcode_qualification_pass": False,
        "fpga_dna_observed": False, "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False,
    }


def execute_request(raw: bytes) -> bytes:
    """Fixed production route. The only substitution point is native transport itself."""
    issuers = _load_trust_config()
    context, _, _ = _validate_request(raw, issuers)
    permit = transport.issue_fk0957_topology_permit(
        context["descriptor"], context["descriptor_sha256"],
        nonce=context["permit_nonce"], authorization_id=context["authorization_id"],
        authorization_sha256=context["authorization_sha256"],
        operation_id=context["operation_id"])
    # The transport gate independently revalidates the signed request and
    # consumes its authorization. This prevents raw digest injection through
    # direct internal transport calls.
    transport._authorize_remote_permit(permit, request_raw=raw)
    result = transport.run_fk0957_topology_discovery(permit)
    parsed = transport.validate_transport_observation(permit, result)
    record = _unsigned_record(context, permit, result, parsed)
    encoded = canonical(record)
    if len(encoded) > MAX_RECORD_BYTES:
        raise Refusal("UNSIGNED_RECORD_OVERSIZED", "LOCAL_VALIDATION")
    return encoded


def supervisor_capability_valid(fd: int = 3) -> bool:
    """True only for the inherited connected socket created by the root supervisor.

    This is a kernel peer-credential check, not an environment/token check. A
    direct Python caller can create a socketpair, but its peer UID will be its
    own UID rather than root. The descriptor is passed only by the supervisor
    when it has validated and durably consumed the signed authorization.
    """
    if not hasattr(socket, "SO_PEERCRED"):
        return False
    try:
        duplicate = socket.socket(fileno=os.dup(fd))
        try:
            if duplicate.family != socket.AF_UNIX:
                return False
            _pid, uid, _gid = __import__("struct").unpack(
                "3i", duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            # The public supervisor IPC socket also has a root peer. It is
            # pathname-connected and must never itself confer child capability.
            # The capability is an unnamed socketpair created by the daemon
            # specifically for the supervised child.
            peer_name = duplicate.getpeername()
            return uid == 0 and peer_name == ""
        finally:
            duplicate.close()
    except (OSError, ValueError, struct.error):
        return False


def main() -> int:
    if len(sys.argv) != 1:
        sys.stdout.buffer.write(canonical(Refusal("ARGUMENTS_NOT_ALLOWED").envelope()))
        return 2
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    try:
        result = execute_request(raw)
    except Refusal as exc:
        result = canonical(exc.envelope())
        sys.stdout.buffer.write(result)
        return 2
    except BaseException:
        sys.stdout.buffer.write(canonical(Refusal("INTERNAL_REFUSAL").envelope()))
        return 2
    sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
