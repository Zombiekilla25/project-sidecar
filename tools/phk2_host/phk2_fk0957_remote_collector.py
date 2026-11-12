#!/usr/bin/env python3
"""Unsigned, descriptor-only FK0957 evidence collector for remote stdin use."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import types
from datetime import datetime, timezone

BACKEND_PIN = "46dd16ddb2429dc63a26e052bc37facc0ce569adb18bd0f5f44ffeaeb885bf75"
OBSERVER_PIN = "e6afea8706df6c9c9855ddf7ca86d8054b3c1fb759f06d1aca77b2431d549210"
EXPECTED_ADAPTER_SERIAL = "153300000957A"
EXPECTED_CARD_ID = "153300000957"
REFUSAL_CODES = frozenset({
    "NO_MATCHING_TARGET", "MULTIPLE_MATCHING_TARGETS", "INCOMPLETE_DESCRIPTOR_METADATA",
    "EXPECTED_SERIAL_NOT_FOUND", "UNEXPECTED_PEER_DEVICE", "BACKEND_PIN_MISMATCH",
    "TARGET_MAPPING_MISSING", "TARGET_MAPPING_AMBIGUOUS", "SOURCE_PROVENANCE_MISMATCH",
    "DESCRIPTOR_READ_FAILED", "INTERNAL_REFUSAL",
})
FAILURE_FIELDS = frozenset({
    "status", "phase", "refusal_code", "cards_opened", "second_card_opened",
    "write_count", "reset_count", "program_count", "jtag_operations",
})


class CollectorRefusal(RuntimeError):
    def __init__(self, refusal_code: str):
        self.refusal_code = refusal_code if refusal_code in REFUSAL_CODES else "INTERNAL_REFUSAL"
        super().__init__(self.refusal_code)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _repo_root() -> Path:
    bundle_root = os.environ.get("FK0957_BUNDLE_ROOT")
    if not bundle_root:
        raise CollectorRefusal("SOURCE_PROVENANCE_MISMATCH")
    root = Path(bundle_root)
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise CollectorRefusal("SOURCE_PROVENANCE_MISMATCH") from exc
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir() or
            root_stat.st_mode & 0o077):
        raise CollectorRefusal("SOURCE_PROVENANCE_MISMATCH")
    return root


def _execute_verified_module(name: str, path: Path, source: bytes):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


def _load_reviewed_backend():
    root = _repo_root()
    here = root / "tools" / "phk2_host"
    backend_path = here / "phk2_fk0957_readonly_backend.py"
    observer_path = here / "phk2_fk0957_identity_observer.py"
    try:
        backend_bytes = backend_path.read_bytes()
        observer_bytes = observer_path.read_bytes()
    except OSError as exc:
        raise CollectorRefusal("BACKEND_PIN_MISMATCH") from exc
    backend_hash = hashlib.sha256(backend_bytes).hexdigest()
    if backend_hash != BACKEND_PIN:
        raise CollectorRefusal("BACKEND_PIN_MISMATCH")
    if hashlib.sha256(observer_bytes).hexdigest() != OBSERVER_PIN:
        raise CollectorRefusal("SOURCE_PROVENANCE_MISMATCH")
    try:
        observer_module = _execute_verified_module(
            "phk2_fk0957_identity_observer", observer_path, observer_bytes)
        backend_module = _execute_verified_module(
            "phk2_fk0957_readonly_backend", backend_path, backend_bytes)
        return root, backend_hash, observer_module, backend_module
    except Exception as exc:
        raise CollectorRefusal("INTERNAL_REFUSAL") from exc


def _backend_refusal_code(exc: Exception) -> str:
    code = getattr(exc, "refusal_code", "INTERNAL_REFUSAL")
    return code if isinstance(code, str) and code in REFUSAL_CODES else "INTERNAL_REFUSAL"


def collect(collector_sha256: str, session_nonce: str) -> dict:
    if (not isinstance(collector_sha256, str) or len(collector_sha256) != 64 or
            any(c not in "0123456789abcdef" for c in collector_sha256) or
            not isinstance(session_nonce, str) or len(session_nonce) != 64 or
            any(c not in "0123456789abcdef" for c in session_nonce)):
        raise CollectorRefusal("SOURCE_PROVENANCE_MISMATCH")
    if os.environ.get("FK0957_TARGET") != "FK0957":
        raise CollectorRefusal("SOURCE_PROVENANCE_MISMATCH")
    root, backend_hash, observer_module, backend_module = _load_reviewed_backend()
    try:
        backend = backend_module.FK0957ReadOnlyBackend()
        selector = observer_module.TargetSelector()
        selection = backend.select_exact(selector)
    except Exception as exc:
        raise CollectorRefusal(_backend_refusal_code(exc)) from exc
    if getattr(selection, "card_id", None) is None:
        raise CollectorRefusal("TARGET_MAPPING_MISSING")
    if selection.card_id != EXPECTED_CARD_ID:
        raise CollectorRefusal("TARGET_MAPPING_AMBIGUOUS")
    try:
        transport = backend.open_selected(selection)
        try:
            observed = transport.observe()
        finally:
            transport.close()
    except Exception as exc:
        raise CollectorRefusal(_backend_refusal_code(exc)) from exc
    if not isinstance(observed, dict):
        raise CollectorRefusal("INCOMPLETE_DESCRIPTOR_METADATA")
    accessed = observed.get("accessed_card_ids")
    if accessed != [EXPECTED_CARD_ID]:
        if not accessed:
            raise CollectorRefusal("TARGET_MAPPING_MISSING")
        raise CollectorRefusal("TARGET_MAPPING_AMBIGUOUS")
    ident = observed.get("adapter_identity")
    required_identity = {"vid", "pid", "manufacturer", "product", "interface", "usb_path"}
    if (not isinstance(ident, dict) or set(ident) != required_identity or
            any(not isinstance(ident.get(k), str) or not ident[k] for k in required_identity) or
            not isinstance(observed.get("adapter_serial"), str) or
            not isinstance(observed.get("card_id"), str)):
        raise CollectorRefusal("INCOMPLETE_DESCRIPTOR_METADATA")
    if observed["adapter_serial"] != EXPECTED_ADAPTER_SERIAL:
        raise CollectorRefusal("EXPECTED_SERIAL_NOT_FOUND")
    if observed["card_id"] != EXPECTED_CARD_ID:
        raise CollectorRefusal("TARGET_MAPPING_AMBIGUOUS")
    try:
        commit = backend.BACKEND_IDENTITY["source_commit"]
        hostname = socket.gethostname()
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        payload = {
            "schema": "fk0957-unsigned-descriptor-evidence", "version": 1,
            "target_selector": "FK0957", "collector_source_sha256": collector_sha256,
            "session_nonce": session_nonce, "backend_source_sha256": backend_hash,
            "source_commit": commit, "remote_hostname": hostname,
            "acquisition_timestamp": timestamp,
            "ftdi_vid": ident["vid"], "ftdi_pid": ident["pid"],
            "manufacturer": ident["manufacturer"], "product": ident["product"],
            "interface": ident["interface"], "usb_path": ident["usb_path"],
            "adapter_serial": observed["adapter_serial"], "fk0957_mapping": observed["card_id"],
            "WRITE_COUNT": 0, "RESET_COUNT": 0, "PROGRAM_COUNT": 0, "JTAG_OPERATIONS": 0,
        }
        canonical(payload)
        return payload
    except CollectorRefusal:
        raise
    except Exception as exc:
        raise CollectorRefusal("INTERNAL_REFUSAL") from exc


def refusal_envelope(refusal_code: str) -> dict:
    if not isinstance(refusal_code, str) or refusal_code not in REFUSAL_CODES:
        refusal_code = "INTERNAL_REFUSAL"
    return {
        "status": "REFUSED", "phase": "COLLECTOR", "refusal_code": refusal_code,
        "cards_opened": 0, "second_card_opened": False,
        "write_count": 0, "reset_count": 0, "program_count": 0,
        "jtag_operations": 0,
    }


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise CollectorRefusal("SOURCE_PROVENANCE_MISMATCH")
        sys.stdout.buffer.write(canonical(collect(sys.argv[1], sys.argv[2])) + b"\n")
    except Exception as exc:
        code = _backend_refusal_code(exc)
        sys.stdout.buffer.write(canonical(refusal_envelope(code)) + b"\n")
        raise SystemExit(2)
