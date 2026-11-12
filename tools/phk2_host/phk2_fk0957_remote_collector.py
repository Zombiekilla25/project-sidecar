#!/usr/bin/env python3
"""Unsigned, descriptor-only FK0957 evidence collector for remote stdin use."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import types
from datetime import datetime, timezone

_bundle_root = os.environ.get("FK0957_BUNDLE_ROOT")
if _bundle_root:
    REPO = Path(_bundle_root)
    root_stat = REPO.lstat()
    if REPO.is_symlink() or not REPO.is_absolute() or not REPO.is_dir() or root_stat.st_mode & 0o077:
        raise RuntimeError("ephemeral bundle root is unsafe")
else:
    REPO = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"],
                                        stderr=subprocess.DEVNULL, text=True).strip()).resolve()
HERE = REPO / "tools" / "phk2_host"
BACKEND = HERE / "phk2_fk0957_readonly_backend.py"
OBSERVER = HERE / "phk2_fk0957_identity_observer.py"
# Pins match the committed local reviewed source inventory. Verify bytes before
# importing either module so modified remote code never executes.
BACKEND_PIN = "977511315676f531352197432547fe6a0ad74acc46bc727c19eed67a6f3097a9"
OBSERVER_PIN = "0bed50e3fec1eedcabada9fda2f05f1d90e586c3d8b8dc5364a2c7f5a3e09f90"
backend_bytes = BACKEND.read_bytes()
observer_bytes = OBSERVER.read_bytes()
backend_hash = hashlib.sha256(backend_bytes).hexdigest()
if backend_hash != BACKEND_PIN:
    raise RuntimeError("remote backend source pin mismatch")
if hashlib.sha256(observer_bytes).hexdigest() != OBSERVER_PIN:
    raise RuntimeError("remote observer source pin mismatch")
def execute_verified_module(name: str, path: Path, source: bytes):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


# Execute the exact byte arrays whose hashes were checked above, avoiding a
# path re-open race between verification and import.
observer_module = execute_verified_module("phk2_fk0957_identity_observer", OBSERVER, observer_bytes)
backend_module = execute_verified_module("phk2_fk0957_readonly_backend", BACKEND, backend_bytes)
TargetSelector = observer_module.TargetSelector
FK0957ReadOnlyBackend = backend_module.FK0957ReadOnlyBackend


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def collect(collector_sha256: str, session_nonce: str) -> dict:
    if len(collector_sha256) != 64 or any(c not in "0123456789abcdef" for c in collector_sha256):
        raise RuntimeError("collector hash malformed")
    if len(session_nonce) != 64 or any(c not in "0123456789abcdef" for c in session_nonce):
        raise RuntimeError("session nonce malformed")
    if os.environ.get("FK0957_TARGET") != "FK0957":
        raise RuntimeError("exact FK0957 target selector required")
    backend = FK0957ReadOnlyBackend()
    selection = backend.select_exact(TargetSelector())  # resolve before descriptor observation
    transport = backend.open_selected(selection)
    try:
        observed = transport.observe()
    finally:
        transport.close()
    ident = observed["adapter_identity"]
    if observed.get("accessed_card_ids") != ["153300000957"]:
        raise RuntimeError("incomplete or ambiguous target metadata")
    commit = backend.BACKEND_IDENTITY["source_commit"]
    payload = {
        "schema": "fk0957-unsigned-descriptor-evidence", "version": 1,
        "target_selector": "FK0957", "collector_source_sha256": collector_sha256,
        "session_nonce": session_nonce,
        "backend_source_sha256": backend_hash, "source_commit": commit,
        "remote_hostname": socket.gethostname(),
        "acquisition_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "ftdi_vid": ident["vid"], "ftdi_pid": ident["pid"],
        "manufacturer": ident["manufacturer"], "product": ident["product"],
        "interface": ident["interface"], "usb_path": ident["usb_path"],
        "adapter_serial": observed["adapter_serial"], "fk0957_mapping": observed["card_id"],
        "WRITE_COUNT": 0, "RESET_COUNT": 0, "PROGRAM_COUNT": 0, "JTAG_OPERATIONS": 0,
    }
    return payload


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise RuntimeError("expected collector SHA256 and session nonce")
        sys.stdout.buffer.write(canonical(collect(sys.argv[1], sys.argv[2])) + b"\n")
    except Exception as exc:
        print(f"collection refused: {exc}", file=sys.stderr)
        raise SystemExit(2)
