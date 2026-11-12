#!/usr/bin/env python3
"""Fail-closed, read-only FK0957 identity observer.

This module does not contain a USB/JTAG/XVC implementation. A future backend
must be separately reviewed and pinned before the live CLI will accept it.
Only exact-serial selection may precede opening a transport.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types
from typing import Any, Mapping, Protocol

OBSERVER_VERSION = "1.0.0"
TARGET_SUFFIX = "0957"
EXPECTED_ADAPTER_SERIAL = "153300000957A"
EXPECTED_USB_SERIAL = "153300000957"
EXPECTED_CARD_ID = "153300000957"
OBSERVER_PATH = Path(__file__).resolve()
# Descriptor-only backend reviewed from its exact source commit. The source
# file hashes bind the legacy implementation used as reference; they do not
# authorize the legacy MPSSE implementation itself.
_FK0957_BACKEND_SPEC = "phk2_fk0957_readonly_backend:create_backend"
REVIEWED_BACKENDS: Mapping[str, str] = {
    _FK0957_BACKEND_SPEC: "bc7b69f84e2851b017cf3a0e60e0e49c74f23467d97104528722992fcfd2add2",
}
REVIEWED_BACKEND_PATHS: Mapping[str, str] = {
    _FK0957_BACKEND_SPEC: "tools/phk2_host/phk2_fk0957_readonly_backend.py",
}
REVIEWED_BACKEND_SOURCE_PINS: Mapping[str, Mapping[str, Any]] = {
    _FK0957_BACKEND_SPEC: {
        "source_commit": "e2feedcfde44563854a3cf41fe4526c231ed385b",
        "source_file_hashes": {
            "tools/phk1_raw_bscan/usb_identity.hpp": "916e436168d4a7cf057e1019a06f0b2207d9122246e7bae22a73121549eb2fcb",
            "tools/phk1_raw_bscan/usb_selection.cpp": "6bd03fd54b2a94d0a056c3eb155b6c50cdc65a530eae752aeb93f5fedf41df48",
            "tools/phk1_raw_bscan/libftdi_io.cpp": "4b61ff5c78f6c666e5888d56ffda885edf6923fc4d72b361b75b6e56ca949194",
            "tools/phk1_raw_bscan/identify_only.cpp": "31260a7c6a3ac437bcfc1dcd6e8914d700c74ab26600a1bdb7c2b957e9e4d117",
        },
    },
}
READ_ONLY_METHODS = frozenset({"select_exact", "open_selected", "observe", "close"})
FORBIDDEN_METHODS = frozenset({"write", "write_exact", "read_exact", "register_write", "program", "configure", "reset", "reconfigure", "tap_update", "shift_ir", "shift_dr", "mpsse", "send_command", "workload_change", "service_change"})


class Refusal(RuntimeError):
    """An unsafe, ambiguous, or incomplete identity observation was refused."""


@dataclass(frozen=True)
class TargetSelector:
    adapter_serial: str = EXPECTED_ADAPTER_SERIAL
    expected_usb_serial: str = EXPECTED_USB_SERIAL
    card_id: str = EXPECTED_CARD_ID
    serial_suffix: str = TARGET_SUFFIX

    def validate(self) -> None:
        if (self.adapter_serial != EXPECTED_ADAPTER_SERIAL or
                self.expected_usb_serial != EXPECTED_USB_SERIAL or
                self.card_id != EXPECTED_CARD_ID or
                self.serial_suffix != TARGET_SUFFIX or
                not self.card_id.endswith(self.serial_suffix)):
            raise Refusal("selector must identify only FK0957 by its exact adapter serial and card ID")


@dataclass(frozen=True)
class Selection:
    adapter_serial: str
    usb_descriptor_serial: str
    card_id: str
    serial_suffix: str
    matching_devices: int
    serial_scoped_before_open: bool
    requires_write: bool = False
    endpoint_token: str = ""


class ReadOnlyBackend(Protocol):
    METHOD_ACCESS: Mapping[str, str]
    BACKEND_IDENTITY: Mapping[str, str]
    SINGLE_DEVICE_SERIAL_SCOPE: bool

    def select_exact(self, selector: TargetSelector) -> Selection: ...
    def open_selected(self, selection: Selection) -> Any: ...


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise Refusal("evidence contains non-canonical or non-JSON values") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _source_commit(repo: Path) -> str:
    try:
        value = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Refusal("source commit cannot be determined") from exc
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise Refusal("source commit is malformed")
    return value


def _validate_backend(backend: Any) -> None:
    methods = getattr(backend, "METHOD_ACCESS", None)
    if not isinstance(methods, Mapping) or set(methods) != READ_ONLY_METHODS or any(v != "READ_ONLY" for v in methods.values()):
        raise Refusal("backend methods are not statically classified as the exact READ_ONLY observer surface")
    if any(callable(getattr(backend, name, None)) for name in FORBIDDEN_METHODS):
        raise Refusal("backend exposes a forbidden mutation method")
    identity = getattr(backend, "BACKEND_IDENTITY", None)
    if not isinstance(identity, Mapping) or not all(isinstance(identity.get(k), str) and identity[k].strip() for k in ("name", "version", "sha256")):
        raise Refusal("backend identity is incomplete")
    if not re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]):
        raise Refusal("backend source hash is malformed")
    if (not isinstance(identity.get("source_commit"), str) or
            not re.fullmatch(r"[0-9a-f]{40}", identity["source_commit"])):
        raise Refusal("backend source commit pin is missing or malformed")
    try:
        file_hashes = json.loads(identity.get("source_file_hashes", ""))
    except (TypeError, ValueError) as exc:
        raise Refusal("backend source-file hash inventory is malformed") from exc
    if not isinstance(file_hashes, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or
            not re.fullmatch(r"[0-9a-f]{64}", v) for k, v in file_hashes.items()):
        raise Refusal("backend source-file hash inventory is incomplete")
    if getattr(backend, "SINGLE_DEVICE_SERIAL_SCOPE", None) is not True:
        raise Refusal("backend cannot guarantee exact single-device serial scoping before open")


def _validate_observations(observations: Any, selection: Selection) -> dict[str, Any]:
    if not isinstance(observations, Mapping):
        raise Refusal("backend returned malformed observations")
    allowed = {"adapter_identity", "adapter_serial", "usb_descriptor_serial", "card_id", "fpga_dna", "idcode", "target_part",
               "jtag_chain", "loaded_image_identity", "bridge_identity", "accessed_card_ids"}
    if set(observations) - allowed:
        raise Refusal("backend returned an unapproved observation field")
    if (observations.get("adapter_serial") != selection.adapter_serial or
            observations.get("usb_descriptor_serial") != selection.usb_descriptor_serial or
            observations.get("card_id") != selection.card_id):
        raise Refusal("target identity changed during observation")
    accessed = observations.get("accessed_card_ids")
    if accessed != [EXPECTED_CARD_ID]:
        raise Refusal("observation did not prove exactly one FK0957 card was accessed")
    clean = dict(observations)
    clean.pop("accessed_card_ids")
    return clean


def observe(backend: ReadOnlyBackend, selector: TargetSelector, *, repo: Path,
            signing_key_path: Path) -> dict[str, Any]:
    """Select exact target, then open and perform only manifest-approved reads."""
    selector.validate()
    _validate_backend(backend)

    # Selection is a distinct, serial-scoped pre-open gate. No transport method
    # is available until it returns a unique proof for the exact requested FK.
    selection = backend.select_exact(selector)
    if not isinstance(selection, Selection):
        raise Refusal("backend did not provide a typed target-selection proof")
    if (selection.adapter_serial != selector.adapter_serial or
            selection.usb_descriptor_serial != selector.expected_usb_serial or
            selection.card_id != selector.card_id or
            selection.serial_suffix != selector.serial_suffix or selection.matching_devices != 1 or
            selection.serial_scoped_before_open is not True or selection.requires_write is not False or
            not selection.endpoint_token):
        raise Refusal("target selection is missing, ambiguous, mismatched, or requires mutation")

    transport = backend.open_selected(selection)
    try:
        transport_methods = getattr(transport, "METHOD_ACCESS", None)
        if not isinstance(transport_methods, Mapping) or dict(transport_methods) != {"observe": "READ_ONLY", "close": "READ_ONLY"}:
            raise Refusal("opened transport methods are not statically READ_ONLY")
        if any(callable(getattr(transport, name, None)) for name in FORBIDDEN_METHODS):
            raise Refusal("opened transport exposes a forbidden mutation method")
        first = dict(selection.__dict__)
        raw = transport.observe()
        observations = _validate_observations(raw, selection)
        # Re-read identity using the same observation call's returned fields;
        # the backend contract must make its observation atomic. Selection and
        # observed adapter/card identity are compared before evidence creation.
        if (observations["adapter_serial"] != first["adapter_serial"] or
                observations["usb_descriptor_serial"] != first["usb_descriptor_serial"] or
                observations["card_id"] != first["card_id"]):
            raise Refusal("identity changed during observation")
    finally:
        transport.close()

    backend_identity = dict(backend.BACKEND_IDENTITY)
    _validate_backend(backend)
    repo = repo.resolve()
    source_commit = _source_commit(repo)
    observer_sha = _sha256(OBSERVER_PATH.read_bytes())
    payload = {
        "schema": "PHK2-FK0957-READ-ONLY-IDENTITY-v1",
        "target_selector": asdict(selector),
        "captured_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "backend_identity": backend_identity,
        "observations": observations,
        "source_commit": source_commit,
        "observer_version": OBSERVER_VERSION,
        "observer_sha256": observer_sha,
        "write_count": 0,
        "program_count": 0,
        "reset_count": 0,
    }
    canonical = _canonical(payload)
    digest = _sha256(canonical)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(signing_key_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("evidence signer must be Ed25519")
        signature = key.sign(canonical)
    except Exception as exc:
        raise Refusal("evidence signing key unavailable, invalid, or cannot sign") from exc
    return {"payload": payload, "payload_sha256": digest,
            "signature_algorithm": "Ed25519", "signature_hex": signature.hex()}


def _load_reviewed_backend(spec: str, expected_sha256: str) -> Any:
    """Hash exact repository-pinned bytes before executing backend code."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise Refusal("a reviewed backend SHA256 pin is required")
    if REVIEWED_BACKENDS.get(spec) != expected_sha256:
        raise Refusal("backend is not present in the source-pinned reviewed-backend allowlist")
    _module_name, sep, object_name = spec.partition(":")
    if not sep or not _module_name or not object_name:
        raise Refusal("backend must be specified as module:factory")
    relative_path = REVIEWED_BACKEND_PATHS.get(spec)
    if not relative_path:
        raise Refusal("backend has no repository-pinned source path")
    repo = OBSERVER_PATH.parents[2].resolve()
    module_path = (repo / relative_path).resolve()
    try:
        module_path.relative_to(repo)
        source_bytes = module_path.read_bytes()
    except (OSError, ValueError) as exc:
        raise Refusal("pinned backend source is missing or escapes the repository") from exc
    if _sha256(source_bytes) != expected_sha256:
        raise Refusal("backend source does not match reviewed SHA256")

    # Execute only the byte string whose digest was just checked. Ordinary
    # importlib lookup could execute a shadow module before its __file__ hash
    # was checked, so it is intentionally not used for this trust boundary.
    module_name = f"_phk2_reviewed_backend_{expected_sha256[:16]}"
    module = types.ModuleType(module_name)
    module.__file__ = str(module_path)
    sys.modules[module_name] = module
    try:
        exec(compile(source_bytes, str(module_path), "exec"), module.__dict__)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        raise Refusal("pinned backend source failed during initialization") from exc
    factory = getattr(module, object_name, None)
    if not callable(factory):
        raise Refusal("reviewed backend factory is missing")
    backend = factory()
    source_pin = REVIEWED_BACKEND_SOURCE_PINS.get(spec)
    if source_pin is None:
        raise Refusal("backend has no exact reviewed source commit/file pin")
    try:
        pinned_hashes = json.loads(backend.BACKEND_IDENTITY["source_file_hashes"])
    except (KeyError, TypeError, ValueError) as exc:
        raise Refusal("backend source-file hashes are unavailable") from exc
    if (backend.BACKEND_IDENTITY.get("source_commit") != source_pin["source_commit"] or
            pinned_hashes != source_pin["source_file_hashes"]):
        raise Refusal("backend source commit or reference-file hashes differ from reviewed pin")
    return backend


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=("FK0957",), help="exact single authorized target")
    parser.add_argument("--backend", required=True, help="separately reviewed module:factory")
    parser.add_argument("--backend-sha256", required=True, help="reviewed backend source SHA256 pin")
    parser.add_argument("--signing-key", required=True, type=Path, help="operator-provisioned Ed25519 PEM key")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=OBSERVER_PATH.parents[2])
    args = parser.parse_args(argv)
    try:
        backend = _load_reviewed_backend(args.backend, args.backend_sha256)
        evidence = observe(backend, TargetSelector(), repo=args.repo, signing_key_path=args.signing_key)
        args.output.write_bytes(_canonical(evidence) + b"\n")
    except (Refusal, OSError, ImportError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
