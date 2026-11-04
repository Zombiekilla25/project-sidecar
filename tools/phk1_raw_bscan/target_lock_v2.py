#!/usr/bin/env python3
"""Pure, fail-closed PHK1 image-role and target-lock model.

This module has no USB, JTAG, subprocess, or filesystem side effects. The live
lock collector may gather evidence separately; all image-role, freshness,
replay, peer, and TOCTOU decisions are made here and are fixture-testable.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
from typing import Any

LOCK_SCHEMA = "sidecar-raw-jtag-target-lock-v2"
LOCK_TTL_SECONDS = 600
MAX_FUTURE_SKEW_SECONDS = 0
TARGET_FIELDS = (
    "usb_path", "ftdi_serial", "vid", "pid", "interface", "idcode",
    "dna", "bridge_lane", "workload_binding",
)
IMAGE_FIELDS = ("role", "image_id", "sha256", "size", "target_part", "path")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class LockValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_sha256(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()


def _image(image: dict, role: str) -> dict:
    if not isinstance(image, dict) or any(k not in image for k in IMAGE_FIELDS):
        raise LockValidationError("IMAGE_SHAPE", f"{role} image identity is incomplete")
    if image["role"] != role or not HEX64.fullmatch(str(image["sha256"])):
        raise LockValidationError("IMAGE_ROLE", f"image role/hash is invalid for {role}")
    if role == "CANDIDATE_IMAGE_TO_PROGRAM":
        if not isinstance(image["size"], int) or image["size"] <= 0:
            raise LockValidationError("IMAGE_SIZE", f"invalid {role} image size")
    elif image["size"] is not None and (not isinstance(image["size"], int) or image["size"] <= 0):
        raise LockValidationError("IMAGE_SIZE", f"invalid {role} image size")
    if not all(isinstance(image[k], str) and image[k] for k in ("image_id", "target_part", "path")):
        raise LockValidationError("IMAGE_IDENTITY", f"invalid {role} image identity")
    return {k: image[k] for k in IMAGE_FIELDS}


def _physical(identity: dict, label: str) -> dict:
    if not isinstance(identity, dict) or any(k not in identity for k in TARGET_FIELDS):
        raise LockValidationError("PHYSICAL_IDENTITY", f"{label} physical identity is incomplete")
    result = {k: identity[k] for k in TARGET_FIELDS}
    if any(not isinstance(v, str) or not v for v in result.values()):
        raise LockValidationError("PHYSICAL_IDENTITY", f"{label} physical identity has empty fields")
    return result


def _utc(value: str, label: str) -> datetime:
    if not isinstance(value, str):
        raise LockValidationError("TIME_FORMAT", f"{label} timestamp missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LockValidationError("TIME_FORMAT", f"{label} timestamp malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LockValidationError("TIME_FORMAT", f"{label} timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def build_lock(*, target_identity: dict, peer_identity: dict,
               current_image: dict, candidate_image: dict, rollback_image: dict,
               created_utc: str, expires_utc: str, authorization_nonce: str | None = None,
               maintenance_generation: str, candidate_manifest_sha256: str,
               qualification_sha256: str, current_image_evidence: str,
               rollback_authority: str, intended_action: str | None = None,
               run_id: str | None = None) -> dict:
    """Build a v2 authorization record; current, candidate, and rollback stay distinct."""
    target = _physical(target_identity, "target")
    peer = _physical(peer_identity, "peer")
    if any(target[k] == peer[k] for k in ("usb_path", "ftdi_serial", "dna", "bridge_lane")):
        raise LockValidationError("PEER_OVERLAP", "target and peer physical identities overlap")
    current = _image(current_image, "CURRENT_LOADED_IMAGE")
    candidate = _image(candidate_image, "CANDIDATE_IMAGE_TO_PROGRAM")
    rollback = _image(rollback_image, "ROLLBACK_IMAGE")
    if len({current["target_part"], candidate["target_part"], rollback["target_part"]}) != 1:
        raise LockValidationError("PART_MISMATCH", "current/candidate/rollback parts differ")
    if not HEX64.fullmatch(candidate_manifest_sha256) or not HEX64.fullmatch(qualification_sha256):
        raise LockValidationError("QUALIFICATION_ID", "candidate manifest/qualification identity is invalid")
    if not isinstance(maintenance_generation, str) or not maintenance_generation:
        raise LockValidationError("MAINTENANCE_GENERATION", "maintenance generation is required")
    if not isinstance(current_image_evidence, str) or not current_image_evidence:
        raise LockValidationError("CURRENT_IMAGE_EVIDENCE", "current image evidence reference is required")
    if not isinstance(rollback_authority, str) or not rollback_authority:
        raise LockValidationError("ROLLBACK_AUTHORITY", "rollback authority reference is required")
    nonce = authorization_nonce or secrets.token_urlsafe(24)
    if not isinstance(nonce, str) or len(nonce) < 16 or len(nonce) > 128:
        raise LockValidationError("NONCE", "authorization nonce must contain 16–128 characters")
    created, expires = _utc(created_utc, "created"), _utc(expires_utc, "expires")
    if expires <= created or (expires - created).total_seconds() > LOCK_TTL_SECONDS:
        raise LockValidationError("TTL", "lock expiration must be after creation and within 600 seconds")
    action = intended_action
    if action is None:
        if current["sha256"] == rollback["sha256"]:
            action = "PROGRAM_CANDIDATE"
        elif current["sha256"] == candidate["sha256"]:
            action = "VERIFY_CANDIDATE"
        else:
            raise LockValidationError("CURRENT_IMAGE_ROLE", "current image is neither candidate nor rollback baseline")
    if action == "PROGRAM_CANDIDATE" and current["sha256"] != rollback["sha256"]:
        raise LockValidationError("PREPROGRAM_BASELINE", "program authorization requires rollback image as current baseline")
    if action == "VERIFY_CANDIDATE" and current["sha256"] != candidate["sha256"]:
        raise LockValidationError("POSTPROGRAM_IMAGE", "verification authorization requires candidate as current image")
    if action not in {"PROGRAM_CANDIDATE", "VERIFY_CANDIDATE"}:
        raise LockValidationError("ACTION", "unsupported lock action")
    lock = {
        "schema": LOCK_SCHEMA, "schema_version": 2, "status": "PASS",
        "target_identity": target, "peer_identity": peer,
        "current_image": current, "candidate_image": candidate, "rollback_image": rollback,
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "qualification_sha256": qualification_sha256,
        "run_id": run_id or maintenance_generation,
        "current_image_evidence": current_image_evidence,
        "rollback_authority": rollback_authority,
        "created_utc": created.isoformat().replace("+00:00", "Z"),
        "expires_utc": expires.isoformat().replace("+00:00", "Z"),
        "authorization_nonce": nonce,
        "maintenance_scope": "target_only_canary",
        "maintenance_generation": maintenance_generation,
        "peer_exclusion": {"peer_program_allowed": False, "peer_identity_sha256": canonical_sha256(peer)},
        "max_programmed_device_count": 1,
        "programmed_device_count": 0 if action == "PROGRAM_CANDIDATE" else 1,
        "peer_program_count": 0,
        "raw_device_handle_count": 0,
        "peer_handle_open": False,
        "intended_action": action,
    }
    lock["lock_sha256"] = canonical_sha256(lock)
    return lock


def validate_lock(lock: dict, *, now: datetime, expected_target: dict, expected_peer: dict,
                  expected_candidate: dict, expected_rollback: dict,
                  expected_manifest_sha256: str, expected_qualification_sha256: str,
                  expected_maintenance_generation: str, used_nonces: set[str] | None = None,
                  expected_current_image: dict | None = None,
                  expected_rollback_authority: str | None = None,
                  intended_action: str = "PROGRAM_CANDIDATE") -> dict:
    """Validate lock against freshly supplied identities and file hashes before an action."""
    if not isinstance(lock, dict) or lock.get("schema") != LOCK_SCHEMA or lock.get("schema_version") != 2 or lock.get("status") != "PASS":
        raise LockValidationError("SCHEMA", "unsupported lock schema/status")
    body = deepcopy(lock); recorded_digest = body.pop("lock_sha256", None)
    if not isinstance(recorded_digest, str) or recorded_digest != canonical_sha256(body):
        raise LockValidationError("LOCK_INTEGRITY", "lock contents do not match lock SHA256")
    created, expires = _utc(lock.get("created_utc"), "created"), _utc(lock.get("expires_utc"), "expires")
    current = now.astimezone(timezone.utc)
    if created > current + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
        raise LockValidationError("FUTURE", "lock creation time is in the future")
    if expires <= current or (current - created).total_seconds() > LOCK_TTL_SECONDS:
        raise LockValidationError("STALE", "lock is expired or older than the 600-second limit")
    if expires <= created or (expires - created).total_seconds() > LOCK_TTL_SECONDS:
        raise LockValidationError("TTL", "lock expiration interval is invalid")
    nonce = lock.get("authorization_nonce")
    if not isinstance(nonce, str) or len(nonce) < 16 or (used_nonces is not None and nonce in used_nonces):
        raise LockValidationError("NONCE_REPLAY", "authorization nonce is missing, short, or already used")
    if lock.get("maintenance_scope") != "target_only_canary" or lock.get("maintenance_generation") != expected_maintenance_generation:
        raise LockValidationError("MAINTENANCE_GENERATION", "maintenance scope/generation changed")
    target = _physical(lock.get("target_identity"), "target")
    peer = _physical(lock.get("peer_identity"), "peer")
    if target != _physical(expected_target, "expected target"):
        raise LockValidationError("WRONG_TARGET", "physical target identity changed")
    if peer != _physical(expected_peer, "expected peer") or target["dna"] == peer["dna"]:
        raise LockValidationError("WRONG_PEER", "peer identity/exclusion changed")
    if lock.get("peer_exclusion") != {"peer_program_allowed": False, "peer_identity_sha256": canonical_sha256(peer)}:
        raise LockValidationError("PEER_AUTHORIZATION", "peer programming is not explicitly excluded")
    if lock.get("max_programmed_device_count") != 1 or lock.get("peer_program_count") != 0:
        raise LockValidationError("PROGRAM_LIMIT", "lock is not a one-device peer-excluded authorization")
    if lock.get("raw_device_handle_count") != 0 or lock.get("peer_handle_open") is not False:
        raise LockValidationError("OPEN_HANDLE", "target or peer handle is already open")
    candidate = _image(lock.get("candidate_image"), "CANDIDATE_IMAGE_TO_PROGRAM")
    rollback = _image(lock.get("rollback_image"), "ROLLBACK_IMAGE")
    current_image = _image(lock.get("current_image"), "CURRENT_LOADED_IMAGE")
    expected_candidate = _image(expected_candidate, "CANDIDATE_IMAGE_TO_PROGRAM")
    expected_rollback = _image(expected_rollback, "ROLLBACK_IMAGE")
    if candidate != expected_candidate or lock.get("candidate_manifest_sha256") != expected_manifest_sha256 or lock.get("qualification_sha256") != expected_qualification_sha256:
        raise LockValidationError("WRONG_CANDIDATE", "candidate file/manifest/qualification identity changed")
    if rollback != expected_rollback or not lock.get("rollback_authority") or (expected_rollback_authority is not None and lock.get("rollback_authority") != expected_rollback_authority):
        raise LockValidationError("WRONG_ROLLBACK", "rollback file or authority identity changed")
    if expected_current_image is not None and current_image != _image(expected_current_image, "CURRENT_LOADED_IMAGE"):
        raise LockValidationError("CURRENT_IMAGE_CHANGED", "current/baseline image identity changed")
    if lock.get("intended_action") != intended_action:
        raise LockValidationError("ACTION", "lock intended action does not match requested action")
    if intended_action == "PROGRAM_CANDIDATE":
        if lock.get("programmed_device_count") != 0:
            raise LockValidationError("PROGRAM_LIMIT", "program authorization has already been consumed")
        if current_image["sha256"] != rollback["sha256"]:
            raise LockValidationError("PREPROGRAM_BASELINE", "XBT baseline must be current; candidate need not be currently loaded")
    elif intended_action == "VERIFY_CANDIDATE":
        if lock.get("programmed_device_count") != 1:
            raise LockValidationError("PROGRAM_LIMIT", "verification lock must record one programmed target")
        if current_image["sha256"] != candidate["sha256"]:
            raise LockValidationError("POSTPROGRAM_IMAGE", "candidate must be current for verification")
    else:
        raise LockValidationError("ACTION", "unsupported action")
    if not lock.get("current_image_evidence"):
        raise LockValidationError("CURRENT_IMAGE_EVIDENCE", "current image lacks an evidence reference")
    if not isinstance(lock.get("candidate_manifest_sha256"), str) or not HEX64.fullmatch(lock["candidate_manifest_sha256"]):
        raise LockValidationError("QUALIFICATION_ID", "candidate manifest identity is malformed")
    if not isinstance(lock.get("qualification_sha256"), str) or not HEX64.fullmatch(lock["qualification_sha256"]):
        raise LockValidationError("QUALIFICATION_ID", "qualification identity is malformed")
    return lock


def transition_image_state(state: dict, event: str) -> dict:
    """Model state transitions without any device interaction."""
    out = deepcopy(state)
    if event == "program_success":
        if out["current_image"]["sha256"] != out["rollback_image"]["sha256"]:
            raise LockValidationError("PREPROGRAM_BASELINE", "program transition requires current XBT baseline")
        out["current_image"] = deepcopy(out["candidate_image"])
    elif event in {"rollback_success", "failure_restore"}:
        out["current_image"] = deepcopy(out["rollback_image"])
        out["production_restored"] = True
    else:
        raise LockValidationError("TRANSITION", "unknown modeled image transition")
    return out


def simulate_failure_restore(failure_phase: str, initial_state: dict) -> dict:
    phases = ("lock_generation", "maintenance_enter", "bridge_release", "jit_validation",
              "program_start", "program_failure", "runner_start", "hello", "user3_poll",
              "vector", "verification", "rollback")
    if failure_phase not in phases:
        raise LockValidationError("FAILURE_PHASE", "unknown modeled failure phase")
    out = deepcopy(initial_state)
    out["failure_phase"] = failure_phase
    out["maintenance_active"] = failure_phase not in {"lock_generation", "maintenance_enter"}
    out["peer_program_count"] = 0
    if failure_phase in {"runner_start", "hello", "user3_poll", "vector", "verification", "rollback"}:
        out = transition_image_state(out, "program_success")
    # All failure branches terminate with verified rollback; before a program
    # the baseline is already XBT, so no rollback programming is modeled.
    out = transition_image_state(out, "failure_restore")
    out["bridge_restored"] = True
    out["miners_restored"] = 8
    out["protected_workload_continuity"] = True
    out["maintenance_active"] = False
    out["raw_runner_active"] = False
    return out
