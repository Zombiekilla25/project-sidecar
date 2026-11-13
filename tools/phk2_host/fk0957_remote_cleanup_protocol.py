#!/usr/bin/env python3
"""Strict RGB-side contract for FK0957 remote process receipts and status.

This module validates protocol records only. It performs no SSH, process
inspection, signaling, or device access. The remote endpoint must implement
the receipt storage and read-only query rules documented in the handoff.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

NOT_STARTED = "CONFIRMED_NOT_STARTED"
RUNNING_EXPECTED_PROCESS = "CONFIRMED_RUNNING"
EXITED_SUCCESS = "CONFIRMED_EXITED_SUCCESS"
EXITED_REFUSAL = "CONFIRMED_EXITED_REFUSAL"
EXITED_FAILURE = "CONFIRMED_EXITED_FAILURE"
IDENTITY_MISMATCH = "PROCESS_IDENTITY_MISMATCH"
STATUS_INSPECTION_FAILED = "STATUS_INSPECTION_FAILED"
TRANSPORT_FAILED = "TRANSPORT_FAILED"
UNKNOWN = "UNKNOWN"
STATUSES = {NOT_STARTED, RUNNING_EXPECTED_PROCESS, EXITED_SUCCESS,
            EXITED_REFUSAL, EXITED_FAILURE, IDENTITY_MISMATCH,
            STATUS_INSPECTION_FAILED, TRANSPORT_FAILED, UNKNOWN}
# This legacy same-UID receipt protocol is not an authoritative child reaper.
# Only the separately protected supervisor may authorize shared-owner restore.
RESTORABLE: set[str] = set()
RECEIPT_STATE_FOR_STATUS = {
    EXITED_SUCCESS: "EXITED_SUCCESS",
    EXITED_REFUSAL: "EXITED_REFUSAL",
    EXITED_FAILURE: "EXITED_FAILURE",
}

OP_ID = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RECEIPT_ID = re.compile(r"[0-9a-f]{32}\Z")
START_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
SAFE_AUTH_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
RECEIPT_SCHEMA = "fk0957-remote-process-receipt-v1"
STATUS_SCHEMA = "fk0957-remote-process-status-v2"
RECEIPT_KEYS = {
    "schema", "operation_id", "release_authorization_id",
    "release_authorization_sha256", "target_selector", "usb_descriptor_serial",
    "adapter_serial", "expected_executable", "expected_executable_sha256",
    "release_manifest_sha256", "source_commit", "release_authorization_expires_utc",
    "remote_host", "remote_user", "receipt_id",
    "created_utc", "updated_utc", "one_shot", "state", "process", "exit_code",
}
PROCESS_KEYS = {"pid", "start_identity", "uid", "executable",
                "executable_sha256", "argv_sha256", "cwd", "operation_id_argument"}
STATUS_KEYS = {
    "schema", "operation_id", "query_nonce", "observed_utc",
    "release_authorization_id", "release_authorization_sha256",
    "target_selector", "release_manifest_sha256", "remote_host", "remote_user",
    "status", "receipt_sha256", "receipt", "process_identity",
}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse_canonical(raw: bytes, limit: int) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > limit:
        raise ValueError("record absent or oversized")
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    if not isinstance(value, dict) or canonical(value) != raw:
        raise ValueError("record is not canonical JSON")
    return value


def _timestamp(value: Any, *, now: datetime, max_age_seconds: int) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            return False
        age = (now.astimezone(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()
    except (ValueError, TypeError):
        return False
    return 0 <= age <= max_age_seconds


def _valid_process(value: Any, *, operation_id: str, expected_user: str,
                   expected_uid: int,
                   expected_executable: str, expected_executable_sha256: str,
                   expected_argv_sha256: str,
                   expected_cwd: str | None = None) -> bool:
    if not isinstance(value, dict) or set(value) != PROCESS_KEYS:
        return False
    if (type(value["pid"]) is not int or value["pid"] <= 1 or
            type(value["uid"]) is not int or value["uid"] != expected_uid or
            not isinstance(value["start_identity"], str) or
            not START_ID.fullmatch(value["start_identity"])):
        return False
    return (value["executable"] == expected_executable and
            value["executable_sha256"] == expected_executable_sha256 and
            HEX64.fullmatch(str(value["executable_sha256"])) is not None and
            value["argv_sha256"] == expected_argv_sha256 and
            HEX64.fullmatch(str(value["argv_sha256"])) is not None and
            value["operation_id_argument"] == operation_id and
            isinstance(value["cwd"], str) and value["cwd"].startswith("/") and
            (expected_cwd is None or value["cwd"] == expected_cwd) and
            value.get("user") in (None, expected_user))


def validate_receipt(raw: bytes, *, operation_id: str, release_authorization_id: str,
                     release_authorization_sha256: str, release_manifest_sha256: str,
                     source_commit: str,
                     release_authorization_expires_utc: str,
                     expected_receipt_id: str,
                     expected_host: str, expected_user: str, expected_uid: int,
                     expected_executable: str, expected_executable_sha256: str,
                     expected_argv_sha256: str,
                     expected_cwd: str | None = None, now: datetime,
                     max_age_seconds: int = 120) -> dict[str, Any]:
    """Validate a canonical remote receipt against locally approved bindings.

    File safety is a remote writer/reader obligation: private per-operation
    directory mode 0700; receipt mode 0600, regular, nlink=1; open via held
    directory FD with O_NOFOLLOW; atomic no-replace creation and atomic state
    replacement. This function refuses incomplete or changed receipt bytes.
    """
    row = _parse_canonical(raw, 16 * 1024)
    if set(row) != RECEIPT_KEYS or row["schema"] != RECEIPT_SCHEMA:
        raise ValueError("receipt schema or fields mismatch")
    bindings = (row["operation_id"] == operation_id and OP_ID.fullmatch(operation_id) and
                row["release_authorization_id"] == release_authorization_id and
                row["release_authorization_sha256"] == release_authorization_sha256 and
                row["release_manifest_sha256"] == release_manifest_sha256 and
                row["source_commit"] == source_commit and
                re.fullmatch(r"[0-9a-f]{40}", str(row["source_commit"])) is not None and
                row["release_authorization_expires_utc"] == release_authorization_expires_utc and
                row["receipt_id"] == expected_receipt_id and
                row["target_selector"] == "FK0957" and
                row["usb_descriptor_serial"] == "153300000957" and
                row["adapter_serial"] == "153300000957A" and
                row["remote_host"] == expected_host and row["remote_user"] == expected_user and
                row["expected_executable"] == expected_executable and
                row["expected_executable_sha256"] == expected_executable_sha256 and
                HEX64.fullmatch(str(row["release_authorization_sha256"])) is not None and
                HEX64.fullmatch(str(row["release_manifest_sha256"])) is not None and
                HEX64.fullmatch(str(row["expected_executable_sha256"])) is not None and
                SAFE_AUTH_ID.fullmatch(str(row["release_authorization_id"])) is not None and
                RECEIPT_ID.fullmatch(str(row["receipt_id"])) is not None and
                type(row["one_shot"]) is bool and row["one_shot"] is True and
                _timestamp(row["created_utc"], now=now, max_age_seconds=max_age_seconds) and
                _timestamp(row["updated_utc"], now=now, max_age_seconds=max_age_seconds))
    try:
        authorization_expiry = datetime.fromisoformat(
            row["release_authorization_expires_utc"].replace("Z", "+00:00"))
        receipt_created = datetime.fromisoformat(row["created_utc"].replace("Z", "+00:00"))
        if authorization_expiry.utcoffset() is None or receipt_created.utcoffset() is None:
            raise ValueError("timezone required")
        bindings = bindings and receipt_created <= authorization_expiry
    except (AttributeError, TypeError, ValueError):
        bindings = False
    if not bindings:
        raise ValueError("receipt provenance, target, identity, or freshness mismatch")
    state = row["state"]
    if type(state) is not str:
        raise ValueError("receipt state type invalid")
    if state in {"PREPARED", "CLAIMED"}:
        if row["process"] is not None or row["exit_code"] is not None:
            raise ValueError("PREPARED receipt contains process/exit claims")
    elif state == "RUNNING":
        if row["exit_code"] is not None or not _valid_process(
                row["process"], operation_id=operation_id, expected_user=expected_user,
                expected_uid=expected_uid,
                expected_executable=expected_executable,
                expected_executable_sha256=expected_executable_sha256,
                expected_argv_sha256=expected_argv_sha256,
                expected_cwd=expected_cwd):
            raise ValueError("RUNNING receipt process identity mismatch")
    elif state in {"EXITED_SUCCESS", "EXITED_REFUSAL", "EXITED_FAILURE"}:
        if type(row["exit_code"]) is not int or not _valid_process(
                row["process"], operation_id=operation_id, expected_user=expected_user,
                expected_uid=expected_uid,
                expected_executable=expected_executable,
                expected_executable_sha256=expected_executable_sha256,
                expected_argv_sha256=expected_argv_sha256,
                expected_cwd=expected_cwd):
            raise ValueError("terminal receipt lacks exact process identity or exit code")
        if ((state == "EXITED_SUCCESS" and row["exit_code"] != 0) or
                (state in {"EXITED_REFUSAL", "EXITED_FAILURE"} and row["exit_code"] == 0)):
            raise ValueError("receipt exit class contradicts exit code")
    else:
        raise ValueError("unknown one-shot receipt state")
    return row


def validate_status(raw: bytes, *, operation_id: str, query_nonce: str,
                    release_authorization_id: str, release_authorization_sha256: str,
                    release_manifest_sha256: str, expected_receipt_id: str,
                    source_commit: str,
                    release_authorization_expires_utc: str,
                    expected_host: str, expected_user: str, expected_uid: int,
                    expected_executable: str, expected_executable_sha256: str,
                    expected_argv_sha256: str,
                    expected_cwd: str | None = None, now: datetime,
                    max_age_seconds: int = 10) -> str:
    """Validate one challenge-bound status response; every defect maps UNKNOWN."""
    try:
        status = _parse_canonical(raw, 24 * 1024)
        if set(status) != STATUS_KEYS or status["schema"] != STATUS_SCHEMA:
            return UNKNOWN
        if (status["operation_id"] != operation_id or not OP_ID.fullmatch(operation_id) or
                status["query_nonce"] != query_nonce or not HEX64.fullmatch(query_nonce) or
                status["release_authorization_id"] != release_authorization_id or
                status["release_authorization_sha256"] != release_authorization_sha256 or
                status["release_manifest_sha256"] != release_manifest_sha256 or
                status["target_selector"] != "FK0957" or
                status["remote_host"] != expected_host or status["remote_user"] != expected_user or
                not _timestamp(status["observed_utc"], now=now, max_age_seconds=max_age_seconds) or
                status["status"] not in STATUSES):
            return UNKNOWN
        receipt = status["receipt"]
        if receipt is None:
            return UNKNOWN
        receipt_raw = canonical(receipt)
        if hashlib.sha256(receipt_raw).hexdigest() != status["receipt_sha256"]:
            return UNKNOWN
        receipt = validate_receipt(
            receipt_raw, operation_id=operation_id,
            release_authorization_id=release_authorization_id,
            release_authorization_sha256=release_authorization_sha256,
            release_manifest_sha256=release_manifest_sha256,
            source_commit=source_commit,
            release_authorization_expires_utc=release_authorization_expires_utc,
            expected_receipt_id=expected_receipt_id,
            expected_host=expected_host, expected_user=expected_user, expected_uid=expected_uid,
            expected_executable=expected_executable,
            expected_executable_sha256=expected_executable_sha256,
            expected_argv_sha256=expected_argv_sha256,
            expected_cwd=expected_cwd, now=now, max_age_seconds=120)
        claimed = status["status"]
        if claimed == NOT_STARTED:
            return UNKNOWN
        if claimed == RUNNING_EXPECTED_PROCESS:
            expected_process = receipt["process"]
            actual = status["process_identity"]
            if actual != expected_process or not _valid_process(
                    actual, operation_id=operation_id, expected_user=expected_user,
                    expected_uid=expected_uid,
                    expected_executable=expected_executable,
                    expected_executable_sha256=expected_executable_sha256,
                    expected_argv_sha256=expected_argv_sha256,
                    expected_cwd=expected_cwd):
                return IDENTITY_MISMATCH if isinstance(actual, dict) else UNKNOWN
            return RUNNING_EXPECTED_PROCESS if receipt["state"] == "RUNNING" else UNKNOWN
        if claimed in {EXITED_SUCCESS, EXITED_REFUSAL, EXITED_FAILURE}:
            # Caller-writable receipt state plus PID absence is not proof the
            # authoritative supervisor reaped the exact child.
            return UNKNOWN
        if claimed == IDENTITY_MISMATCH:
            return IDENTITY_MISMATCH
        if claimed == STATUS_INSPECTION_FAILED:
            return STATUS_INSPECTION_FAILED
        return UNKNOWN
    except (UnicodeError, ValueError, TypeError, KeyError, OverflowError):
        return UNKNOWN


def restore_allowed(status: str) -> bool:
    """Legacy receipts can never authorize ownership restoration."""
    return False


def classify_status_query(*, transport_return_code: Any, response_bytes: Any,
                          validator_kwargs: dict[str, Any]) -> str:
    """Keep SSH transport, status inspection, and process state distinct.

    A nonzero SSH return (including 255), timeout represented by absent bytes,
    malformed response, or failed validator is never evidence of process exit.
    """
    if type(transport_return_code) is not int or transport_return_code != 0:
        return TRANSPORT_FAILED
    if type(response_bytes) is not bytes or not response_bytes:
        return STATUS_INSPECTION_FAILED
    if type(validator_kwargs) is not dict:
        return STATUS_INSPECTION_FAILED
    try:
        envelope = _parse_canonical(response_bytes, 24 * 1024)
        state = validate_status(response_bytes, **validator_kwargs)
    except (UnicodeError, TypeError, ValueError, KeyError, OverflowError):
        return STATUS_INSPECTION_FAILED
    if state == UNKNOWN:
        # A canonical, challenge-bound UNKNOWN is a valid observation that
        # process state is unresolved. Other UNKNOWN results mean inspection
        # could not authenticate/validate the response.
        return UNKNOWN if envelope.get("status") == UNKNOWN else STATUS_INSPECTION_FAILED
    return state


def receipt_transition_allowed(old_state: str, new_state: str) -> bool:
    """Require monotonic one-shot receipt transitions; terminal rows freeze."""
    if type(old_state) is not str or type(new_state) is not str:
        return False
    allowed = {
        "PREPARED": {"PREPARED", "CLAIMED"},
        "CLAIMED": {"CLAIMED", "RUNNING"},
        # Only the protected supervisor may write terminal process states.
        "RUNNING": {"RUNNING"},
    }
    return new_state in allowed.get(old_state, set())


def one_shot_claim_allowed(state: str, *, claimed: bool) -> bool:
    """Only an unclaimed PREPARED receipt can atomically launch the process."""
    return type(state) is str and type(claimed) is bool and state == "PREPARED" and claimed is False


def receipt_storage_safe(*, expected_uid: int, file_uid: int, file_mode: int,
                         file_nlink: int, file_regular: bool, file_symlink: bool,
                         parents: list[tuple[int, int, bool, bool]]) -> bool:
    """Remote endpoint storage predicate for (uid, mode, symlink, directory).

    `parents` are ordered root-to-leaf tuples of (uid, mode, is_directory,
    is_symlink). The operation directory is the final parent and must be 0700;
    every parent must be a real directory, non-symlink, owned by root or the
    remote user, and not group/world writable.
    """
    if (file_uid != expected_uid or file_mode != 0o600 or file_nlink != 1 or
            not file_regular or file_symlink or not parents):
        return False
    for index, (uid, mode, is_dir, is_link) in enumerate(parents):
        if (not is_dir or is_link or uid not in {0, expected_uid} or mode & 0o022):
            return False
        if index == len(parents) - 1 and (uid != expected_uid or mode != 0o700):
            return False
    return True


def receipt_path_identity_stable(*, parent_before: tuple[int, int],
                                parent_after: tuple[int, int],
                                file_before: tuple[int, int, int, int, int],
                                file_after: tuple[int, int, int, int, int]) -> bool:
    """Require stable held parent and receipt inode/content metadata on read."""
    values = (parent_before, parent_after, file_before, file_after)
    return (all(isinstance(pair, tuple) and len(pair) in (2, 5) and
                all(type(item) is int and item >= 0 for item in pair) for pair in values) and
            parent_before == parent_after and file_before == file_after and
            parent_before[1] != 0 and file_before[1] != 0)
