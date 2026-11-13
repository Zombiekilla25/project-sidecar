"""Narrow one-shot local CLI for FK0957 topology discovery.

The command accepts only signed descriptor evidence and a local evidence
destination. Physical selection and both fixed scans remain internal to the
reviewed transport module. This module has no remote command or scan options.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Any, Sequence

import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as orchestrator
import phk2_fk0957_topology_transport as transport

MAX_DESCRIPTOR_BYTES = 1024 * 1024
_ENVELOPE_KEYS = frozenset({
    "status", "phase", "code", "evidence_path", "signature_verified",
    "return_code", "target_candidates", "device_opened", "scan_a_started",
    "scan_a_tck_emitted", "scan_b_started", "scan_b_tck_emitted",
    "transport_closed", "permit_consumed", "operation_state", "close_from_state",
})
_PHASE_CODES = {
    "PRELIVE_VALIDATION": {"TRANSACTION_PIN_MISMATCH"},
    "PERMIT_VALIDATION": {"PERMIT_INVALID", "DESCRIPTOR_STALE"},
    "LIBRARY_PROVENANCE": {"LIBRARY_PIN_MISMATCH"},
    "FTDI_CONTEXT_CREATE": {"FTDI_CONTEXT_FAILED"},
    "REMOTE_BOOTSTRAP": {"REMOTE_BOOTSTRAP_FAILED"},
    "DEVICE_ENUMERATION": {"ENUMERATION_FAILED"},
    "DEVICE_SELECTION": {"CANDIDATE_IDENTITY_MISMATCH", "NO_TARGET_CANDIDATE",
                          "MULTIPLE_TARGET_CANDIDATES"},
    "DEVICE_OPEN": {"DEVICE_OPEN_FAILED"},
    "MPSSE_INIT": {"MPSSE_INIT_FAILED"},
    "SCAN_A_WRITE": {"SCAN_A_WRITE_FAILED"},
    "SCAN_A_READ": {"SCAN_A_READ_FAILED"},
    "SCAN_B_WRITE": {"SCAN_B_WRITE_FAILED"},
    "SCAN_B_READ": {"SCAN_B_READ_FAILED"},
    "TRANSPORT_CLOSE": {"TRANSPORT_CLOSE_FAILED"},
    "LOCAL_VALIDATION": {"LOCAL_VALIDATION_FAILED"},
    "LOCAL_SIGNING": {"LOCAL_SIGNING_FAILED"},
    "INTERNAL_REFUSAL": {"INTERNAL_REFUSAL"},
}


def _read_descriptor(path: Path) -> bytes:
    parent_fd, name = orchestrator._open_path_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_size < 1 or info.st_size > MAX_DESCRIPTOR_BYTES):
                raise ValueError("descriptor evidence file rejected")
            chunks = bytearray()
            while len(chunks) <= MAX_DESCRIPTOR_BYTES:
                block = os.read(fd, min(65536, MAX_DESCRIPTOR_BYTES + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if not chunks or len(chunks) > MAX_DESCRIPTOR_BYTES:
                raise ValueError("descriptor evidence size rejected")
            after = os.fstat(fd)
            if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise ValueError("descriptor evidence changed while reading")
            return bytes(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _fallback_refusal(phase: str, code: str) -> bytes:
    trace = transport._AttemptTrace()
    trace.phase = phase
    trace.permit_consumed = 0
    return trace.refuse(code=code, phase=phase).canonical_envelope()


def _bounded_envelope(value: Any) -> bool:
    if (not isinstance(value, dict) or set(value) != _ENVELOPE_KEYS or
            value.get("status") != "REFUSED" or
            value.get("phase") not in transport.REFUSAL_PHASES or
            value.get("code") not in transport.REFUSAL_CODES or
            value.get("code") not in _PHASE_CODES.get(value.get("phase"), set()) or
            value.get("evidence_path") != "none" or
            value.get("signature_verified") is not False):
        return False
    rc = value.get("return_code")
    if rc is not None and (type(rc) is not int or not -255 <= rc <= 255):
        return False
    candidates = value.get("target_candidates")
    if candidates != "unknown" and (type(candidates) is not int or not 0 <= candidates <= 256):
        return False
    opened = value.get("device_opened")
    consumed = value.get("permit_consumed")
    if ((opened != "unknown" and (type(opened) is not int or opened not in (0, 1))) or
            (consumed != "unknown" and (type(consumed) is not int or consumed not in (0, 1)))):
        return False
    for key in ("scan_a_started", "scan_b_started", "transport_closed"):
        if type(value.get(key)) is not int or value[key] not in (0, 1):
            return False
    for key, limit in (("scan_a_tck_emitted", 591), ("scan_b_tck_emitted", 586)):
        item = value.get(key)
        if type(item) is not int or not 0 <= item <= limit:
            return False
    phase = value["phase"]
    a_started, b_started = value["scan_a_started"], value["scan_b_started"]
    a_tcks, b_tcks = value["scan_a_tck_emitted"], value["scan_b_tck_emitted"]
    closed = value["transport_closed"]
    state = value.get("operation_state")
    close_from = value.get("close_from_state")
    ranks = transport._OPERATION_STATE_RANK
    if state not in ranks:
        return False
    if state in {"TRANSPORT_CLOSING", "TRANSPORT_CLOSED"}:
        if close_from not in ranks or ranks[close_from] >= ranks["TRANSPORT_CLOSING"]:
            return False
        if closed != (1 if state == "TRANSPORT_CLOSED" else 0):
            return False
        progress_state = close_from
    elif state in {"LOCAL_VALIDATED", "SIGNED_STAGED"}:
        if close_from != "SCAN_B_COMPLETE" or closed != 1:
            return False
        progress_state = state
    elif close_from is not None or closed != 0:
        return False
    else:
        progress_state = state
    if state in {"LOCAL_VALIDATED", "SIGNED_STAGED"} and close_from != "SCAN_B_COMPLETE":
        return False
    if ranks[progress_state] >= ranks["PERMIT_VALIDATED"] and consumed != 1:
        return False
    if ranks[progress_state] >= ranks["DEVICE_SELECTED"]:
        if candidates != 1:
            return False
    elif candidates != "unknown" and (type(candidates) is not int or candidates < 0):
        return False
    if phase == "DEVICE_SELECTION":
        if (type(candidates) is not int or
                value["code"] == "NO_TARGET_CANDIDATE" and candidates != 0 or
                value["code"] == "MULTIPLE_TARGET_CANDIDATES" and candidates < 2 or
                value["code"] == "CANDIDATE_IDENTITY_MISMATCH" and candidates != 1):
            return False

    rank = ranks[progress_state]
    has_open = rank >= ranks["DEVICE_OPENED"]
    has_a = rank >= ranks["SCAN_A_ACTIVE"]
    a_complete = rank >= ranks["SCAN_A_COMPLETE"]
    has_b = rank >= ranks["SCAN_B_ACTIVE"]
    b_complete = rank >= ranks["SCAN_B_COMPLETE"]
    if opened != int(has_open) or a_started != int(has_a) or b_started != int(has_b):
        return False
    if (not has_a and a_tcks != 0 or a_complete and a_tcks != 591 or
            has_a and not a_complete and a_tcks > 591 or
            not has_b and b_tcks != 0 or b_complete and b_tcks != 586 or
            has_b and not b_complete and b_tcks > 586):
        return False

    # Validate each report against the actual monotonic point at which its
    # operation can fail.  The coarse operation state records completed
    # transitions; phase plus TCK counters records an in-flight write/read.
    no_scans = not any((a_started, a_tcks, b_started, b_tcks))
    no_candidates = candidates == 0
    closing = state in {"TRANSPORT_CLOSING", "TRANSPORT_CLOSED"}
    if closing:
        closable_states = {
            "DEVICE_SELECTED", "DEVICE_OPENED", "MPSSE_READY", "SCAN_A_ACTIVE",
            "SCAN_A_NAV_WRITE", "SCAN_A_BULK_WRITE", "SCAN_A_BULK_READ",
            "SCAN_A_FINAL_WRITE", "SCAN_A_FINAL_READ", "SCAN_A_EXIT_WRITE",
            "SCAN_A_COMPLETE", "SCAN_B_ACTIVE", "SCAN_B_NAV_WRITE",
            "SCAN_B_BULK_WRITE", "SCAN_B_BULK_READ", "SCAN_B_FINAL_WRITE",
            "SCAN_B_FINAL_READ", "SCAN_B_EXIT_WRITE", "SCAN_B_COMPLETE",
        }
        if close_from not in closable_states:
            return False
        prior_rank = ranks[close_from]
        expected_open = int(prior_rank >= ranks["DEVICE_OPENED"])
        expected_a_started = int(prior_rank >= ranks["SCAN_A_ACTIVE"])
        expected_b_started = int(prior_rank >= ranks["SCAN_B_ACTIVE"])
        if (consumed != 1 or candidates != 1 or opened != expected_open or
                a_started != expected_a_started or b_started != expected_b_started):
            return False
        a_ranges = {
            "SCAN_A_ACTIVE": (0, 0), "SCAN_A_NAV_WRITE": (0, 9),
            "SCAN_A_BULK_WRITE": (9, 585), "SCAN_A_BULK_READ": (585, 585),
            "SCAN_A_FINAL_WRITE": (585, 586), "SCAN_A_FINAL_READ": (586, 586),
            "SCAN_A_EXIT_WRITE": (586, 591), "SCAN_A_COMPLETE": (591, 591),
        }
        b_ranges = {
            "SCAN_B_ACTIVE": (0, 0), "SCAN_B_NAV_WRITE": (0, 4),
            "SCAN_B_BULK_WRITE": (4, 580), "SCAN_B_BULK_READ": (580, 580),
            "SCAN_B_FINAL_WRITE": (580, 581), "SCAN_B_FINAL_READ": (581, 581),
            "SCAN_B_EXIT_WRITE": (581, 586), "SCAN_B_COMPLETE": (586, 586),
        }
        if close_from in a_ranges:
            low, high = a_ranges[close_from]
            if not low <= a_tcks <= high or b_tcks != 0:
                return False
        elif prior_rank < ranks["SCAN_A_ACTIVE"]:
            if a_tcks != 0 or b_tcks != 0:
                return False
        elif a_tcks != 591:
            return False
        if close_from in b_ranges:
            low, high = b_ranges[close_from]
            if not low <= b_tcks <= high:
                return False
        elif b_tcks != 0:
            return False
    phase_state = progress_state
    close_flag_allowed = closing or closed == 0
    if phase in {"PRELIVE_VALIDATION", "PERMIT_VALIDATION"}:
        allowed_states = ({"PRELIVE": 0, "PERMIT_VALIDATED": 1}
                          if phase == "PRELIVE_VALIDATION" else {"PRELIVE": 0})
        if (phase_state not in allowed_states or consumed != allowed_states.get(phase_state) or
                not no_candidates or
                opened or not no_scans or not close_flag_allowed):
            return False
    elif phase == "LIBRARY_PROVENANCE":
        if (phase_state not in {"PERMIT_VALIDATED", "RUNTIME_READY"} or
                consumed != 1 or not no_candidates or
                opened or not no_scans or not close_flag_allowed):
            return False
    elif phase in {"FTDI_CONTEXT_CREATE", "REMOTE_BOOTSTRAP"}:
        if (phase_state != "RUNTIME_READY" or consumed != 1 or not no_candidates or
                opened or not no_scans or not close_flag_allowed):
            return False
    elif phase in {"DEVICE_ENUMERATION", "DEVICE_SELECTION"}:
        if (phase_state != "ENUMERATING" or consumed != 1 or opened or not no_scans or
                not close_flag_allowed):
            return False
    elif phase == "DEVICE_OPEN":
        if (phase_state != "DEVICE_SELECTED" or consumed != 1 or candidates != 1 or
                opened != 0 or not no_scans or not close_flag_allowed):
            return False
    elif phase == "MPSSE_INIT":
        if (phase_state != "DEVICE_OPENED" or consumed != 1 or candidates != 1 or
                opened != 1 or not no_scans or not close_flag_allowed):
            return False
    elif phase == "SCAN_A_WRITE":
        write_ranges = {
            "SCAN_A_NAV_WRITE": (0, 9), "SCAN_A_BULK_WRITE": (9, 585),
            "SCAN_A_FINAL_WRITE": (585, 586), "SCAN_A_EXIT_WRITE": (586, 591),
        }
        if (phase_state not in {"SCAN_A_NAV_WRITE", "SCAN_A_BULK_WRITE",
                                "SCAN_A_FINAL_WRITE", "SCAN_A_EXIT_WRITE"} or
                consumed != 1 or candidates != 1 or
                opened != 1 or not a_started or
                not write_ranges.get(phase_state, (1, 0))[0] <= a_tcks <=
                write_ranges.get(phase_state, (1, 0))[1] or
                b_started or b_tcks != 0 or not close_flag_allowed):
            return False
    elif phase == "SCAN_A_READ":
        expected_read = {"SCAN_A_BULK_READ": 585, "SCAN_A_FINAL_READ": 586}
        if (phase_state not in expected_read or consumed != 1 or candidates != 1 or
                opened != 1 or not a_started or a_tcks != expected_read.get(phase_state) or
                b_started or b_tcks != 0 or not close_flag_allowed):
            return False
    elif phase == "SCAN_B_WRITE":
        write_ranges = {
            "SCAN_B_NAV_WRITE": (0, 4), "SCAN_B_BULK_WRITE": (4, 580),
            "SCAN_B_FINAL_WRITE": (580, 581), "SCAN_B_EXIT_WRITE": (581, 586),
        }
        if (phase_state not in {"SCAN_B_NAV_WRITE", "SCAN_B_BULK_WRITE",
                                "SCAN_B_FINAL_WRITE", "SCAN_B_EXIT_WRITE"} or
                consumed != 1 or candidates != 1 or
                opened != 1 or not a_started or a_tcks != 591 or not b_started or
                not write_ranges.get(phase_state, (1, 0))[0] <= b_tcks <=
                write_ranges.get(phase_state, (1, 0))[1] or not close_flag_allowed):
            return False
    elif phase == "SCAN_B_READ":
        expected_read = {"SCAN_B_BULK_READ": 580, "SCAN_B_FINAL_READ": 581}
        if (phase_state not in expected_read or consumed != 1 or candidates != 1 or
                opened != 1 or not a_started or a_tcks != 591 or not b_started or
                b_tcks != expected_read.get(phase_state) or not close_flag_allowed):
            return False
    elif phase == "TRANSPORT_CLOSE":
        if (not closing or
                close_from not in {"DEVICE_SELECTED", "DEVICE_OPENED", "MPSSE_READY",
                                   "SCAN_A_ACTIVE", "SCAN_A_NAV_WRITE", "SCAN_A_BULK_WRITE",
                                   "SCAN_A_BULK_READ", "SCAN_A_FINAL_WRITE", "SCAN_A_FINAL_READ",
                                   "SCAN_A_EXIT_WRITE", "SCAN_A_COMPLETE", "SCAN_B_ACTIVE",
                                   "SCAN_B_NAV_WRITE", "SCAN_B_BULK_WRITE", "SCAN_B_BULK_READ",
                                   "SCAN_B_FINAL_WRITE", "SCAN_B_FINAL_READ", "SCAN_B_EXIT_WRITE",
                                   "SCAN_B_COMPLETE"}):
            return False
    elif phase == "LOCAL_VALIDATION":
        if (state != "TRANSPORT_CLOSED" or close_from != "SCAN_B_COMPLETE" or
                consumed != 1 or candidates != 1 or opened != 1 or
                not a_started or a_tcks != 591 or not b_started or b_tcks != 586 or
                closed != 1):
            return False
    elif phase == "LOCAL_SIGNING":
        if (state != "LOCAL_VALIDATED" or close_from != "SCAN_B_COMPLETE" or
                consumed != 1 or candidates != 1 or opened != 1 or
                not a_started or a_tcks != 591 or not b_started or b_tcks != 586 or
                closed != 1):
            return False
    elif phase == "INTERNAL_REFUSAL":
        if (state != "PRELIVE" or consumed != 0 or not no_candidates or opened or
                not no_scans or closed):
            return False
    return True


def _safe_refusal(exc: BaseException) -> bytes:
    """Forward only a strictly validated canonical envelope; suppress all text."""
    if isinstance(exc, transport.Refusal):
        try:
            raw = exc.canonical_envelope()
            value = json.loads(raw)
            if not _bounded_envelope(value):
                raise ValueError("invalid refusal schema")
            return orchestrator.canonical(value)
        except Exception:
            pass
    return _fallback_refusal("INTERNAL_REFUSAL", "INTERNAL_REFUSAL")


def _verify_signed_record(document: Any) -> dict[str, Any]:
    if (not isinstance(document, dict) or
            set(document) != {"payload", "payload_sha256", "signature_algorithm",
                              "signature_hex", "signer_fingerprint"} or
            document.get("signature_algorithm") != "Ed25519" or
            document.get("signer_fingerprint") != identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256):
        raise ValueError("signed record envelope rejected")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("signed record payload rejected")
    payload_bytes = orchestrator.canonical(payload)
    if hashlib.sha256(payload_bytes).hexdigest() != document.get("payload_sha256"):
        raise ValueError("signed record digest rejected")
    signature_hex = document.get("signature_hex")
    if not isinstance(signature_hex, str) or len(signature_hex) != 128:
        raise ValueError("signed record signature encoding rejected")
    try:
        signature = bytes.fromhex(signature_hex)
        identity_gate._trusted_signer().verify(signature, payload_bytes)
    except Exception as exc:
        raise ValueError("signed record signature rejected") from exc
    required = {
        "topology_discovery_only": True,
        "idcode_qualification_pass": False,
        "fpga_dna_observed": False,
        "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False,
        "card_id": "FK0957",
        "adapter_serial": "153300000957A",
        "usb_descriptor_serial": "153300000957",
        "scan_a_tck_count": 591,
        "scan_b_tck_count": 586,
        "total_tck_count": 1177,
        "write_count": 0,
        "reset_count": 0,
        "program_count": 0,
    }
    if any(payload.get(key) != value for key, value in required.items()):
        raise ValueError("signed record policy fields rejected")
    return payload


def _success_summary(payload: dict[str, Any], evidence_path: Path,
                     evidence_sha256: str) -> dict[str, Any]:
    try:
        raw_a = bytes.fromhex(payload["scan_a_raw_tdo_hex"])
        raw_b = bytes.fromhex(payload["scan_b_raw_tdo_hex"])
        scan_a_tx = payload["scan_a_transaction_sha256"]
        scan_b_tx = payload["scan_b_transaction_sha256"]
        for digest in (scan_a_tx, scan_b_tx):
            if (not isinstance(digest, str) or len(digest) != 64 or
                    any(ch not in "0123456789abcdef" for ch in digest)):
                raise ValueError
    except Exception as exc:
        raise ValueError("signed record observation fields rejected") from exc
    aggregate = payload.get("aggregate_dr_length")
    taps = payload.get("observed_taps_tdo_to_tdi")
    if type(aggregate) is not int or aggregate < 1 or not isinstance(taps, list) or not taps:
        raise ValueError("signed record does not contain a completed topology parse")
    return {
        "status": "SIGNED",
        "target": "FK0957",
        "scan_a_tck_count": 591,
        "scan_b_tck_count": 586,
        "total_tck_count": 1177,
        "scan_a_transaction_sha256": scan_a_tx,
        "scan_b_transaction_sha256": scan_b_tx,
        "scan_a_raw_tdo_bytes": len(raw_a),
        "scan_a_raw_tdo_sha256": hashlib.sha256(raw_a).hexdigest(),
        "scan_b_raw_tdo_bytes": len(raw_b),
        "scan_b_raw_tdo_sha256": hashlib.sha256(raw_b).hexdigest(),
        "parse_status": "PASS",
        "evidence_path": str(evidence_path),
        "evidence_sha256": evidence_sha256,
        "signature_verified": True,
        "write_count": 0,
        "reset_count": 0,
        "program_count": 0,
        "jtag_operation_count": 1,
    }


def _publish_evidence_atomic(path: Path, data: bytes,
                             publish_state: list[str] | None = None) -> None:
    """Publish validated evidence from a private, mode-0600 staging file."""
    path = Path(path)
    parent_fd, output_name = orchestrator._open_path_parent(path)
    temp_dir = f".fk0957-evidence-{secrets.token_hex(16)}"
    temp_name = "record.tmp"
    temp_dir_created = False
    temp_file_created = False
    temp_fd = None
    published = False
    try:
        try:
            os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("evidence output already exists")
        os.mkdir(temp_dir, 0o700, dir_fd=parent_fd)
        temp_dir_created = True
        temp_fd = os.open(temp_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                          getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            dir_info = os.fstat(temp_fd)
            if (not stat.S_ISDIR(dir_info.st_mode) or stat.S_IMODE(dir_info.st_mode) != 0o700 or
                    dir_info.st_uid != os.geteuid()):
                raise ValueError("private evidence staging directory rejected")
            file_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                              getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=temp_fd)
            temp_file_created = True
            file_info = None
            try:
                file_info = os.fstat(file_fd)
                if (not stat.S_ISREG(file_info.st_mode) or file_info.st_nlink != 1 or
                        stat.S_IMODE(file_info.st_mode) != 0o600):
                    raise ValueError("private evidence staging file rejected")
                with os.fdopen(file_fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                current = os.stat(temp_name, dir_fd=temp_fd, follow_symlinks=False)
                if ((current.st_dev, current.st_ino) != (file_info.st_dev, file_info.st_ino) or
                        not stat.S_ISREG(current.st_mode) or current.st_nlink != 1):
                    raise ValueError("evidence staging file changed")
                try:
                    os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("evidence output changed before publish")
                try:
                    # linkat-style publication is atomic and refuses an
                    # existing destination. os.replace would overwrite a file
                    # created after the preceding absence check.
                    os.link(temp_name, output_name, src_dir_fd=temp_fd,
                            dst_dir_fd=parent_fd, follow_symlinks=False)
                except BaseException:
                    # A signal or wrapper error can be observed after link()
                    # succeeded. Resolve that ambiguous result by the staged
                    # inode; never report REFUSED for our published record.
                    try:
                        final_info = os.stat(output_name, dir_fd=parent_fd,
                                             follow_symlinks=False)
                    except OSError:
                        raise
                    if ((final_info.st_dev, final_info.st_ino) !=
                            (file_info.st_dev, file_info.st_ino) or
                            not stat.S_ISREG(final_info.st_mode)):
                        raise
                published = True
                if publish_state is not None:
                    publish_state[0] = "EVIDENCE_PUBLISHED"
                try:
                    os.unlink(temp_name, dir_fd=temp_fd)
                    temp_file_created = False
                except OSError:
                    # Publication is already committed. Cleanup is retried by
                    # the enclosing finally block and cannot downgrade success.
                    pass
            except BaseException:
                # Cover interruption after link returned but before the
                # commit state assignment. The destination inode is the
                # receipt for the irreversible publish point.
                if not published and file_info is not None:
                    try:
                        final_info = os.stat(output_name, dir_fd=parent_fd,
                                             follow_symlinks=False)
                    except OSError:
                        final_info = None
                    if (final_info is not None and
                            (final_info.st_dev, final_info.st_ino) ==
                            (file_info.st_dev, file_info.st_ino) and
                            stat.S_ISREG(final_info.st_mode)):
                        temp_file_created = False
                        published = True
                        if publish_state is not None:
                            publish_state[0] = "EVIDENCE_PUBLISHED"
                try:
                    os.close(file_fd)
                except OSError:
                    pass
                raise
        finally:
            if temp_file_created:
                try:
                    os.unlink(temp_name, dir_fd=temp_fd)
                except OSError:
                    pass
                temp_file_created = False
            try:
                os.close(temp_fd)
            except OSError:
                # Once the atomic rename succeeds, the validated operation is
                # committed. A close error cannot turn it into a refusal after
                # publishing the accepted record.
                if not published:
                    raise
    finally:
        if temp_dir_created:
            try:
                os.rmdir(temp_dir, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            if not published:
                raise


def run_once(descriptor_path: Path, output_path: Path) -> tuple[bytes, int]:
    try:
        descriptor = _read_descriptor(descriptor_path)
        descriptor_sha256 = hashlib.sha256(descriptor).hexdigest()
    except Exception:
        return _fallback_refusal("PRELIVE_VALIDATION", "INTERNAL_REFUSAL") + b"\n", 2

    try:
        signed = transport.perform_fk0957_topology_discovery_once(
            descriptor, descriptor_sha256)
    except BaseException as exc:
        return _safe_refusal(exc) + b"\n", 2

    try:
        payload = _verify_signed_record(signed)
        evidence_bytes = orchestrator.canonical(signed) + b"\n"
        summary = _success_summary(payload, output_path, hashlib.sha256(evidence_bytes).hexdigest())
        summary_bytes = orchestrator.canonical(summary) + b"\n"
        publish_state = ["SIGNED_STAGED"]
        _publish_evidence_atomic(output_path, evidence_bytes, publish_state)
        return summary_bytes, 0
    except BaseException:
        if "publish_state" in locals() and publish_state[0] == "EVIDENCE_PUBLISHED":
            return (b"FK0957_POST_SUCCESS_REPORTING_FAULT=YES EVIDENCE_PUBLISHED=YES\n", 3)
        return _fallback_refusal("INTERNAL_REFUSAL", "INTERNAL_REFUSAL") + b"\n", 2


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # noqa: D401 - suppress argparse internals
        raise ValueError("invalid operator arguments")


def _emit_report(output: bytes, status: int, *, published: bool) -> int:
    try:
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return status
    except BaseException:
        if published:
            try:
                sys.stderr.buffer.write(
                    b"FK0957_POST_SUCCESS_REPORTING_FAULT=YES EVIDENCE_PUBLISHED=YES\n")
                sys.stderr.buffer.flush()
            except BaseException:
                pass
            return 3
        return status


def main(argv: Sequence[str] | None = None) -> int:
    parser = _ArgumentParser(prog="fk0957_topology_live_one_shot")
    parser.add_argument("--descriptor-evidence", required=True,
                        help="path to fresh signed FK0957 descriptor evidence")
    parser.add_argument("--output", required=True,
                        help="local path for the signed topology-discovery record")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    except Exception:
        return _emit_report(
            _fallback_refusal("PRELIVE_VALIDATION", "INTERNAL_REFUSAL") + b"\n",
            2, published=False)
    output, status = run_once(Path(args.descriptor_evidence), Path(args.output))
    return _emit_report(output, status, published=status in (0, 3))


if __name__ == "__main__":
    raise SystemExit(main())
