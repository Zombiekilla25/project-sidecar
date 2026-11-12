#!/usr/bin/env python3
"""Fail-closed PHK2 physical-close evidence parsers and pre-transport gate.

This module has no network, USB, XVC, JTAG, or FPGA programming backend.
"""
from __future__ import annotations

import base64
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import inspect
import io
import json
import math
import os
from pathlib import Path
import re
import statistics
import subprocess
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from physical_tck_preflight import Refusal, PINNED_REVIEWED_BRIDGE_SHA256, PINNED_REVIEWED_BUILD_ID

V51_SOURCE_COMMIT = "5f65f0ec8900ecaae3c498223bef0efb2542c047"
V51_SOURCE_TREE_HASH = "dcc879775d80e07ab41bc9af955a29a3fd8ba6f9"
V51_EVIDENCE_COMMIT = "e89810b832ee7c1909bd92c449f33abb26b6882e"
V51_EVIDENCE_TREE_HASH = "ee77ec6fc70042bdfd2c2d0e9175118c1cad92fd"
V51_ROUTED_DCP_SHA256 = "0bd52785662a3c38f68667f85c75acdef33c109502794610669ab8e1cf61e9af"
V51_RECORD_COMMIT = "6ad11b72fc62a452195245984b69f236d4d3b315"
V51_QUALIFICATION_RECORD_PATH = "results/phk2-v5_1-independent-qualification.json"
V51_QUALIFICATION_RECORD_SHA256 = "25b875c707aaa1ee43ec1da064b3fec0b2297aed87be4aacb2c7c2260b26c90e"
MATRIX_COMMIT = "6ad11b72fc62a452195245984b69f236d4d3b315"
MATRIX_PATH = "results/phk2-v3-post-route-intake-20261110/qualification.json"
MATRIX_SHA256 = "286209989a3984f9d20243df645621e29cbbeaa3b8508f4a9ab1029afefedd94"
AUDIT_COMMIT = "ce29de787c5d7c5fa4b9772e671cc9627ac1bbb8"
AUDIT_PATH = "results/phk2-closure-runner-independent-audit.json"
AUDIT_SHA256 = "5fae107b0872beb2aaf3c5093e007abc97db19618cc02a8432a8f21d6e06ac91"
ROLLBACK_COMMIT = "14fabd8f3d100c421a072765815b5360237046d7"
ROLLBACK_PATH = "release/PHK2_V5_1_RELEASE/rollback/ROLLBACK_IMAGE_MANIFEST.json"
ROLLBACK_SHA256 = "1b7088f48baed2a10c50c2b38a7b926af505722c614e236b13811a89a2972fdb"
# A trust store must be provisioned and its hash pinned by the authorized
# deployment owner. No signer or trust-root hash is available in this lane.
PINNED_TRUST_STORE_SHA256: str | None = None

CASE_A_ID = "40"
CASE_A_NAME = "host_TCK_frequency_contract"
CASE_B_ID = "33"
CASE_B_NAME = "clock_interaction_no_unsafe"
CASE_IDS = (CASE_A_ID, CASE_B_ID)
EXPECTED_TARGET_PART = "xcvu33p-fsvh2104-2-e"

V51_BASE = "results/phk2-v5_1-common-reset-20261110/revision1"
V51_MANIFEST_PATH = f"{V51_BASE}/V5_1_EVIDENCE_MANIFEST.json"
V51_SUMS_PATH = f"{V51_BASE}/SHA256SUMS"
V51_CLOCKS_PATH = f"{V51_BASE}/synthesis/clocks.rpt"
V51_TIMING_PATH = f"{V51_BASE}/route/timing_summary.rpt"

def _git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Refusal(f"immutable Git evidence unavailable: {' '.join(args)}") from exc


def _blob(repo: Path, commit: str, path: str) -> bytes:
    return _git(repo, "show", f"{commit}:{path}")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def verify_pretransport_journal(raw: bytes) -> dict[str, Any]:
    """Validate a durable append-only journal that begins before any open."""
    try:
        rows = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal("pre-transport journal is malformed") from exc
    if not rows:
        raise Refusal("pre-transport journal is empty")
    previous = "0" * 64
    events = []
    for seq, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("sequence") != seq or row.get("previous_entry_sha256") != previous:
            raise Refusal("pre-transport journal sequence/hash chain is discontinuous")
        entry_hash = row.get("entry_sha256")
        body = {k: v for k, v in row.items() if k != "entry_sha256"}
        if not isinstance(entry_hash, str) or _sha(_canonical(body)) != entry_hash:
            raise Refusal("pre-transport journal entry hash mismatch")
        event = row.get("event")
        if not isinstance(event, str) or not event:
            raise Refusal("pre-transport journal event malformed")
        events.append(event)
        previous = entry_hash
    if events[0] != "PRE_TRANSPORT":
        raise Refusal("journal does not begin with PRE_TRANSPORT")
    required = ("TRANSPORT_OPEN_REQUESTED", "TRANSPORT_OPENED", "CASE_A_CAPTURED",
                "CASE_B_CAPTURED", "CASE_A_RESULT", "CASE_B_RESULT", "FINAL_IDLE_CLOSE")
    cursor = 1
    for event in required:
        try:
            cursor = events.index(event, cursor) + 1
        except ValueError as exc:
            raise Refusal(f"journal incomplete; missing ordered event {event}") from exc
    return {"event_count": len(events), "events": events,
            "initial_entry_sha256": rows[0]["entry_sha256"], "journal_sha256": _sha(raw)}


def verify_journal_chain(raw: bytes) -> dict[str, Any]:
    try:
        rows = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal("evidence journal is malformed") from exc
    if not rows:
        raise Refusal("evidence journal is empty")
    previous = "0" * 64
    for seq, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("sequence") != seq or row.get("previous_entry_sha256") != previous:
            raise Refusal("evidence journal sequence/hash chain is discontinuous")
        entry_hash = row.get("entry_sha256")
        body = {k: v for k, v in row.items() if k != "entry_sha256"}
        if not isinstance(entry_hash, str) or _sha(_canonical(body)) != entry_hash:
            raise Refusal("evidence journal entry hash mismatch")
        previous = entry_hash
    if rows[0].get("event") != "PRE_TRANSPORT":
        raise Refusal("journal was not initialized before transport")
    return {"entry_count": len(rows), "first_entry_sha256": rows[0]["entry_sha256"],
            "last_entry_sha256": previous, "journal_sha256": _sha(raw)}


def _json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise Refusal(f"{label} must be a JSON object")
    return value


def _utc(value: Any, label: str, *, max_age_s: int = 300, now: datetime | None = None) -> datetime:
    if not isinstance(value, str):
        raise Refusal(f"{label} timestamp missing")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refusal(f"{label} timestamp invalid") from exc
    current = now or datetime.now(timezone.utc)
    if result.tzinfo is None or result > current or (current - result).total_seconds() > max_age_s:
        raise Refusal(f"{label} timestamp stale or future-dated")
    return result


@dataclass(frozen=True)
class V51Binding:
    source_commit: str
    source_tree_hash: str
    evidence_commit: str
    evidence_tree_hash: str
    routed_dcp_sha256: str
    qualification_record_sha256: str
    matrix_sha256: str
    case_a: dict[str, Any]
    case_b: dict[str, Any]
    tck_envelope: dict[str, Any]
    tck_envelope_sha256: str
    qualified_physical_envelope_available: bool
    expected_card_id: str
    expected_adapter_id: str
    expected_idcode: str
    expected_fpga_dna: str
    expected_target_part: str


def verify_immutable_v51(repo: str | Path) -> V51Binding:
    """Verify v5.1 package and the exact immutable 38/40 case rows."""
    root = Path(repo).resolve(strict=True)
    for commit, tree in ((V51_SOURCE_COMMIT, V51_SOURCE_TREE_HASH),
                         (V51_EVIDENCE_COMMIT, V51_EVIDENCE_TREE_HASH)):
        if _git(root, "rev-parse", f"{commit}^{{tree}}").decode().strip() != tree:
            raise Refusal("v5.1 source/evidence tree identity mismatch")
    manifest = _json(_blob(root, V51_EVIDENCE_COMMIT, V51_MANIFEST_PATH), "v5.1 evidence manifest")
    if manifest["source"]["commit"] != V51_SOURCE_COMMIT or manifest["source"]["tree_hash"] != V51_SOURCE_TREE_HASH:
        raise Refusal("v5.1 evidence manifest source identity mismatch")
    if manifest["checkpoints"]["ROUTED_DCP"]["sha256"] != V51_ROUTED_DCP_SHA256:
        raise Refusal("v5.1 routed DCP identity mismatch")
    sums: dict[str, str] = {}
    for line in _blob(root, V51_EVIDENCE_COMMIT, V51_SUMS_PATH).decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match.group(2) in sums:
            raise Refusal("v5.1 SHA256SUMS malformed")
        sums[match.group(2)] = match.group(1)
    if len(sums) != 124:
        raise Refusal("v5.1 SHA256SUMS entry count mismatch")
    for rel, digest in sums.items():
        if _sha(_blob(root, V51_EVIDENCE_COMMIT, f"{V51_BASE}/{rel}")) != digest:
            raise Refusal(f"v5.1 evidence checksum mismatch: {rel}")
    record_bytes = _blob(root, V51_RECORD_COMMIT, V51_QUALIFICATION_RECORD_PATH)
    matrix_bytes = _blob(root, MATRIX_COMMIT, MATRIX_PATH)
    audit_bytes = _blob(root, AUDIT_COMMIT, AUDIT_PATH)
    if _sha(record_bytes) != V51_QUALIFICATION_RECORD_SHA256 or _sha(matrix_bytes) != MATRIX_SHA256 or _sha(audit_bytes) != AUDIT_SHA256:
        raise Refusal("v5.1 qualification record, matrix, or case audit hash mismatch")
    record, matrix, audit = (_json(record_bytes, "v5.1 qualification record"),
                             _json(matrix_bytes, "40-case matrix"), _json(audit_bytes, "immutable case audit"))
    rollback_bytes = _blob(root, ROLLBACK_COMMIT, ROLLBACK_PATH)
    if _sha(rollback_bytes) != ROLLBACK_SHA256:
        raise Refusal("immutable rollback manifest hash mismatch")
    rollback = _json(rollback_bytes, "rollback manifest")
    if rollback.get("rollback_qualified") is not True:
        raise Refusal("immutable rollback manifest is not qualified")
    card_id = rollback.get("fk0957_program_history", {}).get("card_id")
    adapter_block = rollback.get("fk0957_program_history", {}).get("post_program_identity", {})
    adapter_id = adapter_block.get("jtag_serial") or adapter_block.get("usb_serial")
    idcode = adapter_block.get("idcode")
    dna = adapter_block.get("dna")
    if (card_id != "153300000957" or adapter_id != "153300000957A" or
            not isinstance(idcode, str) or not re.fullmatch(r"[0-9a-fA-F]{8}", idcode) or
            not isinstance(dna, str) or not re.fullmatch(r"[0-9a-fA-F]{24}", dna)):
        raise Refusal("immutable canary card/adapter/IDCODE identity is incomplete")
    q = record["qualification"]
    if (q["tck_independent_cases"], q["tck_independent_pass"], q["tck_independent_fail"],
        q["qualification_cases"], q["qualification_cases_pass"], q["qualification_cases_fail"],
        q["qualification_cases_blocked_only_by_tck"]) != (38, 38, 0, 40, 38, 0, 2):
        raise Refusal("immutable v5.1 record is not the expected 38/40 result")
    if record["v5_1_evidence"]["commit"] != V51_EVIDENCE_COMMIT or record["v5_1_source"]["commit"] != V51_SOURCE_COMMIT:
        raise Refusal("independent qualification record points to another v5.1 design")
    cases = matrix["qualification_cases"]
    if len(cases) != 40 or cases[39] != {
        "case": CASE_A_NAME, "detail": "Physical host maximum TCK frequency/duty contract not qualified",
        "domain": "TCK_DEPENDENT", "result": "UNRESOLVED"} or cases[32] != {
        "case": CASE_B_NAME,
        "detail": "bscan_tck       bscan_tck       rise - fall   490.31     0.00            0          927           500.00  Partial Common Node  Timed (unsafe)",
        "domain": "TCK_DEPENDENT", "result": "UNRESOLVED"}:
        raise Refusal("case A/B matrix rows do not match pinned ordinal definitions")
    # This preserved v3 intake matrix still records the earlier 36/38 tally;
    # the immutable v5.1 independent record is the authority for the current
    # 38/40 result. The matrix is used only to bind exact case identities.
    if matrix.get("tck_dependent_cases") != 2 or matrix.get("tck_dependent_unresolved") != 2:
        raise Refusal("preserved matrix no longer has exactly two unresolved TCK rows")
    cases_audit = audit["cases"]
    if cases_audit["A"]["ordinal_id"] != 40 or cases_audit["A"]["matrix_name"] != CASE_A_NAME or cases_audit["B"]["ordinal_id"] != 33 or cases_audit["B"]["matrix_name"] != CASE_B_NAME:
        raise Refusal("case audit does not bind both exact matrix rows")

    clocks = _blob(root, V51_EVIDENCE_COMMIT, V51_CLOCKS_PATH).decode(errors="replace")
    timing = _blob(root, V51_EVIDENCE_COMMIT, V51_TIMING_PATH).decode(errors="replace")
    match = re.search(r"^bscan_tck\s+20\.000\s+\{0\.000 10\.000\}", clocks, re.M)
    timing_match = re.search(r"^bscan_tck\s+\{0\.000 10\.000\}\s+20\.000\s+50\.000", timing, re.M)
    if not match or not timing_match:
        raise Refusal("v5.1 routed analysis clock evidence missing/mismatched")
    route_envelope = {
        "schema": "PHK2-V5_1-TCK-ANALYSIS-REFERENCE-v1",
        "source_commit": V51_SOURCE_COMMIT,
        "source_tree_hash": V51_SOURCE_TREE_HASH,
        "routed_dcp_sha256": V51_ROUTED_DCP_SHA256,
        "qualification_record_sha256": V51_QUALIFICATION_RECORD_SHA256,
        "matrix_sha256": MATRIX_SHA256,
        "clock_object": "bscan_tck",
        "analysis_frequency_hz": 50000000,
        "analysis_period_ns": 20.0,
        "analysis_rise_ns": 0.0,
        "analysis_fall_ns": 10.0,
        "physical_tck_contract_qualified": False,
        "physical_waveform_limits": None,
    }
    return V51Binding(V51_SOURCE_COMMIT, V51_SOURCE_TREE_HASH, V51_EVIDENCE_COMMIT,
                      V51_EVIDENCE_TREE_HASH, V51_ROUTED_DCP_SHA256,
                      V51_QUALIFICATION_RECORD_SHA256, MATRIX_SHA256,
                      {"case_id": CASE_A_ID, **cases[39], **cases_audit["A"]},
                      {"case_id": CASE_B_ID, **cases[32], **cases_audit["B"]},
                      route_envelope, _sha(_canonical(route_envelope)), False,
                      card_id, adapter_id, idcode.lower(), dna.lower(), EXPECTED_TARGET_PART)


def validate_case_manifest(manifest: dict[str, Any], binding: V51Binding) -> None:
    """Hard-bind cases, source/matrix/route identities and analysis-envelope hash."""
    if manifest.get("TCK_INDEPENDENT_PASS") != 38 or manifest.get("TCK_INDEPENDENT_FAIL") != 0:
        raise Refusal("closure manifest must bind the v5.1 38/0 independent result")
    identity = manifest.get("v5_1_identity")
    expected = {"source_commit": binding.source_commit, "source_tree_hash": binding.source_tree_hash,
                "routed_dcp_sha256": binding.routed_dcp_sha256,
                "qualification_record_sha256": binding.qualification_record_sha256,
                "matrix_sha256": binding.matrix_sha256,
                "evidence_commit": binding.evidence_commit}
    if identity != expected:
        raise Refusal("manifest is not cryptographically bound to exact v5.1 qualification/route")
    matrix_ref = manifest.get("qualification_matrix")
    if not isinstance(matrix_ref, dict) or matrix_ref.get("sha256") != binding.matrix_sha256 or matrix_ref.get("commit") != MATRIX_COMMIT or matrix_ref.get("path") != MATRIX_PATH:
        raise Refusal("qualification matrix reference is not the immutable 40-case source")
    cases = manifest.get("tck_dependent_cases")
    expected_cases = [
        {"case_id": CASE_A_ID, "case": CASE_A_NAME, "kind": "PHYSICAL_TCK_WAVEFORM",
         "matrix_detail": "Physical host maximum TCK frequency/duty contract not qualified"},
        {"case_id": CASE_B_ID, "case": CASE_B_NAME, "kind": "BSCAN_CLOCK_INTERACTION",
         "matrix_detail": "bscan_tck       bscan_tck       rise - fall   490.31     0.00            0          927           500.00  Partial Common Node  Timed (unsafe)"},
    ]
    if cases != expected_cases:
        raise Refusal("TCK case definitions/IDs/order do not exactly match immutable matrix rows 40 and 33")
    if manifest.get("TCK_ENVELOPE_SHA256") != binding.tck_envelope_sha256 or manifest.get("TCK_ANALYSIS_REFERENCE") != binding.tck_envelope:
        raise Refusal("TCK analysis reference/hash is not bound to exact v5.1 routed artifact")
    artifact = manifest.get("artifacts", {}).get("routed_dcp")
    if not isinstance(artifact, dict) or artifact.get("sha256") != binding.routed_dcp_sha256:
        raise Refusal("route artifact hash differs from exact v5.1 routed DCP")


def verify_signed_document(wrapper: dict[str, Any], trusted_keys: dict[str, dict[str, Any]],
                           required_role: str, *, now: datetime | None = None) -> dict[str, Any]:
    """Verify canonical Ed25519 signed payload; boolean signature claims are ignored."""
    if wrapper.get("schema") != "PHK2-SIGNED-PHYSICAL-EVIDENCE-v1":
        raise Refusal("signed physical evidence schema missing")
    payload = wrapper.get("payload")
    signature = wrapper.get("signature")
    if not isinstance(payload, dict) or not isinstance(signature, dict):
        raise Refusal("signed evidence payload/signature missing")
    key_id = signature.get("key_id")
    key_record = trusted_keys.get(key_id) if isinstance(key_id, str) else None
    if not isinstance(key_record, dict) or required_role not in key_record.get("roles", []):
        raise Refusal("signature key is not in the configured trust roots for this role")
    if signature.get("algorithm") != "Ed25519":
        raise Refusal("only Ed25519 signed evidence is accepted")
    try:
        public_raw = base64.b64decode(key_record["public_key_b64"], validate=True)
        signature_raw = base64.b64decode(signature["value_b64"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature_raw, _canonical(payload))
    except Exception as exc:
        raise Refusal("cryptographic signature verification failed") from exc
    if payload.get("provenance") == "PHYSICAL_REAL":
        _utc(payload.get("captured_utc"), "physical capture", max_age_s=86400, now=now)
    return payload


def parse_waveform_csv(raw: bytes, summary: dict[str, Any] | None = None, *,
                       expected_rising_edges: int | None = None) -> dict[str, float | int]:
    """Parse PHK2-TCK-WAVEFORM-CSV-v1 sampled digital trace and derive metrics."""
    try:
        text = raw.decode("utf-8", errors="strict")
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames != ["sample_index", "timestamp_ns", "logic_level"]:
            raise Refusal("waveform CSV schema/header mismatch")
        samples = []
        for row in reader:
            idx = int(row["sample_index"])
            timestamp = float(row["timestamp_ns"])
            level = int(row["logic_level"])
            if not math.isfinite(timestamp) or level not in (0, 1):
                raise Refusal("waveform sample contains invalid timestamp or level")
            samples.append((idx, timestamp, level))
    except (UnicodeDecodeError, csv.Error, ValueError, TypeError) as exc:
        if isinstance(exc, Refusal):
            raise
        raise Refusal("waveform bytes are unparsable") from exc
    if len(samples) < 30:
        raise Refusal("waveform has too few samples")
    if any(row[0] != i for i, row in enumerate(samples)):
        raise Refusal("waveform sample indices are not contiguous")
    if any(samples[i][1] >= samples[i + 1][1] for i in range(len(samples) - 1)):
        raise Refusal("waveform timestamps are not strictly monotonic")
    if expected_rising_edges is not None:
        if isinstance(expected_rising_edges, bool) or expected_rising_edges != 87:
            raise Refusal("physical Case A edge contract must remain exactly 87 rising edges")
    edges = [(timestamp, level) for (_, timestamp, level), (_, _, prev) in zip(samples[1:], samples[:-1]) if level != prev]
    rising = [t for t, level in edges if level == 1]
    falling = [t for t, level in edges if level == 0]
    if len(rising) < 11 or len(falling) < 10:
        raise Refusal("waveform must contain at least 10 complete periods")
    if expected_rising_edges is not None:
        if (len(rising) != expected_rising_edges or len(falling) != expected_rising_edges or
                len(edges) != expected_rising_edges * 2 or edges[0][1] != 1 or edges[-1][1] != 0):
            raise Refusal("Case A waveform edge sequence is incomplete, extra, or out of order")
        if samples[0][2] != 0 or samples[-1][2] != 0:
            raise Refusal("Case A waveform must begin and end at idle-low")
        first_rise = rising[0]
        final_fall = falling[-1]
        final_rise = rising[-1]
        pretrigger_ns = first_rise - samples[0][1]
        posttrigger_ns = samples[-1][1] - first_rise
        final_high_ns = final_fall - final_rise
        idle_tail_ns = samples[-1][1] - final_fall
        if pretrigger_ns < 1_000.0:
            raise Refusal("Case A waveform lacks the required 1 us pre-trigger low interval")
        if posttrigger_ns < 20_000.0:
            raise Refusal("Case A waveform lacks the required 20 us post-trigger capture window")
        if final_high_ns <= 0 or idle_tail_ns < 1_000.0:
            raise Refusal("Case A final pulse or 1 us idle-low tail is incomplete")
    highs, lows, periods = [], [], []
    for i in range(len(rising) - 1):
        between = [t for t in falling if rising[i] < t < rising[i + 1]]
        if len(between) != 1:
            raise Refusal("waveform has missing or extra transitions within a period")
        fall = between[0]
        high = fall - rising[i]
        low = rising[i + 1] - fall
        period = rising[i + 1] - rising[i]
        if high <= 0 or low <= 0 or not math.isclose(high + low, period, rel_tol=0, abs_tol=1e-9):
            raise Refusal("waveform pulse widths are impossible")
        highs.append(high); lows.append(low); periods.append(period)
    mean_period = statistics.fmean(periods)
    mean_high = statistics.fmean(highs)
    mean_low = statistics.fmean(lows)
    duty = 100.0 * mean_high / mean_period
    if not (0.0 < duty < 100.0):
        raise Refusal("waveform duty cycle is impossible")
    deviations = [p - mean_period for p in periods]
    result: dict[str, float | int] = {
        "MEASURED_TCK_HZ": 1_000_000_000.0 / mean_period,
        "MEASURED_PERIOD_NS": mean_period,
        "MEASURED_HIGH_NS": mean_high,
        "MEASURED_LOW_NS": mean_low,
        "MEASURED_DUTY_CYCLE": duty,
        "JITTER_MIN_NS": min(deviations),
        "JITTER_MAX_NS": max(deviations),
        "MEASURED_JITTER_P2P_NS": max(deviations) - min(deviations),
        "MEASURED_JITTER_RMS_NS": math.sqrt(statistics.fmean(d * d for d in deviations)),
        "SAMPLE_COUNT": len(samples),
        "RISING_EDGE_COUNT": len(rising),
    }
    if expected_rising_edges is not None:
        result.update({"FINAL_HIGH_NS": final_high_ns, "PRETRIGGER_NS": pretrigger_ns,
                       "POSTTRIGGER_NS": posttrigger_ns, "IDLE_TAIL_NS": idle_tail_ns})
    if summary is not None:
        for name, value in result.items():
            supplied = summary.get(name)
            if isinstance(supplied, bool) or not isinstance(supplied, (int, float)) or not math.isfinite(supplied):
                raise Refusal(f"waveform summary missing/invalid {name}")
            if isinstance(value, int):
                if supplied != value:
                    raise Refusal(f"waveform summary/raw mismatch: {name}")
            elif not math.isclose(float(supplied), float(value), rel_tol=0.001, abs_tol=0.001):
                raise Refusal(f"waveform summary/raw mismatch: {name}")
    return result


TAP_TMS = tuple([1] * 5 + [0] + [1, 1, 0, 0] + [0, 0, 0, 0, 0, 1] + [1, 0] + [1, 0, 0] + [0] * 63 + [1] + [1, 0])
TAP_TDI = tuple([0] * 10 + [1, 0, 0, 1, 0, 0] + [0] * (len(TAP_TMS) - 16))
TAP_STATES = ("TEST_LOGIC_RESET", "RUN_TEST_IDLE", "SELECT_DR_SCAN", "CAPTURE_DR", "SHIFT_DR",
              "EXIT1_DR", "PAUSE_DR", "EXIT2_DR", "UPDATE_DR", "SELECT_IR_SCAN", "CAPTURE_IR",
              "SHIFT_IR", "EXIT1_IR", "PAUSE_IR", "EXIT2_IR", "UPDATE_IR")
TAP_NEXT = {
    "TEST_LOGIC_RESET": ("RUN_TEST_IDLE", "TEST_LOGIC_RESET"),
    "RUN_TEST_IDLE": ("RUN_TEST_IDLE", "SELECT_DR_SCAN"),
    "SELECT_DR_SCAN": ("CAPTURE_DR", "SELECT_IR_SCAN"),
    "CAPTURE_DR": ("SHIFT_DR", "EXIT1_DR"),
    "SHIFT_DR": ("SHIFT_DR", "EXIT1_DR"),
    "EXIT1_DR": ("PAUSE_DR", "UPDATE_DR"),
    "PAUSE_DR": ("PAUSE_DR", "EXIT2_DR"),
    "EXIT2_DR": ("SHIFT_DR", "UPDATE_DR"),
    "UPDATE_DR": ("RUN_TEST_IDLE", "SELECT_DR_SCAN"),
    "SELECT_IR_SCAN": ("CAPTURE_IR", "TEST_LOGIC_RESET"),
    "CAPTURE_IR": ("SHIFT_IR", "EXIT1_IR"),
    "SHIFT_IR": ("SHIFT_IR", "EXIT1_IR"),
    "EXIT1_IR": ("PAUSE_IR", "UPDATE_IR"),
    "PAUSE_IR": ("PAUSE_IR", "EXIT2_IR"),
    "EXIT2_IR": ("SHIFT_IR", "UPDATE_IR"),
    "UPDATE_IR": ("RUN_TEST_IDLE", "SELECT_DR_SCAN"),
}


def parse_tap_transcript(raw: bytes, expected_idcode: str) -> dict[str, Any]:
    try:
        doc = _json(raw, "TAP transcript")
    except Refusal as exc:
        raise Refusal("malformed TAP transcript JSON") from exc
    if doc.get("schema") != "PHK2-TAP-TRACE-v1" or doc.get("sequence") != "RESET_IDCODE_87_CYCLES":
        raise Refusal("TAP transcript schema/sequence mismatch")
    records = doc.get("cycles")
    if not isinstance(records, list) or len(records) != 87:
        raise Refusal("TAP transcript must contain exactly 87 clock records")
    state = "UNKNOWN"
    previous_timestamp = -math.inf
    tdo_dr = []
    observed_ir = []
    states = []
    for i, row in enumerate(records):
        if not isinstance(row, dict) or row.get("seq") != i or row.get("tms") != TAP_TMS[i] or row.get("tdi") != TAP_TDI[i]:
            raise Refusal("TAP transcript differs from the exact reset/IDCODE-only vector")
        if row.get("tdo") not in (0, 1):
            raise Refusal("TAP TDO bit malformed")
        timestamp = row.get("timestamp_ns")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp) or timestamp <= previous_timestamp:
            raise Refusal("TAP timestamps are malformed/non-monotonic")
        previous_timestamp = timestamp
        if state == "UNKNOWN":
            state = "TEST_LOGIC_RESET" if i == 4 else "UNKNOWN"
        else:
            state = TAP_NEXT[state][row["tms"]]
        states.append(state)
        if 10 <= i <= 15:
            observed_ir.append(row["tdi"])
        if 21 <= i <= 84:
            tdo_dr.append(row["tdo"])
    instruction = sum(bit << index for index, bit in enumerate(observed_ir))
    if instruction != 0x09:
        raise Refusal("TAP transcript selected a non-IDCODE instruction")
    if len(expected_idcode) != 8 or not re.fullmatch(r"[0-9a-fA-F]{8}", expected_idcode):
        raise Refusal("expected card IDCODE is missing/invalid")
    expected_word = int(expected_idcode, 16)
    expected_tdo = [(expected_word >> i) & 1 for i in range(32)] + [0] * 32
    if tdo_dr != expected_tdo:
        raise Refusal("TAP transcript IDCODE response/padding mismatch")
    if states[-1] != "RUN_TEST_IDLE":
        raise Refusal("TAP transcript did not end in Run-Test/Idle")
    if doc.get("derived_final_state") != "RUN_TEST_IDLE":
        raise Refusal("TAP declared final state disagrees with parsed transcript")
    return {"tap_cycles": len(records), "instruction": "IDCODE", "instruction_value": instruction,
            "idcode": expected_idcode.lower(), "before_state": "RESET_BY_FIVE_TMS_ONES",
            "after_state": states[-1], "user_instructions": [], "configuration_instruction": False}


def validate_peer_proof(payload: dict[str, Any], expected: dict[str, Any], *, now: datetime | None = None) -> str:
    if payload.get("schema") != "PHK2-PEER-EXCLUSION-PROOF-v1":
        raise Refusal("peer proof schema missing")
    _utc(payload.get("captured_utc"), "peer proof", max_age_s=300, now=now)
    server = payload.get("server")
    listener = payload.get("listener")
    lock = payload.get("local_lock")
    if not isinstance(server, dict) or not isinstance(listener, dict) or not isinstance(lock, dict):
        raise Refusal("peer proof server/listener/lock content missing")
    for field in ("pid", "exe_path", "sha256", "build_id", "service_unit", "service_config_sha256", "port"):
        if server.get(field) != expected.get(field):
            raise Refusal(f"peer proof server identity mismatch: {field}")
    if listener != {"pid": server["pid"], "port": server["port"], "state": "LISTEN"}:
        raise Refusal("expected XVC listening socket ownership proof mismatch")
    if not isinstance(server.get("pid"), int) or server["pid"] <= 1 or not isinstance(server.get("exe_path"), str) or not server["exe_path"].startswith("/"):
        raise Refusal("peer proof process identity is malformed")
    if payload.get("existing_foreign_clients") != [] or payload.get("competing_xvc_jtag_processes") != []:
        raise Refusal("peer proof reports active/competing peer")
    if (lock.get("held") is not True or lock.get("owner_pid") != payload.get("runner_pid") or
            lock.get("lock_key") != expected.get("lock_key") or
            not isinstance(lock.get("path"), str) or not lock["path"].startswith("/")):
        raise Refusal("peer proof local exclusive lock content mismatch")
    if not isinstance(payload.get("runner_pid"), int) or payload["runner_pid"] <= 0:
        raise Refusal("peer proof runner PID invalid")
    return _sha(_canonical(payload))


def validate_card_identity(payload: dict[str, Any], expected: dict[str, Any]) -> dict[str, str]:
    if payload.get("schema") != "PHK2-CARD-ADAPTER-IDENTITY-v1":
        raise Refusal("card/adapter identity schema missing")
    _utc(payload.get("captured_utc"), "card/adapter identity", max_age_s=300)
    mapping = (("EXPECTED_CARD_ID", "expected_card_id", "expected_card_id"),
               ("OBSERVED_CARD_ID", "observed_card_id", "expected_card_id"),
               ("EXPECTED_ADAPTER_ID", "expected_adapter_id", "expected_adapter_id"),
               ("OBSERVED_ADAPTER_ID", "observed_adapter_id", "expected_adapter_id"),
               ("BRIDGE_SHA256", "bridge_sha256", "bridge_sha256"),
               ("EXPECTED_FPGA_DNA", "expected_fpga_dna", "expected_fpga_dna"),
               ("OBSERVED_FPGA_DNA", "observed_fpga_dna", "expected_fpga_dna"),
               ("EXPECTED_TARGET_PART", "expected_target_part", "expected_target_part"),
               ("OBSERVED_TARGET_PART", "observed_target_part", "expected_target_part"))
    output = {}
    for label, field, expected_field in mapping:
        value = payload.get(field)
        if not isinstance(value, str) or not value or value != expected.get(expected_field):
            raise Refusal(f"card/adapter identity mismatch or missing: {label}")
        output[label] = value
    if (payload.get("one_card_scope") is not True or
            not isinstance(payload.get("observed_idcode"), str) or
            payload["observed_idcode"].lower() != expected.get("expected_idcode", "").lower()):
        raise Refusal("card scope or observed IDCODE mismatch")
    return output


def validate_authorization(payload: dict[str, Any], *, trusted_keys: dict[str, dict[str, Any]],
                           qualification_hash: str, bridge_sha256: str, card_id: str,
                           nonce: str, now: datetime | None = None) -> dict[str, Any]:
    signature_wrapper = {"schema": "PHK2-SIGNED-PHYSICAL-EVIDENCE-v1", "payload": payload,
                         "signature": payload.pop("_signature", None)}
    # Callers should pass the signed wrapper directly; this form is retained
    # only for a clear refusal if somebody tries boolean authorization.
    del signature_wrapper
    raise Refusal("authorization must be supplied as a signed Ed25519 wrapper")


def validate_signed_authorization(wrapper: dict[str, Any], trusted_keys: dict[str, dict[str, Any]], *,
                                  qualification_hash: str, bridge_sha256: str, card_id: str,
                                  nonce: str, service_config_sha256: str | None = None,
                                  peer_expectation_sha256: str | None = None,
                                  rollback_manifest_sha256: str | None = None,
                                  capture_backend_sha256: str | None = None,
                                  now: datetime | None = None) -> dict[str, Any]:
    payload = verify_signed_document(wrapper, trusted_keys, "authorization", now=now)
    if payload.get("authorized_operation") != "PHK2_PHYSICAL_TCK_CLOSURE":
        raise Refusal("authorization operation mismatch")
    if payload.get("card_scope") != 1 or payload.get("card_id") != card_id:
        raise Refusal("authorization is not bound to exactly the expected one card")
    if payload.get("qualification_record_sha256") != qualification_hash or payload.get("bridge_sha256") != bridge_sha256:
        raise Refusal("authorization qualification/bridge identity mismatch")
    if service_config_sha256 is not None and payload.get("service_config_sha256") != service_config_sha256:
        raise Refusal("authorization service configuration identity mismatch")
    if peer_expectation_sha256 is not None and payload.get("peer_expectation_sha256") != peer_expectation_sha256:
        raise Refusal("authorization peer-exclusion expectation identity mismatch")
    if rollback_manifest_sha256 is not None and payload.get("rollback_manifest_sha256") != rollback_manifest_sha256:
        raise Refusal("authorization rollback manifest identity mismatch")
    if capture_backend_sha256 is not None and payload.get("capture_backend_sha256") != capture_backend_sha256:
        raise Refusal("authorization capture backend identity mismatch")
    if payload.get("session_nonce") != nonce or payload.get("case_ids") != list(CASE_IDS):
        raise Refusal("authorization nonce or exact case IDs mismatch")
    if not isinstance(payload.get("operator_id"), str) or not payload["operator_id"].strip() or not isinstance(payload.get("authorization_id"), str) or not payload["authorization_id"].strip():
        raise Refusal("authorization/operator identifier missing")
    issued = _utc(payload.get("issued_utc"), "authorization issue", max_age_s=86400, now=now)
    try:
        expiry = datetime.fromisoformat(payload["expires_utc"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise Refusal("authorization expiry invalid") from exc
    if expiry.tzinfo is None or expiry <= (now or datetime.now(timezone.utc)) or expiry <= issued:
        raise Refusal("authorization expired or time interval invalid")
    return payload


def validate_authorization_status(wrapper: dict[str, Any], trusted_keys: dict[str, dict[str, Any]], *,
                                  authorization_id: str, authorization_sha256: str,
                                  now: datetime | None = None) -> dict[str, Any]:
    payload = verify_signed_document(wrapper, trusted_keys, "authorization_status", now=now)
    if (payload.get("schema") != "PHK2-AUTHORIZATION-STATUS-v1" or
            payload.get("status") != "ACTIVE" or
            payload.get("authorization_id") != authorization_id or
            payload.get("authorization_sha256") != authorization_sha256):
        raise Refusal("authorization is revoked or status proof is not bound to this artifact")
    _utc(payload.get("checked_utc"), "authorization status", max_age_s=300, now=now)
    return payload


def validate_signed_capture(wrapper: dict[str, Any], trusted_keys: dict[str, dict[str, Any]], *,
                            expected_role: str, expected_case_id: str,
                            expected_record_sha256: str,
                            expected_session_nonce: str | None = None,
                            now: datetime | None = None) -> tuple[dict[str, Any], bytes]:
    """Verify physical provenance and return the signed raw capture bytes.

    The signer must be a configured trust root. A PHYSICAL_REAL string or a
    production_evidence boolean without a valid signature is never evidence.
    """
    payload = verify_signed_document(wrapper, trusted_keys, expected_role, now=now)
    if payload.get("provenance") != "PHYSICAL_REAL" or payload.get("synthetic_fixture") is not False:
        raise Refusal("capture provenance is not cryptographically attested PHYSICAL_REAL")
    if payload.get("qualification_record_sha256") != expected_record_sha256 or payload.get("case_id") != expected_case_id:
        raise Refusal("capture is not bound to exact v5.1 record/case")
    if expected_session_nonce is not None and payload.get("session_nonce") != expected_session_nonce:
        raise Refusal("capture is not bound to the current authorized session")
    try:
        raw = base64.b64decode(payload["raw_capture_b64"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise Refusal("signed capture raw bytes are missing or malformed") from exc
    if not raw or payload.get("raw_capture_sha256") != _sha(raw):
        raise Refusal("signed capture bytes are empty or hash-mismatched")
    return payload, raw


def validate_case_a_instrument_evidence(payload: dict[str, Any]) -> bytes:
    """Require the signed native acquisition and its calibration context."""
    try:
        native = base64.b64decode(payload["native_acquisition_b64"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise Refusal("Case A native instrument acquisition is missing or malformed") from exc
    if not native or payload.get("native_acquisition_sha256") != _sha(native):
        raise Refusal("Case A native instrument acquisition hash mismatch")
    metadata = payload.get("instrument_metadata")
    required = ("instrument_model", "instrument_serial", "probe_id", "calibration_certificate_sha256",
                "calibration_valid_until_utc", "bandwidth_hz", "sample_rate_hz", "voltage_threshold_v",
                "coupling", "channel", "timebase", "trigger", "capture_window", "software_version",
                "measurement_uncertainty_ns")
    if not isinstance(metadata, dict) or any(metadata.get(key) in (None, "") for key in required):
        raise Refusal("Case A instrument/calibration metadata is incomplete")
    if not re.fullmatch(r"[0-9a-f]{64}", str(metadata["calibration_certificate_sha256"])):
        raise Refusal("Case A calibration certificate hash is malformed")
    try:
        calibration_expiry = datetime.fromisoformat(metadata["calibration_valid_until_utc"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise Refusal("instrument calibration expiry timestamp is invalid") from exc
    if calibration_expiry.tzinfo is None or calibration_expiry <= datetime.now(timezone.utc):
        raise Refusal("instrument calibration is expired or has no timezone")
    for field in ("bandwidth_hz", "sample_rate_hz", "voltage_threshold_v", "measurement_uncertainty_ns"):
        value = metadata[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise Refusal(f"Case A instrument metadata is invalid: {field}")
    if metadata["bandwidth_hz"] <= 0 or metadata["sample_rate_hz"] <= 0 or metadata["measurement_uncertainty_ns"] <= 0:
        raise Refusal("Case A instrument bandwidth, sample rate, and uncertainty must be positive")
    return native


def validate_physical_capture_package(*, trusted_keys: dict[str, dict[str, Any]],
                                      waveform_wrapper: dict[str, Any], tap_wrapper: dict[str, Any],
                                      binding: V51Binding, expected_idcode: str,
                                      expected_session_nonce: str,
                                      case_b_method_record: dict[str, Any] | None = None,
                                      authorization_payload: dict[str, Any] | None = None,
                                      expected_target_identity: dict[str, Any] | None = None,
                                      now: datetime | None = None) -> dict[str, Any]:
    """Parse signed captures against immutable qualification and approved method."""
    wave_payload, wave_raw = validate_signed_capture(
        waveform_wrapper, trusted_keys, expected_role="capture", expected_case_id=CASE_A_ID,
        expected_record_sha256=binding.qualification_record_sha256,
        expected_session_nonce=expected_session_nonce, now=now)
    waveform = parse_waveform_csv(wave_raw, wave_payload.get("summary"), expected_rising_edges=87)
    validate_case_a_instrument_evidence(wave_payload)
    if waveform["RISING_EDGE_COUNT"] != 87:
        raise Refusal("Case A waveform must contain exactly 87 TCK rising edges")
    tap_payload, tap_raw = validate_signed_capture(
        tap_wrapper, trusted_keys, expected_role="capture", expected_case_id=CASE_B_ID,
        expected_record_sha256=binding.qualification_record_sha256,
        expected_session_nonce=expected_session_nonce, now=now)
    from phk2_case_b_method import (parse_case_b_transcript,
                                    validate_approved_case_b_method_record)
    validated_method = validate_approved_case_b_method_record(
        case_b_method_record, binding=binding, trusted_keys=trusted_keys,
        expected_target_identity=expected_target_identity or {},
        authorization_payload=authorization_payload or {}, session_nonce=expected_session_nonce, now=now)
    tap = parse_case_b_transcript(tap_raw, tap_payload, validated_method,
                                  session_nonce=expected_session_nonce)
    if (tap_payload.get("fpga_programming") is not False or
            tap_payload.get("workload_changed") is not False or
            tap_payload.get("settck_used_as_measurement") is not False):
        raise Refusal("signed Case B capture reports a prohibited action or invalid TCK proof source")
    close = tap_payload.get("final_close")
    if not isinstance(close, dict) or close != {
            "transport_closed": True, "tap_idle": True, "peer_count_after": 0}:
        raise Refusal("signed Case B capture lacks exact final idle/closed evidence")
    return {"waveform": waveform, "tap": tap,
            "waveform_capture_sha256": _sha(wave_raw), "tap_capture_sha256": _sha(tap_raw)}


def validate_readiness_attestation(wrapper: dict[str, Any], trusted_keys: dict[str, dict[str, Any]], *,
                                   role: str, schema: str, expected: dict[str, Any],
                                   now: datetime | None = None) -> dict[str, Any]:
    payload = verify_signed_document(wrapper, trusted_keys, role, now=now)
    if payload.get("schema") != schema or payload.get("status") != "READY" or payload.get("synthetic_fixture") is not False:
        raise Refusal(f"signed {role} readiness attestation is malformed or not READY")
    for key, value in expected.items():
        if payload.get(key) != value:
            raise Refusal(f"signed {role} readiness identity mismatch: {key}")
    _utc(payload.get("validated_utc"), f"{role} readiness", max_age_s=300, now=now)
    return payload


class PreTransportJournal:
    """Exclusive durable hash-chain journal initialized before transport."""
    def __init__(self, path: str | Path, session_nonce: str):
        self.path = Path(path)
        self.session_nonce = session_nonce
        self.previous = "0" * 64
        self.fd: int | None = None
        self.sequence = 0
        self.initial_entry_sha256: str | None = None

    def initialize(self, binding: dict[str, Any]) -> str:
        parent = self.path.parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = parent.stat(follow_symlinks=False)
        if not info.st_mode & 0o170000 == 0o040000 or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise Refusal("journal directory must be private and owned by operator")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            self.fd = os.open(self.path, flags, 0o600)
            self.append("PRE_TRANSPORT", {"session_nonce": self.session_nonce, **binding})
            os.fsync(self.fd)
            dirfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
            return _sha(self.path.read_bytes())
        except Exception as exc:
            if self.fd is not None:
                os.close(self.fd); self.fd = None
            try:
                self.path.unlink()
            except OSError:
                pass
            if isinstance(exc, Refusal):
                raise
            raise Refusal("pre-transport evidence journal initialization failed") from exc

    def append(self, event: str, payload: dict[str, Any]) -> str:
        if self.fd is None:
            raise Refusal("journal not initialized before event append")
        record = {"sequence": self.sequence,
                  "event": event, "payload_sha256": _sha(_canonical(payload)),
                  "previous_entry_sha256": self.previous}
        record["entry_sha256"] = _sha(_canonical(record))
        encoded = _canonical(record) + b"\n"
        view = memoryview(encoded)
        while view:
            written = os.write(self.fd, view)
            view = view[written:]
        os.fsync(self.fd)
        self.previous = record["entry_sha256"]
        self.sequence += 1
        if self.initial_entry_sha256 is None:
            self.initial_entry_sha256 = self.previous
        return self.previous


def _peer_runtime_digest(payload: dict[str, Any]) -> str:
    return _sha(_canonical({key: payload.get(key) for key in (
        "server", "listener", "existing_foreign_clients", "competing_xvc_jtag_processes",
        "runner_pid", "local_lock")}))


def _card_runtime_digest(payload: dict[str, Any]) -> str:
    return _sha(_canonical({key: payload.get(key) for key in (
        "expected_card_id", "observed_card_id", "expected_adapter_id", "observed_adapter_id",
        "bridge_sha256", "observed_idcode", "one_card_scope")}))


def _backend_runtime_digest(payload: dict[str, Any]) -> str:
    return _sha(_canonical({key: payload.get(key) for key in (
        "backend_id", "backend_sha256", "backend_version", "capture_device_id",
        "transport_factory_sha256", "state_revalidator_sha256")}))


def callable_identity_sha256(callback: Callable[..., Any], label: str = "callback") -> str:
    """Hash reviewed module identity and exact callable name/code identity."""
    if not callable(callback):
        raise Refusal(f"{label} is not callable")
    target = callback if inspect.isfunction(callback) or inspect.ismethod(callback) else getattr(type(callback), "__call__", None)
    if target is None or getattr(target, "__code__", None) is None:
        raise Refusal(f"{label} has no inspectable Python code identity")
    source = inspect.getsourcefile(target)
    if not source:
        raise Refusal(f"{label} source module is unavailable")
    try:
        source_bytes = Path(source).resolve(strict=True).read_bytes()
    except OSError as exc:
        raise Refusal(f"{label} source identity cannot be read") from exc
    code = target.__code__
    identity = {"source_sha256": _sha(source_bytes), "module": target.__module__,
                "qualname": target.__qualname__, "firstlineno": code.co_firstlineno,
                "bytecode_sha256": _sha(code.co_code)}
    return _sha(_canonical(identity))


def transport_factory_identity_sha256(factory: Callable[..., Any]) -> str:
    return callable_identity_sha256(factory, "transport opener")


def _create_physical_transport(_target_identity_sha256: str,
                               _candidate_image_sha256: str) -> Any:
    """Private transport seam; no physical backend is installed in this tree."""
    raise Refusal("reviewed physical capture/transport backend is not installed")


def _execute_case_a_capture(transport: Any) -> dict[str, Any]:
    capture = getattr(transport, "capture_case_a", None)
    if not callable(capture):
        raise Refusal("physical capture backend does not implement Case A")
    result = capture()
    if not isinstance(result, dict):
        raise Refusal("Case A backend result is malformed")
    return result


def _execute_case_b_capture(transport: Any) -> dict[str, Any]:
    capture = getattr(transport, "capture_case_b", None)
    if not callable(capture):
        raise Refusal("physical capture backend does not implement Case B")
    result = capture()
    if not isinstance(result, dict):
        raise Refusal("Case B backend result is malformed")
    return result


def _case_b_expected_target_identity(card_payload: Any, candidate_image_sha256: Any) -> dict[str, Any]:
    """Bind Case B to the freshly signed observed image, not only a host expectation."""
    if not isinstance(card_payload, dict):
        raise Refusal("Case-B fresh signed target identity is missing")
    observed_image = card_payload.get("loaded_image_sha256")
    if (not isinstance(observed_image, str) or not re.fullmatch(r"[0-9a-f]{64}", observed_image) or
            observed_image != candidate_image_sha256):
        raise Refusal("Case-B fresh signed loaded-image identity is missing, malformed, or mismatched")
    return {
        "card_id": card_payload.get("observed_card_id"),
        "adapter_id": card_payload.get("observed_adapter_id"),
        "fpga_dna": card_payload.get("observed_fpga_dna"),
        "idcode": card_payload.get("observed_idcode"),
        "target_part": card_payload.get("observed_target_part"),
        "jtag_chain_topology": card_payload.get("observed_jtag_chain_topology"),
        "loaded_image_sha256": observed_image,
    }


class TrustedKeyStore(dict):
    """Parsed signer keys whose containing store matched the software pin."""
    def __init__(self, *args, verified_sha256: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.verified_sha256 = verified_sha256


def master_pretransport_gate(*, repo: str | Path, closure_manifest: dict[str, Any],
                             signed_authorization: dict[str, Any], signed_authorization_status: dict[str, Any],
                             trusted_keys: dict[str, dict[str, Any]],
                             peer_proof: dict[str, Any], peer_expectation: dict[str, Any],
                             signed_card_identity: dict[str, Any], card_expectation: dict[str, Any],
                             signed_rollback_attestation: dict[str, Any],
                             signed_capture_backend_attestation: dict[str, Any],
                             rollback_expectation: dict[str, Any], capture_backend_expectation: dict[str, Any],
                             tck_envelope_qualified: bool, journal_path: str | Path,
                             session_nonce: str, qualification_hash: str,
                             bridge_sha256: str, endpoint_target_identity_sha256: str,
                             candidate_image_sha256: str,
                             state_revalidator: Callable[[], dict[str, str]],
                             signed_case_b_method_record: dict[str, Any] | None = None) -> Any:
    if (not isinstance(trusted_keys, TrustedKeyStore) or PINNED_TRUST_STORE_SHA256 is None or
            trusted_keys.verified_sha256 != PINNED_TRUST_STORE_SHA256):
        raise Refusal("no operator-approved cryptographic trust root is pinned for physical authorization")
    binding = verify_immutable_v51(repo)
    if closure_manifest.get("qualification_record_sha256") != qualification_hash or qualification_hash != V51_QUALIFICATION_RECORD_SHA256:
        raise Refusal("v5.1 qualification record hash mismatch")
    if bridge_sha256 != PINNED_REVIEWED_BRIDGE_SHA256 or bridge_sha256 != card_expectation.get("bridge_sha256"):
        raise Refusal("exact bridge identity mismatch")
    validate_case_manifest(closure_manifest, binding)
    if peer_proof.get("_signature_wrapper") is not None:
        peer_payload = verify_signed_document(peer_proof["_signature_wrapper"], trusted_keys, "peer")
    else:
        raise Refusal("peer proof must be cryptographically signed")
    peer_hash = validate_peer_proof(peer_payload, peer_expectation)
    if (peer_expectation.get("sha256") != PINNED_REVIEWED_BRIDGE_SHA256 or
            peer_expectation.get("build_id") != PINNED_REVIEWED_BUILD_ID):
        raise Refusal("peer expectation is not the exact statically reviewed SQRL/XVC bridge")
    card_payload = verify_signed_document(signed_card_identity, trusted_keys, "identity")
    if (card_expectation.get("expected_card_id") != binding.expected_card_id or
            card_expectation.get("expected_adapter_id") != binding.expected_adapter_id or
            str(card_expectation.get("expected_idcode", "")).lower() != binding.expected_idcode or
            str(card_expectation.get("expected_fpga_dna", "")).lower() != binding.expected_fpga_dna or
            card_expectation.get("expected_target_part") != binding.expected_target_part or
            card_expectation.get("bridge_sha256") != PINNED_REVIEWED_BRIDGE_SHA256):
        raise Refusal("expected canary/adapter/FPGA DNA/part/IDCODE/bridge differs from immutable approved identity")
    card = validate_card_identity(card_payload, card_expectation)
    if rollback_expectation.get("rollback_manifest_sha256") != ROLLBACK_SHA256:
        raise Refusal("rollback readiness is not bound to the immutable qualified rollback manifest")
    rollback_payload = validate_readiness_attestation(signed_rollback_attestation, trusted_keys,
                                    role="rollback", schema="PHK2-ROLLBACK-READINESS-v1",
                                    expected=rollback_expectation)
    if not tck_envelope_qualified or not binding.qualified_physical_envelope_available:
        raise Refusal("v5.1 record has no qualified physical TCK envelope")
    auth = validate_signed_authorization(signed_authorization, trusted_keys,
                                        qualification_hash=qualification_hash,
                                        bridge_sha256=bridge_sha256,
                                        card_id=card["OBSERVED_CARD_ID"], nonce=session_nonce,
                                        service_config_sha256=peer_expectation.get("service_config_sha256"),
                                        peer_expectation_sha256=_sha(_canonical(peer_expectation)),
                                        rollback_manifest_sha256=rollback_payload["rollback_manifest_sha256"],
                                        capture_backend_sha256=capture_backend_expectation.get("backend_sha256"))
    authorization_sha256 = _sha(_canonical(signed_authorization))
    auth_status_payload = validate_authorization_status(signed_authorization_status, trusted_keys,
                                  authorization_id=auth["authorization_id"],
                                  authorization_sha256=authorization_sha256)
    auth_status_digest = _sha(_canonical({key: auth_status_payload[key] for key in (
        "schema", "status", "authorization_id", "authorization_sha256")}))
    capture_payload = validate_readiness_attestation(signed_capture_backend_attestation, trusted_keys,
                                    role="capture_backend", schema="PHK2-CAPTURE-BACKEND-READY-v1",
                                    expected=capture_backend_expectation)
    # The gate selects the private, source-pinned opener. Callers cannot pass
    # or receive a factory that can be recombined with audit metadata.
    factory_identity = transport_factory_identity_sha256(_create_physical_transport)
    if factory_identity != capture_payload.get("transport_factory_sha256"):
        raise Refusal("transport opener does not match signed capture-backend implementation identity")
    revalidator_identity = callable_identity_sha256(state_revalidator, "live-state revalidator")
    if revalidator_identity != capture_payload.get("state_revalidator_sha256"):
        raise Refusal("live-state revalidator differs from signed capture-backend identity")
    journal = PreTransportJournal(journal_path, session_nonce)
    journal_hash = journal.initialize({"qualification_record_sha256": qualification_hash,
                                       "bridge_sha256": bridge_sha256,
                                       "peer_proof_sha256": peer_hash,
                                       "authorization_id": auth["authorization_id"],
                                       "card_id": card["OBSERVED_CARD_ID"],
                                       "case_ids": list(CASE_IDS)})
    claims = {
        "session_nonce": session_nonce,
        "source_commit": binding.source_commit,
        "source_tree_hash": binding.source_tree_hash,
        "routed_dcp_sha256": binding.routed_dcp_sha256,
        "qualification_record_sha256": qualification_hash,
        "case_ids": CASE_IDS,
        "bridge_sha256": bridge_sha256,
        "expected_card_id": card["OBSERVED_CARD_ID"],
        "expected_adapter_id": card["OBSERVED_ADAPTER_ID"],
        "card_identity_sha256": _card_runtime_digest(card_payload),
        "peer_proof_sha256": peer_hash,
        "peer_state_sha256": _peer_runtime_digest(peer_payload),
        "authorization_artifact_sha256": _sha(_canonical(signed_authorization)),
        "authorization_status_sha256": auth_status_digest,
        "capture_backend_identity_sha256": _backend_runtime_digest(capture_payload),
        "transport_factory_sha256": factory_identity,
        "state_revalidator_sha256": revalidator_identity,
        "evidence_journal_sha256": journal_hash,
        "endpoint_target_identity_sha256": endpoint_target_identity_sha256,
        "candidate_image_sha256": candidate_image_sha256,
    }
    expected_runtime = {
        # These are the mutable external observations. Immutable source,
        # route, authorization, and journal identities are independently
        # revalidated below and are not delegated to the observation callback.
        "routed_dcp_sha256": binding.routed_dcp_sha256,
        "card_identity_sha256": claims["card_identity_sha256"],
        "peer_state_sha256": claims["peer_state_sha256"],
        "authorization_status_sha256": auth_status_digest,
        "capture_backend_identity_sha256": claims["capture_backend_identity_sha256"],
        "transport_factory_sha256": factory_identity,
        "state_revalidator_sha256": revalidator_identity,
        "endpoint_target_identity_sha256": endpoint_target_identity_sha256,
        "candidate_image_sha256": candidate_image_sha256,
    }
    def revalidate_all() -> dict[str, str]:
        if callable_identity_sha256(state_revalidator, "live-state revalidator") != claims["state_revalidator_sha256"]:
            raise Refusal("live-state revalidation code changed after capability issuance")
        fresh_binding = verify_immutable_v51(repo)
        validate_case_manifest(closure_manifest, fresh_binding)
        if (fresh_binding.source_commit != claims["source_commit"] or
                fresh_binding.source_tree_hash != claims["source_tree_hash"] or
                fresh_binding.routed_dcp_sha256 != claims["routed_dcp_sha256"] or
                fresh_binding.qualification_record_sha256 != claims["qualification_record_sha256"]):
            raise Refusal("immutable qualification/artifact changed after capability issuance")
        current_auth = validate_signed_authorization(
            signed_authorization, trusted_keys,
            qualification_hash=claims["qualification_record_sha256"],
            bridge_sha256=claims["bridge_sha256"],
            card_id=claims["expected_card_id"], nonce=claims["session_nonce"],
            service_config_sha256=peer_expectation.get("service_config_sha256"),
            peer_expectation_sha256=_sha(_canonical(peer_expectation)),
            rollback_manifest_sha256=rollback_payload["rollback_manifest_sha256"],
            capture_backend_sha256=capture_payload["backend_sha256"])
        if _sha(_canonical(signed_authorization)) != claims["authorization_artifact_sha256"]:
            raise Refusal("authorization artifact changed after capability issuance")
        live = state_revalidator()
        if not isinstance(live, dict):
            raise Refusal("live state revalidator did not return a mapping")
        live_auth_status = validate_authorization_status(live.get("authorization_status_wrapper"), trusted_keys,
                                      authorization_id=current_auth["authorization_id"],
                                      authorization_sha256=claims["authorization_artifact_sha256"])
        current_status_digest = _sha(_canonical({key: live_auth_status[key] for key in (
            "schema", "status", "authorization_id", "authorization_sha256")}))
        if current_status_digest != claims["authorization_status_sha256"]:
            raise Refusal("authorization status identity changed after capability issuance")
        return {key: value for key, value in live.items() if key != "authorization_status_wrapper"}

    def check_journal() -> None:
        if journal.fd is None:
            raise Refusal("evidence journal is unavailable")
        try:
            fd_stat = os.fstat(journal.fd)
            path_stat = journal.path.stat(follow_symlinks=False)
        except OSError as exc:
            raise Refusal("evidence journal is no longer available") from exc
        if (fd_stat.st_dev != path_stat.st_dev or fd_stat.st_ino != path_stat.st_ino or
                path_stat.st_nlink != 1 or path_stat.st_uid != os.getuid() or
                path_stat.st_mode & 0o077 or not journal.path.is_file()):
            raise Refusal("evidence journal identity/permissions changed")
        journal_state = verify_journal_chain(journal.path.read_bytes())
        if (journal_state["last_entry_sha256"] != journal.previous or
                journal_state["entry_count"] != journal.sequence or
                journal_state["first_entry_sha256"] != journal.initial_entry_sha256):
            raise Refusal("evidence journal contents changed or fsync/append state diverged")

    seal = object()

    class GatedPhysicalExecutor:
        """Locally defined sealed executor; no importable authority record exists."""
        __slots__ = ("__transport", "__journal", "__claims", "__revalidate",
                     "__expected_runtime", "__state", "__case_a_wrapper",
                     "__case_a_complete", "__case_b_complete")

        def __init__(self, issuer: object):
            if issuer is not seal:
                raise Refusal("executor construction is private to the master gate")
            self.__transport = None
            self.__journal = journal
            self.__claims = dict(claims)
            self.__revalidate = revalidate_all
            self.__expected_runtime = dict(expected_runtime)
            self.__state = "PRETRANSPORT"
            self.__case_a_wrapper = None
            self.__case_a_complete = False
            self.__case_b_complete = False

        def __reduce_ex__(self, _protocol: int):
            raise TypeError("live physical executors cannot be serialized")

        def __copy__(self):
            raise TypeError("live physical executors cannot be copied")

        def __deepcopy__(self, _memo):
            raise TypeError("live physical executors cannot be copied")

        @property
        def state(self) -> str:
            return self.__state

        def audit_metadata(self) -> dict[str, Any]:
            return {**self.__claims, "state": self.__state}

        def __check_live(self, allowed: tuple[str, ...]) -> None:
            if self.__state not in allowed or self.__transport is None:
                raise Refusal(f"executor state {self.__state} does not allow this operation")
            try:
                actual = self.__revalidate()
                if not isinstance(actual, dict):
                    raise Refusal("executor revalidator did not return identity claims")
                for key, value in self.__expected_runtime.items():
                    if actual.get(key) != value:
                        raise Refusal(f"executor state changed: {key}")
                check_journal()
            except Exception as exc:
                self.__state = "ABORTED"
                try:
                    self.__journal.append("EXECUTOR_INVALIDATED", {"reason": type(exc).__name__})
                except Exception:
                    pass
                try:
                    self.__transport.close()
                except Exception:
                    pass
                if isinstance(exc, Refusal):
                    raise
                raise Refusal("executor live-state check failed") from exc

        def __open_from_master(self, issuer: object) -> None:
            if issuer is not seal or self.__state != "PRETRANSPORT":
                raise Refusal("only the master gate may open this executor")
            try:
                actual = self.__revalidate()
                for key, value in self.__expected_runtime.items():
                    if actual.get(key) != value:
                        raise Refusal(f"pretransport state changed: {key}")
                check_journal()
                self.__journal.append("TRANSPORT_OPEN_REQUESTED", {
                    "session_nonce": self.__claims["session_nonce"],
                    "evidence_journal_sha256": self.__claims["evidence_journal_sha256"]})
                check_journal()
                if transport_factory_identity_sha256(_create_physical_transport) != self.__claims["transport_factory_sha256"]:
                    raise Refusal("private transport opener changed after review")
                transport = _create_physical_transport(
                    self.__claims["endpoint_target_identity_sha256"],
                    self.__claims["candidate_image_sha256"])
                if transport is None or not callable(getattr(transport, "close", None)):
                    raise Refusal("private transport opener returned an invalid transport")
                self.__transport = transport
                self.__journal.append("TRANSPORT_OPENED", {"session_nonce": self.__claims["session_nonce"]})
                self.__state = "OPEN"
            except Exception:
                self.__state = "ABORTED"
                if self.__transport is not None:
                    try:
                        self.__transport.close()
                    except Exception:
                        pass
                try:
                    self.__journal.append("TRANSPORT_OPEN_FAILED", {"session_nonce": self.__claims["session_nonce"]})
                except Exception:
                    pass
                raise

        def run_case_a(self) -> dict[str, Any]:
            self.__check_live(("OPEN",))
            self.__state = "CASE_A"
            try:
                wrapper = _execute_case_a_capture(self.__transport)
                payload, raw = validate_signed_capture(
                    wrapper, trusted_keys, expected_role="capture", expected_case_id=CASE_A_ID,
                    expected_record_sha256=qualification_hash,
                    expected_session_nonce=self.__claims["session_nonce"])
                waveform = parse_waveform_csv(raw, payload.get("summary"), expected_rising_edges=87)
                validate_case_a_instrument_evidence(payload)
                if waveform["RISING_EDGE_COUNT"] != 87:
                    raise Refusal("Case A waveform must contain exactly 87 TCK rising edges")
                limits = binding.tck_envelope.get("physical_waveform_limits")
                if not isinstance(limits, dict):
                    raise Refusal("v5.1 physical TCK envelope is not qualified")
                for field, key in (
                    ("MEASURED_TCK_HZ", "minimum_tck_hz"),
                    ("MEASURED_TCK_HZ", "maximum_tck_hz"),
                    ("MEASURED_HIGH_NS", "minimum_high_ns"),
                    ("MEASURED_HIGH_NS", "maximum_high_ns"),
                    ("MEASURED_LOW_NS", "minimum_low_ns"),
                    ("MEASURED_LOW_NS", "maximum_low_ns"),
                    ("MEASURED_DUTY_CYCLE", "minimum_duty_cycle_percent"),
                    ("MEASURED_DUTY_CYCLE", "maximum_duty_cycle_percent"),
                    ("JITTER_MIN_NS", "minimum_jitter_ns"),
                    ("JITTER_MAX_NS", "maximum_jitter_ns")):
                    limit = limits.get(key)
                    if not isinstance(limit, (int, float)) or not math.isfinite(limit):
                        raise Refusal(f"qualified physical TCK envelope lacks {key}")
                    if key.startswith("minimum_") and waveform[field] < limit:
                        raise Refusal(f"Case A waveform below qualified {key}")
                    if key.startswith("maximum_") and waveform[field] > limit:
                        raise Refusal(f"Case A waveform above qualified {key}")
                self.__case_a_wrapper = wrapper
                self.__case_a_complete = True
                self.__journal.append("CASE_A_CAPTURED", {
                    "case_id": CASE_A_ID, "capture_sha256": _sha(raw),
                    "waveform": waveform})
                return waveform
            except Exception:
                self.abort()
                raise

        def run_case_b(self) -> dict[str, Any]:
            self.__check_live(("CASE_A",))
            if not self.__case_a_complete:
                raise Refusal("Case B requires successful Case A completion")
            self.__state = "CASE_B"
            try:
                target_identity = _case_b_expected_target_identity(card_payload, candidate_image_sha256)
                # The approved method is an execution prerequisite, not merely
                # a post-capture evidence check. Refuse before invoking the
                # backend, which may clock the TAP and perform BSCAN.
                from phk2_case_b_method import validate_approved_case_b_method_record
                validate_approved_case_b_method_record(
                    signed_case_b_method_record, binding=binding, trusted_keys=trusted_keys,
                    expected_target_identity=target_identity,
                    authorization_payload=auth,
                    session_nonce=self.__claims["session_nonce"])
                wrapper = _execute_case_b_capture(self.__transport)
                result = validate_physical_capture_package(
                    trusted_keys=trusted_keys, waveform_wrapper=self.__case_a_wrapper,
                    tap_wrapper=wrapper, binding=binding, expected_idcode=binding.expected_idcode,
                    expected_session_nonce=self.__claims["session_nonce"],
                    case_b_method_record=signed_case_b_method_record,
                    authorization_payload=auth,
                    expected_target_identity=target_identity)
                self.__case_b_complete = True
                self.__journal.append("CASE_B_CAPTURED", {
                    "case_id": CASE_B_ID,
                    "tap_capture_sha256": result["tap_capture_sha256"],
                    "tap": result["tap"]})
                return result
            except Exception:
                self.abort()
                raise

        def close(self) -> None:
            if self.__state in ("CLOSED", "ABORTED"):
                raise Refusal(f"executor is already {self.__state.lower()}")
            transport = self.__transport
            self.__state = "CLOSED"
            try:
                self.__journal.append("FINAL_IDLE_CLOSE", {
                    "case_a_complete": self.__case_a_complete,
                    "case_b_complete": self.__case_b_complete})
            finally:
                if transport is not None:
                    transport.close()

        def abort(self) -> None:
            if self.__state in ("CLOSED", "ABORTED"):
                raise Refusal(f"executor is already {self.__state.lower()}")
            transport = self.__transport
            self.__state = "ABORTED"
            try:
                self.__journal.append("ABORTED", {"session_nonce": self.__claims["session_nonce"]})
            finally:
                if transport is not None:
                    transport.close()

    executor = GatedPhysicalExecutor(seal)
    getattr(executor, f"_{GatedPhysicalExecutor.__name__}__open_from_master")(seal)
    return executor


def load_trust_store(path: str | Path) -> dict[str, dict[str, Any]]:
    if PINNED_TRUST_STORE_SHA256 is None:
        raise Refusal("no operator-approved trust-store hash is configured")
    trust_path = Path(path).resolve(strict=True)
    info = trust_path.stat(follow_symlinks=False)
    if not trust_path.is_file() or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise Refusal("trusted signer store ownership/permissions are unsafe")
    trust_bytes = trust_path.read_bytes()
    actual_hash = _sha(trust_bytes)
    if actual_hash != PINNED_TRUST_STORE_SHA256:
        raise Refusal("trusted signer store differs from the software-pinned hash")
    data = _json(trust_bytes, "trusted signer store")
    if data.get("schema") != "PHK2-TRUSTED-SIGNERS-v1":
        raise Refusal("trusted signer store schema mismatch")
    keys = data.get("keys")
    if not isinstance(keys, list) or not keys:
        raise Refusal("no trusted authorization/capture public keys are configured")
    result = {}
    for row in keys:
        if not isinstance(row, dict) or not isinstance(row.get("key_id"), str) or row["key_id"] in result:
            raise Refusal("trusted signer record malformed/duplicated")
        if row.get("algorithm") != "Ed25519" or not isinstance(row.get("roles"), list) or not row["roles"]:
            raise Refusal("trusted signer algorithm/roles invalid")
        raw = base64.b64decode(row.get("public_key_b64", ""), validate=True)
        if len(raw) != 32:
            raise Refusal("Ed25519 public key length invalid")
        result[row["key_id"]] = row
    return TrustedKeyStore(result, verified_sha256=actual_hash)
