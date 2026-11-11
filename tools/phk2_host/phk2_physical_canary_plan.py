#!/usr/bin/env python3
"""Offline-only PHK2 FK0957 canary plan verifier; no physical executor exists here."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
from typing import Any

from phk2_physical_close_guard import verify_immutable_v51, CASE_A_ID, CASE_B_ID

ENVELOPE_COMMIT = "a01a735fb1e1d0e9b918a2d20c0733ba244b4ee0"
ENVELOPE_BASE = "results/phk2-v5_1-common-reset-20261110/tck_envelope"
ENVELOPE_PATH = f"{ENVELOPE_BASE}/PHK2_V5_1_TCK_ENVELOPE.json"
ENVELOPE_SHA256 = "eea838b5d4dcf930b856299a909684a8eecc86f0d539bf9eb6cc7b8a26297e49"
SUMS_PATH = f"{ENVELOPE_BASE}/SHA256SUMS"
SUMS_SHA256 = "7b0ba6de12201b93d40b8b6bc4ee7dd3adcfdf8d2b9420d15ed1823a0d4b7f09"
SOURCE_COMMIT = "5f65f0ec8900ecaae3c498223bef0efb2542c047"
SOURCE_TREE = "dcc879775d80e07ab41bc9af955a29a3fd8ba6f9"
ROUTED_DCP_SHA256 = "0bd52785662a3c38f68667f85c75acdef33c109502794610669ab8e1cf61e9af"
ENVELOPE_QUALIFICATION_COMMIT = "af539f88e99d4815010db7372dbc83decad2bd05"
REVIEWED_BRIDGE_SHA256 = "8c7230f0bf586e9297dc0e568bd19278aeeb7cff8dbb3dde150811f11393218a"
REVIEWED_BRIDGE_BUILD_ID = "b0562d538761373e2f1025c8bc8d8188ff8a0c40"
TARGET_PART = "xcvu33p-fsvh2104-2-e"
EXPECTED_CANARY = {
    "name": "FK0957",
    "card_id": "153300000957",
    "adapter_id": "153300000957A",
    "usb_serial": "153300000957",
    "idcode": "04b69093",
    "historical_fpga_dna": "4000000001295d813c80a445",
    "target_part": TARGET_PART,
    "authorized_card_count": 1,
}


def _git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"immutable local Git object unavailable: {' '.join(args)}") from exc


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _relative_git_path(value: str, repo: Path) -> str:
    p = Path(value)
    if p.is_absolute():
        external_prefix = "/home/rmann/project-sidecar-phk2-v5_1-common-reset-20261110/"
        if value.startswith(external_prefix):
            return value[len(external_prefix):]
        try:
            return p.resolve().relative_to(repo.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError(f"checksum path escapes repository: {value}") from exc
    clean = PurePosixPath(value.lstrip("* ")).as_posix()
    if clean.startswith("../") or clean == "..":
        raise ValueError(f"checksum path escapes repository: {value}")
    return clean


def verify_envelope(repo: Path, *, verify_all: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    sums_raw = _git(repo, "show", f"{ENVELOPE_COMMIT}:{SUMS_PATH}")
    if _sha(sums_raw) != SUMS_SHA256:
        raise ValueError("immutable TCK envelope SHA256SUMS identity mismatch")
    envelope_raw = _git(repo, "show", f"{ENVELOPE_COMMIT}:{ENVELOPE_PATH}")
    if _sha(envelope_raw) != ENVELOPE_SHA256:
        raise ValueError("immutable TCK envelope JSON identity mismatch")
    try:
        envelope = json.loads(envelope_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("immutable TCK envelope JSON is malformed") from exc

    rows: list[tuple[str, str]] = []
    for line in sums_raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        digest, path = line.split(None, 1)
        if len(digest) != 64:
            raise ValueError("TCK envelope checksum row is malformed")
        rows.append((digest.lower(), _relative_git_path(path, repo)))
    if len(rows) != 733:
        raise ValueError(f"expected 733 immutable envelope evidence entries, found {len(rows)}")
    if verify_all:
        for digest, path in rows:
            if _sha(_git(repo, "show", f"{ENVELOPE_COMMIT}:{path}")) != digest:
                raise ValueError(f"TCK envelope evidence hash mismatch: {path}")

    identity = envelope.get("identity", {})
    limits = envelope.get("envelope", {})
    if (envelope.get("artifact_ready") is not True or envelope.get("analysis_only") is not True or
            envelope.get("additional_offline_analysis_required") is not False):
        raise ValueError("TCK envelope is not complete routed analysis evidence")
    exact_identity = {
        "source_commit": SOURCE_COMMIT,
        "source_tree_hash": SOURCE_TREE,
        "routed_dcp_sha256": ROUTED_DCP_SHA256,
        "qualification_commit": ENVELOPE_QUALIFICATION_COMMIT,
        "target_part": TARGET_PART,
    }
    if any(identity.get(key) != value for key, value in exact_identity.items()):
        raise ValueError("TCK envelope is bound to a different source, route, qualification, or part")
    expected_limits = {
        "qualified_tck_min_hz": (5_000_000, "PROVEN_TESTED_RECTANGLE_ENDPOINTS"),
        "qualified_tck_max_hz": (40_000_000, "PROVEN_TESTED_RECTANGLE_ENDPOINTS"),
        "qualified_period_min_ns": (25.0, "PROVEN_TESTED_RECTANGLE_ENDPOINTS"),
        "qualified_period_max_ns": (200.0, "PROVEN_TESTED_RECTANGLE_ENDPOINTS"),
        "qualified_high_ns_min": (10.0, "PROVEN_TESTED_RECTANGLE_CORNERS"),
        "qualified_low_ns_min": (10.0, "PROVEN_TESTED_RECTANGLE_CORNERS"),
        "qualified_duty_cycle_min": (0.4, "PROVEN_TESTED_RECTANGLE_CORNERS"),
        "qualified_duty_cycle_max": (0.6, "PROVEN_TESTED_RECTANGLE_CORNERS"),
    }
    for key, (value, status) in expected_limits.items():
        item = limits.get(key)
        if not isinstance(item, dict) or item.get("value") != value or item.get("status") != status:
            raise ValueError(f"TCK envelope limit missing or mismatched: {key}")
    for flag in ("frequency_limit_qualified", "high_time_limit_qualified",
                 "low_time_limit_qualified", "duty_cycle_limit_qualified"):
        if limits.get(flag) is not True:
            raise ValueError(f"TCK envelope qualification flag is false: {flag}")
    if limits.get("jitter_limit_qualified") is not False or envelope.get("physical_measurement_still_required") is not True:
        raise ValueError("TCK envelope must preserve unqualified jitter and required physical measurement")
    if limits.get("physical_host_tck_contract_proven") is not False:
        raise ValueError("routed timing analysis must not promote physical host TCK")
    return envelope, {"sha256sums_entries": len(rows), "sha256sums_valid": True,
                      "envelope_json_sha256": ENVELOPE_SHA256,
                      "sha256sums_sha256": SUMS_SHA256}


def build_plan(repo: Path, *, verify_all: bool = True) -> dict[str, Any]:
    envelope, integrity = verify_envelope(repo, verify_all=verify_all)
    binding = verify_immutable_v51(repo)
    if (binding.case_a["case_id"] != CASE_A_ID or binding.case_b["case_id"] != CASE_B_ID):
        raise ValueError("v5.1 qualification case IDs changed")
    e = envelope["envelope"]
    prerequisites = [
        {"id": "AUTHORIZATION_TRUST_ROOT", "ready": False,
         "reason": "No operator-approved signing trust root is pinned in this worktree."},
        {"id": "DEPLOYED_BRIDGE_MATCH", "ready": False,
         "reason": "Static bridge identity is pinned, but current remote process ELF/service-config identity is not freshly attested."},
        {"id": "REAL_CAPTURE_BACKEND", "ready": False,
         "reason": "No instrument acquisition backend is installed; the private transport opener refuses."},
        {"id": "EFFECTIVE_5MHZ_CLOCK_CONTROL", "ready": False,
         "reason": "Reviewed SQRL/XVC settck echoes the request without configuring MPSSE; no effective 5 MHz setter is installed."},
        {"id": "PHYSICAL_JITTER_LIMIT", "ready": False,
         "reason": "The routed envelope explicitly marks physical jitter limit unqualified."},
        {"id": "LIVE_CARD_ADAPTER_ATTESTATION", "ready": False,
         "reason": "Historical FK0957 mapping exists; current v5.1 live card observation is still required."},
        {"id": "BSCAN_INTERNAL_OBSERVATION_METHOD", "ready": False,
         "reason": "The matrix requires physical TCK/BSCAN correlation; IDCODE-only evidence cannot attest internal USER-branch behavior, and no separately authorized read-only BSCAN observer is defined."},
        {"id": "CASE_B_EXACT_METHOD_AUTHORIZATION", "ready": False,
         "reason": "The authenticated matrix does not authorize a USER instruction; no case-bound authorization or exact USER3 transaction is pinned."},
    ]
    return {
        "schema": "PHK2-FK0957-PHYSICAL-CANARY-PLAN-v1",
        "mode": "OFFLINE_PREPARATION_ONLY",
        "execution_enabled": False,
        "physical_canary_readiness": "FAIL",
        "qualification": {
            "offline_pass": "38/40",
            "case_a": {"id": CASE_A_ID, "name": binding.case_a["case"], "status": "UNQUALIFIED"},
            "case_b": {"id": CASE_B_ID, "name": binding.case_b["case"], "status": "UNQUALIFIED"},
            "promotion_requires_authentic_physical_evidence": True,
        },
        "immutable_tck_envelope": {
            "commit": ENVELOPE_COMMIT,
            "path": ENVELOPE_PATH,
            "qualification_commit": ENVELOPE_QUALIFICATION_COMMIT,
            "source_commit": SOURCE_COMMIT,
            "source_tree_hash": SOURCE_TREE,
            "routed_dcp_sha256": ROUTED_DCP_SHA256,
            "limits": {
                "tck_min_hz": 5_000_000,
                "tck_max_hz": 40_000_000,
                "period_min_ns": 25.0,
                "period_max_ns": 200.0,
                "high_ns_min": 10.0,
                "low_ns_min": 10.0,
                "duty_cycle_min_percent": 40.0,
                "duty_cycle_max_percent": 60.0,
                "jitter_numeric_limit_ns": None,
                "jitter_status": "NOT_QUALIFIED",
            },
            **integrity,
        },
        "reviewed_bridge_identity": {"sha256": REVIEWED_BRIDGE_SHA256, "build_id": REVIEWED_BRIDGE_BUILD_ID,
                                    "current_deployment_attested": False},
        "one_card_scope": EXPECTED_CANARY,
        "first_requested_tck": {
            "target_hz": 5_000_000,
            "period_ns": 200.0,
            "target_duty_cycle_percent": 50.0,
            "target_high_ns": 100.0,
            "target_low_ns": 100.0,
            "status": "PLAN_ONLY_EFFECTIVE_RATE_UNPROVEN",
            "control_rule": "Do not rely on XVC settck readback. A reviewed adapter clock-control path must set this rate before the first scan; measured TCK must confirm it remains inside the envelope.",
        },
        "case_a_measurement": {
            "measurement_point": "identified adapter TCK/SK output at the JTAG connector, referenced to the adapter ground, using the exact physical pinout for the authorized adapter revision",
            "capture": "single-shot raw waveform, trigger on first rising TCK edge; 1 us pre-trigger and 20 us post-trigger; capture exactly one bounded 87-TCK scan and its idle tail",
            "raw_format": "Preserve instrument-native acquisition plus lossless CSV sample_index,timestamp_ns,logic_level derived using documented voltage thresholds; retain calibration, instrument/probe IDs, bandwidth, sample rate, threshold, coupling, timebase, channel and acquisition metadata.",
            "acceptance": {
                "every_period_ns": "25.0 <= period <= 200.0",
                "every_high_ns": "high >= 10.0",
                "every_low_ns": "low >= 10.0",
                "every_duty_cycle_percent": "40.0 <= duty <= 60.0",
                "jitter": "Compute min/max, peak-to-peak and RMS from raw edges. No numeric PASS limit exists; Case A cannot pass until a qualified jitter limit and capture-instrument uncertainty rule are bound.",
                "waveform_stability": "Reject missing/extra edges, non-monotonic samples, clipped/saturated captures, invalid thresholds, unstable period/pulse metrics, summary/raw mismatch, or incomplete capture.",
            },
            "settck_echo_is_measurement": False,
        },
        "case_b_sequence": {
            "matrix_case_id": CASE_B_ID,
            "routed_clock_interaction_criterion": binding.case_b["matrix_detail"],
            "approved_baseline_sequence": "TAP reset, six-bit IDCODE instruction 0x09, 64-bit DR capture per the pinned PHK2 parser (87 TCK total), finish Run-Test/Idle; capture the same physical waveform and semantic TAP transcript.",
            "baseline_limit": "This IDCODE-only scan and adapter waveform do not by themselves prove internal BSCAN USER-branch behavior or clear the matrix's unsafe clock-interaction row.",
            "internal_observation": "Blocked pending a matrix-approved, case-bound read-only method and exact expected observations; do not guess an instruction opcode or select USER1/USER2/USER3.",
            "fpga_programming": False,
            "workload_change": False,
            "user_instructions_authorized": False,
        },
        "preflight_gates": [
            "Verify exact immutable qualification and TCK-envelope commits/hashes.",
            "One-card-only signed authorization bound to FK0957, the v5.1 source/tree/route, bridge, cases 40 and 33, session nonce, expiry and operator.",
            "Verify expected adapter serial 153300000957A and card ID 153300000957 from independent signed live evidence; IDCODE 04b69093 is family identification only, not unique identity.",
            "Match expected historical FPGA DNA 4000000001295d813c80a445 and xcvu33p-fsvh2104-2-e; if live DNA/card mapping cannot be established before transport, refuse.",
            "Verify exact deployed bridge ELF/build/service-config hash and effective clock-control implementation; settck echo is not proof.",
            "Process/socket-only peer exclusion, one listener, zero existing clients, no competing XVC/JTAG process, exclusive OS lock, and signed network ACL proof; no protocol probe during preflight.",
            "Capture backend, calibrated instrument metadata, evidence journal directory, append-only/hash-chain, fsync and rollback/recovery checks all ready before transport.",
        ],
        "abort_conditions": [
            "Any identity/hash/config/authorization/peer/lock mismatch or stale evidence.",
            "Any measured TCK period, high/low width or duty cycle outside the qualified rectangle; any unbounded/missing jitter policy.",
            "Any unexpected TAP state/response/instruction, USER or configuration instruction, extra/missing clock, malformed capture, or transport disconnect.",
            "Any workload/configuration/image change, second client, reconnect, journal write/fsync failure, or ambiguity in completion/idle state.",
        ],
        "rollback_recovery": {
            "test_mutates_fpga_image": False,
            "test_mutates_workload": False,
            "normal_close": "Return TAP to Run-Test/Idle, stop after the bounded scan, close the single transport, verify zero sessions, seal evidence, then release peer exclusion/lock.",
            "failure": "Abort immediately; do not retry, reconnect, program, reset the FPGA, restart/stop services or miners. Preserve the lock and evidence; require separate authorized recovery if transport/TAP idle or image/workload preservation cannot be proven.",
            "image_restore": "No programming rollback is part of this test. Any image discrepancy is a stop-and-escalate condition for a separately authorized recovery procedure.",
        },
        "prerequisites": prerequisites,
        "remaining_prerequisites": [row["id"] for row in prerequisites if not row["ready"]],
        "physical_evidence_passes": {CASE_A_ID: False, CASE_B_ID: False},
        "hardware_access_count": 0,
        "live_xvc_connections": 0,
        "jtag_transactions": 0,
        "fpga_program_attempts": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--skip-all-sum-entry-check", action="store_true",
                        help="verify the pinned manifest/envelope only; never enables execution")
    args = parser.parse_args()
    try:
        plan = build_plan(args.repo.resolve(), verify_all=not args.skip_all_sum_entry_check)
    except Exception as exc:
        print(json.dumps({"schema": "PHK2-FK0957-PHYSICAL-CANARY-PLAN-v1",
                          "physical_canary_readiness": "FAIL",
                          "execution_enabled": False, "refusal": str(exc)}, indent=2))
        return 2
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
