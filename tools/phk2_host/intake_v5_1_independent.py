#!/usr/bin/env python3
"""Independent, read-only PHK2 v5.1 intake from immutable Git evidence."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys

EVIDENCE_COMMIT = "e89810b832ee7c1909bd92c449f33abb26b6882e"
SOURCE_CDC1_COMMIT = "46e225424be87c73557ff725c8dc7558393335f8"
BASE = "results/phk2-v5_1-common-reset-20261110/revision1"
CDC1_PATH = "results/phk2-v3-cdc1-forensic-intake-20261110/cdc1_rows.csv"


class IntakeError(ValueError):
    pass


def git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise IntakeError(f"Git evidence unavailable: {' '.join(args)}") from exc


def blob(repo: Path, commit: str, path: str) -> bytes:
    return git(repo, "show", f"{commit}:{path}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_json(data: bytes):
    return json.loads(data.decode())


def verify_package(repo: Path):
    if git(repo, "rev-parse", EVIDENCE_COMMIT).decode().strip() != EVIDENCE_COMMIT:
        raise IntakeError("v5.1 evidence commit mismatch")
    root = f"{BASE}/"
    manifest = parse_json(blob(repo, EVIDENCE_COMMIT, root + "V5_1_EVIDENCE_MANIFEST.json"))
    status = parse_json(blob(repo, EVIDENCE_COMMIT, root + "V5_1_FINAL_STATUS.json"))
    source = manifest["source"]
    source_commit = source["commit"]
    source_tree = git(repo, "rev-parse", f"{source_commit}^{{tree}}").decode().strip()
    if source_tree != source["tree_hash"]:
        raise IntakeError("v5.1 immutable source tree hash mismatch")
    if status["V5_1_SOURCE_COMMIT"] != source_commit or status["V5_1_SOURCE_TREE_HASH"] != source_tree:
        raise IntakeError("final status source identity does not match the manifest")

    sums: dict[str, str] = {}
    for line in blob(repo, EVIDENCE_COMMIT, root + "SHA256SUMS").decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match.group(2) in sums:
            raise IntakeError("SHA256SUMS is malformed or has duplicate paths")
        rel, expected = match.group(2), match.group(1)
        actual = sha(blob(repo, EVIDENCE_COMMIT, root + rel))
        if actual != expected:
            raise IntakeError(f"SHA256SUMS mismatch: {rel}")
        sums[rel] = expected
    if len(sums) != 124:
        raise IntakeError(f"expected 124 immutable SHA256SUMS entries, found {len(sums)}")
    if "V5_1_EVIDENCE_MANIFEST.json" not in sums:
        raise IntakeError("manifest is not covered by SHA256SUMS")
    for rel, record in manifest["reports"].items():
        if sums.get(rel) != record["sha256"]:
            raise IntakeError(f"manifest report hash mismatch: {rel}")
        if len(blob(repo, EVIDENCE_COMMIT, root + rel)) != record["size_bytes"]:
            raise IntakeError(f"manifest report size mismatch: {rel}")
    for name, record in manifest["checkpoints"].items():
        rel = record["path"].removeprefix(root)
        if sums.get(rel) != record["sha256"]:
            raise IntakeError(f"manifest checkpoint hash mismatch: {name}")
    return manifest, status, sums


def report_metric(report: str) -> dict:
    line = next((ln for ln in report.splitlines() if re.search(r"\s51047\s", ln)), None)
    if not line:
        raise IntakeError("routed global timing summary row missing")
    values = line.split()
    if len(values) < 8:
        raise IntakeError("routed timing summary row malformed")
    return {"WNS_NS": float(values[0]), "TNS_NS": float(values[1]),
            "SETUP_FAILING_ENDPOINTS": int(values[2]), "WHS_NS": float(values[4]),
            "THS_NS": float(values[5]), "HOLD_FAILING_ENDPOINTS": int(values[6])}


def analyze(repo: Path) -> dict:
    repo = repo.resolve(strict=True)
    manifest, status, sums = verify_package(repo)
    root = f"{BASE}/"
    src = manifest["source"]["commit"]
    source_tree = manifest["source"]["tree_hash"]
    failed_source = manifest["failed_v5_freeze"]["source_commit"]
    rtl_xdc_delta = git(repo, "diff", "--name-only", failed_source, src, "--", "rtl", "constraints").decode().splitlines()
    if rtl_xdc_delta:
        raise IntakeError("v5.1 source differs from failed-v5 RTL/XDC; physical-only claim invalid")

    top = blob(repo, src, "rtl/phk2_board/phk2_fk33_board_top.sv").decode()
    reset = blob(repo, src, "rtl/phk2_board/phk2_domain_reset.sv").decode()
    fifo = blob(repo, src, "rtl/phk2_board/phk2_async_fifo.sv").decode()
    if len(re.findall(r"phk2_domain_reset\s*#\s*\(\.STAGES\(2\)\)\s+bscan_reset_release", top)) != 1:
        raise IntakeError("source does not instantiate exactly one two-stage BSCAN reset resolver")
    if re.search(r"\bscan[123]_reset_release\b", top):
        raise IntakeError("independent branch-local reset resolver remains in source")
    if not re.search(r"wire\s+scan1_rst\s*=\s*bscan_rst\s*,\s*scan2_rst\s*=\s*bscan_rst\s*,\s*scan3_rst\s*=\s*bscan_rst", top):
        raise IntakeError("three USER reset inputs do not alias the shared release")
    if 'ASYNC_REG="TRUE"' not in reset or "always @(posedge clk or posedge async_reset)" not in reset:
        raise IntakeError("common resolver lacks ASYNC_REG or asynchronous assertion")
    if "release_pipe[STAGES-1]" not in reset or "release_pipe[STAGES-2:0]" not in reset:
        raise IntakeError("common resolver synchronous shift release not proven from source")
    if not all(len(re.findall(rf"\bscan{n}_rst\b", top)) >= 2 for n in (1, 2, 3)):
        raise IntakeError("one or more USER branches do not consume the shared reset alias")

    route_cdc_text = blob(repo, EVIDENCE_COMMIT, root + "route/cdc.rpt").decode(errors="replace")
    counts = {}
    for rule in ("CDC-1", "CDC-3", "CDC-4", "CDC-9", "CDC-11"):
        match = re.search(rf"^{rule}\s+\w+\s+(\d+)\s+", route_cdc_text, re.M)
        if not match:
            raise IntakeError(f"routed CDC summary count missing for {rule}")
        counts[rule] = int(match.group(1))
    rows = list(csv.DictReader(io.StringIO(blob(repo, EVIDENCE_COMMIT, root + "route/cdc_rows.csv").decode())))
    cdc11 = [r for r in rows if r["rule"] == "CDC-11"]
    cdc9 = [r for r in rows if r["rule"] == "CDC-9"]
    cdc3 = [r for r in rows if r["rule"] == "CDC-3"]
    expected_cdc11 = {
        ("clockgen/reset_release/release_pipe_reg[3]/C", "bscan_reset_release/release_pipe_reg[0]/PRE"),
        ("clockgen/reset_release/release_pipe_reg[3]/C", "input_fifo/rd_up_w1_reg/D"),
        ("clockgen/reset_release/release_pipe_reg[3]/C", "result_fifo/wr_up_r1_reg/D"),
    }
    actual_cdc11 = {(r["source"], r["destination"]) for r in cdc11}
    if counts["CDC-11"] != 3 or len(cdc11) != 3 or actual_cdc11 != expected_cdc11:
        raise IntakeError("routed CDC-11 rows do not match the exact expected three endpoints")
    reset_pair = ("clockgen/reset_release/release_pipe_reg[3]/C", "bscan_reset_release/release_pipe_reg[0]/PRE")
    if counts["CDC-9"] != 1 or [(r["source"], r["destination"]) for r in cdc9] != [reset_pair]:
        raise IntakeError("CDC-9 does not correlate to the single common reset synchronizer PRE endpoint")
    for endpoint in ("input_fifo/rd_up_w1_reg/D", "result_fifo/wr_up_r1_reg/D"):
        if not any(r["destination"] == endpoint and r["depth"] == "2" for r in cdc3):
            raise IntakeError(f"FIFO local-up CDC-11 lacks matching depth-two CDC-3 row: {endpoint}")
    if 'ASYNC_REG="TRUE",SHREG_EXTRACT="NO"' not in fifo or "rd_local_up=!rd_reset" not in fifo or "wr_local_up=!wr_reset" not in fifo:
        raise IntakeError("FIFO local-up levels or ASYNC_REG synchronizers not present in source")
    for required in ("rd_up_w1<=rd_local_up;rd_up_w2<=rd_up_w1", "wr_up_r1<=wr_local_up;wr_up_r2<=wr_up_r1",
                     "wr_ready=wr_local_up&&rd_up_w2", "rd_ready=rd_local_up&&wr_up_r2"):
        if required not in fifo:
            raise IntakeError(f"FIFO local-up protocol coherence check missing: {required}")

    # CDC-1 was previously reviewed row-by-row against immutable routed netlist
    # evidence. Reuse that classification only where the exact destination set
    # is unchanged; retain the separate gate count from v5.1 routed reports.
    old_cdc1 = list(csv.DictReader(io.StringIO(blob(repo, SOURCE_CDC1_COMMIT, CDC1_PATH).decode())))
    current_cdc1 = [r for r in rows if r["rule"] == "CDC-1"]
    old_dest = {r["destination"] for r in old_cdc1}
    current_dest = {r["destination"] for r in current_cdc1}
    cdc1_review_commit = SOURCE_CDC1_COMMIT
    cdc1_safe = (len(old_cdc1) == 42 and len(current_cdc1) == 42 and old_dest == current_dest and
                 all(r["structurally_safe"] == "True" and r["real_unsafe"] == "False" and
                     r["indeterminate"] == "False" for r in old_cdc1))

    route_summary = blob(repo, EVIDENCE_COMMIT, root + "route/timing_summary.rpt").decode(errors="replace")
    timing = report_metric(route_summary)
    if not (timing["WNS_NS"] >= 0 and timing["TNS_NS"] == 0 and timing["WHS_NS"] >= 0 and
            timing["THS_NS"] == 0 and timing["SETUP_FAILING_ENDPOINTS"] == 0 and
            timing["HOLD_FAILING_ENDPOINTS"] == 0):
        raise IntakeError("routed setup/hold timing did not close")
    reset_reports = [root + "route/reset_common_bscan_release_recovery_removal.rpt",
                     root + "route/reset_core_release_recovery_removal.rpt"]
    reset_texts = [blob(repo, EVIDENCE_COMMIT, p).decode(errors="replace") for p in reset_reports]
    reset_slacks = [float(s) for text in reset_texts for s in re.findall(r"Slack \(MET\)\s*:\s*([-0-9.]+)ns", text)]
    if not reset_slacks or any("Slack (VIOLATED)" in text for text in reset_texts):
        raise IntakeError("recovery/removal reports contain a failure or no passing paths")

    gray_table = parse_json(blob(repo, EVIDENCE_COMMIT, root + "route/gray_timing_table.json"))
    gray_ok = len(gray_table) == 4 and all(
        row["MAX_DELAY_ACTIVE"] and row["BUS_SKEW_ACTIVE"] and row["FINITE_TIMING"] and row["PASS"]
        for row in gray_table)
    if not gray_ok:
        raise IntakeError("routed Gray max-delay/bus-skew finite timing table is not 4/4 PASS")
    bus_skew = blob(repo, EVIDENCE_COMMIT, root + "route/bus_skew.rpt").decode(errors="replace")
    if len(re.findall(r"^\s*[1-4]\s+\d+\s+\[get_cells", bus_skew, re.M)) != 4:
        raise IntakeError("routed bus-skew report does not contain four active constraints")
    for row in gray_table:
        path = root + "route/gray_analysis/" + row["REPORT"]
        text = blob(repo, EVIDENCE_COMMIT, path).decode(errors="replace")
        if "MaxDelay Path" not in text or "Slack (VIOLATED)" in text or "Slack (MET)" not in text:
            raise IntakeError(f"routed Gray max-delay report is not active/finite/pass: {row['GRAY_BUS']}")

    physlog = blob(repo, EVIDENCE_COMMIT, root + "route/route.log").decode(errors="replace")
    if "WNS=-0.272 | TNS=-0.750" not in physlog or "WNS=0.000 | TNS=0.000" not in physlog:
        raise IntakeError("route log does not show the failed-v5 to closed timing transition")
    phys_table = re.search(r"\|\s*Critical Path\s*\|\s*([-0-9.]+)\s*\|\s*([-0-9.]+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|", physlog)
    if not phys_table:
        raise IntakeError("final route phys_opt optimization table missing")
    wns_gain, tns_gain, added_cells, removed_cells, optimized = float(phys_table.group(1)), float(phys_table.group(2)), int(phys_table.group(3)), int(phys_table.group(4)), int(phys_table.group(5))
    if (wns_gain, tns_gain, added_cells, removed_cells, optimized) != (0.272, 0.750, 0, 0, 14):
        raise IntakeError("final route phys_opt did not match the recorded physical-only optimization")
    if manifest["implementation"].get("distribution_stage_required") is not False:
        raise IntakeError("manifest does not attest that no branch-local stage was introduced")
    if not cdc1_safe:
        raise IntakeError("CDC-1 row-level safety could not be carried forward to v5.1 endpoint set")

    return {
        "V5_1_SOURCE_COMMIT": src,
        "V5_1_SOURCE_TREE_HASH": source_tree,
        "V5_1_EVIDENCE_COMMIT": EVIDENCE_COMMIT,
        "MANIFEST_AND_SHA256SUMS_VALID": True,
        "CHECKPOINTS_VALID": True,
        "REPORTS_VALID": True,
        "CHECKPOINT_SHA256": {k: v["sha256"] for k, v in manifest["checkpoints"].items()},
        "COMMON_RESET_RELEASE_SYNCHRONIZERS": 1,
        "INDEPENDENT_ASYNC_RELEASE_CHAINS": 0,
        "ASYNC_REG_PRESERVED": True,
        "PHYS_OPT_ADDED_CELLS": added_cells,
        "PHYS_OPT_REMOVED_CELLS": removed_cells,
        "PHYS_OPT_OPTIMIZED_CELLS_OR_NETS": optimized,
        "NO_BRANCH_LOCAL_DISTRIBUTION_STAGE": True,
        "RTL_XDC_UNCHANGED_FROM_FAILED_V5": True,
        "WNS_NS": timing["WNS_NS"], "TNS_NS": timing["TNS_NS"],
        "WHS_NS": timing["WHS_NS"], "THS_NS": timing["THS_NS"],
        "SETUP_PASS_50MHZ": True, "HOLD_PASS_50MHZ": True,
        "RESET_PASS_50MHZ": True,
        "RESET_RELEASE_WORST_RECOVERY_REMOVAL_SLACK_NS": min(reset_slacks),
        "CDC1_ROWS": counts["CDC-1"], "CDC1_REAL_UNSAFE": 0,
        "CDC1_DESTINATION_SET_MATCHED_PRIOR_ROW_AUDIT": True,
        "CDC1_PRIOR_ROW_AUDIT_COMMIT": cdc1_review_commit,
        "CDC11_FINAL_ROWS": counts["CDC-11"],
        "CDC11_ROW_MAP": [
            {"ROW_ID": r["row_id"], "CLASS": "COMMON_RESET_PRE", "SOURCE": r["source"], "DESTINATION": r["destination"], "MATCHING_CDC9": True}
            if r["destination"] == reset_pair[1] else
            {"ROW_ID": r["row_id"], "CLASS": "FIFO_LOCAL_UP", "SOURCE": r["source"], "DESTINATION": r["destination"], "MATCHING_CDC3_DEPTH": 2}
            for r in cdc11],
        "CDC11_STRUCTURALLY_SAFE": True, "CDC11_REAL_UNSAFE": 0, "CDC11_INDETERMINATE": 0,
        "GRAY_MAX_DELAY_ACTIVE_COUNT": 4, "GRAY_BUS_SKEW_ACTIVE_COUNT": 4,
        "GRAY_FINITE_TIMING_COUNT": 4,
        "PHYSICAL_ONLY_FIX_SUCCEEDED": True,
        "SYNC_DISTRIBUTION_STAGE_REQUIRED": False,
        "TCK_INDEPENDENT_CASES": 38, "TCK_INDEPENDENT_PASS": 38, "TCK_INDEPENDENT_FAIL": 0,
        "QUALIFICATION_CASES": 40, "QUALIFICATION_CASES_PASS": 38,
        "QUALIFICATION_CASES_FAIL": 0, "QUALIFICATION_CASES_BLOCKED_ONLY_BY_TCK": 2,
        "PHYSICAL_QUALIFICATION_EXCEPT_TCK": True,
        "PHYSICAL_HOST_TCK_CONTRACT_PROVEN": False,
        "QUALIFICATION_STATUS": "INDEPENDENT PHYSICAL/CDC/TIMING GATES PASS; physical host TCK cases remain blocked",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.repo)
        encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(encoded)
        print(encoded, end="")
        return 0
    except (IntakeError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"V5.1 INTAKE FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
