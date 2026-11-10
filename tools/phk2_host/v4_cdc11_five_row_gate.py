#!/usr/bin/env python3
"""Strict offline gate for the immutable PHK2 v4 five-row CDC-11 bundle.

Reads committed Git objects only. It never checks out the implementation
commit or invokes Vivado, hardware, USB, XVC, or JTAG.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

EVIDENCE_COMMIT = "6b0080dcd82daef773c7a83235e4ede5fe1df31d"
SOURCE_COMMIT = "5a6ceadb8fc2eb6d972b5d338b507ab0b5296a2a"
EVIDENCE_DIR = "results/phk2-v4-reset-correction-20261110/revision2"
ROWS_FILE = f"{EVIDENCE_DIR}/v4_cdc11_rows.csv"
SUMMARY_FILE = f"{EVIDENCE_DIR}/v4_final.json"
REPORT_FILE = f"{EVIDENCE_DIR}/v4_final_report.md"
XDC_FILE = f"{EVIDENCE_DIR}/v4_targeted_constraints.xdc"
SOURCE_TREE = "18139976ecd88843c93a43d3f8bb08659049307b"
EXPECTED_DCP = "853af691b7ab1d8e8ac8b108e5a13fba6c2c5a4e357171caf99c2154ad45d400"


class Refusal(ValueError):
    pass


def git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Refusal(f"cannot read required Git object: {' '.join(args)}") from exc


def blob(root: Path, commit: str, path: str) -> bytes:
    return git(root, "show", f"{commit}:{path}")


def tree_hash(root: Path, commit: str) -> str:
    return git(root, "rev-parse", f"{commit}^{{tree}}").decode().strip()


def infer(row: dict[str, str]) -> str:
    dst = row["DESTINATION"]
    if re.fullmatch(r"scan[123]_reset_release/release_pipe_reg\[0\]/PRE", dst):
        return "RESET_RELEASE"
    if dst in ("input_fifo/rd_up_w1_reg/D", "result_fifo/wr_up_r1_reg/D"):
        return "FIFO_LOCAL_UP_HANDSHAKE"
    # Deliberately do not classify based on the supplied TOPOLOGY column.
    return "OTHER"


def analyze(root: Path) -> dict:
    root = root.resolve(strict=True)
    if git(root, "rev-parse", EVIDENCE_COMMIT).decode().strip() != EVIDENCE_COMMIT:
        raise Refusal("evidence commit object identity mismatch")
    if tree_hash(root, SOURCE_COMMIT) != SOURCE_TREE:
        raise Refusal("v4 source tree identity mismatch")
    if git(root, "rev-parse", f"{EVIDENCE_COMMIT}^1").decode().strip() != "3c120c8b861880a14abc162c1a7b396243bdac55":
        raise Refusal("evidence commit ancestry mismatch")
    summary = json.loads(blob(root, EVIDENCE_COMMIT, SUMMARY_FILE))
    report = blob(root, EVIDENCE_COMMIT, REPORT_FILE).decode()
    xdc = blob(root, EVIDENCE_COMMIT, XDC_FILE).decode()
    rows_text = blob(root, EVIDENCE_COMMIT, ROWS_FILE).decode()
    if summary.get("v4_commit") != SOURCE_COMMIT or summary.get("v4_tree_hash") != SOURCE_TREE:
        raise Refusal("summary source identity differs from immutable source commit")
    if summary.get("routed_dcp_sha256") != EXPECTED_DCP:
        raise Refusal("reported routed DCP identity mismatch")
    reader = csv.DictReader(rows_text.splitlines())
    rows = list(reader)
    if len(rows) != 5 or summary.get("cdc11_rows_after") != 5 or summary.get("cdc11_critical_after") != 5:
        raise Refusal(f"strict gate requires exactly five routed CDC-11 rows, got {len(rows)}")
    if [int(r["ROW"]) for r in rows] != [1, 2, 3, 4, 5] or any(r["RULE"] != "CDC-11" for r in rows):
        raise Refusal("row IDs/rules are incomplete, duplicated, or not CDC-11")
    expected_endpoints = {
        "input_fifo/rd_up_w1_reg/D", "result_fifo/wr_up_r1_reg/D",
        "scan1_reset_release/release_pipe_reg[0]/PRE",
        "scan2_reset_release/release_pipe_reg[0]/PRE",
        "scan3_reset_release/release_pipe_reg[0]/PRE",
    }
    if {r["DESTINATION"] for r in rows} != expected_endpoints:
        raise Refusal("five CDC-11 destinations are not the exact independently reviewed endpoints")
    if any(r["SOURCE"] != "clockgen/reset_release/release_pipe_reg[3]/C" for r in rows):
        raise Refusal("CDC-11 source fanout identity differs across rows")

    fifo = blob(root, SOURCE_COMMIT, "rtl/phk2_board/phk2_async_fifo.sv").decode()
    reset = blob(root, SOURCE_COMMIT, "rtl/phk2_board/phk2_domain_reset.sv").decode()
    top = blob(root, SOURCE_COMMIT, "rtl/phk2_board/phk2_fk33_board_top.sv").decode()
    # Confirm exact destinations against source-declared synchronizer and reset
    # structures. Classification comes from endpoint identity, not metadata.
    if not all(s in fifo for s in ("rd_up_w1", "rd_up_w2", "wr_up_r1", "wr_up_r2",
                                   "rd_local_up", "wr_local_up", "wr_ready", "rd_ready")):
        raise Refusal("FIFO local-up source structure does not corroborate endpoints")
    if 'ASYNC_REG="TRUE"' not in fifo or "rd_up_w1<=rd_local_up" not in fifo or "wr_up_r1<=wr_local_up" not in fifo:
        raise Refusal("FIFO handshake synchronizer attributes/level transfers unproven")
    if 'ASYNC_REG="TRUE"' not in reset or "posedge async_reset" not in reset or "posedge clk" not in reset:
        raise Refusal("reset source does not prove async assertion and clocked release")
    if not all(f"scan{i}_reset_release" in top for i in range(1, 4)):
        raise Refusal("three reset release instances are not present in immutable source")

    classified = {"RESET_RELEASE": [], "FIFO_LOCAL_UP_HANDSHAKE": [],
                  "CONTROL": [], "DATA": [], "OTHER": []}
    for row in rows:
        category = infer(row)
        row["INDEPENDENT_CLASSIFICATION"] = category
        classified[category].append(row)

    # Source-level protocol review: both local-up indications are levels; each
    # has two destination-clock stages; ready/empty/full and pointer state are
    # gated by a single synchronized copy within the owning FIFO domain.
    fifo_protocol = {
        "source_domain": "core_clk (core_rst release)",
        "destination_domains": {"input_fifo/rd_up_w1": "tck2", "result_fifo/wr_up_r1": "tck1"},
        "signal_type": "level (local_up = !local_reset)",
        "stages": 2,
        "reconvergence": "one synchronized value per FIFO direction; used in local ready/empty/full and pointer gating",
        "divergent_copies": False,
        "startup_inconsistent_fifo_state": False,
        "source_review_only": True,
    }
    # Five endpoints are present in the committed normalized inventory, but
    # raw routed CDC/clock/reset reports are absent from that commit. The XDC
    # applies one bscan_tck clock object to all three INTERNAL_TCK pins. Thus
    # the claimed independent domain roots/periods cannot be proven here.
    raw_report_paths = [x for x in ("report_cdc", "reset_bscan1_release_recovery_removal.rpt")
                        if x in git(root, "ls-tree", "-r", "--name-only", EVIDENCE_COMMIT).decode()]
    exact_clock_inventory = bool(re.search(r"report_clocks|CLOCK_ROOT|SOURCE_PINS", report))
    reported_domains = summary.get("destination_clock_domains", [])
    same_domain_duplicates = "INDETERMINATE"  # no routed root/relationship inventory
    reset_proof = {
        "async_assert_source_proven": True,
        "sync_deassert_source_proven": True,
        "async_reg_source_proven": True,
        "stage_count_source_and_bundle": 2,
        "one_chain_per_named_tck": len(classified["RESET_RELEASE"]) == 3,
        "same_domain_consumer_release_sharing": "source summary only; routed net fanout inventory absent",
        "recovery_removal": "summary asserts pass; raw routed reports absent",
        "stopped_clock_behavior": "RTL semantics and summary assert safe; raw mapped endpoint proof absent",
    }
    # Explicit detect that v4 XDC models all pins under one shared clock object.
    shared_clock_model = bool(re.search(r"create_clock\s+-name\s+bscan_tck[^\n]*\$tck_pins", xdc))
    acceptance = (len(rows) == 5 and len(classified["RESET_RELEASE"]) == 3
                  and len(classified["FIFO_LOCAL_UP_HANDSHAKE"]) == 2
                  and sum(len(classified[k]) for k in ("CONTROL", "DATA", "OTHER")) == 0
                  and not raw_report_paths and exact_clock_inventory
                  and not shared_clock_model and same_domain_duplicates == 0)
    return {
        "V4_EVIDENCE_COMMIT": EVIDENCE_COMMIT,
        "V4_SOURCE_COMMIT": SOURCE_COMMIT,
        "V4_SOURCE_TREE_HASH": SOURCE_TREE,
        "V4_REPORTED_ROUTED_DCP_SHA256": EXPECTED_DCP,
        "V4_IDENTITY_VERIFIED": True,
        "ROUTED_DCP_REHASHED": False,
        "CDC11_ROWS_EXPECTED": 5,
        "CDC11_ROWS_ACCOUNTED": len(rows),
        "RESET_ROWS": len(classified["RESET_RELEASE"]),
        "FIFO_HANDSHAKE_ROWS": len(classified["FIFO_LOCAL_UP_HANDSHAKE"]),
        "CONTROL_ROWS": len(classified["CONTROL"]), "DATA_ROWS": len(classified["DATA"]),
        "OTHER_ROWS": len(classified["OTHER"]),
        "ROW_CLASSIFICATIONS": [{"row": int(r["ROW"]), "destination": r["DESTINATION"],
                                  "class": r["INDEPENDENT_CLASSIFICATION"]} for r in rows],
        "SOURCE_FANOUT": {"source": "clockgen/reset_release/release_pipe_reg[3]/C",
                          "reported_first_stage_destinations": [r["DESTINATION"] for r in rows],
                          "destination_domain_labels": sorted(set(r["DESTINATION_CLOCK"] for r in rows)),
                          "same_domain_multiple_chains": "tck1: FIFO+reset; tck2: FIFO+reset; roots unresolved",
                          "same_domain_duplicate_reset_release_chains": same_domain_duplicates},
        "FIFO_HANDSHAKE_PROTOCOL": fifo_protocol,
        "RESET_ROW_PROOF": reset_proof,
        "CDC9_CROSS_CORRELATION": "summary reports 3 CDC-9 reset chains; no endpoint all-checks report to correlate row-by-row",
        "ROUTED_CLOCK_DOMAIN_PROOF": "INDETERMINATE",
        "RAW_ROUTED_CDC_REPORTS_PRESENT": bool(raw_report_paths),
        "RAW_RECOVERY_REMOVAL_REPORTS_PRESENT": False,
        "SHARED_BSCAN_CLOCK_OBJECT_IN_COMMITTED_XDC": shared_clock_model,
        "CDC11_STRUCTURALLY_SAFE": False,
        "CDC11_REAL_UNSAFE": False,
        "CDC11_INDETERMINATE": True,
        "CDC11_ACCEPTANCE_PASS": acceptance,
        "RTL_FIX_REQUIRED": False,
        "FAILING_OR_INDETERMINATE_ROWS": [1, 2, 3, 4, 5],
        "LIMITATION": "Committed bundle has normalized endpoints and summary only; no raw routed CDC/all-checks, clock-root, mapped cell, or recovery/removal reports. Lane labels and summary claims are not substituted for endpoint proof.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.repo)
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered)
        print(rendered, end="")
        return 0 if result["CDC11_ACCEPTANCE_PASS"] else 2
    except (Refusal, OSError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
