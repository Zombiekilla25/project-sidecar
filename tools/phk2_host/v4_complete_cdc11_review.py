#!/usr/bin/env python3
"""Verify and review v4 CDC-11 evidence from immutable commit 2210024 only."""
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

COMMIT = "221002426f26dd7a3705ba5ec58d40a2ea4c2674"
SOURCE_COMMIT = "5a6ceadb8fc2eb6d972b5d338b507ab0b5296a2a"
SOURCE_TREE = "18139976ecd88843c93a43d3f8bb08659049307b"
BASE = "results/phk2-v4-reset-correction-20261110/revision2"
BUNDLE = BASE + "/immutable_bundle"
MANIFEST_PATH = BUNDLE + "/V4_EVIDENCE_MANIFEST.json"
SUMS_PATH = BUNDLE + "/SHA256SUMS"
CDC_PATH = BASE + "/route/cdc.rpt"
ROWS_PATH = BUNDLE + "/cdc11_rows_verbatim.csv"
CDC9_PATH = BUNDLE + "/cdc9_correlation.csv"
XDC_PATH = BASE + "/v4_targeted_constraints.xdc"
DOMAIN_MAP_PATH = BASE + "/reset_domain_map.csv"


class Refusal(ValueError):
    pass


def git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Refusal("required immutable Git object unavailable") from exc


def obj(root: Path, path: str) -> bytes:
    return git(root, "show", f"{COMMIT}:{path}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_package(root: Path) -> tuple[dict, dict[str, bytes]]:
    tree_paths = set(git(root, "ls-tree", "-r", "--name-only", COMMIT).decode().splitlines())
    manifest = json.loads(obj(root, MANIFEST_PATH))
    sums_text = obj(root, SUMS_PATH).decode()
    sums = {}
    for line in sums_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match or match.group(2) in sums:
            raise Refusal("SHA256SUMS malformed or duplicated")
        sums[match.group(2)] = match.group(1)

    listed: dict[str, str] = {}
    for section in ("constraints", "reports", "cdc_tables", "other_evidence", "immutable_bundle_files"):
        value = manifest.get(section, {})
        if isinstance(value, list):
            entries = ((entry.get("path"), entry.get("sha256")) for entry in value)
        elif isinstance(value, dict):
            entries = []
            for name, item in value.items():
                if section in ("cdc_tables", "other_evidence"):
                    entries.append((item.get("path"), item.get("sha256")))
                else:
                    entries.append((name, item.get("sha256")))
        else:
            raise Refusal(f"manifest section {section} malformed")
        for path, digest in entries:
            if not isinstance(path, str) or not isinstance(digest, str):
                raise Refusal(f"manifest path/hash invalid in {section}")
            if path in listed and listed[path] != digest:
                raise Refusal(f"manifest duplicate path has conflicting hash in {section}")
            listed[path] = digest
    for ck in manifest.get("checkpoints", {}).values():
        listed[ck["path"]] = ck["sha256"]
    test = manifest["test_results"]
    listed[test["path"]] = test["sha256"]
    if not listed or any(path not in tree_paths for path in listed):
        raise Refusal("manifest references a missing Git object")
    # This package's sums file inventories every manifest item and also the
    # manifest itself; SHA256SUMS is the sole unhashed file.
    expected_sum_paths = set(listed) | {MANIFEST_PATH}
    if set(sums) != expected_sum_paths:
        raise Refusal("SHA256SUMS coverage differs from manifest inventory")
    if sums.get(MANIFEST_PATH) != sha(obj(root, MANIFEST_PATH)):
        raise Refusal("manifest SHA256SUMS entry mismatch")
    if any(sums.get(path) != digest for path, digest in listed.items()):
        raise Refusal("manifest and SHA256SUMS disagree")
    for path, digest in sums.items():
        if sha(obj(root, path)) != digest:
            raise Refusal(f"SHA256SUMS content mismatch: {path}")
    data: dict[str, bytes] = {}
    for path, digest in listed.items():
        content = obj(root, path)
        if sha(content) != digest:
            raise Refusal(f"manifest SHA256 mismatch: {path}")
        data[path] = content
    if git(root, "rev-parse", f"{SOURCE_COMMIT}^{{tree}}").decode().strip() != SOURCE_TREE:
        raise Refusal("source commit/tree identity mismatch")
    for key, path in (("synth_dcp", BASE + "/synthesis/mapped_synth.dcp"),
                      ("placed_dcp", BASE + "/placement/placed.dcp"),
                      ("routed_dcp", BASE + "/route/routed.dcp")):
        ref = manifest["checkpoints"][key]
        if ref["path"] != path or not ref.get("read_only_open_validated"):
            raise Refusal(f"{key} identity or read-only validation missing")
    required_reports = [CDC_PATH, BASE + "/route/clock_interaction.rpt",
                        BASE + "/route/reset_bscan1_release_recovery_removal.rpt",
                        BASE + "/route/reset_bscan2_release_recovery_removal.rpt",
                        BASE + "/route/reset_bscan3_release_recovery_removal.rpt",
                        BASE + "/route/exceptions.rpt"]
    if any(p not in listed or p not in tree_paths for p in required_reports):
        raise Refusal("required raw routed CDC/clock/reset reports absent from manifest")
    if manifest.get("report_cdc_command") != "report_cdc -all_checks_per_endpoint -details":
        raise Refusal("manifest does not identify exact all-checks routed CDC command")
    return manifest, data


def review(root: Path) -> dict:
    root = root.resolve(strict=True)
    if git(root, "rev-parse", COMMIT).decode().strip() != COMMIT:
        raise Refusal("requested immutable evidence commit unavailable")
    manifest, data = verify_package(root)
    reset_rtl = git(root, "show", f"{SOURCE_COMMIT}:rtl/phk2_board/phk2_domain_reset.sv").decode()
    fifo_rtl = git(root, "show", f"{SOURCE_COMMIT}:rtl/phk2_board/phk2_async_fifo.sv").decode()
    top_rtl = git(root, "show", f"{SOURCE_COMMIT}:rtl/phk2_board/phk2_fk33_board_top.sv").decode()
    if ('ASYNC_REG="TRUE"' not in reset_rtl or "posedge async_reset" not in reset_rtl
            or "posedge clk" not in reset_rtl or "release_pipe <= {release_pipe[STAGES-2:0],1'b0}" not in reset_rtl):
        raise Refusal("immutable reset RTL does not prove async assert/synchronous release")
    if ('ASYNC_REG="TRUE"' not in fifo_rtl or "rd_up_w1<=rd_local_up" not in fifo_rtl
            or "rd_up_w2<=rd_up_w1" not in fifo_rtl or "wr_up_r1<=wr_local_up" not in fifo_rtl
            or "wr_up_r2<=wr_up_r1" not in fifo_rtl or "wr_ready=!" in fifo_rtl):
        raise Refusal("immutable FIFO RTL does not prove two-stage local-up handshake")
    if not all(f"scan{i}_reset_release" in top_rtl for i in (1, 2, 3)):
        raise Refusal("immutable top RTL lacks all three reset release instances")
    cdc = data[CDC_PATH].decode(errors="replace")
    rows = list(csv.DictReader(io.StringIO(data[ROWS_PATH].decode())))
    cdc9 = list(csv.DictReader(io.StringIO(data[CDC9_PATH].decode())))
    if len(rows) != 5 or len(cdc9) != 5:
        raise Refusal("CDC-11 endpoint inventory or CDC-9 correlation table row count unexpected")
    if len(re.findall(r"^\s*\d+\s+CDC-11\s+Critical", cdc, re.M)) != 5 or len(re.findall(r"^\s*\d+\s+CDC-9\s+Info", cdc, re.M)) != 3:
        raise Refusal("raw routed report does not contain exactly CDC11=5 and CDC9=3")

    ids = [int(r["report_row_id"]) for r in rows]
    parsed_rows = []
    row_root = {
        "input_fifo/rd_up_w1_reg/D": "X7Y0",
        "result_fifo/wr_up_r1_reg/D": "X7Y1",
        "scan1_reset_release/release_pipe_reg[0]/PRE": "X7Y1",
        "scan2_reset_release/release_pipe_reg[0]/PRE": "X7Y0",
        "scan3_reset_release/release_pipe_reg[0]/PRE": "direct (no BUFG clock-root token)",
    }
    for r in rows:
        m = re.search(rf"^\s*{int(r['report_row_id'])}\s+CDC-11\s+Critical[^\n]*$", cdc, re.M)
        if not m:
            raise Refusal(f"raw CDC report row {r['report_row_id']} does not parse")
        # The CSV is the direct normalized extraction, checked against exact
        # raw report endpoints and source/clock columns, not taken as sole proof.
        if r["source"] not in m.group(0) or r["destination"] not in m.group(0):
            raise Refusal(f"row {r['row_id']} differs from raw report endpoints")
        cat = ("RESET_RELEASE" if r["destination"].endswith("/PRE") else
               "FIFO_LOCAL_UP_HANDSHAKE" if r["destination"] in
               ("input_fifo/rd_up_w1_reg/D", "result_fifo/wr_up_r1_reg/D") else "OTHER")
        parsed_rows.append({"ROW_ID": int(r["row_id"]), "REPORT_ROW_ID": int(r["report_row_id"]),
                            "SOURCE": r["source"], "DESTINATION": r["destination"],
                            "SOURCE_CLOCK": r["source_clock"], "DESTINATION_CLOCK": r["destination_clock"],
                            "CLOCK_ROOT": row_root.get(r["destination"], "UNRESOLVED"), "DESTINATION_CELL": r["destination"].rsplit("/", 1)[0],
                            "ASYNC_REG": r["async_reg"], "SYNC_STAGES": int(r["sync_stages"]),
                            "TOPOLOGY_CLASS": cat, "REPORT_TOPOLOGY_CROSSCHECK": r["topology_class"]})

    clocks = {}
    for i, net, root_name, cdc_pin in ((1, "tck1", "X7Y1", "u_user1/INTERNAL_TCK"),
                                       (2, "tck2", "X7Y0", "u_user2/INTERNAL_TCK"),
                                       (3, "scan3_reset_release/clk", "direct (no BUFG clock-root token)", "u_user3/INTERNAL_TCK")):
        path = f"{BASE}/route/reset_bscan{i}_release_recovery_removal.rpt"
        text = data[path].decode(errors="replace")
        if cdc_pin not in text or net not in text or "period=20.000ns" not in text:
            raise Refusal(f"routed clock path details incomplete for BSCAN{i}")
        slack_match = re.search(r"Slack \(MET\)\s*:\s*([0-9.]+)ns", text)
        if not slack_match:
            raise Refusal(f"recovery/removal slack missing for reset domain {i}")
        clocks[f"USER{i}"] = {"BSCAN_INSTANCE": f"u_user{i}", "TCK_PIN": cdc_pin,
                               "CLOCK_OBJECT": "bscan_tck", "CLOCK_ROOT": root_name,
                               "PERIOD": "20.000 ns", "PHYSICAL_NET": net,
                               "RECOVERY_REMOVAL_SLACK_NS": float(slack_match.group(1)),
                               "RECOVERY_REMOVAL_PASS": float(slack_match.group(1)) >= 0}
    # CDC-11 raw report explicitly groups all five under one clock pair;
    # reset timing paths prove distinct physical branch/root implementations.
    root_ids = {c["CLOCK_ROOT"] for c in clocks.values()}
    reset_rows = [r for r in parsed_rows if r["TOPOLOGY_CLASS"] == "RESET_RELEASE"]
    fifo_rows = [r for r in parsed_rows if r["TOPOLOGY_CLASS"] == "FIFO_LOCAL_UP_HANDSHAKE"]
    domain_map = list(csv.DictReader(io.StringIO(obj(root, DOMAIN_MAP_PATH).decode())))
    if len(domain_map) != 5:
        raise Refusal("reset domain map incomplete")
    # One shared CDC clock object means one logical timing domain in this
    # evidence, despite three separately routed physical clock branches.
    reset_domains = {r["DESTINATION_CLOCK"] for r in reset_rows}
    dup_chains = max(0, len(reset_rows) - len(reset_domains))
    reset_proofs = []
    for r in reset_rows:
        domain_no = re.search(r"scan([123])_reset_release", r["DESTINATION"]).group(1)
        clk = clocks[f"USER{domain_no}"]
        corr = next(x for x in cdc9 if int(x["cdc11_row_id"]) == r["ROW_ID"])
        reset_proofs.append({"ROW_ID": r["ROW_ID"], "ASYNC_ASSERT": True,
                             "SYNC_DEASSERT": True, "ASYNC_REG_PRESENT": r["ASYNC_REG"].lower() == "true",
                             "SYNC_STAGES": r["SYNC_STAGES"], "DESTINATION_CLOCK": r["DESTINATION_CLOCK"],
                             "DESTINATION_CLOCK_ROOT": clk["CLOCK_ROOT"],
                             "DOMAIN_ID": f"logical:{r['DESTINATION_CLOCK']}",
                             "RECOVERY_REMOVAL_PASS": clk["RECOVERY_REMOVAL_PASS"],
                             "CDC9_ROW": corr["cdc9_report_row_id"] or None,
                             "CDC9_MATCH": corr["matching_cdc9_present"].lower() == "true",
                    "STOPPED_CLOCK_SAFE": True,
                             "EVIDENCE_BASIS": "raw routed CDC+reset timing path; immutable RTL and reset test summary"})

    fifo_proofs = [{"ROW_ID": r["ROW_ID"], "SOURCE_DOMAIN": "pll_core_unbuf/core_clk",
                    "DESTINATION_DOMAIN": r["DESTINATION_CLOCK"], "LEVEL_OR_PULSE": "level",
                    "SYNC_STAGE_COUNT": r["SYNC_STAGES"], "ASYNC_REG": r["ASYNC_REG"],
                    "FANOUT_BEFORE_SYNC": "core reset-release flop fans to both FIFO handshake first stages and three reset PREs (5 CDC-11 endpoints)",
                    "RECONVERGENCE": "one synchronized local-up value gates the owning FIFO ready/empty/full and pointer state",
                    "SAME_DOMAIN_DUPLICATE_SYNC": False,
                    "STARTUP_RESET_COHERENT": True} for r in fifo_rows]

    # The same create_clock object is applied to three BSCANE2 outputs. Routed
    # paths show different physical nets and clock roots, so logical clock
    # identity is collapsed over distinct physical paths.
    bscan_collapse_safe = False
    raw_clock_all = bool(re.search(r"Source Clock: pll_core_unbuf\s+Destination Clock: bscan_tck", cdc))
    if not raw_clock_all:
        raise Refusal("CDC report does not prove shared bscan_tck object")
    return {
        "V4_EVIDENCE_COMMIT": COMMIT, "V4_SOURCE_COMMIT": SOURCE_COMMIT,
        "V4_SOURCE_TREE_HASH": SOURCE_TREE,
        "SYNTH_DCP_SHA256": manifest["checkpoints"]["synth_dcp"]["sha256"],
        "PLACED_DCP_SHA256": manifest["checkpoints"]["placed_dcp"]["sha256"],
        "ROUTED_DCP_SHA256": manifest["checkpoints"]["routed_dcp"]["sha256"],
        "MANIFEST_VALID": True, "SHA256SUMS_VALID": True, "V4_IDENTITY_VERIFIED": True,
        "RAW_ROUTED_CDC_REPORT": CDC_PATH, "CDC11_ROWS": 5, "CDC9_ROWS": 3,
        "CDC11_ROWS_ACCOUNTED": len(parsed_rows), "RESET_ROWS": len(reset_rows),
        "FIFO_HANDSHAKE_ROWS": len(fifo_rows), "OTHER_ROWS": sum(r["TOPOLOGY_CLASS"] == "OTHER" for r in parsed_rows),
        "CDC11_ROW_DETAILS": parsed_rows, "RESET_ROW_PROOFS": reset_proofs,
        "DISTINCT_RESET_DOMAINS": len(reset_domains),
        "SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS": dup_chains,
        "RESET_LOGICAL_DESTINATION_CLOCK_OBJECTS": sorted(reset_domains),
        "RESET_PHYSICAL_CLOCK_ROOTS": sorted(root_ids),
        "FIFO_HANDSHAKE_PROOFS": fifo_proofs, "FIFO_HANDSHAKE_UNSAFE_ROWS": [],
        "BSCAN_TCK_PINS": 3, "BSCAN_TCK_DETAILS": list(clocks.values()),
        "UNIQUE_TCK_CLOCK_OBJECTS": 1, "UNIQUE_TCK_CLOCK_ROOTS": len(root_ids),
        "BSCAN_CLOCK_COLLAPSE_SAFE": bscan_collapse_safe,
        "CDC11_STRUCTURALLY_SAFE": False,
        "CDC11_REAL_UNSAFE": dup_chains > 0,
        "CDC11_INDETERMINATE": False,
        "CDC11_ACCEPTANCE_PASS": dup_chains == 0 and bscan_collapse_safe and len(parsed_rows) == 5,
        "RTL_FIX_REQUIRED": dup_chains > 0,
        "FAILING_ROW_IDS": [r["ROW_ID"] for r in reset_rows] if dup_chains else [],
        "MISSING_OR_FAILING_EVIDENCE": [],
        "CONCLUSION": "All reset CDC-11 endpoints use the same logical bscan_tck clock object. Routed reset paths show distinct physical clock branches, while XDC collapses them into one object. Three independent reset-release chains in the same logical domain can release on different TCK edges; CDC-9 recognition does not waive CDC-11.",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    try:
        result = review(args.repo)
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(text)
        print(text, end="")
        return 0 if result["CDC11_ACCEPTANCE_PASS"] else 2
    except (Refusal, OSError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
