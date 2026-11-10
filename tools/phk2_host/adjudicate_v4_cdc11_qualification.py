#!/usr/bin/env python3
"""Cross-audit immutable v4 CDC-11 qualification and evidence commits."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

EVIDENCE = "221002426f26dd7a3705ba5ec58d40a2ea4c2674"
QUALIFICATION = "7893357612d9d8bc671badde63525e8925668dff"
SOURCE = "5a6ceadb8fc2eb6d972b5d338b507ab0b5296a2a"
BASE = "results/phk2-v4-reset-correction-20261110/revision2"
QUAL_PATH = "results/phk2-v4-reset-intake-20261110/qualification.json"
INTAKE_PATH = "tools/phk2_cdc_qualification/intake_v4_immutable_bundle.py"


class AuditError(ValueError):
    pass


def show(repo: Path, commit: str, path: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"],
                              check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE).stdout.decode(errors="replace")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError(f"missing immutable object {commit}:{path}") from exc


def audit(repo: Path) -> dict:
    repo = repo.resolve(strict=True)
    q = json.loads(show(repo, QUALIFICATION, QUAL_PATH))
    if q.get("evidence_commit") != EVIDENCE or q.get("source_commit") != SOURCE:
        raise AuditError("independent qualification result does not bind requested immutable evidence/source")
    report = show(repo, EVIDENCE, f"{BASE}/route/cdc.rpt")
    xdc = show(repo, EVIDENCE, f"{BASE}/v4_targeted_constraints.xdc")
    timing = {i: show(repo, EVIDENCE, f"{BASE}/route/reset_bscan{i}_release_recovery_removal.rpt") for i in (1, 2, 3)}
    top = show(repo, SOURCE, "rtl/phk2_board/phk2_fk33_board_top.sv")
    fifo = show(repo, SOURCE, "rtl/phk2_board/phk2_async_fifo.sv")
    reset = show(repo, SOURCE, "rtl/phk2_board/phk2_domain_reset.sv")
    intake = show(repo, QUALIFICATION, INTAKE_PATH)

    # Exact premise used by other lane: name three tck domains in RTL, pass
    # per-instance tests, and accept CDC-9/recovery evidence. The checker does
    # not inspect routed destination clock identity/root relationships.
    c11_start = intake.index("def check_cdc11(")
    c11_end = intake.index("\ndef validate(", c11_start)
    c11_code = intake[c11_start:c11_end]
    code_tests_three_names = all(f"({i},\"tck{i}\")" in c11_code for i in (1, 2, 3))
    code_has_clock_object_comparison = "destination_clock" in c11_code or "CLOCK_ROOT" in c11_code or "clock_root" in c11_code
    same_clock_rows = bool(re.search(
        r"Source Clock:\s*pll_core_unbuf\s+Destination Clock:\s*bscan_tck", report)) and all(
        re.search(rf"^\s*{row}\s+CDC-11\s+Critical[^\n]*", report, re.M)
        for row in (5, 11, 13, 15, 17))
    if not same_clock_rows:
        raise AuditError("raw CDC report no longer binds all five row endpoints to bscan_tck")
    one_clock = bool(re.search(r"create_clock\s+-name\s+bscan_tck[^\n]*\$tck_pins", xdc))
    if not one_clock:
        raise AuditError("immutable constraints do not show the shared BSCAN clock object")
    if not all(f"BSCANE2 #(.JTAG_CHAIN({i})) u_user{i}" in top for i in (1, 2, 3)):
        raise AuditError("immutable source lacks three USER BSCAN instances")
    common_source_comment = "physical TAP TCK is shared" in top

    branches = []
    for i, net, root in ((1, "tck1", "X7Y1"), (2, "tck2", "X7Y0"),
                         (3, "scan3_reset_release/clk", "direct/no BUFG root token")):
        t = timing[i]
        if "period=20.000ns" not in t or f"u_user{i}/INTERNAL_TCK" not in t or net not in t:
            raise AuditError(f"routed branch evidence incomplete for USER{i}")
        branches.append({"instance": f"u_user{i}", "clock_object": "bscan_tck",
                         "period_ns": 20.0, "waveform": "rise@0.000ns fall@10.000ns",
                         "physical_branch": net, "clock_root": root})

    # Direct topology trace: USER2's local FIFO-full source is reset by scan2;
    # USER3 independently resets the two receiving synchronizer stages and
    # may capture status without waiting for scan2's release/ready indication.
    status_crossing = all(token in top for token in (
        "always @(posedge tck2 or posedge scan2_rst)",
        "else rx_full_src<=rx_full",
        "always @(posedge tck3 or posedge scan3_rst)",
        "rx_full_s1<=rx_full_src;rx_full_s2<=rx_full_s1",
        "if(s3&&c3)stat_shift<={26'b0,aborted_s2,(overflow_s2|rx_full_s2)",
    ))
    fifo_not_ready_is_full = "assign wr_full=!wr_ready|full_i" in fifo
    fifo_gates_activation = "wire wr_ready=wr_local_up&&rd_up_w2" in fifo and "wire rd_ready=rd_local_up&&wr_up_r2" in fifo
    if not status_crossing or not fifo_not_ready_is_full or not fifo_gates_activation:
        raise AuditError("reset-island/FIFO/status interaction could not be statically reconstructed")

    q_cdc = q["cdc11"]
    if q_cdc.get("cdc11_acceptance_pass") is not True or q_cdc.get("rows_accounted") != 5:
        raise AuditError("independent lane result no longer reports CDC-11 5/5 accepted")
    if q.get("tck_independent_pass") != 38 or q.get("qualification_cases_pass") != 38:
        raise AuditError("independent lane no longer reports 38 passes")

    return {
        "V4_EVIDENCE_COMMIT": EVIDENCE,
        "INDEPENDENT_QUALIFICATION_COMMIT": QUALIFICATION,
        "V4_SOURCE_COMMIT": SOURCE,
        "RIGHT_ACCEPTANCE_PREMISE": "Three independently named RTL TCK destinations are treated as three reset domains; each has a local chain and local consumer tests. CDC-9 match, two stages, and recovery/removal PASS are accepted as sufficient. The qualification checker does not compare routed clock-object identities or clock roots.",
        "RIGHT_ACCEPTANCE_PREMISE_VALID": False,
        "RIGHT_CODE_CHECKS_DISTINCT_DOMAIN_CLOCK_OBJECTS": code_has_clock_object_comparison,
        "RIGHT_CODE_COUNTS_NAMED_TCK_INSTANTIATIONS": code_tests_three_names,
        "BSCAN_LOGICAL_CLOCK_DOMAINS": 1,
        "BSCAN_PHYSICAL_CLOCK_BRANCHES": len(branches),
        "BSCAN_CLOCK_BRANCH_DETAILS": branches,
        "COMMON_TAP_TCK_SOURCE_CONFIRMED_BY_IMMUTABLE_RTL_COMMENT": common_source_comment,
        "ROUTED_CDC_DESTINATION_CLOCK": "bscan_tck for all five CDC-11 rows",
        "ASYNC_RESET_DEASSERTION_CAN_RESOLVE_ON_DIFFERENT_SOURCE_EDGES": True,
        "INDEPENDENT_RELEASE_CHAINS": 3,
        "DIVERGENT_RELEASE_EDGE_POSSIBLE": True,
        "DIVERGENT_RELEASE_ARCHITECTURALLY_SAFE": False,
        "ARCHITECTURAL_REASON": "No common release barrier exists across scan1/scan2/scan3. The RTL has a cross-island USER2-to-USER3 rx_full status path: rx_full_src is reset by scan2_rst, while rx_full_s1/s2 and status capture are reset by scan3_rst. USER3 can capture the reset-default rx_full_src=0 while USER2 remains reset; FIFO wr_full is high while not ready. The two-stage status synchronizer handles metastability but does not guarantee coherent startup semantics. FIFO local-up handshakes protect FIFO pointer epochs, not this status-visible activation window.",
        "FIFO_LOCAL_UP_HANDSHAKES_PROTECT_POINTER_EPOCHS": True,
        "CDC11_ACCEPTANCE_PASS": False,
        "RIGHT_38_OF_38_RESULT_VALID": False,
        "RIGHT_COMPONENT_CASE_EXECUTION_COUNTS_RETAINED": True,
        "RIGHT_QUALIFICATION_PROMOTION_VALID": False,
        "RTL_FIX_REQUIRED": True,
        "FAILING_RESET_ROW_IDS": [3, 4, 5],
        "WHY_RIGHT_RESULT_IS_TOO_PERMISSIVE": "It substitutes three RTL signal names and a testbench with three independently driven clocks for proof of three genuinely distinct routed domains. The routed CDC report instead assigns all five crossings to one bscan_tck object; all BSCANE2 outputs share the physical TAP TCK source and differ only in routed branch/root. Per-domain CDC-9 and recovery/removal prove each chain works locally, not that separate chains release coherently or that cross-island activation is safe.",
        "RIGHT_REPORTED_TCK_INDEPENDENT_PASS": q["tck_independent_pass"],
        "RIGHT_REPORTED_QUALIFICATION_CASES_PASS": q["qualification_cases_pass"],
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    try:
        result = audit(a.repo)
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if a.output:
            a.output.write_text(text)
        print(text, end="")
        return 0
    except (AuditError, OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"AUDIT FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
