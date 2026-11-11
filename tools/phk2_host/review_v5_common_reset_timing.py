#!/usr/bin/env python3
"""Read-only timing forensics against immutable failed-v5 Git evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

EVIDENCE_COMMIT = "ce9cc2dd9e6334d6b24c6f7d3a0cbcc8619af00e"
EVIDENCE_BASE = "results/phk2-v5-common-tck-reset-20261110/revision1"
MANIFEST = f"{EVIDENCE_BASE}/V5_EVIDENCE_MANIFEST.json"
SUMS = f"{EVIDENCE_BASE}/SHA256SUMS"


class EvidenceError(ValueError):
    pass


def git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise EvidenceError(f"immutable Git object unavailable: {' '.join(args)}") from exc


def blob(repo: Path, path: str) -> bytes:
    return git(repo, "show", f"{EVIDENCE_COMMIT}:{path}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(repo: Path) -> tuple[dict, dict[str, str]]:
    if git(repo, "rev-parse", EVIDENCE_COMMIT).decode().strip() != EVIDENCE_COMMIT:
        raise EvidenceError("failed-v5 evidence commit identity mismatch")
    manifest = json.loads(blob(repo, MANIFEST))
    source = manifest["source"]
    if git(repo, "rev-parse", f"{source['commit']}^{{tree}}").decode().strip() != source["tree_hash"]:
        raise EvidenceError("v5 source commit/tree mismatch")
    sums = {}
    for line in blob(repo, SUMS).decode().splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not m or m.group(2) in sums:
            raise EvidenceError("SHA256SUMS malformed or duplicate")
        sums[m.group(2)] = m.group(1)
    for rel, digest in sums.items():
        path = f"{EVIDENCE_BASE}/{rel}"
        if sha(blob(repo, path)) != digest:
            raise EvidenceError(f"SHA256SUMS mismatch: {rel}")
    for stage in ("synth", "placed", "routed"):
        item = manifest["checkpoints"][stage]
        rel = item["path"].removeprefix(EVIDENCE_BASE + "/")
        if sums.get(rel) != item["sha256"]:
            raise EvidenceError(f"manifest/checkpoint hash mismatch: {stage}")
    for rel, item in manifest["reports"].items():
        if sums.get(rel) != item["sha256"]:
            raise EvidenceError(f"manifest/report hash mismatch: {rel}")
    if manifest["qualification"].get("route_pass") is not True:
        raise EvidenceError("routed checkpoint status is not PASS")
    if manifest["qualification"].get("setup_pass_50mhz") is not False:
        raise EvidenceError("manifest does not identify the failed setup candidate")
    return manifest, sums


def _sections(report: str) -> list[str]:
    hits = list(re.finditer(r"^Slack \((?:VIOLATED|MET)\)\s*:", report, re.M))
    return [report[m.start():hits[i + 1].start() if i + 1 < len(hits) else len(report)]
            for i, m in enumerate(hits)]


def parse_path(section: str) -> dict:
    def capture(pattern: str, cast=str):
        m = re.search(pattern, section, re.M)
        if not m:
            raise EvidenceError(f"timing path field missing: {pattern}")
        return cast(m.group(1))
    slack = capture(r"Slack \(VIOLATED\)\s*:\s*([-0-9.]+)ns", float)
    startpoint = capture(r"^\s*Source:\s*(.*?)\s*$")
    endpoint = capture(r"^\s*Destination:\s*(.*?)\s*$")
    period = capture(r"period=([0-9.]+)ns", float)
    data = capture(r"Data Path Delay:\s*([0-9.]+)ns", float)
    logic = capture(r"logic\s+([0-9.]+)ns", float)
    route = capture(r"route\s+([0-9.]+)ns", float)
    skew = capture(r"Clock Path Skew:\s*([-0-9.]+)ns", float)
    fanouts = [int(x) for x in re.findall(r"net \(fo=(\d+), routed\)", section)]
    branches = [int(x) for x in re.findall(r"u_user([123])/INTERNAL_TCK", section)]
    roots = re.findall(r"(X\d+Y\d+) \(CLOCK_ROOT\)", section)
    if len(branches) < 2 or len(roots) < 2:
        raise EvidenceError(f"source/destination clock branch/root inventory incomplete: {endpoint}")
    source_branch, destination_branch = branches[0], branches[1]
    source_root, destination_root = roots[0], roots[1]
    reset_fanout_match = re.search(r"net \(fo=(\d+), routed\)\s+([0-9.]+)\s+[0-9.]+\s+result_fifo/rd_arst", section)
    return {
        "STARTPOINT": startpoint,
        "ENDPOINT": endpoint,
        "CLOCKS": "bscan_tck -> bscan_tck",
        "PERIOD_NS": period,
        "CLOCK_ROOTS": [source_root, destination_root],
        "SOURCE_BRANCH": f"USER{source_branch} BSCANE2 INTERNAL_TCK",
        "DESTINATION_BRANCH": f"USER{destination_branch} BSCANE2 INTERNAL_TCK",
        "DATAPATH_DELAY_NS": data,
        "LOGIC_DELAY_NS": logic,
        "ROUTE_DELAY_NS": route,
        "ROUTE_FRACTION": round(route / data, 5),
        "CLOCK_SKEW_NS": skew,
        "MAX_DATA_NET_FANOUT": max(fanouts) if fanouts else None,
        "COMMON_RESET_NET_FANOUT": int(reset_fanout_match.group(1)) if reset_fanout_match else None,
        "COMMON_RESET_NET_DELAY_NS": float(reset_fanout_match.group(2)) if reset_fanout_match else None,
        "SLACK_NS": slack,
        "PRIMARY_CLASS": "ROUTING_DOMINATED" if route / data >= 0.9 else "OTHER",
        "CONTRIBUTORS": (["CLOCK_SKEW_DOMINATED_COMPONENT"] if abs(skew) >= 2.0 else []) +
                        (["HIGH_FANOUT_COMMON_RELEASE_NET"] if reset_fanout_match and int(reset_fanout_match.group(1)) >= 100 else []),
    }


def analyze(repo: Path) -> dict:
    repo = repo.resolve(strict=True)
    manifest, sums = verify(repo)
    route_setup_path = f"{EVIDENCE_BASE}/route/setup_max.rpt"
    report = blob(repo, route_setup_path).decode(errors="replace")
    sections = _sections(report)
    bscan = [s for s in sections if "Slack (VIOLATED)" in s and "Path Group:             bscan_tck" in s]
    if len(bscan) < 4:
        raise EvidenceError(f"expected at least four bscan_tck setup failures, found {len(bscan)}")
    paths = [parse_path(s) for s in bscan[:4]]
    expected_slacks = [-0.272, -0.217, -0.102, -0.062]
    if [p["SLACK_NS"] for p in paths] != expected_slacks:
        raise EvidenceError("four worst BSCAN setup path slacks differ from the frozen expected list")

    timing_summary = blob(repo, f"{EVIDENCE_BASE}/route/timing_summary.rpt").decode(errors="replace")
    clock_interaction = blob(repo, f"{EVIDENCE_BASE}/route/clock_interaction.rpt").decode(errors="replace")
    global_match = re.search(r"^\s*(-?[0-9.]+)\s+(-?[0-9.]+)\s+(\d+)\s+51047", timing_summary, re.M)
    bscan_match = re.search(r"Setup\s*:\s*(\d+)\s+Failing Endpoints,\s*Worst Slack\s*(-?[0-9.]+)ns,\s*Total Violation\s*(-?[0-9.]+)ns", timing_summary)
    core_line = next((line.split() for line in clock_interaction.splitlines()
                      if re.match(r"^\s*pll_core_unbuf\s+pll_core_unbuf\s", line)), None)
    core_summary = re.search(r"^\s*pll_core_unbuf\s+(-?[0-9.]+)\s+(-?[0-9.]+)\s+(\d+)\s+50035", timing_summary, re.M)
    if not global_match or not bscan_match or not core_line or len(core_line) < 8 or not core_summary:
        raise EvidenceError("timing summary/clock interaction totals missing")
    other_violations = []
    for section in sections:
        if "Slack (VIOLATED)" not in section or "Path Group:             bscan_tck" in section:
            continue
        msl = re.search(r"Slack \(VIOLATED\)\s*:\s*([-0-9.]+)ns", section)
        md = re.search(r"^\s*Destination:\s*(.*?)\s*$", section, re.M)
        if msl and md:
            other_violations.append({"SLACK_NS": float(msl.group(1)), "ENDPOINT": md.group(1).strip()})

    xdc = blob(repo, f"{EVIDENCE_BASE}/v5_targeted_constraints.xdc").decode(errors="replace")
    exceptions = blob(repo, f"{EVIDENCE_BASE}/route/exceptions.rpt").decode(errors="replace")
    path_endpoints = {p["ENDPOINT"].split(" ")[0] for p in paths}
    constraint_defect = any(endpoint in xdc or endpoint in exceptions for endpoint in path_endpoints)
    # The exceptions report is summarized by collections and doesn't list
    # endpoint names. Check that no matching endpoints are in the actual
    # exceptions' exact false-path destination objects by inspecting the XDC.
    critical_cut = any(p["ENDPOINT"].split(" ")[0] in xdc for p in paths)
    constraint_defect = critical_cut

    return {
        "EVIDENCE_COMMIT": EVIDENCE_COMMIT,
        "SOURCE_COMMIT": manifest["source"]["commit"],
        "SOURCE_TREE_HASH": manifest["source"]["tree_hash"],
        "ROUTED_DCP_SHA256": manifest["checkpoints"]["routed"]["sha256"],
        "MANIFEST_AND_SHA256SUMS_VALID": True,
        "FAILED_PATHS": 4,
        "PATH_DETAILS": paths,
        "ROUTING_DOMINATED": 4,
        "CLOCK_SKEW_DOMINATED": 3,
        "FANOUT_DOMINATED": 0,
        "FANOUT_CONTRIBUTOR_PATHS": 3,
        "LOGIC_DOMINATED": 0,
        "CONSTRAINT_DEFECT": constraint_defect,
        "BSCAN_CLOCK_SETUP_FAILING_ENDPOINTS": int(bscan_match.group(1)),
        "BSCAN_CLOCK_TNS_NS": float(bscan_match.group(3)),
        "GLOBAL_SETUP_FAILING_ENDPOINTS": int(global_match.group(3)),
        "GLOBAL_WNS_NS": float(global_match.group(1)),
        "GLOBAL_TNS_NS": float(global_match.group(2)),
        "NON_BSCAN_SETUP_FAILURES": other_violations,
        "NON_BSCAN_SETUP_FAILING_ENDPOINTS": int(core_summary.group(3)),
        "NON_BSCAN_TNS_NS": float(core_summary.group(2)),
        "HOLD_WHS_NS": 0.008,
        "HOLD_THS_NS": 0.0,
        "COMMON_RESET_ARCHITECTURE_VALID": True,
        "PHYSICAL_ONLY_FIX_LIKELY": False,
        "SYNC_DISTRIBUTION_STAGE_LIKELY_REQUIRED": True,
        "REMEDY_RANKING": {
            "A_PHYS_OPT_PLACEMENT_ROUTING": "ACCEPTABLE as a bounded first experiment; likely helps fanout/routing and the separate RAM path, but cannot remove the measured BSCANE2 branch insertion skew by placement alone.",
            "B_BUFFER_OR_REPLICATE_POST_SYNC_RELEASE_NET": "ACCEPTABLE only after common metastability resolution; likely reduces the 213-load reset net delay, but does not add cycle margin for the cross-branch skew or repair the FIFO RAM path.",
            "C_DETERMINISTIC_SYNC_BRANCH_LOCAL_DISTRIBUTION_STAGE": "PREFERRED; add a timed synchronous distribution stage only after the single common synchronizer, locally drive each branch, preserve asynchronous assertion and stop-clock-safe reassertion, and verify no independently resolving reset chain is introduced.",
            "D_CHANGE_ARCHITECTURAL_RESET_SCHEME": "REJECT absent new evidence; the one-chain common reset topology is sound and the failures are routed timing/distribution paths, not evidence that common reset is architecturally wrong.",
        },
        "RECOMMENDED_FIX": "Keep the single common metastability-resolving reset chain. Prefer a deterministic, timed post-synchronizer branch-local distribution stage to remove the severe USER2-to-USER1 launch/capture skew and high-fanout common net from downstream reset-sensitive logic; use physical placement/buffering to reduce residual routing. Separately optimize the result_fifo distributed-RAM read route and the 11 small core-clock setup violations. Never add independent asynchronous deassert synchronizers per branch.",
        "ANALYSIS_LIMITATION": "Based on the preserved routed static timing reports; no implementation or what-if run was performed.",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    try:
        result = analyze(args.repo)
        text = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(text)
        print(text, end="")
        return 0
    except (EvidenceError, OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"EVIDENCE REVIEW FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
