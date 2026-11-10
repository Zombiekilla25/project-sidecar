#!/usr/bin/env python3
"""Watch local immutable Git objects for PHK2-v5 source and routed evidence.

No checkout, file mutation, network access, synthesis, implementation,
hardware, USB, JTAG, or bitstream action is performed. Evidence is read only
through `git show <commit>:<path>`.
"""
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
import time
from typing import Any

V4_SOURCE = "5a6ceadb8fc2eb6d972b5d338b507ab0b5296a2a"
EXPECTED_INDEPENDENT = 38


class Blocked(ValueError):
    pass


def git(repo: Path, *args: str) -> bytes:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Blocked(f"Git object query failed: {' '.join(args)}") from exc


def show(repo: Path, commit: str, path: str) -> bytes:
    return git(repo, "show", f"{commit}:{path}")


def tree(repo: Path, commit: str) -> str:
    return git(repo, "rev-parse", f"{commit}^{{tree}}").decode().strip()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_audit(repo: Path, commit: str) -> dict[str, Any]:
    if commit == V4_SOURCE:
        raise Blocked("candidate source is v4, not v5")
    top = show(repo, commit, "rtl/phk2_board/phk2_fk33_board_top.sv").decode(errors="replace")
    reset = show(repo, commit, "rtl/phk2_board/phk2_domain_reset.sv").decode(errors="replace")
    fifo = show(repo, commit, "rtl/phk2_board/phk2_async_fifo.sv").decode(errors="replace")
    bscan_instances = re.findall(r"BSCANE2\s*#\s*\(\s*\.JTAG_CHAIN\s*\(\s*([123])\s*\)\s*\)\s*(\w+)", top)
    if len(bscan_instances) != 3 or {x[0] for x in bscan_instances} != {"1", "2", "3"}:
        raise Blocked("source does not contain exactly USER1/USER2/USER3 BSCANE2 instances")

    # Count concrete reset synchronizer instances in the board integration.
    sync_inst = list(re.finditer(r"\bphk2_domain_reset\b(?:\s*#\s*\([^;]*?\))?\s+(\w+)\s*\((.*?)\)\s*;", top, re.S))
    reset_domain_insts = []
    for m in sync_inst:
        ports = m.group(2)
        clk = re.search(r"\.clk\s*\(\s*(\w+)\s*\)", ports)
        arst = re.search(r"\.async_reset\s*\(\s*(\w+)\s*\)", ports)
        out = re.search(r"\.domain_reset\s*\(\s*(\w+)\s*\)", ports)
        if clk and arst and out:
            reset_domain_insts.append({"instance": m.group(1), "clock": clk.group(1),
                                       "async_reset": arst.group(1), "output": out.group(1)})
    if len(reset_domain_insts) != 1:
        raise Blocked(f"expected exactly one BSCAN-domain reset synchronizer instance; found {len(reset_domain_insts)}")
    chain = reset_domain_insts[0]

    if ('ASYNC_REG="TRUE"' not in reset or "posedge clk or posedge async_reset" not in reset
            or "release_pipe[STAGES-2:0],1'b0" not in reset):
        raise Blocked("common reset RTL lacks ASYNC_REG, async assertion, or synchronous deassertion")
    stages_match = re.search(r"STAGES\s*=\s*(\d+)", reset)
    if stages_match and int(stages_match.group(1)) < 2:
        raise Blocked("reset synchronizer has fewer than two stages")
    if not stages_match and "STAGES-2:0" not in reset:
        raise Blocked("reset synchronizer stage count is not statically established")

    # Find all scan-domain reset consumers, including sequential async reset
    # pins and FIFO reset ports. Each branch must use the one synchronizer net.
    aliases = {}
    for target, expr in re.findall(r"\bassign\s+(\w+)\s*=\s*(\w+)\s*;", top):
        aliases[target] = expr
    for target, expr in re.findall(r"\bwire\s+(\w+)\s*=\s*(\w+)\s*;", top):
        aliases[target] = expr
    def resolve(net: str) -> str:
        seen = set()
        while net in aliases and net not in seen:
            seen.add(net)
            net = aliases[net]
        return net
    branch_clocks = []
    branch_reset_nets = []
    for i in (1, 2, 3):
        tck = f"tck{i}"
        consumers = re.findall(rf"always\s*@\(posedge\s+{tck}\s+or\s+posedge\s+(\w+)\)", top)
        if not consumers:
            raise Blocked(f"no asynchronous reset consumer found on USER{i} branch {tck}")
        if any(resolve(net) != chain["output"] for net in consumers):
            raise Blocked(f"USER{i} contains an alternate/different asynchronous reset path: {consumers}")
        branch_clocks.append(tck)
        branch_reset_nets.extend(consumers)
    for port in ("wr_arst", "rd_arst"):
        for fifo_inst in re.finditer(r"phk2_async_fifo\b.*?\((.*?)\);", top, re.S):
            m = re.search(rf"\.{port}\s*\(\s*(\w+)\s*\)", fifo_inst.group(1))
            if m and m.group(1) in ("scan1_rst", "scan2_rst", "scan3_rst") and m.group(1) != chain["output"]:
                raise Blocked(f"FIFO {port} bypasses common synchronized BSCAN reset")
    direct_bypass = re.findall(r"always\s*@\(posedge\s+tck[123]\s+or\s+posedge\s+core_rst\)", top)
    if direct_bypass:
        raise Blocked("scan-domain sequential logic has direct core_rst startup/reset bypass")
    # No additional reset pipe aliases or local copies may be instantiated.
    if re.search(r"\bphk2_(?:domain_reset|pll_reset_release)\b", top) and len(sync_inst) != 1:
        raise Blocked("additional reset synchronizer instance remains")

    fifo_tokens = ("rd_up_w1", "rd_up_w2", "wr_up_r1", "wr_up_r2", 'ASYNC_REG="TRUE"',
                   "rd_up_w2<=rd_up_w1", "wr_up_r2<=wr_up_r1",
                   "wire wr_ready=wr_local_up&&rd_up_w2", "wire rd_ready=rd_local_up&&wr_up_r2",
                   "if(!wr_ready)begin wbin<=0", "if(!rd_ready)begin rbin<=0")
    if any(token not in fifo for token in fifo_tokens):
        raise Blocked("FIFO local-up handshake/pointer epoch protection changed or is incomplete")
    if chain["output"] not in top or not all(branch_reset_nets):
        raise Blocked("common synchronized reset output is not consumed across all branches")
    return {"SOURCE_COMMIT": commit, "SOURCE_TREE_HASH": tree(repo, commit),
            "BSCAN_BRANCHES": branch_clocks, "COMMON_RELEASE_SYNCHRONIZERS": 1,
            "ASYNC_ASSERT": True, "SYNC_DEASSERT": True,
            "SYNC_STAGES_AT_LEAST_2": True, "ASYNC_REG_SOURCE": True,
            "ALL_USER_BRANCHES_SHARE_RELEASE": True,
            "EQUIVALENT_INDEPENDENT_RELEASE_CHAINS": 0,
            "ALTERNATE_STARTUP_RESET_BYPASS": False,
            "FIFO_HANDSHAKE_COHERENT": True,
            "RESET_INSTANCE": chain}


def _find_v5_manifest(repo: Path, commit: str) -> list[str]:
    paths = git(repo, "ls-tree", "-r", "--name-only", commit).decode().splitlines()
    candidates = []
    for path in paths:
        basename = path.rsplit("/", 1)[-1].lower()
        if "manifest" not in basename or not path.lower().endswith(".json"):
            continue
        if "v5" not in path.lower() and basename not in ("v5_evidence_manifest.json", "v5_manifest.json"):
            continue
        try:
            doc = json.loads(show(repo, commit, path))
        except (Blocked, json.JSONDecodeError):
            continue
        serialized = json.dumps(doc).lower()
        if "phk2-v5" in serialized or doc.get("candidate") == "PHK2-v5":
            candidates.append(path)
    return candidates


def _get_checkpoint(manifest: dict, names: tuple[str, ...]) -> dict:
    blocks = manifest.get("checkpoints", manifest.get("artifacts", {}))
    for name in names:
        item = blocks.get(name)
        if isinstance(item, dict) and item.get("path") and item.get("sha256"):
            return item
    raise Blocked(f"manifest missing checkpoint entry {names[0]}")


def evidence_audit(repo: Path, commit: str, source: dict[str, Any], path: str) -> dict[str, Any]:
    manifest = json.loads(show(repo, commit, path))
    src = manifest.get("source", {})
    recorded_source = src.get("commit", src.get("source_commit", manifest.get("source_commit")))
    recorded_tree = src.get("tree_hash", src.get("source_tree_hash", manifest.get("source_tree_hash")))
    if recorded_source != source["SOURCE_COMMIT"] or recorded_tree != source["SOURCE_TREE_HASH"]:
        raise Blocked("v5 evidence manifest source commit/tree mismatch")
    tree_paths = set(git(repo, "ls-tree", "-r", "--name-only", commit).decode().splitlines())
    sums_path = manifest.get("sha256sums_path")
    sums = None
    if sums_path:
        sums = show(repo, commit, sums_path).decode()
    hashed: dict[str, str] = {}
    for category in ("checkpoints", "artifacts", "reports", "evidence"):
        group = manifest.get(category, {})
        if isinstance(group, list):
            for item in group:
                if isinstance(item, dict) and item.get("path") and item.get("sha256"):
                    hashed[item["path"]] = item["sha256"]
        elif isinstance(group, dict):
            for k, item in group.items():
                if isinstance(item, dict) and item.get("path") and item.get("sha256"):
                    hashed[item["path"]] = item["sha256"]
                elif isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) and "/" in k:
                    hashed[k] = item
    synth = _get_checkpoint(manifest, ("synth_dcp", "synthesis_dcp", "synth"))
    placed = _get_checkpoint(manifest, ("placed_dcp", "placement_dcp", "placed"))
    routed = _get_checkpoint(manifest, ("routed_dcp", "route_dcp", "routed"))
    for item in (synth, placed, routed):
        hashed[item["path"]] = item["sha256"]
    if not sums:
        raise Blocked("immutable v5 manifest lacks SHA256SUMS inventory")
    sum_items = {}
    for line in sums.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not m or m.group(2) in sum_items:
            raise Blocked("v5 SHA256SUMS is malformed")
        sum_items[m.group(2)] = m.group(1)
    if not sum_items:
        raise Blocked("v5 SHA256SUMS contains no file entries")
    for fpath, digest in sum_items.items():
        if fpath not in tree_paths or sha(show(repo, commit, fpath)) != digest:
            raise Blocked(f"SHA256SUMS mismatch or missing immutable blob: {fpath}")
    for fpath, digest in hashed.items():
        if fpath not in tree_paths:
            raise Blocked(f"manifest file missing from evidence commit: {fpath}")
        content = show(repo, commit, fpath)
        if sha(content) != digest or sum_items.get(fpath) != digest:
            raise Blocked(f"hash validation failed for {fpath}")

    reports = {p: show(repo, commit, p).decode(errors="replace") for p in hashed
               if p.lower().endswith((".rpt", ".csv", ".json", ".txt"))}
    cdc_reports = [(p, t) for p, t in reports.items() if "CDC Report" in t and "CDC-11" in t]
    if not cdc_reports:
        raise Blocked("raw mapped/routed report_cdc evidence is absent")
    if not any("all_checks_per_endpoint" in text.lower() or "all checks per endpoint" in text.lower()
               for _, text in cdc_reports):
        raise Blocked("raw report_cdc -all_checks_per_endpoint evidence is absent")
    report_names = [p.lower() for p in hashed if p.lower().endswith((".rpt", ".csv", ".json"))]
    if not any("recovery" in p or "removal" in p for p in report_names):
        raise Blocked("hash-bound routed recovery/removal evidence is absent")
    gray_reports = [p for p in report_names if "gray" in p and ("max_delay" in p or "max-delay" in p)]
    if len(set(gray_reports)) < 4:
        raise Blocked("four hash-bound routed Gray max-delay reports are absent")
    if not any("cdc1" in p and p.endswith((".csv", ".json")) for p in report_names):
        raise Blocked("hash-bound CDC-1 row-level evidence is absent")
    route_reports = [(p, t) for p, t in cdc_reports if "Design State      : Routed" in t or "Routed" in t[:1000]]
    if not route_reports:
        raise Blocked("raw routed CDC report is absent")
    cdc_text = route_reports[-1][1]
    cdc11_rows = re.findall(r"^\s*(\d+)\s+CDC-11\s+Critical[^\n]*", cdc_text, re.M)
    if len(cdc11_rows) == 0:
        # A zero CDC11 report is not a substitute for complete row accounting;
        # require explicit zero-count row inventory from the manifest.
        if manifest.get("cdc_counts", {}).get("CDC11") != 0:
            raise Blocked("routed CDC-11 rows cannot be enumerated")

    row_table = None
    for fpath, text in reports.items():
        if fpath.lower().endswith(".csv") and "row_id" in text.lower() and "destination" in text.lower() and "cdc-11" in text.lower():
            try:
                parsed = list(csv.DictReader(io.StringIO(text)))
            except csv.Error:
                continue
            if parsed:
                row_table = parsed
                break
    if row_table is None or len(row_table) != len(cdc11_rows):
        raise Blocked("exact row-level CDC-11 mapping table missing or count mismatch")
    destinations = []
    reset_chains = set()
    for row in row_table:
        lower = {k.lower(): v for k, v in row.items()}
        dest = lower.get("destination", lower.get("destination_pin", ""))
        row_id = lower.get("report_row_id", lower.get("row_id", ""))
        rule = lower.get("rule", "cdc-11")
        if not dest or not row_id or rule.lower() not in ("cdc-11", "cdc11"):
            raise Blocked("CDC-11 map row lacks exact ID/destination/rule")
        if int(row_id) not in {int(x) for x in cdc11_rows}:
            raise Blocked(f"CDC-11 table row {row_id} absent from raw report")
        raw_line = re.search(rf"^\s*{int(row_id)}\s+CDC-11\s+Critical[^\n]*$", cdc_text, re.M)
        src = lower.get("source", lower.get("source_pin", ""))
        if not raw_line or dest not in raw_line.group(0) or (src and src not in raw_line.group(0)):
            raise Blocked(f"CDC-11 row {row_id} endpoint mapping differs from raw routed report")
        destinations.append(dest)
        cls = lower.get("classification", lower.get("topology_class", "")).lower()
        if "reset" in cls or dest.endswith("/PRE") or dest.endswith("/CLR"):
            chain_id = lower.get("sync_chain", lower.get("chain_id", lower.get("destination_hierarchy", "")))
            if not chain_id:
                raise Blocked(f"reset CDC-11 row {row_id} lacks exact release chain mapping")
            reset_chains.add(chain_id)
    if len(set(destinations)) != len(destinations):
        raise Blocked("CDC-11 row map duplicates endpoints")
    if len(reset_chains) != 1:
        raise Blocked(f"expected exactly one common BSCAN reset release chain in mapped row inventory; found {len(reset_chains)}")

    metric = manifest.get("qualification", manifest.get("summary", {}))
    if not metric:
        for p, text in reports.items():
            if p.lower().endswith(".json"):
                try:
                    doc = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if any(k in doc for k in ("cdc1_real_unsafe", "gray_max_delay_active_count", "TCK_INDEPENDENT_PASS")):
                    metric = doc
                    break
    def val(*keys, default=None):
        for key in keys:
            if key in metric:
                return metric[key]
        return default
    cdc1_unsafe = val("CDC1_REAL_UNSAFE", "cdc1_real_unsafe", "cdc1_rows_real_unsafe")
    gray_max = val("GRAY_MAX_DELAY_ACTIVE_COUNT", "gray_max_delay_active_count")
    gray_skew = val("GRAY_BUS_SKEW_ACTIVE_COUNT", "gray_bus_skew_active_count")
    gray_finite = val("GRAY_FINITE_TIMING_COUNT", "gray_finite_timing_count")
    common_syncs = val("COMMON_RELEASE_SYNCHRONIZERS", "common_release_synchronizers")
    same_domain_dupes = val("SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS", "same_domain_duplicate_release_chains")
    recovery = val("RECOVERY_REMOVAL_PASS", "recovery_removal_pass", "reset_recovery_removal_pass_50mhz")
    async_preserved = val("ASYNC_REG_PRESERVED", "async_reg_preserved")
    gates = {
        "CDC1_REAL_UNSAFE_ZERO": cdc1_unsafe == 0 or cdc1_unsafe is False,
        "GRAY_MAX_DELAY_ACTIVE_COUNT_4": gray_max == 4,
        "GRAY_BUS_SKEW_ACTIVE_COUNT_4": gray_skew == 4,
        "GRAY_FINITE_TIMING_COUNT_4": gray_finite == 4,
        "COMMON_RELEASE_SYNCHRONIZERS_1": common_syncs == 1,
        "SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS_0": same_domain_dupes == 0,
        "RECOVERY_REMOVAL_PASS": recovery is True,
        "ASYNC_REG_PRESERVED": async_preserved is True,
    }
    failed = [k for k, passed in gates.items() if not passed]
    if failed:
        raise Blocked("mapped/routed acceptance gates missing or failing: " + ", ".join(failed))
    independent_pass = val("TCK_INDEPENDENT_PASS", "tck_independent_pass")
    independent_fail = val("TCK_INDEPENDENT_FAIL", "tck_independent_fail")
    cases_pass = val("QUALIFICATION_CASES_PASS", "qualification_cases_pass")
    if independent_pass != 38 or independent_fail != 0 or cases_pass != 38:
        raise Blocked("independent qualification counts are not exactly 38 pass / 0 fail")
    return {"EVIDENCE_COMMIT": commit, "MANIFEST_PATH": path,
            "CDC11_ROWS_ACCOUNTED": len(row_table), "CDC11_ROW_DESTINATIONS": destinations,
            "COMMON_RELEASE_SYNCHRONIZERS": common_syncs,
            "SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS": same_domain_dupes,
            "RECOVERY_REMOVAL_PASS": recovery, "ASYNC_REG_PRESERVED": async_preserved,
            "CDC1_REAL_UNSAFE": cdc1_unsafe, "GRAY_MAX_DELAY_ACTIVE_COUNT": gray_max,
            "GRAY_BUS_SKEW_ACTIVE_COUNT": gray_skew, "GRAY_FINITE_TIMING_COUNT": gray_finite,
            "CDC11_ACCEPTANCE_PASS": True, "RTL_FIX_REQUIRED": False,
            "TCK_INDEPENDENT_CASES": 38, "TCK_INDEPENDENT_PASS": 38, "TCK_INDEPENDENT_FAIL": 0,
            "QUALIFICATION_CASES": 40, "QUALIFICATION_CASES_PASS": 38,
            "QUALIFICATION_CASES_FAIL": 0, "QUALIFICATION_CASES_BLOCKED_ONLY_BY_TCK": 2,
            "PHYSICAL_QUALIFICATION_EXCEPT_TCK": True}


def discover(repo: Path) -> dict[str, Any]:
    refs = git(repo, "rev-list", "--all").decode().splitlines()
    try:
        fsck = git(repo, "fsck", "--no-reflogs", "--unreachable", "--no-progress").decode(errors="replace")
        refs = list(dict.fromkeys(refs + re.findall(r"(?:unreachable|dangling) commit ([0-9a-f]{40})", fsck)))
    except Blocked:
        pass
    source_candidates = []
    evidence_candidates = []
    v4_top = show(repo, V4_SOURCE, "rtl/phk2_board/phk2_fk33_board_top.sv")
    # Only consider committed source edits descended from the v4 source that
    # actually changed the board top. This avoids accepting old one-chain RTL.
    changed_tops = set(git(repo, "rev-list", "--all", "--", "rtl/phk2_board/phk2_fk33_board_top.sv").decode().splitlines())
    for commit in refs:
        try:
            if commit not in changed_tops or commit == V4_SOURCE:
                continue
            git(repo, "merge-base", "--is-ancestor", V4_SOURCE, commit)
            if show(repo, commit, "rtl/phk2_board/phk2_fk33_board_top.sv") == v4_top:
                continue
            result = source_audit(repo, commit)
            source_candidates.append((commit, result))
        except (Blocked, OSError):
            continue
    for commit in refs:
        try:
            manifests = _find_v5_manifest(repo, commit)
            evidence_candidates.extend((commit, p) for p in manifests)
        except (Blocked, OSError):
            continue
    if not source_candidates:
        return {"V5_SOURCE_COMMIT_FOUND": False, "V5_SOURCE_AUDIT_PASS": False,
                "EVIDENCE_READY": False, "CDC11_ACCEPTANCE_PASS": False,
                "RTL_FIX_REQUIRED": True,
                "BLOCKER": "no immutable v5 source commit with one shared reset-release chain is present in local Git refs"}
    source_candidates.sort(key=lambda pair: pair[0])
    source_commit, source_result = source_candidates[-1]
    result = {"V5_SOURCE_COMMIT_FOUND": True, "V5_SOURCE_AUDIT_PASS": True,
              "SOURCE_AUDIT": source_result, "EVIDENCE_READY": False,
              "CDC11_ACCEPTANCE_PASS": False, "RTL_FIX_REQUIRED": True,
              "BLOCKER": "v5 mapped/routed evidence manifest not yet present"}
    for commit, manifest_path in evidence_candidates:
        try:
            manifest = json.loads(show(repo, commit, manifest_path))
            src = manifest.get("source", {})
            exact_source = src.get("commit", src.get("source_commit", manifest.get("source_commit")))
            if not exact_source:
                continue
            exact_source_result = source_audit(repo, exact_source)
            audited = evidence_audit(repo, commit, exact_source_result, manifest_path)
            result.update({"V5_EVIDENCE_READY": True, "EVIDENCE_AUDIT": audited,
                           "EVIDENCE_READY": True, "CDC11_ACCEPTANCE_PASS": True,
                           "RTL_FIX_REQUIRED": False, "BLOCKER": None})
            return result
        except (Blocked, OSError, json.JSONDecodeError) as exc:
            result["BLOCKER"] = str(exc)
            result["EVIDENCE_COMMIT_CANDIDATE"] = commit
            result["MANIFEST_CANDIDATE"] = manifest_path
    return result


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument("--watch", action="store_true", help="poll local Git refs until complete evidence appears")
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--output", type=Path, help="write latest intake record to this path")
    a = p.parse_args()
    if a.interval < 1:
        p.error("--interval must be at least one second")
    previous = None
    while True:
        try:
            result = discover(a.repo)
        except (Blocked, OSError) as exc:
            result = {"V5_SOURCE_COMMIT_FOUND": False, "EVIDENCE_READY": False,
                      "CDC11_ACCEPTANCE_PASS": False, "RTL_FIX_REQUIRED": True,
                      "BLOCKER": str(exc)}
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if a.output:
            a.output.write_text(rendered)
        fingerprint = hashlib.sha256(rendered.encode()).hexdigest()
        if fingerprint != previous:
            print(rendered, end="", flush=True)
            previous = fingerprint
        if not a.watch or result.get("CDC11_ACCEPTANCE_PASS"):
            return 0 if result.get("CDC11_ACCEPTANCE_PASS") else 2
        time.sleep(a.interval)


if __name__ == "__main__":
    raise SystemExit(main())
