#!/usr/bin/env python3
"""Offline intake/review of mapped or routed Vivado CDC-11 reset evidence.

No Vivado invocation, implementation, hardware access, or source mutation is
performed. CDC topology is accepted only from a hash-bound normalized capture
generated from Vivado reports and the exact source snapshot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any

from physical_tck_preflight import Refusal

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file(root: Path, ref: Any, label: str) -> tuple[Path, str]:
    if not isinstance(ref, dict):
        raise Refusal(f"{label} reference missing")
    rel, expected = ref.get("path"), ref.get("sha256")
    if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
        raise Refusal(f"{label} path must be package-relative")
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise Refusal(f"{label} SHA256 invalid")
    path = root / rel
    cursor = root
    for part in Path(rel).parts:
        cursor /= part
        if cursor.is_symlink():
            raise Refusal(f"{label} cannot traverse symlinks")
    real = path.resolve(strict=True)
    try:
        real.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise Refusal(f"{label} escapes package") from exc
    actual = sha256(real)
    if actual != expected:
        raise Refusal(f"{label} hash mismatch")
    return real, actual


def _clock_fingerprint(clock: dict[str, Any]) -> tuple[Any, ...]:
    required = ("clock_object", "clock_root", "period_ps", "generated_clock_relationship",
                "physical_clock_source", "logical_domain")
    if not isinstance(clock, dict) or any(k not in clock for k in required):
        raise Refusal("clock identity missing object/root/period/generated/source/domain fields")
    period = clock["period_ps"]
    if isinstance(period, bool) or not isinstance(period, (int, float)) or not math.isfinite(period) or period <= 0:
        raise Refusal("clock period must be finite and positive")
    if any(not isinstance(clock[k], str) or not clock[k].strip() for k in required if k != "period_ps"):
        raise Refusal("clock identity contains empty values")
    # Clock name aliases alone do not make independent domains. The root,
    # generated relationship, physical source, period and declared domain do.
    return (clock["clock_root"], float(period), clock["generated_clock_relationship"],
            clock["physical_clock_source"], clock["logical_domain"])


def _check_source(root: Path, source: Any) -> str:
    if not isinstance(source, dict):
        raise Refusal("immutable source identity missing")
    commit, tree_hash = source.get("SOURCE_COMMIT"), source.get("SOURCE_TREE_HASH")
    if not isinstance(commit, str) or not HEX40.fullmatch(commit) or not isinstance(tree_hash, str) or not HEX64.fullmatch(tree_hash):
        raise Refusal("source commit/tree hash invalid")
    _, actual_tree_hash = _file(root, source.get("SOURCE_TREE_ARCHIVE"), "source tree archive")
    if actual_tree_hash != tree_hash:
        raise Refusal("source tree archive does not match SOURCE_TREE_HASH")
    entries = source.get("SOURCE_FILES")
    if not isinstance(entries, dict) or not entries:
        raise Refusal("source file identity list missing")
    for name, digest in entries.items():
        if not isinstance(name, str) or not isinstance(digest, str) or not HEX64.fullmatch(digest):
            raise Refusal("source file hash entry malformed")
        _file(root, {"path": name, "sha256": digest}, f"immutable source file {name}")
    return commit


def review_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path).resolve(strict=True)
    root = report_path.parent
    try:
        evidence = json.loads(report_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"review evidence unreadable: {exc}") from exc
    if not isinstance(evidence, dict) or evidence.get("schema") != "PHK2-VIVADO-CDC11-RESET-REVIEW-v1":
        raise Refusal("unsupported CDC review evidence schema")
    if evidence.get("synthetic_fixture") is not False:
        raise Refusal("synthetic evidence cannot be accepted as Vivado evidence")
    commit = _check_source(root, evidence.get("source"))
    for key in ("mapped_checkpoint", "cdc_default_report", "cdc_all_checks_report", "timing_summary_report",
                "recovery_removal_report", "exceptions_report", "clock_inventory_report", "reset_cell_inventory_report"):
        _file(root, evidence.get(key), key)
    checkpoint = evidence["mapped_checkpoint"]
    if checkpoint.get("stage") not in ("SYNTH_MAPPED", "ROUTED") or checkpoint.get("source_commit") != commit:
        raise Refusal("mapped checkpoint stage/source identity mismatch")
    methodology = evidence.get("cdc_methodology")
    if not isinstance(methodology, dict) or methodology.get("all_checks_per_endpoint") is not True:
        raise Refusal("report_cdc -all_checks_per_endpoint evidence is required")
    if methodology.get("cdc_default_report_generated") is not True:
        raise Refusal("default report_cdc cross-check is required")
    counts = evidence.get("reported_counts")
    rows, chains = evidence.get("cdc11_rows"), evidence.get("cdc9_reset_chains")
    if not isinstance(counts, dict) or not isinstance(rows, list) or not isinstance(chains, list):
        raise Refusal("CDC row/chain inventories missing")
    if counts.get("CDC11_COUNT") != len(rows) or counts.get("CDC9_COUNT") != len(chains):
        raise Refusal("declared CDC counts differ from inventories")
    if len(rows) != 3:
        raise Refusal(f"expected exactly 3 CDC-11 rows, found {len(rows)}")
    if len(chains) != 3:
        raise Refusal(f"expected exactly 3 CDC-9 reset chains, found {len(chains)}")

    chain_by_id: dict[str, dict[str, Any]] = {}
    domain_chains: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for chain in chains:
        if not isinstance(chain, dict) or not isinstance(chain.get("chain_id"), str) or chain["chain_id"] in chain_by_id:
            raise Refusal("CDC-9 chain IDs missing or duplicated")
        clock = chain.get("destination_clock")
        fingerprint = _clock_fingerprint(clock)
        chain_by_id[chain["chain_id"]] = chain
        domain_chains.setdefault(fingerprint, []).append(chain)
        if not isinstance(chain.get("source_reset"), str) or not chain["source_reset"].strip():
            raise Refusal(f"CDC-9 chain {chain['chain_id']} source reset missing")
        stages = chain.get("stage_cells")
        if not isinstance(stages, list) or len(stages) != chain.get("sync_stages") or any(not isinstance(v, str) or not v for v in stages):
            raise Refusal(f"CDC-9 chain {chain['chain_id']} mapped synchronizer stage cells incomplete")
        if chain.get("rule") != "CDC-9" or chain.get("ASYNC_REG") is not True or chain.get("sync_stages", 0) < 2:
            raise Refusal(f"CDC-9 chain {chain.get('chain_id')} lacks recognized two-stage ASYNC_REG sync")
        for key in ("ASYNC_ASSERT", "SYNC_DEASSERT", "ONE_RELEASE_SYNCHRONIZER_PER_DOMAIN",
                    "ALL_SAME_DOMAIN_CONSUMERS_SHARE_RELEASE", "RESET_DEASSERT_WHILE_CLOCK_STOPPED_SAFE",
                    "DOMAIN_REMAINS_IN_RESET_UNTIL_SYNC_EDGES"):
            if chain.get(key) is not True:
                raise Refusal(f"CDC-9 chain {chain['chain_id']} failed {key}")
        consumers = chain.get("downstream_consumers")
        if not isinstance(consumers, list) or not consumers or any(not isinstance(v, str) or not v for v in consumers):
            raise Refusal(f"CDC-9 chain {chain['chain_id']} downstream consumers missing")
        consumer_release = chain.get("consumer_release_chain_ids")
        if not isinstance(consumer_release, dict) or set(consumer_release) != set(consumers) or set(consumer_release.values()) != {chain["chain_id"]}:
            raise Refusal(f"CDC-9 chain {chain['chain_id']} does not prove one shared release net for all same-domain consumers")
    duplicate_chain_count = sum(max(0, len(group) - 1) for group in domain_chains.values())
    duplicate_domains = [group for group in domain_chains.values() if len(group) > 1]
    label_to_fp: dict[str, tuple[Any, ...]] = {}
    for group_fp, group in domain_chains.items():
        label = group[0]["destination_clock"]["logical_domain"]
        if label in label_to_fp and label_to_fp[label] != group_fp:
            raise Refusal(f"logical domain {label} maps to inconsistent clock roots/relationships")
        label_to_fp[label] = group_fp

    row_ids = set()
    endpoint_check_rows = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("ROW_ID"), str) or row["ROW_ID"] in row_ids:
            raise Refusal("CDC-11 row IDs missing or duplicated")
        row_ids.add(row["ROW_ID"])
        for field in ("SOURCE_RESET", "SOURCE_CELL", "DESTINATION_SYNC_STAGE", "DESTINATION_HIERARCHY", "CDC9_CHAIN", "DOMAIN_ID"):
            if not isinstance(row.get(field), str) or not row[field]:
                raise Refusal(f"CDC-11 {row['ROW_ID']} lacks {field}")
        if row.get("RULE") != "CDC-11" or row.get("ASYNC_REG") is not True or row.get("SYNC_STAGES", 0) < 2:
            raise Refusal(f"CDC-11 {row['ROW_ID']} is not bound to an ASYNC_REG two-stage reset chain")
        if row["CDC9_CHAIN"] not in chain_by_id:
            raise Refusal(f"CDC-11 {row['ROW_ID']} has no corresponding CDC-9 chain")
        chain = chain_by_id[row["CDC9_CHAIN"]]
        row_fp = _clock_fingerprint(row.get("destination_clock"))
        chain_fp = _clock_fingerprint(chain["destination_clock"])
        if row_fp != chain_fp:
            raise Refusal(f"CDC-11 {row['ROW_ID']} destination differs from its CDC-9 chain domain")
        if row["DOMAIN_ID"] != row["destination_clock"]["logical_domain"]:
            raise Refusal(f"CDC-11 {row['ROW_ID']} DOMAIN_ID does not match destination clock logical domain")
        if row["DESTINATION_SYNC_STAGE"] not in chain.get("stage_cells", []):
            raise Refusal(f"CDC-11 {row['ROW_ID']} destination stage is not in the linked CDC-9 chain")
        if row["SOURCE_RESET"] != chain.get("source_reset"):
            raise Refusal(f"CDC-11 {row['ROW_ID']} and CDC-9 chain source reset differ")
        rules = row.get("endpoint_rules")
        if not isinstance(rules, list) or "CDC-11" not in rules:
            raise Refusal(f"CDC-11 {row['ROW_ID']} missing all-checks endpoint rule evidence")
        endpoint_check_rows.append({"row_id": row["ROW_ID"], "rules": rules,
                                    "both_11_and_9": "CDC-9" in rules})

    recovery = evidence.get("recovery_removal")
    if not isinstance(recovery, dict):
        raise Refusal("recovery/removal result missing")
    if recovery.get("analysis_present") is not True:
        recovery_pass = None
    else:
        recovery_pass = recovery.get("pass") is True and recovery.get("false_path_hiding") is False
    gray = evidence.get("gray_constraints")
    if not isinstance(gray, dict) or len(gray.get("max_delay", [])) != 4 or len(gray.get("bus_skew", [])) != 4:
        raise Refusal("all four Gray max-delay and four bus-skew constraints must be inventoried")
    for item in gray["max_delay"]:
        if not isinstance(item, dict) or item.get("active") is not True or isinstance(item.get("value_ns"), bool) or not isinstance(item.get("value_ns"), (int, float)) or not math.isfinite(item["value_ns"]) or item["value_ns"] <= 0:
            raise Refusal("Gray max-delay constraint missing, inactive, or non-finite")
    for item in gray["bus_skew"]:
        if not isinstance(item, dict) or item.get("active") is not True:
            raise Refusal("Gray bus-skew constraint missing or inactive")
        if isinstance(item.get("value_ns"), bool) or not isinstance(item.get("value_ns"), (int, float)) or not math.isfinite(item["value_ns"]) or item["value_ns"] <= 0:
            raise Refusal("Gray bus-skew constraint missing or non-finite")

    distinct = len(domain_chains)
    real_unsafe = duplicate_chain_count > 0
    indeterminate = False
    structural = not real_unsafe
    chain_signatures = [{"chain_id": chain["chain_id"],
                         "stage_cells": chain.get("stage_cells", []),
                         "source_reset": chain["source_reset"],
                         "ASYNC_REG": chain["ASYNC_REG"],
                         "sync_stages": chain["sync_stages"],
                         "downstream_consumers": chain["downstream_consumers"],
                         "consumer_release_chain_ids": chain["consumer_release_chain_ids"],
                         "clock_fingerprint": list(_clock_fingerprint(chain["destination_clock"]))}
                        for chain in chains]
    cdc11_signatures = [{"ROW_ID": row["ROW_ID"], "SOURCE_RESET": row["SOURCE_RESET"],
                         "SOURCE_CELL": row["SOURCE_CELL"], "DESTINATION_SYNC_STAGE": row["DESTINATION_SYNC_STAGE"],
                         "DESTINATION_HIERARCHY": row["DESTINATION_HIERARCHY"], "CDC9_CHAIN": row["CDC9_CHAIN"],
                         "ASYNC_REG": row["ASYNC_REG"], "SYNC_STAGES": row["SYNC_STAGES"],
                         "DOMAIN_ID": row["DOMAIN_ID"], "endpoint_rules": row["endpoint_rules"],
                         "clock_fingerprint": list(_clock_fingerprint(row["destination_clock"]))}
                        for row in rows]
    return {
        "source_commit": commit,
        "V4_MAPPED_IDENTITY_VERIFIED": True,
        "CDC11_ROWS": len(rows), "CDC9_RESET_CHAINS": len(chains),
        "DESTINATION_DOMAINS": distinct,
        "SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS": duplicate_chain_count,
        "row_details": rows,
        "chain_details": chains,
        "domain_details": [{"clock": group[0]["destination_clock"], "chain_ids": [x["chain_id"] for x in group],
                            "consumers": [v for x in group for v in x["downstream_consumers"]]} for group in domain_chains.values()],
        "chain_signatures": chain_signatures,
        "cdc11_signatures": cdc11_signatures,
        "endpoint_rule_precedence": endpoint_check_rows,
        "CDC11_STRUCTURALLY_SAFE": structural,
        "CDC11_REAL_UNSAFE": real_unsafe,
        "CDC11_INDETERMINATE": indeterminate,
        "AMD_METHODOLOGY_CONSISTENT": True,
        "RECOVERY_REMOVAL_ANALYSIS_PRESENT": recovery["analysis_present"],
        "RECOVERY_REMOVAL_PASS": recovery_pass,
        "CDC11_ACCEPTANCE_PENDING_ROUTE": checkpoint["stage"] != "ROUTED",
        "RTL_FIX_REQUIRED": real_unsafe,
    }


def compare_routed(mapped: dict[str, Any], routed: dict[str, Any]) -> dict[str, Any]:
    for field in ("source_commit", "CDC11_ROWS", "CDC9_RESET_CHAINS", "DESTINATION_DOMAINS",
                  "SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS", "chain_signatures", "cdc11_signatures"):
        if mapped.get(field) != routed.get(field):
            raise Refusal(f"routed topology differs from mapped evidence: {field}")
    if routed.get("CDC11_ACCEPTANCE_PENDING_ROUTE") is not False:
        raise Refusal("post-route evidence is not marked ROUTED")
    pass_route = (routed.get("SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS") == 0
                  and routed.get("RECOVERY_REMOVAL_PASS") is True
                  and routed.get("CDC11_STRUCTURALLY_SAFE") is True)
    return {"CDC11_POST_ROUTE_ACCEPTANCE_PASS": pass_route,
            "ASYNC_REG_PROPERTIES_PRESERVED": all(x.get("ASYNC_REG") is True for x in routed["chain_signatures"]),
            "ONE_RELEASE_SYNCHRONIZER_PER_DOMAIN": routed.get("SAME_DOMAIN_DUPLICATE_RELEASE_CHAINS") == 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapped-review", required=True, help="hash-bound mapped Vivado evidence JSON")
    parser.add_argument("--post-route-review", help="optional later routed evidence JSON")
    args = parser.parse_args(argv)
    try:
        mapped = review_report(args.mapped_review)
        result: dict[str, Any] = dict(mapped)
        if args.post_route_review:
            routed = review_report(args.post_route_review)
            result.update(compare_routed(mapped, routed))
        else:
            result["CDC11_POST_ROUTE_ACCEPTANCE_PASS"] = False
        print(json.dumps(result, indent=2))
    except (Refusal, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"V4_MAPPED_IDENTITY_VERIFIED": False, "CDC11_INDETERMINATE": True,
                          "refusal": str(exc), "CDC11_ACCEPTANCE_PENDING_ROUTE": True}, indent=2), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
