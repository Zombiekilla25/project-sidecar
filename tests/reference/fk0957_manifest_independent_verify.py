#!/usr/bin/env python3
"""Independent, read-only verification of a candidate's unsigned release pins."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", required=True, type=Path)
    ap.add_argument("--expected-commit", required=True)
    ap.add_argument("--output", type=Path)
    a = ap.parse_args()
    root = a.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, check=True, capture_output=True, text=True).stdout
    if head != a.expected_commit or dirty:
        raise SystemExit("candidate HEAD/cleanliness mismatch")
    manifest_path = root / "results/fk0957-release-candidate-source-manifest.json"
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    source = manifest["source_hashes"]
    source_errors = [name for name, expected in source.items()
                     if not re.fullmatch(r"[0-9a-f]{64}", expected) or
                     not (root / name).is_file() or sha(root / name) != expected]
    runtime = manifest["runtime_inventory"]
    runtime_errors = []
    for item in runtime:
        path = Path(item["path"])
        if not path.is_file() or path.resolve(strict=True) != path or sha(path) != item["sha256"]:
            runtime_errors.append(item["logical_name"] + ":path-or-sha")
            continue
        note = subprocess.run(["readelf", "-n", str(path)], check=True,
                              capture_output=True, text=True).stdout
        build_ids = re.findall(r"Build ID: ([0-9a-f]+)", note)
        if item["build_id"] not in build_ids:
            runtime_errors.append(item["logical_name"] + ":build-id")
    profile = root / "ops/phk2/FK0957_TOPOLOGY_TRANSACTION_PROFILE.json"
    trust = root / "ops/phk2/FK0957_REMOTE_TRUST_TEMPLATE.json"
    sidecar = manifest_path.with_suffix(manifest_path.suffix + ".sha256")
    sidecar_ok = sidecar.read_text(encoding="ascii").split()[0] == hashlib.sha256(raw).hexdigest()
    # The manifest's transaction profile digest binds a normalized semantic
    # profile produced from the golden transaction hashes, not the JSON file
    # byte digest. Check both independently: semantic hash and source-file pin.
    trust_ok = sha(trust) == manifest["trust_config_sha256"]
    profile_data = json.loads(profile.read_bytes())
    op = profile_data
    semantic_profile = {
        "schema": "fk0957-fixed-reset-default-dr-profile-v1",
        "scan_a_sha256": op["scan_a_sha256"],
        "scan_b_sha256": op["scan_b_sha256"],
        "scan_a_tck_count": op["scan_a_tck_count"],
        "scan_b_tck_count": op["scan_b_tck_count"],
        "total_tck_count": op["total_tck_count"],
        "ir_update": False,
    }
    semantic_profile_sha = hashlib.sha256(
        (json.dumps(semantic_profile, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True) + "\n").encode("ascii")).hexdigest()
    profile_ok = (semantic_profile_sha == manifest["transaction_profile_sha256"] and
                  source.get("ops/phk2/FK0957_TOPOLOGY_TRANSACTION_PROFILE.json") == sha(profile))
    production_keys = json.loads(trust.read_bytes())
    result = {
        "candidate_head": head,
        "manifest_production_head": manifest.get("production_head"),
        "manifest_source_revision_is_ancestor": subprocess.run(
            ["git", "merge-base", "--is-ancestor", manifest["production_head"], head],
            cwd=root, check=False).returncode == 0,
        "manifest_worktree_clean_claim": manifest.get("worktree_clean") is True,
        "source_count": len(source), "source_hashes_match": not source_errors,
        "source_errors": source_errors,
        "runtime_count": len(runtime), "runtime_hash_and_build_ids_match": not runtime_errors,
        "runtime_errors": runtime_errors,
        "manifest_sidecar_matches": sidecar_ok,
        "transaction_profile_hash_matches": profile_ok,
        "transaction_profile_sha256": semantic_profile_sha,
        "transaction_counts": [profile_data[key] for key in
                               ("scan_a_tck_count", "scan_b_tck_count", "total_tck_count")],
        "transaction_hashes": [profile_data[key] for key in
                                ("scan_a_sha256", "scan_b_sha256")],
        "trust_template_hash_matches": trust_ok,
        "production_trust_keys_provisioned": bool(production_keys.get("release_issuer_public_key_sha256") and
                                                    production_keys.get("handoff_issuer_public_key_sha256")),
        "manifest_authenticated": False,
        "production_authorization_available": False,
        "hardware_access": False,
        "network_access": False,
    }
    result["integrity_checks_pass"] = all((result["manifest_source_revision_is_ancestor"],
        result["manifest_worktree_clean_claim"], result["source_hashes_match"],
        result["runtime_hash_and_build_ids_match"], sidecar_ok, profile_ok, trust_ok))
    text = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if a.output:
        a.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["integrity_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
