#!/usr/bin/env python3
"""Offline target-path replacement matrix after installer verification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, check=True, capture_output=True, text=True,
                           timeout=10).stdout
    if head != args.expected_commit or dirty:
        raise SystemExit("candidate identity or cleanliness mismatch")
    sys.path.insert(0, str(root / "tools/phk2_host"))
    import install_fk0957_supervisor as installer

    started = time.monotonic()
    cases = []
    checkpoints = ("after_installed_verify", "before_finalize",
                   "before_previous_release_cleanup", "after_previous_release_cleanup")
    for old_exists in (False, True):
        for checkpoint in checkpoints:
            if checkpoint.endswith("previous_release_cleanup") and not old_exists:
                continue
            for replacement in ("empty_directory", "decoy_symlink"):
                with tempfile.TemporaryDirectory(prefix="fk0957-target-identity-") as raw:
                    base = Path(raw)
                    parent = base / "deploy"
                    parent.mkdir(mode=0o700)
                    target = parent / "release"
                    displaced = base / "displaced-published-release"
                    decoy = base / "decoy"
                    decoy.mkdir(mode=0o700)
                    if old_exists:
                        installer.stage_package(target)
                    fired = []
                    original = installer._stage_checkpoint

                    def replace_target(name: str, _path: str | None = None) -> None:
                        if name == checkpoint and not fired:
                            fired.append(name)
                            target.rename(displaced)
                            if replacement == "empty_directory":
                                target.mkdir(mode=0o700)
                            else:
                                target.symlink_to(decoy, target_is_directory=True)

                    installer._stage_checkpoint = replace_target
                    try:
                        installer.stage_package(target)
                        outcome = "SUCCESS"
                    except BaseException as exc:
                        outcome = type(exc).__name__
                    finally:
                        installer._stage_checkpoint = original
                    target_valid = target.exists() and not target.is_symlink() and not installer.verify_staged_package(target)
                    displaced_valid = displaced.exists() and not installer.verify_staged_package(displaced)
                    false_success = bool(fired and outcome == "SUCCESS" and not target_valid)
                    cases.append({
                        "old_release": old_exists, "checkpoint": checkpoint,
                        "replacement": replacement, "checkpoint_reached": bool(fired),
                        "outcome": outcome, "requested_target_exists": target.exists(),
                        "requested_target_is_symlink": target.is_symlink(),
                        "requested_target_valid": target_valid,
                        "displaced_published_release_valid": displaced_valid,
                        "success_with_invalid_requested_target": false_success,
                    })
    violations = [case for case in cases if case["success_with_invalid_requested_target"]]
    result = {"schema": "fk0957-independent-target-identity-matrix-v1",
              "candidate_commit": head, "cases": len(cases),
              "violations": violations,
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "hardware_access": False, "network_access": False,
              "pass": not violations}
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
