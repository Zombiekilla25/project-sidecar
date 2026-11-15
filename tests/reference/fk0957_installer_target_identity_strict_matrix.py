#!/usr/bin/env python3
"""Strict target-inode refusal matrix with every candidate outcome retained."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", required=True, type=Path)
    ap.add_argument("--expected-commit", required=True)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args(); root = args.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, check=True, capture_output=True, text=True,
                           timeout=10).stdout
    if head != args.expected_commit or dirty:
        raise SystemExit("candidate identity or cleanliness mismatch")
    sys.path.insert(0, str(root / "tools/phk2_host"))
    import install_fk0957_supervisor as installer

    started = time.monotonic(); cases = []
    for old_exists in (False, True):
        checkpoints = ("after_installed_verify", "before_finalize")
        if old_exists:
            checkpoints += ("before_previous_release_cleanup", "after_previous_release_cleanup")
        for checkpoint in checkpoints:
            for replacement in ("empty_directory", "decoy_symlink", "target_absent"):
                with tempfile.TemporaryDirectory(prefix="fk0957-target-strict-") as raw:
                    base = Path(raw); parent = base / "deploy"
                    parent.mkdir(mode=0o700); target = parent / "release"
                    displaced = base / "displaced-release"; decoy = base / "decoy"
                    decoy.mkdir(mode=0o700)
                    if old_exists:
                        installer.stage_package(target)
                    fired = []; original = installer._stage_checkpoint
                    def substitute(name: str, _path: str | None = None) -> None:
                        if name == checkpoint and not fired:
                            fired.append(name); target.rename(displaced)
                            if replacement == "empty_directory":
                                target.mkdir(mode=0o700)
                            elif replacement == "decoy_symlink":
                                target.symlink_to(decoy, target_is_directory=True)
                    installer._stage_checkpoint = substitute
                    try:
                        installer.stage_package(target)
                        outcome = "RETURNED"; exc_class = None
                    except BaseException as exc:
                        outcome = "REFUSED"; exc_class = type(exc).__name__
                    finally:
                        installer._stage_checkpoint = original
                    target_valid = bool(target.exists() and not target.is_symlink()
                                         and not installer.verify_staged_package(target))
                    displaced_valid = bool(displaced.exists() and not installer.verify_staged_package(displaced))
                    cases.append({"old_release": old_exists, "checkpoint": checkpoint,
                        "replacement": replacement, "checkpoint_reached": bool(fired),
                        "outcome": outcome, "exception_class": exc_class,
                        "requested_target_exists": target.exists() or target.is_symlink(),
                        "requested_target_is_symlink": target.is_symlink(),
                        "requested_target_valid": target_valid,
                        "displaced_verified_target_valid": displaced_valid})
    unsafe = [c for c in cases if c["checkpoint_reached"] and
              (c["outcome"] != "REFUSED" or c["requested_target_valid"])]
    result = {"schema":"fk0957-independent-target-identity-strict-v1",
              "candidate_commit":head,"cases":len(cases),"unsafe_cases":unsafe,
              "case_results":cases,"elapsed_seconds":round(time.monotonic()-started,3),
              "hardware_access":False,"network_access":False,"pass":not unsafe}
    out=args.output.resolve(); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:v for k,v in result.items() if k!="case_results"},sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__": raise SystemExit(main())
