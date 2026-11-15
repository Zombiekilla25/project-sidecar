#!/usr/bin/env python3
"""Strict independent parent identity refusal matrix with every outcome saved."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

EVENTS = ("after_stage_verify", "before_commit", "after_commit",
          "before_installed_verify", "after_installed_verify", "before_finalize",
          "before_previous_release_cleanup", "after_previous_release_cleanup")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", required=True, type=Path)
    ap.add_argument("--expected-commit", required=True)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    root = args.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          text=True, capture_output=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, check=True, text=True, capture_output=True,
                           timeout=10).stdout
    if head != args.expected_commit or dirty:
        raise SystemExit("candidate identity or cleanliness mismatch")
    sys.path.insert(0, str(root / "tools/phk2_host"))
    import install_fk0957_supervisor as installer

    started = time.monotonic()
    cases = []
    for old_exists in (False, True):
        events = EVENTS if old_exists else EVENTS[:6]
        for event in events:
            for replacement in ("new_directory", "symlink_to_original", "symlink_to_decoy"):
                with tempfile.TemporaryDirectory(prefix="fk0957-parent-strict-") as raw:
                    base = Path(raw); parent = base / "deploy"; moved = base / "renamed"
                    decoy = base / "decoy"; parent.mkdir(mode=0o700)
                    target = parent / "release"
                    if old_exists:
                        installer.stage_package(target)
                    original_parent = parent.stat(follow_symlinks=False)
                    fired = []
                    original_checkpoint = installer._stage_checkpoint

                    def substitute(name: str, _path: str | None = None) -> None:
                        if name == event and not fired:
                            fired.append(name); parent.rename(moved)
                            if replacement == "new_directory":
                                parent.mkdir(mode=0o700)
                            else:
                                link_target = moved
                                if replacement == "symlink_to_decoy":
                                    decoy.mkdir(mode=0o700); link_target = decoy
                                parent.symlink_to(link_target, target_is_directory=True)

                    installer._stage_checkpoint = substitute
                    try:
                        result = installer.stage_package(target)
                        outcome = "RETURNED"
                        cleanup_pending = result.cleanup_pending
                    except BaseException as exc:
                        outcome = "REFUSED"
                        cleanup_pending = None
                        exception_class = type(exc).__name__
                    else:
                        exception_class = None
                    finally:
                        installer._stage_checkpoint = original_checkpoint
                    try:
                        named_parent = parent.stat(follow_symlinks=False)
                        current_parent = {"dev": named_parent.st_dev, "ino": named_parent.st_ino,
                                          "is_symlink": parent.is_symlink()}
                    except OSError:
                        current_parent = None
                    path_target_exists = target.exists() or target.is_symlink()
                    target_valid = bool(path_target_exists and not target.is_symlink()
                                         and not installer.verify_staged_package(target))
                    cases.append({
                        "old_release": old_exists, "checkpoint": event,
                        "replacement": replacement, "checkpoint_reached": bool(fired),
                        "outcome": outcome, "exception_class": exception_class,
                        "cleanup_pending": cleanup_pending,
                        "requested_parent_is_symlink": bool(current_parent and current_parent["is_symlink"]),
                        "requested_parent_identity_unchanged": bool(current_parent and
                            (current_parent["dev"], current_parent["ino"]) ==
                            (original_parent.st_dev, original_parent.st_ino)),
                        "requested_target_exists": path_target_exists,
                        "requested_target_valid": target_valid,
                        "renamed_parent_target_valid": bool((moved / "release").exists()
                            and not installer.verify_staged_package(moved / "release")),
                    })
    # Identity substitution is invalid irrespective of whether a target path happens
    # to resolve through a symlink or contain a package with equivalent bytes.
    unsafe = [case for case in cases if case["checkpoint_reached"] and
              (case["outcome"] != "REFUSED" or case["requested_parent_identity_unchanged"])]
    result = {"schema": "fk0957-independent-parent-identity-strict-v1",
              "candidate_commit": head, "cases": len(cases), "unsafe_cases": unsafe,
              "case_results": cases,
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "hardware_access": False, "network_access": False,
              "pass": not unsafe}
    output = args.output.resolve(); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "case_results"}, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
