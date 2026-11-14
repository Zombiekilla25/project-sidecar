#!/usr/bin/env python3
"""Probe installer publication against parent renames at commit checkpoints."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time


EVENTS = ("before_commit", "after_commit", "before_installed_verify",
          "after_installed_verify", "before_finalize",
          "before_previous_release_cleanup", "after_previous_release_cleanup")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", required=True, type=Path)
    ap.add_argument("--expected-commit", required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    root = args.candidate_root.resolve(strict=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, check=True,
                          text=True, capture_output=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, check=True, text=True, capture_output=True,
                           timeout=10).stdout
    if head != args.expected_commit or dirty:
        raise SystemExit("candidate identity or cleanliness mismatch")
    started = time.monotonic()
    sys.path.insert(0, str(root / "tools/phk2_host"))
    import install_fk0957_supervisor as installer

    cases = []
    for old_exists in (False, True):
        for event in EVENTS:
            if event in {"before_previous_release_cleanup", "after_previous_release_cleanup"} and not old_exists:
                continue
            for replacement_kind in ("new_directory", "symlink_to_original", "symlink_to_decoy"):
             with tempfile.TemporaryDirectory(prefix="fk0957-parent-identity-matrix-") as raw:
                base = Path(raw); parent = base / "deploy"; moved = base / "renamed"
                decoy = base / "decoy"
                parent.mkdir(mode=0o700); target = parent / "release"
                if old_exists:
                    installer.stage_package(target)
                    (target / "previous-release-marker").write_text("old")
                fired = []
                original = installer._stage_checkpoint
                def replace_parent(name: str, _path: str | None = None) -> None:
                    if name == event and not fired:
                        fired.append(name)
                        parent.rename(moved)
                        if replacement_kind == "new_directory":
                            parent.mkdir(mode=0o700)
                        else:
                            if replacement_kind == "symlink_to_decoy":
                                decoy.mkdir(mode=0o700)
                                link_target = decoy
                            else:
                                link_target = moved
                            parent.symlink_to(link_target, target_is_directory=True)
                installer._stage_checkpoint = replace_parent
                try:
                    outcome = installer.stage_package(target)
                    returned = "SUCCESS"
                    exc_type = None
                except BaseException as exc:
                    returned = "REFUSED"
                    exc_type = type(exc).__name__
                    outcome = None
                finally:
                    installer._stage_checkpoint = original
                requested_exists = target.exists()
                requested_parent_symlink = parent.is_symlink()
                moved_exists = (moved / "release").exists()
                moved_valid = moved_exists and not installer.verify_staged_package(moved / "release")
                case = {"old_install": old_exists, "checkpoint": event,
                        "replacement_kind": replacement_kind,
                        "checkpoint_reached": bool(fired), "returned": returned,
                        "exception_type": exc_type, "requested_target_exists": requested_exists,
                        "requested_parent_symlink": requested_parent_symlink,
                        "renamed_parent_target_exists": moved_exists,
                        "renamed_parent_target_valid": moved_valid,
                        "reported_success_after_parent_substitution": returned == "SUCCESS" and
                            (not requested_exists or requested_parent_symlink)}
                if outcome is not None:
                    case["cleanup_pending"] = outcome.cleanup_pending
                cases.append(case)
    violations = [case for case in cases if case["reported_success_after_parent_substitution"]]
    result = {"schema": "fk0957-independent-parent-identity-matrix-v1",
              "candidate_commit": head, "cases": len(cases), "violations": violations,
              "elapsed_seconds": round(time.monotonic() - started, 3),
              "hardware_access": False, "network_access": False,
              "pass": not violations}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
