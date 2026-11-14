#!/usr/bin/env python3
"""Minimal offline reproducer for success after installer parent replacement."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
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

    with tempfile.TemporaryDirectory(prefix="fk0957-parent-postverify-") as raw:
        base = Path(raw)
        parent = base / "deploy"
        moved = base / "renamed-deploy"
        parent.mkdir(mode=0o700)
        target = parent / "release"
        fired = False
        original = installer._stage_checkpoint

        def replace_after_verify(name: str, _path: str | None = None) -> None:
            nonlocal fired
            if name == "after_installed_verify" and not fired:
                fired = True
                parent.rename(moved)
                parent.mkdir(mode=0o700)

        installer._stage_checkpoint = replace_after_verify
        try:
            installer.stage_package(target)
            outcome = "SUCCESS"
        except BaseException as exc:
            outcome = type(exc).__name__
        finally:
            installer._stage_checkpoint = original

        reproduced = bool(fired and outcome == "SUCCESS" and not target.exists()
                          and not installer.verify_staged_package(moved / target.name))
        print(json.dumps({
            "candidate_commit": head,
            "checkpoint": "after_installed_verify",
            "replacement": "rename_parent_then_create_empty_parent",
            "checkpoint_reached": fired,
            "installer_outcome": outcome,
            "requested_target_exists": target.exists(),
            "renamed_original_target_complete": bool(
                not installer.verify_staged_package(moved / target.name)),
            "success_returned_without_requested_target": reproduced,
            "hardware_access": False,
            "network_access": False,
        }, sort_keys=True))
        return 0 if reproduced else 1


if __name__ == "__main__":
    raise SystemExit(main())
