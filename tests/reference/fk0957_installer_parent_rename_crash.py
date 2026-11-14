#!/usr/bin/env python3
"""Reproduce recovery limits after an owner renames the install parent at runtime."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate-root", type=Path, required=True)
    ap.add_argument("--expected-commit", required=True)
    args = ap.parse_args()
    root_repo = args.candidate_root.resolve(strict=True)
    actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root_repo,
                            text=True, capture_output=True, check=True, timeout=10).stdout.strip()
    if actual != args.expected_commit:
        raise SystemExit("candidate commit mismatch")
    host = root_repo / "tools/phk2_host"
    sys.path.insert(0, str(host))
    import install_fk0957_supervisor as installer

    with tempfile.TemporaryDirectory(prefix="fk0957-parent-rename-crash-") as raw:
        base = Path(raw)
        parent, moved = base / "deploy", base / "deploy-moved"
        parent.mkdir(mode=0o700)
        destination = parent / "release"
        child = (
            "import os,sys\nfrom pathlib import Path\n"
            "sys.path.insert(0,sys.argv[1]); import install_fk0957_supervisor as p\n"
            "parent=Path(sys.argv[2]); moved=Path(sys.argv[3])\n"
            "def checkpoint(name,path=None):\n"
            " if name=='before_commit':\n"
            "  parent.rename(moved); parent.mkdir(mode=0o700); os._exit(86)\n"
            "p._stage_checkpoint=checkpoint\n"
            "p.stage_package(parent/'release')\n"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", child, str(host), str(parent), str(moved)],
            cwd=root_repo, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=180,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                 "PYTHONDONTWRITEBYTECODE": "1"}, check=False)
        if result.returncode != 86:
            raise SystemExit(f"expected hard-kill checkpoint 86; got {result.returncode}")
        current_path_recovery = installer.recover_staging(destination)
        orphan_before_manual_recovery = sorted(
            entry.name for entry in moved.iterdir()
            if entry.name.startswith(".release.fk0957-stage-"))
        moved_path_recovery = installer.recover_staging(moved / "release")
        orphan_after_manual_recovery = sorted(
            entry.name for entry in moved.iterdir()
            if entry.name.startswith(".release.fk0957-stage-"))
        report = {
            "candidate_commit": actual,
            "child_return_code": result.returncode,
            "recovery_at_replaced_destination": {
                "recovered_stages": current_path_recovery.recovered_stages,
                "unmarked_empty_stages": current_path_recovery.unmarked_empty_stages,
            },
            "siblings_in_renamed_original_parent": orphan_before_manual_recovery,
            "recovery_at_explicit_original_parent": {
                "recovered_stages": moved_path_recovery.recovered_stages,
                "unmarked_empty_stages": moved_path_recovery.unmarked_empty_stages,
            },
            "siblings_after_explicit_recovery": orphan_after_manual_recovery,
            "classification": "manual_recovery_required_if_parent_is_permanently_replaced",
            "target_publication_occurred": destination.exists(),
            "hardware_access": False,
            "network_access": False,
        }
        print(json.dumps(report, sort_keys=True))
        return 0 if (result.returncode == 86 and orphan_before_manual_recovery and
                     not orphan_after_manual_recovery and not destination.exists()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
