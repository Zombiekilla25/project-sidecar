#!/usr/bin/env python3
"""Independent hard-termination sweep for disposable FK0957 installer roots.

This script imports the candidate installer only to run its existing disposable
stage API. It never invokes --apply, changes system paths, or touches devices.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0xF0957)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve(strict=True)
    actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True,
                            capture_output=True, check=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, text=True, capture_output=True, check=True,
                           timeout=10).stdout
    if actual != args.expected_commit or dirty:
        raise SystemExit("candidate identity or cleanliness gate failed")
    host = root / "tools/phk2_host"
    sys.path.insert(0, str(host))
    import install_fk0957_supervisor as installer

    labels: list[tuple[str, str | None]] = []
    original = installer._stage_checkpoint
    installer._stage_checkpoint = lambda name, path=None: labels.append((name, path))
    with tempfile.TemporaryDirectory(prefix="fk0957-enumerate-checkpoints-") as raw:
        installer.stage_package(Path(raw) / "release")
    installer._stage_checkpoint = original
    # Derive the checkpoint set from the candidate under test.  The earlier
    # fixed count went stale when the installer added additional staging
    # boundaries, which prevented the independent campaign from reaching them.
    if not labels or not any(name == "after_commit" for name, _path in labels):
        raise SystemExit(f"candidate exposed an incomplete checkpoint set: {len(labels)}")
    publish_at = next(i + 1 for i, (name, _path) in enumerate(labels)
                      if name == "after_commit")
    child = (
        "import os,sys\nfrom pathlib import Path\n"
        "sys.path.insert(0,sys.argv[1])\nimport install_fk0957_supervisor as i\n"
        "wanted=int(sys.argv[3]); seen=0\n"
        "def stop(name,path=None):\n global seen\n seen+=1\n"
        " if seen==wanted: os._exit(83)\n"
        "i._stage_checkpoint=stop\ni.stage_package(Path(sys.argv[2]))\n"
    )
    results = []
    started_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    started = time.monotonic()
    for old_exists in (False, True):
        order = list(range(1, len(labels) + 1))
        random.Random(args.seed + int(old_exists)).shuffle(order)
        for ordinal in order:
            with tempfile.TemporaryDirectory(prefix="fk0957-hardkill-") as raw:
                parent = Path(raw)
                target = parent / "release"
                old_identity = None
                if old_exists:
                    # Model a real previously installed package; an arbitrary
                    # directory is correctly rejected by the candidate's
                    # pre-existing-install identity gate.
                    installer.stage_package(target)
                    (target / "prior-release-marker").write_text(f"prior:{ordinal}")
                    stat_result = target.stat()
                    old_identity = (stat_result.st_dev, stat_result.st_ino)
                proc = subprocess.run(
                    [args.python, "-c", child, str(host), str(target), str(ordinal)],
                    cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=60, check=False,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                         "PYTHONDONTWRITEBYTECODE": "1"})
                if proc.returncode != 83:
                    raise AssertionError((ordinal, labels[ordinal - 1], proc.returncode,
                                          proc.stderr[-500:].decode("utf-8", "replace")))
                published = ordinal >= publish_at
                siblings = list(parent.glob(".release.fk0957-stage-*"))
                if not published:
                    if target.exists() != old_exists:
                        raise AssertionError((ordinal, "prepublish target existence changed"))
                    if old_exists:
                        current = target.stat()
                        if ((current.st_dev, current.st_ino) != old_identity or
                                (target / "prior-release-marker").read_text() != f"prior:{ordinal}"):
                            raise AssertionError((ordinal, "prior install not preserved"))
                elif not target.exists() or installer.verify_staged_package(target):
                    raise AssertionError((ordinal, "published root is incomplete"))
                for _ in range(2):
                    installer.stage_package(target)
                    if installer.verify_staged_package(target):
                        raise AssertionError((ordinal, "recovery did not produce a complete root"))
                remaining = list(parent.glob(".release.fk0957-stage-*"))
                if remaining:
                    raise AssertionError((ordinal, "staging siblings remain after recovery",
                                          [path.name for path in remaining]))
                transient = [path.name for path in parent.iterdir()
                             if path.name.startswith((".fk0957-marker-delete-", ".fk0957-delete-"))]
                if transient:
                    raise AssertionError((ordinal, "cleanup quarantine remains after recovery",
                                          transient))
                results.append({"old_root": old_exists, "checkpoint_ordinal": ordinal,
                                "checkpoint": labels[ordinal - 1][0],
                                "published_before_kill": published,
                                "staging_siblings_after_recovery": len(remaining)})
    output = {
        "schema": "fk0957-independent-hardkill-audit-v1",
        "candidate_commit": actual,
        "seed": args.seed,
        "checkpoint_count": len(labels),
        "after_commit_checkpoint_ordinal": publish_at,
        "fault_cases": len(results),
        "recovery_attempts": 2 * len(results),
        "prior_install_preserved_before_publish": True,
        "published_root_complete_after_commit": True,
        "repeated_recovery_succeeded": True,
        "cases_leaving_orphan_siblings": sum(bool(x["staging_siblings_after_recovery"])
                                               for x in results),
        "orphan_cleanup_by_recovery": all(not x["staging_siblings_after_recovery"]
                                            for x in results),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "started_utc": started_utc,
        "completed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hardware_access": False,
        "network_access": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(output, sort_keys=True))
    return 0 if output["orphan_cleanup_by_recovery"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
