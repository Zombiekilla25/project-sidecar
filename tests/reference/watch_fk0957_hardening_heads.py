"""Local-only watcher that audits each new stable FK0957 production HEAD.

The watcher never checks out or edits the production worktree. For each new
HEAD it creates a fresh detached worktree and stores all results under the
independent audit repository.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)


def git(repo: Path, *args: str) -> str:
    result = run(["git", "-C", str(repo), *args])
    if result.returncode:
        raise RuntimeError("git command failed: " + " ".join(args))
    return result.stdout.strip()


def fetch_branch(repo: Path, remote: str, branch: str) -> bool:
    refspec = f"refs/heads/{branch}:refs/remotes/{remote}/{branch}"
    result = run(["git", "-C", str(repo), "fetch", "--no-tags", remote, refspec])
    if result.returncode:
        print(f"hardening watcher: fetch failed for {remote}/{branch}; retaining last fetched ref",
              file=sys.stderr, flush=True)
        return False
    return True


def audit_head(repo: Path, audit: Path, sha: str, logical: str) -> dict[str, object]:
    worktrees = audit / "worktrees"
    results = audit / "results" / f"candidate-{sha}"
    worktrees.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)
    tree = worktrees / f"production-{sha}"
    if not tree.exists():
        add = run(["git", "-C", str(repo), "worktree", "add", "--detach", str(tree), sha])
        if add.returncode:
            raise RuntimeError("detached worktree creation failed")
    actual = git(tree, "rev-parse", "HEAD")
    if actual != sha:
        raise RuntimeError("detached worktree HEAD mismatch")

    # A completion declaration is informational, never a substitute for the
    # per-HEAD campaign. Record it against the exact audited object so a final
    # declaration can be distinguished from ordinary incremental commits.
    declaration = run(["git", "-C", str(tree), "grep", "-h", "-I", "-o",
                       "-E", "COMPLETE_HARDENED_CANDIDATE=[0-9a-f]{40}", sha, "--", "."])
    declared_heads = sorted({line.split("=", 1)[1] for line in
                             declaration.stdout.splitlines() if "=" in line})

    # The corrected oracle lives in the sibling reference-model repository.
    reference_repo = Path("/home/rmann/project-sidecar-phk2-reference-model-20261113")
    oracle_script = reference_repo / "tests/reference/fk0957_corrected_oracle_audit.py"
    acceptance = audit / "tests/reference/fk0957_independent_acceptance.py"
    campaign = audit / "tests/reference/fk0957_longrun_attack_campaign.py"
    native = audit / "tests/reference/fk0957_native_runtime_requalification.py"
    commands = {
        "oracle": [sys.executable, str(oracle_script), logical, "--production-tree", str(tree)],
        "acceptance": [sys.executable, str(acceptance), str(tree), "--expected-head", sha],
        "campaign": [sys.executable, str(campaign), "--production-root", str(tree)],
        "native_runtime": [sys.executable, str(native), str(tree)],
        "diff_check": ["git", "-C", str(tree), "diff", "--check"],
    }
    summaries: dict[str, object] = {}
    for name, command in commands.items():
        proc = run(command)
        (results / f"{name}.stdout").write_text(proc.stdout, encoding="utf-8")
        (results / f"{name}.stderr").write_text(proc.stderr, encoding="utf-8")
        summaries[name] = {"exit_code": proc.returncode,
                           "stdout_path": str(results / f"{name}.stdout"),
                           "stderr_path": str(results / f"{name}.stderr")}
    record = {"candidate_head": sha, "detached_worktree": str(tree),
              "complete_candidate_declared_for_this_head": sha in declared_heads,
              "complete_candidate_declarations": declared_heads,
              "suites": summaries, "audit_complete": True}
    (results / "summary.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n",
                                           encoding="utf-8")
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("production_repo", type=Path)
    parser.add_argument("audit_repo", type=Path)
    parser.add_argument("--logical-candidate", required=True)
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--stable-polls", type=int, default=2)
    parser.add_argument("--remote", help="optional remote to refresh read-only before polling")
    parser.add_argument("--remote-branch", help="remote branch to monitor; defaults to current branch")
    parser.add_argument("--fetch-interval", type=float, default=30.0,
                        help="seconds between read-only remote fetches")
    parser.add_argument("--once", action="store_true", help="audit current HEAD once")
    args = parser.parse_args()
    repo, audit = args.production_repo.resolve(), args.audit_repo.resolve()
    if not (repo / ".git").exists() or not (audit / ".git").exists():
        parser.error("both paths must be Git repositories")
    branch = args.remote_branch or git(repo, "branch", "--show-current")
    remote_ref = None
    if args.remote:
        if not branch:
            parser.error("--remote-branch is required when the checkout is detached")
        remote_ref = f"refs/remotes/{args.remote}/{branch}"
        fetch_branch(repo, args.remote, branch)
    seen = git(repo, "rev-parse", remote_ref) if remote_ref else git(repo, "rev-parse", "HEAD")
    if args.once:
        print(json.dumps(audit_head(repo, audit, seen, args.logical_candidate), sort_keys=True))
        return 0
    candidate, stable = None, 0
    last_fetch = time.monotonic()
    while True:
        time.sleep(max(1.0, args.interval))
        if args.remote and time.monotonic() - last_fetch >= max(args.interval, args.fetch_interval):
            fetch_branch(repo, args.remote, branch)
            last_fetch = time.monotonic()
        current = git(repo, "rev-parse", remote_ref) if remote_ref else git(repo, "rev-parse", "HEAD")
        if current == seen:
            candidate, stable = None, 0
            continue
        if current == candidate:
            stable += 1
        else:
            candidate, stable = current, 1
        if stable >= max(2, args.stable_polls):
            record = audit_head(repo, audit, current, args.logical_candidate)
            print(json.dumps(record, sort_keys=True), flush=True)
            seen, candidate, stable = current, None, 0


if __name__ == "__main__":
    raise SystemExit(main())
