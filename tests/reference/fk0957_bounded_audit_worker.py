#!/usr/bin/env python3
"""Resumable, sequential offline worker for a finite FK0957 audit queue.

The worker runs no shell, inherits no ambient environment, allows one child at
a time, enforces per-task and total time limits, and checks STOP between tasks.
The queue is an explicit JSON file; resumption skips completed task IDs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid


def atomic_json(path: Path, value: object) -> None:
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()
    temp = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def append_journal(path: Path, event: dict) -> None:
    raw = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--queue", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--max-hours", type=float, default=6.0)
    args = parser.parse_args()
    if not 0.05 <= args.max_hours <= 6.0:
        parser.error("--max-hours must be between 0.05 and 6")
    root = args.candidate_root.resolve(strict=True)
    state_dir = args.state_dir.resolve()
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_dir.chmod(0o700)
    stop = state_dir / "STOP"
    lock = state_dir / "worker.lock"
    try:
        lockfd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        raise SystemExit("another worker holds the state-directory lock")
    os.write(lockfd, f"pid={os.getpid()}\n".encode()); os.fsync(lockfd)
    os.close(lockfd)
    queue_bytes = args.queue.read_bytes()
    queue = json.loads(queue_bytes)
    if (type(queue) is not dict or set(queue) != {"schema", "candidate_commit", "tasks"} or
            queue["schema"] != "fk0957-offline-audit-queue-v1" or
            queue["candidate_commit"] != args.expected_commit or type(queue["tasks"]) is not list):
        lock.unlink(missing_ok=True)
        raise SystemExit("queue schema or candidate binding invalid")
    actual = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True,
                            capture_output=True, check=True, timeout=10).stdout.strip()
    dirty = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
                           cwd=root, text=True, capture_output=True, check=True,
                           timeout=10).stdout
    if actual != args.expected_commit or dirty:
        lock.unlink(missing_ok=True)
        raise SystemExit("candidate identity/cleanliness gate failed")
    state_path = state_dir / "state.json"
    journal_path = state_dir / "journal.jsonl"
    old = json.loads(state_path.read_text()) if state_path.exists() else {}
    queue_sha256 = hashlib.sha256(queue_bytes).hexdigest()
    if old and old.get("queue_sha256") != queue_sha256:
        lock.unlink(missing_ok=True)
        raise SystemExit("queue changed since checkpoint; use a new state directory")
    # Every recorded terminal task result is preserved and skipped on resume.
    # Re-running a failed test requires a new task ID and seed in a new queue.
    completed = dict(old.get("tasks", {}))
    deadline = time.monotonic() + args.max_hours * 3600
    state = {"schema": "fk0957-audit-worker-state-v1", "candidate_commit": actual,
             "queue_sha256": queue_sha256, "status": "RUNNING",
             "tasks": completed, "started_utc": old.get("started_utc") or
             datetime.now(timezone.utc).isoformat(timespec="seconds")}
    atomic_json(state_path, state)
    append_journal(journal_path, {"event": "worker_start", "candidate_commit": actual,
                                  "queue_sha256": state["queue_sha256"],
                                  "utc": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    try:
        for task in queue["tasks"]:
            if type(task) is not dict or set(task) != {"id", "argv", "cwd", "timeout_seconds", "env"}:
                raise SystemExit("task schema invalid")
            task_id = task["id"]
            if (type(task_id) is not str or not task_id or type(task["argv"]) is not list or
                    re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", task_id) is None or
                    not task["argv"] or any(type(arg) is not str for arg in task["argv"])):
                raise SystemExit("task identity/argv invalid")
            if task_id in completed:
                continue
            if stop.exists():
                state["status"] = "STOPPED_BY_FLAG"
                break
            if time.monotonic() >= deadline:
                state["status"] = "TIME_BUDGET_EXHAUSTED"
                break
            cwd = Path(task["cwd"]).resolve(strict=True)
            timeout = task["timeout_seconds"]
            if type(timeout) is not int or not 1 <= timeout <= 1800:
                raise SystemExit("task timeout outside [1,1800]")
            task_env = task["env"]
            if type(task_env) is not dict or set(task_env) - {"PYTHONHASHSEED"}:
                raise SystemExit("queue may set only PYTHONHASHSEED")
            env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                   "PYTHONDONTWRITEBYTECODE": "1", **task_env}
            log_path = state_dir / f"{task_id}.log"
            start_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
            start = time.monotonic()
            append_journal(journal_path, {"event": "task_start", "task_id": task_id,
                                          "argv": task["argv"], "cwd": str(cwd),
                                          "utc": start_utc})
            with log_path.open("wb") as log:
                proc = subprocess.Popen(task["argv"], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                        close_fds=True)
                effective_timeout = min(timeout, max(1, int(deadline - time.monotonic())))
                task_deadline = time.monotonic() + effective_timeout
                stop_requested = timed_out = False
                while proc.poll() is None:
                    if stop.exists():
                        stop_requested = True
                        break
                    if time.monotonic() >= task_deadline:
                        timed_out = True
                        break
                    time.sleep(0.25)
                if stop_requested or timed_out:
                    os.killpg(proc.pid, signal.SIGKILL)
                    rc = proc.wait(timeout=10)
                    status = "STOPPED_BY_FLAG" if stop_requested else "TIMEOUT"
                else:
                    rc = proc.returncode
                    status = "PASS" if rc == 0 else "FAIL"
                log.flush(); os.fsync(log.fileno())
            result = {"status": status, "return_code": rc, "timed_out": timed_out,
                      "started_utc": start_utc,
                      "elapsed_seconds": round(time.monotonic() - start, 3),
                      "log_path": str(log_path), "log_sha256": file_sha(log_path)}
            state["tasks"][task_id] = result
            atomic_json(state_path, state)
            append_journal(journal_path, {"event": "task_finish", "task_id": task_id,
                                          **result,
                                          "utc": datetime.now(timezone.utc).isoformat(timespec="seconds")})
            if status == "STOPPED_BY_FLAG":
                state["status"] = status
                break
            if status != "PASS":
                # Preserve the failure. Continue only with other independent tasks.
                continue
        else:
            state["status"] = ("COMPLETE" if all(
                result.get("status") == "PASS" for result in state["tasks"].values())
                else "COMPLETE_WITH_FAILURES")
        state["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        atomic_json(state_path, state)
        append_journal(journal_path, {"event": "worker_finish", "status": state["status"],
                                      "utc": state["finished_utc"]})
        print(json.dumps(state, sort_keys=True))
        return 0 if state["status"] == "COMPLETE" else 1
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
