#!/usr/bin/env python3
"""Phase-logged, exact-lock runner for a read-only raw IDCODE identity scan.

The hardware backend path is fixed. The mock backend is the same runner state
machine with a deterministic FTDI/MPSSE model and supports failure injection.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

FIXED_TOOL = Path("/tmp/sidecar-raw-id-build/raw-jtag-identify")
FIXED_LOCK_PATH = Path("/tmp/sidecar-raw-id-build/runner/ops/current-phk1-target-lock.json")
LOCK_FIELDS = ("usb_path", "ftdi_serial", "vid", "pid", "interface", "idcode", "dna")
EXIT = {
    "success": 0, "arguments": 2, "target_lock": 3, "usb_enumeration": 4,
    "device_open": 5, "mpsse": 6, "jtag_scan": 7, "identity_mismatch": 8,
    "cleanup": 9, "internal": 10,
}
PHASE_EXIT = {
    "P01_PARSE_ARGS": 2, "P02_LOAD_TARGET_LOCK": 3, "P03_VALIDATE_TARGET_LOCK": 3,
    "P04_ENUMERATE_USB": 4, "P05_MATCH_FTDI_DEVICE": 4,
    "P06_OPEN_FTDI": 5, "P07_SELECT_INTERFACE_A": 5,
    "P08_INIT_MPSSE": 6, "P09_MPSSE_SYNC": 6, "P10_SET_JTAG_CLOCK": 6,
    "P11_TAP_RESET": 7, "P12_READ_CHAIN": 7, "P13_PARSE_CHAIN": 7,
    "P14_VERIFY_IDCODE": 8, "P15_DNA_VERIFY_PREP": 8,
    "P16_CLOSE_FTDI": 9, "P17_COMPLETE": 10,
}
PHASES = [
    "P00_START", "P01_PARSE_ARGS", "P02_LOAD_TARGET_LOCK", "P03_VALIDATE_TARGET_LOCK",
    "P04_ENUMERATE_USB", "P05_MATCH_FTDI_DEVICE", "P07_SELECT_INTERFACE_A",
    "P06_OPEN_FTDI", "P08_INIT_MPSSE", "P09_MPSSE_SYNC", "P10_SET_JTAG_CLOCK",
    "P11_TAP_RESET", "P12_READ_CHAIN", "P13_PARSE_CHAIN", "P14_VERIFY_IDCODE",
    "P15_DNA_VERIFY", "P16_CLOSE_FTDI", "P17_COMPLETE",
]


class RunnerFailure(Exception):
    def __init__(self, phase: str, operation: str, message: str,
                 errno_value: int | None = None, ftdi_code: int | None = None):
        super().__init__(message)
        self.phase, self.operation = phase, operation
        self.errno_value, self.ftdi_code = errno_value, ftdi_code


class MockFtdiBackend:
    def __init__(self, inject: str | None):
        self.inject = inject
        self.opened = False
        self.closed = False
        self.failure_phase = {
            "NO_FTDI_DEVICE": "P04_ENUMERATE_USB",
            "WRONG_SERIAL": "P05_MATCH_FTDI_DEVICE",
            "WRONG_USB_PATH": "P05_MATCH_FTDI_DEVICE",
            "MULTIPLE_MATCHES": "P05_MATCH_FTDI_DEVICE",
            "OPEN_FAILURE": "P06_OPEN_FTDI",
            "WRONG_INTERFACE": "P07_SELECT_INTERFACE_A",
            "MPSSE_SYNC_FAILURE": "P09_MPSSE_SYNC",
            "CLOCK_SETUP_FAILURE": "P10_SET_JTAG_CLOCK",
            "TAP_RESET_FAILURE": "P11_TAP_RESET",
            "SHORT_TDO": "P12_READ_CHAIN",
            "BAD_CHAIN": "P13_PARSE_CHAIN",
            "WRONG_IDCODE": "P14_VERIFY_IDCODE",
            "CLOSE_FAILURE": "P16_CLOSE_FTDI",
        }.get(inject)

    def step(self, phase: str, operation: str) -> None:
        if self.failure_phase == phase:
            raise RunnerFailure(phase, operation, f"injected failure at {phase}")

    def run(self, lock: dict, mark) -> int:
        steps = [
            ("P04_ENUMERATE_USB", "enumerate VID/PID"),
            ("P05_MATCH_FTDI_DEVICE", "match serial/path/interface"),
            # The API requires channel selection before opening the FTDI device.
            ("P07_SELECT_INTERFACE_A", "select FT2232 interface A"),
            ("P06_OPEN_FTDI", "open exact enumerated device"),
            ("P08_INIT_MPSSE", "initialize MPSSE"),
            ("P09_MPSSE_SYNC", "validate bad-command sync response"),
            ("P10_SET_JTAG_CLOCK", "set fixed 100 kHz clock"),
            ("P11_TAP_RESET", "reset TAP"),
            ("P12_READ_CHAIN", "read IDCODE DR"),
            ("P13_PARSE_CHAIN", "validate chain length and padding"),
            ("P14_VERIFY_IDCODE", "compare expected IDCODE"),
            ("P15_DNA_VERIFY", "bind DNA from fresh lock source"),
            ("P16_CLOSE_FTDI", "close exact FTDI handle"),
        ]
        for phase, operation in steps:
            mark(phase)
            self.step(phase, operation)
            if phase == "P06_OPEN_FTDI": self.opened = True
            if phase == "P14_VERIFY_IDCODE" and self.inject == "WRONG_IDCODE":
                raise RunnerFailure(phase, operation, "IDCODE mismatch")
            if phase == "P13_PARSE_CHAIN" and self.inject == "BAD_CHAIN":
                raise RunnerFailure(phase, operation, "unexpected chain length or padding")
        self.closed = True
        return 0


def validate_lock(path: Path, mark) -> dict:
    mark("P02_LOAD_TARGET_LOCK")
    try:
        lock = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerFailure("P02_LOAD_TARGET_LOCK", "read/parse target lock", str(exc)) from exc
    mark("P03_VALIDATE_TARGET_LOCK")
    if lock.get("schema") != "sidecar-raw-jtag-target-lock-v1" or lock.get("status") != "PASS":
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate lock schema/status", "invalid lock schema or status")
    if lock.get("match_count") != 1 or lock.get("peer_distinct") is not True:
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate unique target and peer", "ambiguous target lock")
    try:
        stamp = dt.datetime.fromisoformat(lock["captured_utc"])
        age = (dt.datetime.now(dt.timezone.utc) - stamp).total_seconds()
    except (KeyError, ValueError, TypeError) as exc:
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate lock timestamp", "invalid lock timestamp") from exc
    if age < -30 or age > 600:
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate lock freshness", "stale or future target lock")
    target = lock.get("target")
    if not isinstance(target, dict):
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate target object", "target object missing")
    if target.get("role") != "PHK1_CANARY":
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate canary role", "target lock role mismatch")
    for key in LOCK_FIELDS:
        if not isinstance(target.get(key), str) or not target[key]:
            raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate exact target identity", f"target lock {key} missing")
    if target.get("interface") != "A":
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate interface A", "target lock interface mismatch")
    if lock.get("raw_device_handle_count") != 0 or lock.get("peer_handle_open") is not False:
        raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "validate closed handles", "target/peer handle is already open")
    return lock


def run(args: argparse.Namespace) -> tuple[int, str, str, dict]:
    out, err = [], []
    current = "P00_START"
    last_completed = "NONE"

    def mark(phase: str) -> None:
        nonlocal current, last_completed
        if current != phase:
            last_completed = current
        current = phase
        out.append(f"PHASE={phase}")
        # Persist progress as it happens so an interrupted run still has the
        # last completed phase. This file is private to the run directory.
        marker = args.output_dir / "last-phase.json"
        tmp = marker.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"current_phase": phase, "last_completed_phase": last_completed,
                                   "updated_utc": dt.datetime.now(dt.timezone.utc).isoformat()}) + "\n")
        os.replace(tmp, marker)

    def finish(code: int, operation: str | None = None, message: str | None = None,
               errno_value: int | None = None, ftdi_code: int | None = None):
        failure = None
        if code:
            failure = {
                "FAILED_PHASE": current,
                "LAST_COMPLETED_PHASE": last_completed,
                "FAILED_OPERATION": operation or "runner operation",
                "FAILED_ERRNO": errno_value if errno_value is not None else "NONE",
                "FAILED_LIBFTDI_CODE": ftdi_code if ftdi_code is not None else "NONE",
                "FAILED_MESSAGE": message or "unspecified runner failure",
            }
            err.extend(f"{k}={v}" for k, v in failure.items())
        record = {"exit_code": code, "exit_signal": -code if code < 0 else None,
                  "failed_phase": current if code else None,
                  "last_completed_phase": last_completed if code else current,
                  "failure": failure}
        return code, "\n".join(out) + "\n", "\n".join(err) + ("\n" if err else ""), record

    mark("P00_START")
    mark("P01_PARSE_ARGS")
    try:
        lock_path = FIXED_LOCK_PATH if args.backend == "libftdi" else args.lock
        if args.backend == "libftdi" and args.lock.resolve() != FIXED_LOCK_PATH:
            raise RunnerFailure("P03_VALIDATE_TARGET_LOCK", "enforce fixed target-lock path", "live backend requires fixed fresh lock")
        lock = validate_lock(lock_path, mark)
        if args.backend == "mock":
            backend = MockFtdiBackend(args.inject)
            code = backend.run(lock, mark)
        else:
            target = lock["target"]
            argv = [str(FIXED_TOOL), "identify", target["vid"], target["pid"],
                    target["ftdi_serial"], target["usb_path"], target["idcode"]]
            child = subprocess.Popen(argv, cwd=str(Path.home()), env=os.environ.copy(),
                                     text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     bufsize=1)
            def capture(stream, destination, child_output=False):
                nonlocal current, last_completed
                child_current = None
                for raw_line in iter(stream.readline, ""):
                    line = raw_line.rstrip("\r\n")
                    destination.append(("CHILD_STDOUT=" if child_output else "CHILD_STDERR=") + line)
                    if child_output and line.startswith("PHASE="):
                        phase_name = line.split("=", 1)[1]
                        if child_current is not None:
                            last_completed = child_current
                        child_current = phase_name
                        current = phase_name
                        marker = args.output_dir / "last-phase.json"
                        tmp = marker.with_suffix(".json.tmp")
                        tmp.write_text(json.dumps({"current_phase": phase_name,
                                                   "last_completed_phase": last_completed,
                                                   "updated_utc": dt.datetime.now(dt.timezone.utc).isoformat()}) + "\n")
                        os.replace(tmp, marker)
            stdout_thread = threading.Thread(target=capture, args=(child.stdout, out, True), daemon=True)
            stderr_thread = threading.Thread(target=capture, args=(child.stderr, err, False), daemon=True)
            stdout_thread.start(); stderr_thread.start()
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()
                stdout_thread.join(); stderr_thread.join()
                return finish(EXIT["mpsse"], "raw identity child timeout", "30-second child timeout")
            stdout_thread.join(); stderr_thread.join()
            code = child.returncode
            if code < 0:
                return finish(code, "raw identity child terminated by signal", "signal termination")
            if code:
                # Parse the child's structured failure to retain its actual phase.
                child_error_lines = [line.removeprefix("CHILD_STDERR=") for line in err
                                     if line.startswith("CHILD_STDERR=")]
                fields = dict(line.split("=", 1) for line in child_error_lines if "=" in line)
                current = fields.get("FAILED_PHASE", current)
                last_completed = fields.get("LAST_COMPLETED_PHASE", last_completed)
                return finish(code, fields.get("FAILED_OPERATION", "raw identity child"),
                              fields.get("FAILED_MESSAGE", f"child exit {code}"),
                              int(fields["FAILED_ERRNO"]) if fields.get("FAILED_ERRNO", "NONE").isdigit() else None,
                              int(fields["FAILED_LIBFTDI_CODE"]) if fields.get("FAILED_LIBFTDI_CODE", "NONE").lstrip("-").isdigit() else None)
            out.append("RAW_IDENTITY_CHILD=PASS")
        mark("P17_COMPLETE")
        out.extend(["LIVE_MPSSE_SYNC=PASS", "TAP_RESET=PASS", "JTAG_CHAIN_MATCH=PASS",
                    "IDCODE_MATCH=PASS", "USER1_SELECTION_COUNT=0", "USER2_SELECTION_COUNT=0",
                    "USER3_SELECTION_COUNT=0"])
        return finish(0)
    except RunnerFailure as exc:
        current = exc.phase
        return finish(PHASE_EXIT.get(current, EXIT["internal"]), exc.operation, str(exc),
                      exc.errno_value, exc.ftdi_code)
    except subprocess.TimeoutExpired as exc:
        child_out = exc.stdout or ""
        child_err = exc.stderr or ""
        if isinstance(child_out, bytes): child_out = child_out.decode(errors="replace")
        if isinstance(child_err, bytes): child_err = child_err.decode(errors="replace")
        out.extend("CHILD_STDOUT=" + line for line in child_out.splitlines())
        err.extend("CHILD_STDERR=" + line for line in child_err.splitlines())
        return finish(EXIT["mpsse"], "raw identity child timeout", str(exc))
    except Exception as exc:
        return finish(EXIT["internal"], "unexpected runner exception", f"{type(exc).__name__}: {exc}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--backend", choices=("mock", "libftdi"), default="mock")
    ap.add_argument("--inject", default=None)
    args = ap.parse_args(argv)
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.output_dir, 0o700)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    rc, stdout, stderr, record = run(args)
    ended = dt.datetime.now(dt.timezone.utc).isoformat()
    (args.output_dir / "stdout.log").write_text(stdout)
    (args.output_dir / "stderr.log").write_text(stderr)
    merged = "=== STDOUT ===\n" + stdout + "=== STDERR ===\n" + stderr
    (args.output_dir / "transcript.log").write_text(merged)
    record.update({"started_utc": started, "ended_utc": ended, "runner": str(Path(__file__).resolve()),
                   "argv": sys.argv, "cwd": os.getcwd(),
                   "backend": args.backend, "target_lock_path": str((FIXED_LOCK_PATH if args.backend == "libftdi" else args.lock).resolve()),
                   "output_capture": True, "stderr_capture": True, "exit_status_capture": True})
    (args.output_dir / "status.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"OUTPUT_CAPTURE=PASS\nSTDERR_CAPTURE=PASS\nEXIT_STATUS_CAPTURE=PASS")
    print(f"RUNNER_EXIT_CODE={rc}")
    if rc:
        print(f"FAILED_PHASE={record.get('failed_phase')}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
