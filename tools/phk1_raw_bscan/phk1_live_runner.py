#!/usr/bin/env python3
"""Fixed-purpose PHK1 RAW_BSCAN runner; hardware I/O is delegated to the
identity-qualified C++ MPSSE backend in raw_bscan_rpc.cpp.

The live CLI has no target, payload, IR, DR, clock, or bitstream arguments.
Only the fixed canary lock, fixed operand-vector-001 file, and three named
operations are accepted. Tests inject an in-memory scan backend.
"""
from __future__ import annotations
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import time
import traceback
from typing import Callable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from transport import PHK1RawTransport, USER_IR, validate_operation
from frame_protocol import build_request, vector_transaction_id
from live_target_lock_v2 import (PART as PATCHED_TARGET_PART, PHK_SHA as PATCHED_PHK_SHA,
    XBT_SHA as KNOWN_XBT_SHA, sha_file, verify_bundle, consume_nonce, V2LockError)
from target_lock_v2 import validate_lock as validate_v2_lock, LockValidationError as V2ValidationError

LOCK_PATH = Path.home() / "civiclight-testbench/phk1-ops/PHK1_RAW_TARGET_LOCK.json"
RPC_PATH = Path(os.environ.get(
    "PHK1_RAW_BSCAN_RPC",
    str(Path.home() / "civiclight-testbench/phk1-ops/tools/phk1_raw_bscan/raw-bscan-rpc")))
AUTHORITATIVE_MAP_PATH = ROOT / "ops/FK33_AUTHORITATIVE_TARGET_MAP.json"
VECTOR_PATH = Path("/home/rmann/civiclight-testbench/phk1-ops/vector/FK_INPUT_PAYLOAD.bin")
from fixture_preflight import FIXTURE_PATH as HELLO_FIXTURE, load_physical_hello_fixture
LOGICAL_HELLO_FIXTURE = ROOT / "ops/PHK1_RAW_HELLO_EXPECTED.json"
VECTOR_FIXTURE = ROOT / "ops/PHK1_RAW_VECTOR001_EXPECTED.json"
CANDIDATE_ID = "PHK1_USER1_TCK_READCLK_RESPONSE_VALID_REFILL_20261103"
CANDIDATE_DIGEST = "47a392b76ebd"
STAGED_CANDIDATE_DIR = Path(os.environ.get("PHK1_CANDIDATE_DIR",
    str(Path.home()/"civiclight-testbench/phk1-ops/candidates"/CANDIDATE_ID/CANDIDATE_DIGEST)))
if not STAGED_CANDIDATE_DIR.exists():
    STAGED_CANDIDATE_DIR = ROOT/"sidecar-evidence/phk1-patched-bitstream-handoff-20261103"
CANDIDATE_BITSTREAM = STAGED_CANDIDATE_DIR/"image/PHK1_USER1_TCK_READCLK_RESPONSE_VALID_REFILL_20261103.bit"
if not CANDIDATE_BITSTREAM.exists():
    CANDIDATE_BITSTREAM = STAGED_CANDIDATE_DIR/"PHK1_USER1_TCK_READCLK_RESPONSE_VALID_REFILL_20261103.bit"
CANDIDATE_MANIFEST = STAGED_CANDIDATE_DIR/"metadata/patched-candidate-manifest.json"
if not CANDIDATE_MANIFEST.exists():
    CANDIDATE_MANIFEST = ROOT/"sidecar-evidence/phk1-patched-bitstream-handoff-20261103/intake-support/patched-candidate-manifest.json"
QUALIFICATION_MANIFEST = STAGED_CANDIDATE_DIR/"metadata/patched-bitstream-image-manifest.json"
if not QUALIFICATION_MANIFEST.exists():
    QUALIFICATION_MANIFEST = ROOT/"sidecar-evidence/phk1-patched-bitstream-handoff-20261103/metadata/PATCHED_BITSTREAM_IMAGE_QUALIFICATION_MANIFEST.json"
ROLLBACK_BITSTREAM = Path(os.environ.get("PHK1_ROLLBACK_BITSTREAM",
    str(Path.home()/"fk33-prl-pod/artifacts/XBT_V4P1.bit")))
ROLLBACK_BINDING = STAGED_CANDIDATE_DIR/"metadata/xbt-rollback-binding.json"
if not ROLLBACK_BINDING.exists():
    ROLLBACK_BINDING = ROOT/"sidecar-evidence/phk1-patched-bitstream-handoff-20261103/intake-support/xbt-rollback-binding.json"
VECTOR_SHA = "7f4b421e8611725432061254f56e70a78a2c51210104e6674bcf10aaebe77b4b"
RAW_SHA = "7a1a4e48b6182144cb9a0ab7d11b80824b0b86194838feeccf106e62253f1eb0"
CANONICAL_SHA = "43dbc52a64ec00e4504328e6f900a6ddebbaadb166cf9e7a90f0f53e7f846ffa"
EXIT = {"success": 0, "usage": 2, "lock": 3, "target": 4, "backend": 5,
        "mpsse": 6, "identity": 7, "hello": 8, "vector": 9,
        "raw_mismatch": 10, "canonical_mismatch": 11, "cleanup": 12, "fixture": 13}
OPS = frozenset({"identify", "hello", "vector001"})
RPC_MODES = OPS | {"session"}  # internal fixed sequence: identify -> HELLO -> vector001
IR_ALLOWED = frozenset({0x09, 0x02, 0x03, 0x22})
VECTOR_FRAME_SHAS = frozenset({
 "d2a6211b2de6d270b00afac16419d0bdcf86ad0ed88237df3405fbbbe7697ef6",
 "50d5efabf4ee0e86381b5483a8c47dd981b58d7674ca83c7e7c1174a6c02f862",
 "ad0574af7d104fda26c90770354be6acc76de036caa1702399539cb82fd38ff2",
 "8c8a1e924099834b36baed805cc2f250ab18b4711dd4bb4f59da66269104c08b",
 "fa0f6d8e0e31204ffb765a0a7aab9a53bf51b097ed3c79ab48d965c188a1e27d",
 "df8855298a6f311ead4a4ed4aff689aedadc1338ca87dede5a94e2a3f4d1162f",
 "5c40fae7f68d2e80f5c385e418fd9f9ad3a21d262424b3dec745539eed98b83d",
 "15e4a3dd8f2987226cd2648fc9d85068811553e5628196822d73b9e4463b05c8"})


class RunnerError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind

def lifecycle_event(path: Path | None, event: str, **fields) -> None:
    """Append a durable, private process/pipe event without touching JTAG I/O."""
    if path is None:
        return
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    row = {"event": event, "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
           "monotonic_ns": time.monotonic_ns(), **fields}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps(row, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)

def approved_bitstream_sha() -> str:
    try:
        manifest=json.loads(CANDIDATE_MANIFEST.read_text())
        qualification=json.loads(QUALIFICATION_MANIFEST.read_text())
        if (manifest.get("candidate_id") != CANDIDATE_ID or
            qualification.get("bitstream_sha256") != PATCHED_PHK_SHA or
            qualification.get("bitstream_size") != 28329335 or
            qualification.get("target_part") != PATCHED_TARGET_PART):
            raise RuntimeError("patched candidate manifest identity mismatch")
        if sha_file(CANDIDATE_BITSTREAM) != PATCHED_PHK_SHA:
            raise RuntimeError("patched candidate image hash mismatch")
        return PATCHED_PHK_SHA
    except (OSError,json.JSONDecodeError) as exc:
        raise RuntimeError(f"patched candidate image/manifest unavailable: {exc}") from exc

BITSTREAM_SHA = approved_bitstream_sha()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_target_lock(path: Path, *, now: dt.datetime | None = None,
                         authoritative_map_path: Path = AUTHORITATIVE_MAP_PATH,
                         expected_maintenance_generation: str | None = None) -> tuple[dict, str]:
    try:
        raw = path.read_bytes()
        lock = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError("lock", f"cannot read target lock: {exc}") from exc
    if lock.get("schema") != "sidecar-raw-jtag-target-lock-v2" or lock.get("schema_version") != 2:
        raise RunnerError("lock", "v2 target lock required; legacy lock formats are rejected")
    try:
        authority = json.loads(authoritative_map_path.read_text())
        canary = authority["phk1_canary_physical_id"]
        peer_id = authority["phk1_peer_physical_id"]
        cards = (authority["card_a"], authority["card_b"])
        card = next(c for c in cards if c.get("ftdi_serial") == canary.get("ftdi_serial"))
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RunnerError("lock", "authoritative physical identity map unavailable") from exc
    if authority.get("status") != "PASS" or authority.get("canary_peer_distinction") != "PASS":
        raise RunnerError("lock", "authoritative physical identity map is not qualified")
    peer_card = next(c for c in cards if c.get("ftdi_serial") == peer_id.get("ftdi_serial"))
    def expected_physical(identity, c):
        return {"usb_path":identity.get("usb_path"), "ftdi_serial":identity.get("ftdi_serial"),
            "vid":str(c.get("vid","")).lower(), "pid":str(c.get("pid","")).lower(),
            "interface":c.get("ftdi_interface"), "idcode":str(identity.get("idcode","")).lower().removeprefix("0x"),
            "dna":identity.get("dna"), "bridge_lane":c.get("bridge_endpoint"),
            "workload_binding":c.get("miner_binding")}
    expected_target=expected_physical(canary,card); expected_peer=expected_physical(peer_id,peer_card)
    if lock.get("intended_action") != "VERIFY_CANDIDATE":
        raise RunnerError("lock", "runner accepts only post-program VERIFY_CANDIDATE locks")
    generation = expected_maintenance_generation or os.environ.get("PHK1_MAINTENANCE_GENERATION")
    if not generation:
        raise RunnerError("lock", "maintenance generation must be supplied by the canary supervisor")
    try:
        cm=json.loads(CANDIDATE_MANIFEST.read_text())
        qm=json.loads(QUALIFICATION_MANIFEST.read_text())
        rb=json.loads(ROLLBACK_BINDING.read_text())
        candidate={"role":"CANDIDATE_IMAGE_TO_PROGRAM","image_id":cm["candidate_id"],
            "sha256":PATCHED_PHK_SHA,"size":28329335,"target_part":PATCHED_TARGET_PART,
            "path":str(CANDIDATE_BITSTREAM.resolve())}
        rollback={"role":"ROLLBACK_IMAGE","image_id":rb["image_id"],"sha256":KNOWN_XBT_SHA,
            "size":ROLLBACK_BITSTREAM.stat().st_size,"target_part":PATCHED_TARGET_PART,
            "path":str(ROLLBACK_BITSTREAM.resolve())}
        current={"role":"CURRENT_LOADED_IMAGE","image_id":cm["candidate_id"],
            "sha256":PATCHED_PHK_SHA,"size":28329335,"target_part":PATCHED_TARGET_PART,
            "path":str(CANDIDATE_BITSTREAM.resolve())}
        validate_v2_lock(lock,now=now or dt.datetime.now(dt.timezone.utc),
            expected_target=expected_target,expected_peer=expected_peer,
            expected_candidate=candidate,expected_rollback=rollback,expected_current_image=current,
            expected_manifest_sha256=sha_file(CANDIDATE_MANIFEST),
            expected_qualification_sha256=sha_file(QUALIFICATION_MANIFEST),
            expected_maintenance_generation=generation,
            expected_rollback_authority=f"sha256:{sha_file(ROLLBACK_BINDING)}",
            intended_action="VERIFY_CANDIDATE")
        if sha_file(CANDIDATE_BITSTREAM) != BITSTREAM_SHA or qm.get("bitstream_sha256") != BITSTREAM_SHA:
            raise RunnerError("lock", "candidate bitstream changed after lock generation")
    except (OSError,KeyError,TypeError,ValueError,V2ValidationError,V2LockError) as exc:
        if isinstance(exc,RunnerError): raise
        raise RunnerError("lock", f"v2 image-role/JIT validation failed: {exc}") from exc
    target={"usb_path":expected_target["usb_path"],"ftdi_serial":expected_target["ftdi_serial"],
        "vid":expected_target["vid"],"pid":expected_target["pid"],"interface":expected_target["interface"],
        "idcode":expected_target["idcode"],"dna":expected_target["dna"],"role":"PHK1_CANARY",
        "bridge_endpoint":expected_target["bridge_lane"],"miner_binding":expected_target["workload_binding"],
        "expected_phk1_bitstream_sha256":PATCHED_PHK_SHA}
    lock["target"] = target
    lock["run_id"] = lock.get("run_id") or lock["maintenance_generation"]
    return lock, sha(raw)


def normalize_idcode(value: str | int) -> int:
    """Parse an IDCODE numerically; leading zeroes are formatting, not identity."""
    try:
        parsed = value if isinstance(value, int) else int(str(value).lower().removeprefix("0x"), 16)
    except (TypeError, ValueError) as exc:
        raise RunnerError("identity", "malformed IDCODE from target lock/backend") from exc
    if parsed < 0 or parsed > 0xffffffff:
        raise RunnerError("identity", "IDCODE is outside the 32-bit JTAG field")
    return parsed


class RpcBackend:
    """Single process lifetime; no reopen or retry after any RPC failure."""
    def __init__(self, target: dict, operation: str, executable: Path = RPC_PATH, timeout_s: float = 30.0):
        if operation not in RPC_MODES:
            raise RunnerError("usage", "backend operation is not allowlisted")
        trace_value = os.environ.get("PHK1_FAILURE_TRACE_PATH")
        self.trace_path = Path(trace_value) if trace_value else None
        self.phase = "backend_start"
        self.last_protocol_event = "none"
        self.operation = operation
        self.proc = subprocess.Popen(
            [str(executable), operation, target["vid"], target["pid"], target["ftdi_serial"],
             target["usb_path"], target["idcode"]], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.timeout_s = timeout_s
        self.closed = False
        self.scans: list[dict] = []
        self.protocol_scans: list[dict] = []
        lifecycle_event(self.trace_path, "CHILD_SPAWNED", parent_pid=os.getpid(), child_pid=self.proc.pid,
                        operation=operation, executable=str(executable), phase=self.phase)
        ready = self._readline()
        fields = ready.split()
        if len(fields) != 5 or fields[0] != "READY":
            self._abort()
            raise RunnerError("identity", "raw backend did not complete MPSSE/IDCODE revalidation")
        actual_idcode = normalize_idcode(fields[1])
        expected_idcode = normalize_idcode(target["idcode"])
        if actual_idcode != expected_idcode:
            self._abort()
            raise RunnerError("identity", f"post-open IDCODE mismatch: got 0x{actual_idcode:08x}, expected 0x{expected_idcode:08x}")
        self.idcode = f"0x{actual_idcode:08x}"
        self.open_ns, self.sync_ns, self.identity_ns = map(int, fields[2:])
        self.identity_verified = True
        self.phase = "target_revalidated"
        self.last_protocol_event = "READY"
        lifecycle_event(self.trace_path, "BACKEND_READY", parent_pid=os.getpid(), child_pid=self.proc.pid,
                        child_poll=self.proc.poll(), phase=self.phase, idcode=self.idcode,
                        open_ns=self.open_ns, sync_ns=self.sync_ns, identity_ns=self.identity_ns)

    def mark_phase(self, phase: str) -> None:
        self.phase = phase
        lifecycle_event(getattr(self, "trace_path", None), "PHASE", parent_pid=os.getpid(),
                        child_pid=getattr(self.proc, "pid", None), child_poll=self.proc.poll(), phase=phase,
                        last_protocol_event=getattr(self, "last_protocol_event", "none"))

    def lifecycle_snapshot(self, event: str) -> dict:
        poll = self.proc.poll()
        def fd_open(stream) -> bool:
            if stream is None or stream.closed:
                return False
            try:
                fcntl.fcntl(stream.fileno(), fcntl.F_GETFD)
                return True
            except (OSError, AttributeError):
                return False
        stdout_pipe_ok = fd_open(getattr(self.proc, "stdout", None))
        stdin_pipe_ok = fd_open(getattr(self.proc, "stdin", None))
        # Deterministic in-memory RPC fixtures model an open request/response
        # channel without OS file descriptors.
        if not hasattr(self.proc, "stdout"):
            stdout_pipe_ok = poll is None
            stdin_pipe_ok = poll is None and not getattr(self, "closed", False)
        stdout_no_hup = poll is None and not hasattr(self.proc, "stdout")
        if stdout_pipe_ok and hasattr(self.proc, "stdout"):
            try:
                p = select.poll(); p.register(self.proc.stdout, select.POLLIN | select.POLLHUP | select.POLLERR)
                flags = dict(p.poll(0)).get(self.proc.stdout.fileno(), 0)
                stdout_no_hup = not bool(flags & (select.POLLHUP | select.POLLERR))
            except (OSError, ValueError):
                stdout_no_hup = False
        result = {"parent_pid": os.getpid(), "child_pid": getattr(self.proc,"pid",None), "child_poll": poll,
                  "phase": getattr(self,"phase","rpc"), "last_protocol_event": getattr(self,"last_protocol_event","none"),
                  "stdin_fd_open": stdin_pipe_ok, "stdout_fd_open": stdout_pipe_ok,
                  "stdout_pipe_no_hup": stdout_no_hup, "stderr_fd_open": fd_open(getattr(self.proc,"stderr",None)),
                  "child_alive": poll is None,
                  "pipe_writable_before_vector": poll is None and stdin_pipe_ok,
                  "pipe_readable_before_vector": poll is None and stdout_pipe_ok and stdout_no_hup}
        lifecycle_event(getattr(self, "trace_path", None), event, **result)
        return result

    def _readline(self) -> str:
        if not self.proc.stdout:
            raise RunnerError("backend", "backend stdout unavailable")
        ready, _, _ = select.select([self.proc.stdout], [], [], self.timeout_s)
        if not ready:
            raise RunnerError("backend", "raw backend response timeout")
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            poll = self.proc.poll()
            lifecycle_event(self.trace_path, "CHILD_EOF", parent_pid=os.getpid(), child_pid=self.proc.pid,
                            child_poll=poll, child_exit_code=poll, phase=self.phase,
                            last_protocol_event=self.last_protocol_event, child_stderr=err[-8000:])
            raise RunnerError("backend", f"raw backend exited (returncode={poll}): {err[-3000:]}")
        lifecycle_event(self.trace_path, "CHILD_STDOUT_RESPONSE", parent_pid=os.getpid(), child_pid=self.proc.pid,
                        child_poll=self.proc.poll(), phase=self.phase, response=line.strip(),
                        last_protocol_event=self.last_protocol_event)
        return line.strip()

    def _write_command(self, line: str) -> None:
        if not self.proc.stdin:
            raise RunnerError("backend", "raw backend stdin unavailable")
        command = line.partition(" ")[0].strip()
        phase = getattr(self, "phase", "rpc")
        self.last_protocol_event = f"{phase}:{command}_write_start"
        lifecycle_event(getattr(self, "trace_path", None), "PARENT_PIPE_WRITE_START", parent_pid=os.getpid(), child_pid=getattr(self.proc,"pid",None),
                        child_poll=self.proc.poll(), phase=phase, command=command,
                        request_bytes=len(line.encode()), request_sha256=sha(line.encode()),
                        last_protocol_event=self.last_protocol_event)
        try:
            self.proc.stdin.write(line)
            self.proc.stdin.flush()
            self.last_protocol_event = f"{phase}:{command}_write_complete"
            lifecycle_event(getattr(self, "trace_path", None), "PARENT_PIPE_WRITE_COMPLETE", parent_pid=os.getpid(), child_pid=getattr(self.proc,"pid",None),
                            child_poll=self.proc.poll(), phase=phase, command=command,
                            request_bytes=len(line.encode()), last_protocol_event=self.last_protocol_event)
        except BrokenPipeError as exc:
            # Preserve the child status and stderr before cleanup. The old
            # implementation killed the RPC child here and lost its reason.
            rc = self.proc.poll()
            try:
                self.proc.wait(timeout=1)
                rc = self.proc.poll()
            except Exception:
                try:
                    self.proc.kill(); self.proc.wait(timeout=1); rc = self.proc.poll()
                except Exception:
                    pass
            err = ""
            if self.proc.stderr:
                try:
                    err = self.proc.stderr.read()
                except Exception:
                    pass
            lifecycle_event(getattr(self, "trace_path", None), "BROKEN_PIPE", parent_pid=os.getpid(), child_pid=getattr(self.proc,"pid",None),
                            child_poll=rc, child_exit_code=rc, phase=phase, command=command,
                            last_protocol_event=self.last_protocol_event, child_stderr=err[-8000:],
                            traceback=traceback.format_exc())
            raise RunnerError("backend", f"RPC child closed stdin (returncode={rc}); stderr={err[-2000:]!r}") from exc

    def shift_ir(self, value: int) -> None:
        if value not in IR_ALLOWED:
            raise RunnerError("identity", "IR outside fixed live allowlist")
        self._write_command(f"IR {value:02x}\n")
        line = self._readline()
        if not line.startswith("IR "):
            raise RunnerError("backend", "invalid IR response")
        self.scans.append({"ir": value, "bits": 6, "tx_sha256": sha(bytes([value])),
                           "rx_sha256": sha(bytes.fromhex(line[3:]))})
        self.last_protocol_event = f"{getattr(self,'phase','rpc')}:IR_response"

    def shift_dr(self, data: bytes) -> bytes:
        bits = len(data) * 8
        if bits not in (8, 32, 768, 196864):
            raise RunnerError("identity", "DR length outside fixed PHK1 framing")
        self._write_command(f"DR {bits} {data.hex()}\n")
        line = self._readline()
        if not line.startswith("DR "):
            raise RunnerError("backend", "invalid DR response")
        rx = bytes.fromhex(line[3:])
        if len(rx) != len(data):
            raise RunnerError("backend", "short/long TDO response")
        self.scans.append({"bits": bits, "tx_sha256": sha(data), "rx_sha256": sha(rx)})
        self.last_protocol_event = f"{getattr(self,'phase','rpc')}:DR_response_{bits}"
        return rx

    def user_scan(self, chain: int, data: bytes) -> bytes:
        ir = USER_IR.get(chain)
        if ir not in IR_ALLOWED:
            raise RunnerError("identity", "USER chain outside fixed allowlist")
        if chain == 3 and (len(data) != 4 or data not in (b"\0"*4, b"PHAB")):
            raise RunnerError("identity", "USER3 payload outside fixed status/abort frames")
        if chain == 2 and not (data == b"\0" or (len(data) == 24608 and sha(data) in VECTOR_FRAME_SHAS)):
            raise RunnerError("identity", "USER2 payload outside fixed prime/vector001 frames")
        if chain == 1 and not (data == b"\0" or (len(data) == 96 and data == b"\0"*96)):
            raise RunnerError("identity", "USER1 payload outside fixed result reads")
        self.shift_ir(ir)
        rx = self.shift_dr(data)
        scan={"chain": f"USER{chain}", "ir": f"0x{ir:02x}", "bits": len(data)*8}
        if len(data) <= 4:
            scan.update({"tx":data.hex(),"rx":rx.hex()})
        else:
            scan.update({"tx_sha256":sha(data),"rx_sha256":sha(rx)})
        self.protocol_scans.append(scan)
        return rx

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.mark_phase("close")
            assert self.proc.stdin
            self._write_command("QUIT\n")
            response = self._readline()
            self.proc.wait(timeout=5)
            if response != "BYE" or self.proc.returncode != 0:
                raise RunnerError("cleanup", "backend did not close cleanly")
            lifecycle_event(getattr(self,"trace_path",None), "CHILD_CLOSED", parent_pid=os.getpid(), child_pid=getattr(self.proc,"pid",None),
                            child_poll=self.proc.poll(), child_exit_code=self.proc.returncode, phase=self.phase)
        except Exception:
            self._abort()
            raise
        self.closed = True

    def _abort(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.closed = True


def write_evidence(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def write_private_bytes(path: Path, data: bytes | None) -> None:
    if data is None:
        return
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(path.parent,0o700)
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_bytes(data); os.chmod(tmp,0o600); os.replace(tmp,path)


def preflight_hello_fixture(path: Path | None = None) -> tuple[dict, str]:
    """Validate the fixed physical transcript before any backend is opened.

    The fixture digest is pinned in the runner so a missing or partial target
    deployment fails locally, before it can consume a hardware attempt.
    """
    path = HELLO_FIXTURE if path is None else path
    try:
        return load_physical_hello_fixture(path, package_root=path.parent)
    except ValueError as exc:
        raise RunnerError("fixture", f"physical HELLO fixture schema invalid: {exc}") from exc


def _transcript_check(scans: list[dict], operation: str) -> bool:
    # Transcript JSON records the logical byte scans. Each scan record is
    # captured by the RPC adapter after the matching IR selection.
    if operation == "hello":
        fixture = json.loads(HELLO_FIXTURE.read_text())
        if len(scans) != len(fixture["dr_shifts"]) or len(fixture["ir_sequence"]) != len(scans):
            return False
        for actual, irscan, expected in zip(scans, fixture["ir_sequence"], fixture["dr_shifts"]):
            # All scan structure and host-to-device bits remain exact. Only
            # TDO from protocol-defined discarded reset/output primes is
            # unspecified and must never be parsed as a PHK1 response.
            if (actual.get("chain"), actual.get("ir"), actual.get("bits"), actual.get("tx")) != (
                    expected.get("chain"), irscan.get("ir"), expected.get("bits"), expected.get("tx")):
                return False
            if expected.get("rx_policy", "compare_exact") == "compare_exact":
                if actual.get("rx") != expected.get("rx"):
                    return False
            elif expected.get("rx_policy") != "discarded_prime_do_not_compare":
                return False
            elif len(actual.get("rx", "")) != len(expected.get("tx", "")):
                return False
        return True
    return True


def run_operation(operation: str, *, lock_path: Path = LOCK_PATH,
                  evidence_dir: Path, backend_factory: Callable[[dict], object],
                  payload_path: Path = VECTOR_PATH) -> dict:
    if operation not in OPS:
        raise RunnerError("usage", "only identify, hello, and vector001 are supported")
    if operation == "hello":
        # Validate before opening FTDI or selecting any USER instruction.
        preflight_hello_fixture()
    lock, lock_hash = validate_target_lock(lock_path)
    run_id = lock["run_id"]
    previous_identify = evidence_dir / "identify.json"
    previous_hello = evidence_dir / "hello.json"
    if operation == "hello":
        if not previous_identify.exists():
            raise RunnerError("target", "identify must pass first in this run")
        ident = json.loads(previous_identify.read_text())
        if ident.get("status") != "PASS" or ident.get("run_id") != run_id or ident.get("target_lock_sha256") != lock_hash:
            raise RunnerError("target", "identify evidence does not match current lock/run")
    if operation == "vector001":
        if not previous_hello.exists():
            raise RunnerError("hello", "vector001 requires saved HELLO PASS evidence")
        hello = json.loads(previous_hello.read_text())
        if hello.get("status") != "PASS" or hello.get("run_id") != run_id or hello.get("target_lock_sha256") != lock_hash:
            raise RunnerError("hello", "HELLO evidence does not match current lock/run")

    started = time.monotonic_ns()
    backend = backend_factory(lock["target"])
    if getattr(backend, "identity_verified", False) is not True:
        backend.close()
        raise RunnerError("target", "backend did not revalidate IDCODE before USER access")
    opened = time.monotonic_ns()
    record: dict = {"schema": "sidecar-phk1-live-runner-evidence-v1", "operation": operation,
                    "run_id": run_id, "target_lock_sha256": lock_hash,
                    "bitstream_sha256": BITSTREAM_SHA, "start_monotonic_ns": started,
                    "backend_open_ns": opened-started,
                    "mpsse_sync_ns": getattr(backend, "sync_ns", None),
                    "target_revalidation_ns": getattr(backend, "identity_ns", None),
                    "autoretry": False, "user_ir_allowlist": sorted(IR_ALLOWED)}
    protocol = None
    try:
        if operation == "identify":
            record.update({"status": "PASS", "idcode_match": True, "dna_gate": "qualified lock evidence",
                           "user_ir_selection_count": 0})
        elif operation == "hello":
            t0 = time.monotonic_ns()
            protocol = PHK1RawTransport(backend, timeout_s=10.0)
            parsed = protocol.hello()
            end = time.monotonic_ns()
            expected = json.loads(LOGICAL_HELLO_FIXTURE.read_text())["parsed_status"]
            if parsed["status_word"] != expected["word"] or not parsed.get("phk1_ready") or parsed.get("error"):
                raise RunnerError("hello", "HELLO response differs from exact qualified fixture")
            scan_records = getattr(backend, "protocol_scans", [])
            record.update({"status": "PASS", "hello": parsed, "hello_time_ns": end-t0,
                           "logical_scan_bits": sum(s["bits"] for s in scan_records),
                           "physical_jtag_clocks": sum(s["bits"] + 17 for s in scan_records),
                           "tx_sha256": sha(b"\0"*14), "rx_sha256": sha(b"\x11\0\0\0"*3+b"\0\0"),
                           "scan_count": len(scan_records), "transcript_match": _transcript_check(scan_records,"hello"),
                           "scans": scan_records})
            if not record["transcript_match"] or record["logical_scan_bits"] != 112:
                raise RunnerError("hello", "HELLO transcript differs bit-for-bit from qualified fixture")
        else:
            payload = payload_path.read_bytes()
            if len(payload) != 196608 or sha(payload) != VECTOR_SHA:
                raise RunnerError("vector", "fixed operand-vector-001 payload identity mismatch")
            txid = vector_transaction_id("operand-vector-001", VECTOR_SHA)
            packed = b"".join(build_request(txid, i, payload[i*24576:(i+1)*24576]) for i in range(8))
            fixture_contract = json.loads(VECTOR_FIXTURE.read_text())["host_pack"]
            if txid != int(json.loads(VECTOR_FIXTURE.read_text())["transaction_id"], 16):
                raise RunnerError("vector", "frozen transaction ID differs from qualified fixture")
            if sha(packed) != fixture_contract["user2_tx_sha256"]:
                raise RunnerError("vector", "packed vector001 stream differs from qualified fixture")
            protocol = PHK1RawTransport(backend, timeout_s=120.0)
            t0 = time.monotonic_ns()
            raw, canonical, details = protocol.vector001(payload)
            end = time.monotonic_ns()
            if sha(raw) != RAW_SHA:
                raise RunnerError("raw_mismatch", "raw result differs from frozen oracle")
            if sha(canonical) != CANONICAL_SHA:
                raise RunnerError("canonical_mismatch", "canonical result differs from frozen oracle")
            scan_records = getattr(backend, "protocol_scans", [])
            record.update({"status": "PASS", "vector_id": "operand-vector-001",
                           "input_sha256": sha(payload), "input_bytes": len(payload),
                           "packed_payload_sha256": sha(packed), "transaction_id": details["transaction_id"],
                           "raw_result_bytes": len(raw), "raw_result_sha256": sha(raw),
                           "canonical_result_sha256": sha(canonical), "raw_oracle": RAW_SHA,
                           "canonical_oracle": CANONICAL_SHA,
                           "logical_scan_bits": {"input": 1574912, "output": 6144,
                                                  "status": sum(s["bits"] for s in scan_records if s.get("bits")==32)},
                           "physical_jtag_clocks": sum(s["bits"] + 17 for s in scan_records),
                           "vector_time_ns": end-t0, "protocol_timings_ns": protocol.last_timings_ns,
                           "scan_count": len(scan_records), "scans": scan_records})
        record["end_monotonic_ns"] = time.monotonic_ns()
        return record
    except RunnerError as exc:
        record.update({"status": "FAIL", "failure_kind": exc.kind, "failure": str(exc),
                       "end_monotonic_ns": time.monotonic_ns()})
        raise
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        kind = {"hello": "hello", "vector001": "vector", "identify": "backend"}[operation]
        if operation == "vector001" and "raw PHK1 result differs" in str(exc):
            kind = "raw_mismatch"
        if operation == "vector001" and "canonical PHK1 result differs" in str(exc):
            kind = "canonical_mismatch"
        record.update({"status": "FAIL", "failure_kind": kind, "failure": message,
                       "end_monotonic_ns": time.monotonic_ns()})
        raise RunnerError(kind, message) from exc
    finally:
        close_error = None
        try:
            backend.close()
            record["backend_closed"] = True
        except Exception as exc:
            record["backend_closed"] = False
            record["cleanup_failure"] = f"{type(exc).__name__}: {exc}"
            if sys.exc_info()[0] is None:
                record.update({"status":"FAIL","failure_kind":"cleanup","failure":record["cleanup_failure"]})
                close_error = RunnerError("cleanup", record["cleanup_failure"])
        if operation == "vector001" and protocol is not None:
            write_private_bytes(evidence_dir/"raw-result.bin",protocol.last_raw_result)
            write_private_bytes(evidence_dir/"canonical-result.bin",protocol.last_canonical_result)
        if operation == "identify":
            write_evidence(previous_identify, record)
        elif operation == "hello":
            write_evidence(previous_hello, record)
        elif operation == "vector001":
            write_evidence(evidence_dir / "vector001.json", record)
        if close_error is not None:
            raise close_error


def run_hello_vector_session(*, lock_path: Path = LOCK_PATH, evidence_dir: Path,
                             backend_factory: Callable[[dict, str], object] | None = None,
                             payload_path: Path = VECTOR_PATH) -> tuple[dict, dict]:
    """Run identity validation, HELLO and Vector001 on one backend lifetime.

    This is the supervisor entrypoint. Both fixtures and the frozen payload
    are validated before opening the backend; HELLO evidence is committed
    before the vector begins, and raw output is persisted as soon as it is
    available, including on later verification/cleanup errors.
    """
    preflight_hello_fixture()
    try:
        payload = payload_path.read_bytes()
        if len(payload) != 196_608 or sha(payload) != VECTOR_SHA:
            raise RunnerError("fixture", "fixed operand-vector-001 payload identity mismatch")
        vector_fixture = json.loads(VECTOR_FIXTURE.read_text())
        if vector_fixture.get("vector_id") not in (None, "operand-vector-001"):
            raise RunnerError("fixture", "Vector001 fixture schema mismatch")
    except RunnerError:
        raise
    except Exception as exc:
        raise RunnerError("fixture", f"cannot preflight Vector001 fixture: {exc}") from exc
    lock, lock_hash = validate_target_lock(lock_path)
    try:
        consume_nonce(lock["authorization_nonce"], evidence_dir/"target-lock-nonce-ledger.json")
    except V2LockError as exc:
        raise RunnerError("lock", str(exc)) from exc
    factory = backend_factory or (lambda target, op: RpcBackend(target, op))
    started = time.monotonic_ns()
    backend = factory(lock["target"], "session")
    if getattr(backend, "identity_verified", False) is not True:
        backend.close()
        raise RunnerError("target", "backend did not revalidate IDCODE before USER access")
    protocol = PHK1RawTransport(backend, timeout_s=120.0)
    hello_record = {"schema":"sidecar-phk1-live-runner-evidence-v1", "operation":"hello",
        "run_id":lock["run_id"], "target_lock_sha256":lock_hash, "bitstream_sha256":BITSTREAM_SHA,
        "start_monotonic_ns":started, "autoretry":False}
    vector_record = {"schema":"sidecar-phk1-live-runner-evidence-v1", "operation":"vector001",
        "run_id":lock["run_id"], "target_lock_sha256":lock_hash, "bitstream_sha256":BITSTREAM_SHA,
        "autoretry":False}
    phase="hello"
    try:
        if hasattr(backend, "mark_phase"):
            backend.mark_phase("hello")
        before_hello = backend.lifecycle_snapshot("RUNNER_ALIVE_BEFORE_HELLO") if hasattr(backend,"lifecycle_snapshot") else {
            "child_pid": None, "child_poll": None, "child_alive": True,
            "pipe_writable_before_vector": True, "pipe_readable_before_vector": True}
        hello_record["runner_before_hello"] = before_hello
        if not before_hello.get("child_alive"):
            raise RunnerError("backend", "persistent RPC runner exited before HELLO")
        t0=time.monotonic_ns()
        parsed=protocol.hello()
        t1=time.monotonic_ns()
        hello_scans=list(getattr(backend,"protocol_scans",[]))
        expected=json.loads(LOGICAL_HELLO_FIXTURE.read_text())["parsed_status"]
        if parsed["status_word"] != expected["word"] or not parsed.get("phk1_ready") or parsed.get("error"):
            raise RunnerError("hello","HELLO response differs from exact qualified fixture")
        if not _transcript_check(hello_scans,"hello") or sum(s["bits"] for s in hello_scans)!=112:
            raise RunnerError("hello","HELLO transcript differs bit-for-bit from qualified fixture")
        hello_record.update({"status":"PASS","hello":parsed,"hello_time_ns":t1-t0,
            "logical_scan_bits":sum(s["bits"] for s in hello_scans),
            "physical_jtag_clocks":sum(s["bits"]+17 for s in hello_scans),
            "scan_count":len(hello_scans),"transcript_match":True,"scans":hello_scans,
            "backend_open_ns":getattr(backend,"open_ns",None),"mpsse_sync_ns":getattr(backend,"sync_ns",None),
            "target_revalidation_ns":getattr(backend,"identity_ns",None)})
        write_evidence(evidence_dir/"identify.json", {"schema":"sidecar-phk1-live-runner-evidence-v1",
            "operation":"identify","run_id":lock["run_id"],"target_lock_sha256":lock_hash,
            "bitstream_sha256":BITSTREAM_SHA,"status":"PASS","idcode_match":True,
            "dna_gate":"qualified lock evidence","user_ir_selection_count":0,"autoretry":False})
        write_evidence(evidence_dir/"hello.json",hello_record)

        # The RPC child and both pipes must remain live after HELLO. This is a
        # read-only OS-state check; it emits no probe bytes and adds no JTAG I/O.
        hello_lifecycle = backend.lifecycle_snapshot("RUNNER_ALIVE_AFTER_HELLO") if hasattr(backend, "lifecycle_snapshot") else {
            "child_pid": None, "child_poll": None, "child_alive": True,
            "pipe_writable_before_vector": True, "pipe_readable_before_vector": True}
        hello_record["runner_after_hello"] = hello_lifecycle
        hello_record.update({"runner_pid":hello_lifecycle.get("child_pid"),
            "runner_poll_after_hello":hello_lifecycle.get("child_poll"),
            "runner_phase_after_hello":hello_lifecycle.get("phase"),
            "runner_alive_after_hello":hello_lifecycle.get("child_alive"),
            "pipe_writable_before_vector":hello_lifecycle.get("pipe_writable_before_vector"),
            "pipe_readable_before_vector":hello_lifecycle.get("pipe_readable_before_vector")})
        write_evidence(evidence_dir/"hello.json",hello_record)
        if not (hello_lifecycle.get("child_alive") and
                hello_lifecycle.get("pipe_writable_before_vector") and
                hello_lifecycle.get("pipe_readable_before_vector")):
            raise RunnerError("backend", "persistent RPC runner or pipe closed after HELLO")

        phase="vector001"
        if hasattr(backend, "mark_phase"):
            backend.mark_phase("vector001")
        txid=vector_transaction_id("operand-vector-001",VECTOR_SHA)
        packed=b"".join(build_request(txid,i,payload[i*24576:(i+1)*24576]) for i in range(8))
        contract=json.loads(VECTOR_FIXTURE.read_text())["host_pack"]
        if txid != int(json.loads(VECTOR_FIXTURE.read_text())["transaction_id"],16) or sha(packed)!=contract["user2_tx_sha256"]:
            raise RunnerError("fixture","Vector001 packed payload differs from qualified fixture")
        scan_start=len(getattr(backend,"protocol_scans",[]))
        vector_start=time.monotonic_ns()
        vector_record["runner_before_vector"] = (backend.lifecycle_snapshot("PIPE_CHECK_BEFORE_VECTOR")
            if hasattr(backend, "lifecycle_snapshot") else hello_lifecycle)
        raw,canonical,details=protocol.vector001(payload)
        vector_end=time.monotonic_ns()
        write_private_bytes(evidence_dir/"raw-result.bin",raw)
        write_private_bytes(evidence_dir/"canonical-result.bin",canonical)
        scans=list(getattr(backend,"protocol_scans",[]))[scan_start:]
        vector_record.update({"status":"PASS","vector_id":"operand-vector-001",
            "input_sha256":sha(payload),"input_bytes":len(payload),"packed_payload_sha256":sha(packed),
            "transaction_id":details["transaction_id"],"raw_result_bytes":len(raw),
            "raw_result_sha256":sha(raw),"canonical_result_sha256":sha(canonical),
            "raw_oracle":RAW_SHA,"canonical_oracle":CANONICAL_SHA,
            "logical_scan_bits":{"input":1574912,"output":6144,
                "status":sum(s["bits"] for s in scans if s.get("bits")==32)},
            "physical_jtag_clocks":sum(s["bits"]+17 for s in scans),"vector_time_ns":vector_end-vector_start,
            "protocol_timings_ns":protocol.last_timings_ns,"scan_count":len(scans),"scans":scans})
        backend.close()
        vector_record["backend_closed"] = True
        write_evidence(evidence_dir/"vector001.json",vector_record)
        return hello_record,vector_record
    except Exception as exc:
        # Preserve any result bytes received before a later failure.
        write_private_bytes(evidence_dir/"raw-result.bin",protocol.last_raw_result)
        write_private_bytes(evidence_dir/"canonical-result.bin",protocol.last_canonical_result)
        failed_record=vector_record if phase=="vector001" else hello_record
        failed_record.update({"parent_phase":phase,"exception_type":type(exc).__name__,
                              "exception_traceback":traceback.format_exc(),
                              "parent_pid":os.getpid()})
        if hasattr(backend, "lifecycle_snapshot"):
            try:
                failed_record["runner_failure_snapshot"] = backend.lifecycle_snapshot("RUNNER_FAILURE")
            except Exception as snapshot_exc:
                failed_record["runner_snapshot_error"] = f"{type(snapshot_exc).__name__}: {snapshot_exc}"
        if isinstance(exc,RunnerError):
            failed_record.update({"status":"FAIL","failure_kind":exc.kind,"failure":str(exc)})
        else:
            failed_record.update({"status":"FAIL","failure_kind":phase,"failure":f"{type(exc).__name__}: {exc}"})
        try:
            backend.close()
            failed_record["backend_closed"] = True
        except Exception as close_exc:
            failed_record["backend_closed"] = False
            failed_record["cleanup_failure"] = f"{type(close_exc).__name__}: {close_exc}"
        write_evidence(evidence_dir/f"{phase}-failure.json",failed_record)
        raise


def main_session(evidence_dir: Path, *, payload_path: Path = VECTOR_PATH) -> int:
    """Fixed internal supervisor entrypoint; no arbitrary operation args."""
    run_hello_vector_session(evidence_dir=evidence_dir,payload_path=payload_path)
    print(json.dumps({"status":"PASS","operations":["identify","hello","vector001"],
                      "backend_sessions":1,"autoretry":False},sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("operation", choices=sorted(OPS))
    ap.add_argument("--evidence-dir", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        if args.operation == "hello":
            preflight_hello_fixture()
        lock, _ = validate_target_lock(LOCK_PATH)
        consume_nonce(lock["authorization_nonce"], args.evidence_dir/"target-lock-nonce-ledger.json")
        if args.operation == "identify":
            factory = lambda target: RpcBackend(target, args.operation)
        else:
            factory = lambda target: RpcBackend(target, args.operation)
        record = run_operation(args.operation, lock_path=LOCK_PATH,
                               evidence_dir=args.evidence_dir, backend_factory=factory)
        print(json.dumps(record, sort_keys=True))
        return EXIT["success"]
    except RunnerError as exc:
        print(f"FAILED_KIND={exc.kind}\nFAILED_MESSAGE={exc}", file=sys.stderr)
        return EXIT.get(exc.kind, 1)
    except Exception as exc:
        print(f"FAILED_KIND=backend\nFAILED_MESSAGE={type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT["backend"]


if __name__ == "__main__":
    raise SystemExit(main())
