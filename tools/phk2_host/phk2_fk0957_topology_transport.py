"""Narrow FK0957 reset-default DR physical transport.

The public transport operation accepts only a previously verified one-use
descriptor permit. Tests replace the private native-backend factory; no CLI,
network path, signing API, generic scan API, or caller-provided transaction exists.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import threading
from typing import Any

import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_topology_discovery as topology


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


CARD_ID = "FK0957"
ADAPTER_SERIAL = "153300000957A"
USB_DESCRIPTOR_SERIAL = "153300000957"
FTDI_VID = 0x0403
FTDI_PID = 0x6010
FTDI_INTERFACE_A = 1
FTDI_INTERFACE_NAME = "A"
SYSFS_USB_ROOT = Path("/sys/bus/usb/devices")
# Immutable Linux x86_64 qualification pins. Package upgrades require an
# intentional source review and pin update; the public API accepts no paths.
@dataclass(frozen=True)
class _LibraryPin:
    name: str
    path: Path
    sha256: str
    build_id: str
    soname: str
    size: int

LIBFTDI_REALPATH = Path("/usr/lib/x86_64-linux-gnu/libftdi1.so.2.5.0")
LIBFTDI_SHA256 = "0e5332df54c66f14ef9107934365b47b9429df02e3ff3402436bd85e9e3e84fe"
LIBFTDI_BUILD_ID = "5d7c81b08d369b6ea8654c825cbdff7fdce1f87c"
LIBUSB_REALPATH = Path("/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0.4.0")
LIBUSB_SHA256 = "751349e3def1808981dc26bbeb746e2d6ff4ca97fc2c8bc8faaa8f46c879057f"
LIBUSB_BUILD_ID = "47533e904f636332fab2f1ca8847ad7759ed19ec"

LIBRARY_PINS = (
    _LibraryPin("libcap", Path("/usr/lib/x86_64-linux-gnu/libcap.so.2.66"),
                "6ac6abc86ac891c6e13486470e26f1d939f47fda9e6b5d5508a7f5ec881adc84",
                "7a7c2bbc541071e68f1c74f691d5ffba03bfb5ad", "libcap.so.2", 51536),
    _LibraryPin("libudev", Path("/usr/lib/x86_64-linux-gnu/libudev.so.1.7.8"),
                "0d6934adafb2ef3c640382440c14d6bd60f391e688c000796ffcea0c72849269",
                "1166cb4a3de6a68b330a78ef0f099ebddf315698", "libudev.so.1", 207288),
    _LibraryPin("libusb", LIBUSB_REALPATH, LIBUSB_SHA256,
                LIBUSB_BUILD_ID, "libusb-1.0.so.0", 117736),
    _LibraryPin("libc", Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
                "755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a",
                "8cebda42d140fc2b09639f8b13a5d5f2e617ef09", "libc.so.6", 2129424),
    _LibraryPin("libftdi", LIBFTDI_REALPATH, LIBFTDI_SHA256,
                LIBFTDI_BUILD_ID, "libftdi1.so.2", 64016),
)
LIBFTDI_PIN = LIBRARY_PINS[-1]
LIBUSB_PIN = LIBRARY_PINS[2]
BITMODE_RESET = 0x00
BITMODE_MPSSE = 0x02
GPIO_MASK = 0x0B
LATENCY_MS = 2
IO_CHUNK_SIZE = 16 * 1024
EXPECTED_SCAN_A_TCK = 591
EXPECTED_SCAN_B_TCK = 586
EXPECTED_TOTAL_TCK = 1177
GOLDEN_SCAN_A_SHA256 = "81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2"
GOLDEN_SCAN_B_SHA256 = "08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a"
GOLDEN_PLAN_SHA256 = "0cf6be1caa3657dad96ccc16b0f87cbbda0c00e52d9bee234d1340c94e64255f"
GOLDEN_COMMAND_CONTRACT_SHA256 = "4aa465a61ae18761eeb608a2eee9796608352a14f4b54b303a6d59db385359c5"
GOLDEN_TMS_SHA256 = "76ccec34707bdc3e646f2bb226ae2d3547f7b40c623dea4933205d44d4abba1a"
GOLDEN_TDI_SHA256 = "8f91089bf5ce1c1fc823596a5aaae7ff7188d9e22c313484ea23c139e7fe7a21"
GOLDEN_TDI_A_SHA256 = "5393dfe214f3c6a197af537b2e94bcdfd73a2713d06c2b395d43a82237c6a246"
GOLDEN_TDI_B_SHA256 = "aac746341b56fbd50ab5f0d63677d261201cf5970f0ddc60f2ffaac6952c3963"

_RESULT_LOCK = threading.Lock()
_SEALED_RESULTS: dict[object, str] = {}
_SIGNED_PERMITS: set[object] = set()
_REMOTE_AUTHORIZED_PERMITS: dict[object, bytes] = {}
_REMOTE_AUTH_LOCK = threading.Lock()
_REMOTE_RELEASE_HEAD: str | None = None


class Refusal(ValueError):
    def __init__(self, message: str = "topology operation refused", *, envelope: "RefusalEnvelope | None" = None):
        super().__init__(message)
        self.envelope = envelope

    def canonical_envelope(self) -> bytes:
        if self.envelope is None:
            raise ValueError("refusal has no internally generated diagnostic envelope")
        return _canonical_json(self.envelope.as_dict())


REFUSAL_PHASES = frozenset({
    "PRELIVE_VALIDATION", "PERMIT_VALIDATION", "LIBRARY_PROVENANCE",
    "FTDI_CONTEXT_CREATE", "REMOTE_BOOTSTRAP", "DEVICE_ENUMERATION",
    "DEVICE_SELECTION", "DEVICE_OPEN", "MPSSE_INIT", "SCAN_A_WRITE",
    "SCAN_A_READ", "SCAN_B_WRITE", "SCAN_B_READ", "TRANSPORT_CLOSE",
    "LOCAL_VALIDATION", "LOCAL_SIGNING", "INTERNAL_REFUSAL",
})
REFUSAL_CODES = frozenset({
    "TRANSACTION_PIN_MISMATCH", "TRUSTED_LAUNCHER_REQUIRED", "PERMIT_INVALID", "DESCRIPTOR_STALE",
    "LIBRARY_PIN_MISMATCH", "FTDI_CONTEXT_FAILED", "REMOTE_BOOTSTRAP_FAILED",
    "ENUMERATION_FAILED", "NO_TARGET_CANDIDATE", "MULTIPLE_TARGET_CANDIDATES",
    "CANDIDATE_IDENTITY_MISMATCH", "DEVICE_OPEN_FAILED", "MPSSE_INIT_FAILED",
    "SCAN_A_WRITE_FAILED", "SCAN_A_READ_FAILED", "SCAN_B_WRITE_FAILED",
    "SCAN_B_READ_FAILED", "TRANSPORT_CLOSE_FAILED", "LOCAL_VALIDATION_FAILED",
    "LOCAL_SIGNING_FAILED", "INTERNAL_REFUSAL",
})
OPERATION_STATES = (
    "PRELIVE", "PERMIT_VALIDATED", "RUNTIME_READY", "ENUMERATING",
    "DEVICE_SELECTED", "DEVICE_OPENED", "MPSSE_READY", "SCAN_A_ACTIVE",
    "SCAN_A_NAV_WRITE", "SCAN_A_BULK_WRITE", "SCAN_A_BULK_READ",
    "SCAN_A_FINAL_WRITE", "SCAN_A_FINAL_READ", "SCAN_A_EXIT_WRITE",
    "SCAN_A_COMPLETE", "SCAN_B_ACTIVE", "SCAN_B_NAV_WRITE",
    "SCAN_B_BULK_WRITE", "SCAN_B_BULK_READ", "SCAN_B_FINAL_WRITE",
    "SCAN_B_FINAL_READ", "SCAN_B_EXIT_WRITE", "SCAN_B_COMPLETE",
    "TRANSPORT_CLOSING", "TRANSPORT_CLOSED", "LOCAL_VALIDATED", "SIGNED_STAGED",
)
_OPERATION_STATE_RANK = {name: index for index, name in enumerate(OPERATION_STATES)}


@dataclass(frozen=True)
class RefusalEnvelope:
    phase: str
    code: str
    return_code: int | None
    target_candidates: int | str
    device_opened: int | str
    scan_a_started: int
    scan_a_tck_emitted: int
    scan_b_started: int
    scan_b_tck_emitted: int
    transport_closed: int
    permit_consumed: int | str
    operation_state: str = "PRELIVE"
    close_from_state: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "REFUSED", "phase": self.phase, "code": self.code,
            "evidence_path": "none", "signature_verified": False,
            "return_code": self.return_code, "target_candidates": self.target_candidates,
            "device_opened": self.device_opened, "scan_a_started": self.scan_a_started,
            "scan_a_tck_emitted": self.scan_a_tck_emitted,
            "scan_b_started": self.scan_b_started,
            "scan_b_tck_emitted": self.scan_b_tck_emitted,
            "transport_closed": self.transport_closed,
            "permit_consumed": self.permit_consumed,
            "operation_state": self.operation_state,
            "close_from_state": self.close_from_state,
        }


class _AttemptTrace:
    def __init__(self):
        self.phase = "PRELIVE_VALIDATION"
        self.return_code = None
        self.target_candidates: int | str = 0
        self.device_opened: int | str = 0
        self.scan_a_started = 0
        self.scan_a_tck_emitted = 0
        self.scan_b_started = 0
        self.scan_b_tck_emitted = 0
        self.transport_closed = 0
        self.permit_consumed: int | str = "unknown"
        self.code_override: str | None = None
        self.operation_state = "PRELIVE"
        self.close_from_state: str | None = None

    def advance(self, state: str) -> None:
        current_rank = _OPERATION_STATE_RANK.get(self.operation_state)
        next_rank = _OPERATION_STATE_RANK.get(state)
        if current_rank is None or next_rank is None or next_rank < current_rank:
            raise Refusal("invalid internal topology progress transition")
        self.operation_state = state

    def begin_close(self) -> None:
        if self.close_from_state is None:
            self.close_from_state = self.operation_state
        self.advance("TRANSPORT_CLOSING")

    def finish_close(self) -> None:
        self.advance("TRANSPORT_CLOSED")

    def refuse(self, *, code: str | None = None, phase: str | None = None) -> Refusal:
        selected_phase = phase or self.phase
        selected_code = code or self.code_override or _DEFAULT_REFUSAL_CODE.get(
            selected_phase, "INTERNAL_REFUSAL")
        if selected_phase not in REFUSAL_PHASES or selected_code not in REFUSAL_CODES:
            selected_phase, selected_code = "INTERNAL_REFUSAL", "INTERNAL_REFUSAL"
        return Refusal(envelope=RefusalEnvelope(
            selected_phase, selected_code, _bounded_return_code(self.return_code),
            _bounded_count(self.target_candidates), self.device_opened,
            self.scan_a_started, _bounded_count(self.scan_a_tck_emitted),
            self.scan_b_started, _bounded_count(self.scan_b_tck_emitted),
            self.transport_closed, self.permit_consumed,
            self.operation_state, self.close_from_state))


_DEFAULT_REFUSAL_CODE = {
    "PRELIVE_VALIDATION": "TRANSACTION_PIN_MISMATCH",
    "PERMIT_VALIDATION": "PERMIT_INVALID",
    "LIBRARY_PROVENANCE": "LIBRARY_PIN_MISMATCH",
    "FTDI_CONTEXT_CREATE": "FTDI_CONTEXT_FAILED",
    "REMOTE_BOOTSTRAP": "REMOTE_BOOTSTRAP_FAILED",
    "DEVICE_ENUMERATION": "ENUMERATION_FAILED",
    "DEVICE_SELECTION": "CANDIDATE_IDENTITY_MISMATCH",
    "DEVICE_OPEN": "DEVICE_OPEN_FAILED",
    "MPSSE_INIT": "MPSSE_INIT_FAILED",
    "SCAN_A_WRITE": "SCAN_A_WRITE_FAILED",
    "SCAN_A_READ": "SCAN_A_READ_FAILED",
    "SCAN_B_WRITE": "SCAN_B_WRITE_FAILED",
    "SCAN_B_READ": "SCAN_B_READ_FAILED",
    "TRANSPORT_CLOSE": "TRANSPORT_CLOSE_FAILED",
    "LOCAL_VALIDATION": "LOCAL_VALIDATION_FAILED",
    "LOCAL_SIGNING": "LOCAL_SIGNING_FAILED",
    "INTERNAL_REFUSAL": "INTERNAL_REFUSAL",
}


def _bounded_count(value: Any) -> int | str:
    if value == "unknown":
        return "unknown"
    if type(value) is int and 0 <= value <= 1177:
        return value
    return "unknown"


def _bounded_candidate_count(value: Any) -> int | str:
    """Saturate the public candidate counter at its reviewed schema bound."""
    if type(value) is not int or value < 0:
        return "unknown"
    return min(value, 256)


def _bounded_return_code(value: Any) -> int | None:
    return value if type(value) is int and -255 <= value <= 255 else None


def _mpsse_tcks_in_prefix(command: bytes, sent: int) -> int:
    if not command:
        return 0
    opcode = command[0]
    if opcode in (0x4B, 0x6B):
        return ((command[1] & 0x07) + 1) if len(command) >= 3 and sent >= 3 else 0
    if opcode == 0x39 and len(command) >= 3:
        declared = ((command[2] << 8) | command[1]) + 1
        return min(declared, max(0, sent - 3)) * 8
    if opcode == 0x3B and len(command) >= 3:
        return ((command[1] & 0x07) + 1) if sent >= len(command) else 0
    return 0


def _diagnostic_refusal(exc: BaseException, trace: _AttemptTrace,
                        *, code: str | None = None, phase: str | None = None) -> Refusal:
    if isinstance(exc, Refusal) and exc.envelope is not None:
        return exc
    return trace.refuse(code=code, phase=phase)


def _permit_consumption_state(permit: Any) -> int | str:
    if not isinstance(permit, topology.DiscoveryPermit):
        return "unknown"
    with topology._PERMIT_LOCK:
        if permit._token in topology._CONSUMED:
            return 1
        if permit._token in topology._ACTIVE:
            return 0
    return "unknown"


def _trace_from_sealed_result(trace: _AttemptTrace, result: Any) -> None:
    if not isinstance(result, TransportObservation):
        return
    with _RESULT_LOCK:
        expected = _SEALED_RESULTS.get(result._proof)
    if expected is None or expected != hashlib.sha256(_observation_payload(result)).hexdigest():
        return
    trace.target_candidates = result.matched_device_count
    trace.device_opened = 1
    trace.scan_a_started = 1
    trace.scan_b_started = 1
    trace.scan_a_tck_emitted = min(result.scan_a_tck_count, EXPECTED_SCAN_A_TCK)
    trace.scan_b_tck_emitted = min(result.scan_b_tck_count, EXPECTED_SCAN_B_TCK)
    trace.transport_closed = 1
    trace.close_from_state = "SCAN_B_COMPLETE"
    if _OPERATION_STATE_RANK[trace.operation_state] < _OPERATION_STATE_RANK["TRANSPORT_CLOSED"]:
        trace.advance("TRANSPORT_CLOSED")


class _FtdiDeviceList(ctypes.Structure):
    pass


_FtdiDeviceListPtr = ctypes.POINTER(_FtdiDeviceList)
_FtdiDeviceList._fields_ = [("next", _FtdiDeviceListPtr), ("dev", ctypes.c_void_p)]


class _UsbDeviceDescriptor(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_uint8), ("bDescriptorType", ctypes.c_uint8),
        ("bcdUSB", ctypes.c_uint16), ("bDeviceClass", ctypes.c_uint8),
        ("bDeviceSubClass", ctypes.c_uint8), ("bDeviceProtocol", ctypes.c_uint8),
        ("bMaxPacketSize0", ctypes.c_uint8), ("idVendor", ctypes.c_uint16),
        ("idProduct", ctypes.c_uint16), ("bcdDevice", ctypes.c_uint16),
        ("iManufacturer", ctypes.c_uint8), ("iProduct", ctypes.c_uint8),
        ("iSerialNumber", ctypes.c_uint8), ("bNumConfigurations", ctypes.c_uint8),
    ]


@dataclass(frozen=True)
class TransportObservation:
    card_id: str
    adapter_serial: str
    usb_descriptor_serial: str
    physical_interface: str
    usb_path: str
    ftdi_vid: str
    ftdi_pid: str
    manufacturer: str
    product: str
    descriptor_evidence_sha256: str
    permit_nonce: str
    authorization_id: str | None
    scan_a_transaction_sha256: str
    scan_a_tck_count: int
    scan_a_raw_tdo: bytes
    scan_b_transaction_sha256: str
    scan_b_tck_count: int
    scan_b_raw_tdo: bytes
    total_tck_count: int
    transport_source_sha256: str
    production_git_head: str
    worktree_clean: bool
    runtime_library_provenance: tuple[tuple[Any, ...], ...]
    matched_device_count: int
    opened_device_count: int
    second_device_opened: bool
    write_count: int
    reset_count: int
    program_count: int
    _proof: Any


def _observation_payload(result: TransportObservation) -> bytes:
    obj = {name: value.hex() if isinstance(value, bytes) else value
           for name, value in result.__dict__.items() if name != "_proof"}
    return _canonical_json(obj)


@dataclass(frozen=True)
class _LoadedLibrary:
    pin: _LibraryPin
    handle: Any
    fd: int
    pre_stat: tuple[int, ...]
    post_stat: tuple[int, ...]
    realpath: str


def _stat_fingerprint(st: os.stat_result) -> tuple[int, ...]:
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            break
        digest.update(block)
        offset += len(block)
        if offset > 100 * 1024 * 1024:
            raise Refusal("approved runtime library exceeds size bound")
    return digest.hexdigest()


def _build_id_fd(fd: int) -> str:
    """Read the GNU build-id note from a bounded ELF64 little-endian image."""
    header = os.pread(fd, 64, 0)
    if (len(header) != 64 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01"):
        raise Refusal("approved runtime library is not ELF64 little-endian")
    phoff = struct.unpack_from("<Q", header, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", header, 54)
    if phentsize < 56 or phnum > 4096 or phoff + phentsize * phnum > os.fstat(fd).st_size:
        raise Refusal("ELF program header table is malformed")
    for index in range(phnum):
        ph = os.pread(fd, phentsize, phoff + index * phentsize)
        if len(ph) != phentsize:
            raise Refusal("ELF program header is truncated")
        if struct.unpack_from("<I", ph, 0)[0] != 4:  # PT_NOTE
            continue
        note_offset, note_size = struct.unpack_from("<QQ", ph, 8)[0], struct.unpack_from("<Q", ph, 32)[0]
        if note_size > 1024 * 1024 or note_offset + note_size > os.fstat(fd).st_size:
            raise Refusal("ELF note segment is malformed")
        notes = os.pread(fd, note_size, note_offset)
        cursor = 0
        while cursor + 12 <= len(notes):
            namesz, descsz, note_type = struct.unpack_from("<III", notes, cursor)
            cursor += 12
            name = notes[cursor:cursor + namesz]
            cursor += (namesz + 3) & ~3
            desc = notes[cursor:cursor + descsz]
            cursor += (descsz + 3) & ~3
            if len(desc) == descsz and name.rstrip(b"\0") == b"GNU" and note_type == 3:
                return desc.hex()
    raise Refusal("ELF GNU build-id is missing")


def _validate_parent_chain(path: Path) -> None:
    current = Path("/")
    for component in path.parts[1:-1]:
        current /= component
        st = current.lstat()
        if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or
                stat.S_IMODE(st.st_mode) & 0o022):
            raise Refusal("approved library parent directory is not protected")


def _proc_maps() -> tuple[str, ...]:
    try:
        rows = Path("/proc/self/maps").read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise Refusal("process mappings are unavailable for runtime verification") from exc
    return tuple(rows)


def _mapped_identity(st: os.stat_result, mappings: tuple[str, ...]) -> str | None:
    expected_dev = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}"
    expected_inode = str(st.st_ino)
    for row in mappings:
        fields = row.split(maxsplit=5)
        if len(fields) < 6 or fields[3].lower() != expected_dev or fields[4] != expected_inode:
            continue
        name = fields[5].removesuffix(" (deleted)")
        try:
            return str(Path(name).resolve(strict=True))
        except (OSError, RuntimeError):
            return name
    return None


def _refuse_ambient_soname(pin: _LibraryPin, mappings: tuple[str, ...]) -> None:
    expected_dev = f"{os.major(pin.path.stat().st_dev):02x}:{os.minor(pin.path.stat().st_dev):02x}"
    expected_inode = str(pin.path.stat().st_ino)
    for row in mappings:
        fields = row.split(maxsplit=5)
        if len(fields) < 6 or Path(fields[5].removesuffix(" (deleted)")).name != pin.soname:
            continue
        if fields[3].lower() != expected_dev or fields[4] != expected_inode:
            raise Refusal("a different object with an approved transport SONAME is already mapped")


def _load_approved_library(pin: _LibraryPin) -> _LoadedLibrary:
    if os.name != "posix" or not Path("/proc/self/maps").exists():
        raise Refusal("approved-library loader requires Linux proc mappings")
    for variable in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
        if os.environ.get(variable):
            raise Refusal("dynamic-loader override environment is set")
    path = pin.path
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise Refusal("approved library path is not a canonical absolute path")
    _validate_parent_chain(path)
    try:
        link_stat = path.lstat()
    except OSError as exc:
        raise Refusal("approved runtime library is missing") from exc
    if stat.S_ISLNK(link_stat.st_mode) or not stat.S_ISREG(link_stat.st_mode):
        raise Refusal("approved runtime library is not a direct regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise Refusal("approved runtime library could not be opened safely") from exc
    try:
        before = os.fstat(fd)
        pre_stat = _stat_fingerprint(before)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or
                not stat.S_IMODE(before.st_mode) & stat.S_IRUSR or
                stat.S_IMODE(before.st_mode) & 0o022 or before.st_size != pin.size or
                (before.st_dev, before.st_ino) != (link_stat.st_dev, link_stat.st_ino)):
            raise Refusal("approved runtime library ownership, mode, inode, or size is invalid")
        if _hash_fd(fd) != pin.sha256 or _build_id_fd(fd) != pin.build_id:
            raise Refusal("approved runtime library hash or build-id mismatch")
        real = str(path.resolve(strict=True))
        if real != str(path):
            raise Refusal("approved runtime library realpath differs from its pin")
        _refuse_ambient_soname(pin, _proc_maps())
        loader_path = f"/proc/self/fd/{fd}"
        try:
            handle = ctypes.CDLL(loader_path, mode=ctypes.RTLD_GLOBAL)
        except OSError as exc:
            raise Refusal("approved runtime library failed to load") from exc
        after = os.fstat(fd)
        post_stat = _stat_fingerprint(after)
        path_after = path.lstat()
        if (pre_stat != post_stat or _hash_fd(fd) != pin.sha256 or _build_id_fd(fd) != pin.build_id or
                path_after.st_ino != after.st_ino or path_after.st_dev != after.st_dev):
            raise Refusal("approved runtime library changed between validation and load")
        mapped = _mapped_identity(after, _proc_maps())
        if mapped != real:
            raise Refusal("loaded runtime mapping differs from the approved realpath/inode")
        return _LoadedLibrary(pin, handle, fd, pre_stat, post_stat, mapped)
    except BaseException:
        os.close(fd)
        raise


def _load_approved_runtime() -> dict[str, _LoadedLibrary]:
    """Load root-owned pinned dependency closure through validated open FDs."""
    for variable in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"):
        if os.environ.get(variable):
            raise Refusal("dynamic-loader override environment is set")
    loaded: dict[str, _LoadedLibrary] = {}
    try:
        for pin in LIBRARY_PINS:
            loaded[pin.name] = _load_approved_library(pin)
    except BaseException:
        for library in loaded.values():
            try:
                os.close(library.fd)
            except OSError:
                pass
        raise
    return loaded


def _require_native_files() -> tuple[Path, ...]:
    paths = []
    for pin in LIBRARY_PINS:
        _validate_parent_chain(pin.path)
        try:
            before = pin.path.lstat()
            if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or
                    before.st_uid != 0 or before.st_nlink != 1 or
                    not stat.S_IMODE(before.st_mode) & stat.S_IRUSR or
                    stat.S_IMODE(before.st_mode) & 0o022 or before.st_size != pin.size):
                raise Refusal("approved runtime library path metadata mismatch")
            fd = os.open(pin.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            raise Refusal("approved runtime library is unavailable") from exc
        try:
            opened = os.fstat(fd)
            if _stat_fingerprint(before) != _stat_fingerprint(opened):
                raise Refusal("approved runtime library inode changed during validation")
            if _hash_fd(fd) != pin.sha256 or _build_id_fd(fd) != pin.build_id:
                raise Refusal("approved runtime library hash or build-id mismatch")
            if _stat_fingerprint(opened) != _stat_fingerprint(os.fstat(fd)):
                raise Refusal("approved runtime library changed during hashing")
        finally:
            os.close(fd)
        paths.append(pin.path)
    return tuple(paths)


def _production_git_state(repo: Path | None = None) -> tuple[str, bool]:
    """Read exact HEAD and cleanliness with Git environment/config overrides removed."""
    root = repo or Path(__file__).resolve().parents[2]
    if _REMOTE_RELEASE_HEAD is not None and not (root / ".git").exists():
        return _REMOTE_RELEASE_HEAD, True
    clean_env = {
        "PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
    }
    try:
        head = subprocess.run(
            ["/usr/bin/git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=clean_env, timeout=5).stdout.strip()
        status = subprocess.run(
            ["/usr/bin/git", "-C", str(root), "status", "--porcelain=v1",
             "--untracked-files=all", "--ignore-submodules=all"],
            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=clean_env, timeout=5).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("production Git state is unavailable") from exc
    if (len(head) != 40 or any(char not in "0123456789abcdef" for char in head) or
            status != ""):
        raise Refusal("production source worktree is not clean or HEAD is malformed")
    return head, True


def transport_source_sha256() -> str:
    """Hash the clean production Git state, runtime-critical sources, and native libraries."""
    repo = Path(__file__).resolve().parents[2]
    head, clean = _production_git_state(repo)
    relative_sources = (
        "tools/phk2_host/phk2_fk0957_topology_transport.py",
        "tools/phk2_host/phk2_fk0957_topology_discovery.py",
        "tools/phk2_host/phk2_fk0957_idcode_gate.py",
    )
    source_files = tuple((item, (repo / item).resolve(strict=True)) for item in relative_sources)
    native_files = tuple((pin.name, path) for pin, path in zip(LIBRARY_PINS, _require_native_files()))
    digest = hashlib.sha256()
    digest.update(b"production_git_head\0" + head.encode("ascii") + b"\0clean=1\0")
    for label, path in source_files + native_files:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > 100 * 1024 * 1024:
            raise Refusal("transport source input is not a bounded regular file")
        raw = path.read_bytes()
        digest.update(label.encode("utf-8") + b"\0")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _bind_verified_remote_release_head(head: str) -> None:
    """Bind a checkout-free deployment to the already signature-verified release."""
    global _REMOTE_RELEASE_HEAD
    if (type(head) is not str or len(head) != 40 or
            any(ch not in "0123456789abcdef" for ch in head)):
        raise Refusal("remote release HEAD is invalid")
    if (Path(__file__).resolve().parents[2] / ".git").exists():
        actual, clean = _production_git_state()
        if not clean or actual != head:
            raise Refusal("remote release Git state mismatch")
        return
    if _REMOTE_RELEASE_HEAD is not None and _REMOTE_RELEASE_HEAD != head:
        raise Refusal("remote release context changed during process")
    _REMOTE_RELEASE_HEAD = head


def _read_sysfs(path: Path, field: str) -> str:
    if field not in {"idVendor", "idProduct", "serial", "manufacturer", "product"}:
        raise Refusal("sysfs field is outside the fixed descriptor allowlist")
    try:
        raw = (path / field).read_bytes()
    except OSError as exc:
        raise Refusal("required sysfs descriptor is unavailable") from exc
    if len(raw) > 256 or b"\x00" in raw:
        raise Refusal("sysfs descriptor is malformed or oversized")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refusal("sysfs descriptor is not UTF-8") from exc
    # sysfs terminates text attributes with one LF. Preserve every other
    # serial byte so whitespace, prefixes, and suffixes cannot normalize into
    # the authorized serial.
    value = decoded[:-1] if field == "serial" and decoded.endswith("\n") else (
        decoded if field == "serial" else decoded.strip())
    if not value:
        raise Refusal("required sysfs descriptor is empty")
    return value


def _format_usb_path(bus: int, ports: tuple[int, ...]) -> str:
    if not 1 <= bus <= 255 or not ports or len(ports) > 8 or any(not 1 <= n <= 255 for n in ports):
        raise Refusal("libusb topology path is malformed")
    return str(bus) + "-" + ".".join(map(str, ports))


def _identity_from_sysfs(path_text: str, descriptor: _UsbDeviceDescriptor) -> topology.DescriptorIdentity:
    if (descriptor.idVendor != FTDI_VID or descriptor.idProduct != FTDI_PID):
        raise Refusal("enumerated libusb candidate is not the approved FTDI VID/PID")
    sysfs = SYSFS_USB_ROOT / path_text
    vendor = _read_sysfs(sysfs, "idVendor").lower()
    product_id = _read_sysfs(sysfs, "idProduct").lower()
    if vendor != f"{FTDI_VID:04x}" or product_id != f"{FTDI_PID:04x}":
        raise Refusal("sysfs VID/PID differs from enumerated libusb descriptor")
    serial = _read_sysfs(sysfs, "serial")
    manufacturer = _read_sysfs(sysfs, "manufacturer")
    product = _read_sysfs(sysfs, "product")
    identity = topology.DescriptorIdentity(CARD_ID, ADAPTER_SERIAL, serial, path_text,
                                           vendor, product_id, manufacturer, product,
                                           FTDI_INTERFACE_NAME)
    if (identity.card_id, identity.adapter_serial, identity.usb_descriptor_serial,
        identity.vid, identity.pid, identity.manufacturer, identity.product,
        identity.interface) != (CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL,
                                f"{FTDI_VID:04x}", f"{FTDI_PID:04x}", "Xilinx", "SQRL FK", "A"):
        raise Refusal("sysfs identity does not match the authorized FK0957 descriptor")
    return identity


def _serial_for_candidate(path_text: str, descriptor: _UsbDeviceDescriptor) -> str | None:
    """Read only enough metadata to filter an enumerated VID/PID peer by exact serial."""
    if descriptor.idVendor != FTDI_VID or descriptor.idProduct != FTDI_PID:
        return None
    sysfs = SYSFS_USB_ROOT / path_text
    try:
        vendor = _read_sysfs(sysfs, "idVendor").lower()
        product = _read_sysfs(sysfs, "idProduct").lower()
        if vendor != f"{FTDI_VID:04x}" or product != f"{FTDI_PID:04x}":
            return None
        return _read_sysfs(sysfs, "serial")
    except Refusal:
        # An unidentifiable peer is ineligible. If the actual target cannot be
        # identified, exact-match cardinality becomes zero and selection refuses.
        return None


class _NativeLibFtdi:
    """libftdi wrapper that enumerates without string-opening candidates."""
    def __init__(self, trace: _AttemptTrace | None = None):
        self._trace = trace
        if self._trace is not None:
            self._trace.phase = "LIBRARY_PROVENANCE"
        self._runtime = _load_approved_runtime()
        self._usb = self._runtime["libusb"].handle
        self._ftdi = self._runtime["libftdi"].handle
        if self._trace is not None:
            self._trace.advance("RUNTIME_READY")
        try:
            self._bind_functions()
            if self._trace is not None:
                self._trace.phase = "FTDI_CONTEXT_CREATE"
            self._ctx = self._ftdi.ftdi_new()
            if not self._ctx:
                raise Refusal("libftdi context allocation failed")
        except BaseException:
            for library in self._runtime.values():
                try:
                    os.close(library.fd)
                except OSError:
                    pass
            raise
        self._list = _FtdiDeviceListPtr()
        self._selected_dev = None
        self._candidate = None
        self._opened = False
        self._closed = False

    def _bind_functions(self) -> None:
        f = self._ftdi
        u = self._usb
        f.ftdi_new.restype = ctypes.c_void_p
        f.ftdi_new.argtypes = []
        f.ftdi_free.restype = None
        f.ftdi_free.argtypes = [ctypes.c_void_p]
        f.ftdi_usb_find_all.restype = ctypes.c_int
        f.ftdi_usb_find_all.argtypes = [ctypes.c_void_p,
                                        ctypes.POINTER(_FtdiDeviceListPtr),
                                        ctypes.c_int, ctypes.c_int]
        f.ftdi_list_free.restype = None
        f.ftdi_list_free.argtypes = [ctypes.POINTER(_FtdiDeviceListPtr)]
        f.ftdi_set_interface.restype = ctypes.c_int
        f.ftdi_set_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
        f.ftdi_usb_open_dev.restype = ctypes.c_int
        f.ftdi_usb_open_dev.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        f.ftdi_set_bitmode.restype = ctypes.c_int
        f.ftdi_set_bitmode.argtypes = [ctypes.c_void_p, ctypes.c_ubyte, ctypes.c_ubyte]
        f.ftdi_set_latency_timer.restype = ctypes.c_int
        f.ftdi_set_latency_timer.argtypes = [ctypes.c_void_p, ctypes.c_ubyte]
        f.ftdi_read_data_set_chunksize.restype = ctypes.c_int
        f.ftdi_read_data_set_chunksize.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        f.ftdi_write_data_set_chunksize.restype = ctypes.c_int
        f.ftdi_write_data_set_chunksize.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        f.ftdi_tcioflush.restype = ctypes.c_int
        f.ftdi_tcioflush.argtypes = [ctypes.c_void_p]
        f.ftdi_write_data.restype = ctypes.c_int
        f.ftdi_write_data.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        f.ftdi_read_data.restype = ctypes.c_int
        f.ftdi_read_data.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
        f.ftdi_usb_close.restype = ctypes.c_int
        f.ftdi_usb_close.argtypes = [ctypes.c_void_p]
        u.libusb_get_device_descriptor.restype = ctypes.c_int
        u.libusb_get_device_descriptor.argtypes = [ctypes.c_void_p, ctypes.POINTER(_UsbDeviceDescriptor)]
        u.libusb_get_bus_number.restype = ctypes.c_uint8
        u.libusb_get_bus_number.argtypes = [ctypes.c_void_p]
        u.libusb_get_port_numbers.restype = ctypes.c_int
        u.libusb_get_port_numbers.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int]

    def enumerate_candidates(self) -> tuple[topology.Candidate, ...]:
        trace = getattr(self, "_trace", None)
        if trace is not None:
            trace.phase = "DEVICE_ENUMERATION"
            trace.advance("ENUMERATING")
        count = self._ftdi.ftdi_usb_find_all(self._ctx, ctypes.byref(self._list), FTDI_VID, FTDI_PID)
        if trace is not None:
            trace.target_candidates = 0 if count >= 0 else "unknown"
            trace.code_override = None
        if count < 0:
            if trace is not None:
                trace.return_code = int(count)
            raise Refusal("libftdi descriptor enumeration failed")
        if count and not self._list:
            raise Refusal("libftdi enumeration count/list disagreement")
        candidates: list[topology.Candidate] = []
        node = self._list
        seen = 0
        while node and seen < count:
            current = node.contents
            dev = current.dev
            node = current.next
            seen += 1
            if not dev:
                continue
            descriptor = _UsbDeviceDescriptor()
            if self._usb.libusb_get_device_descriptor(dev, ctypes.byref(descriptor)) != 0:
                continue
            if descriptor.idVendor != FTDI_VID or descriptor.idProduct != FTDI_PID:
                continue
            bus = int(self._usb.libusb_get_bus_number(dev))
            ports = (ctypes.c_uint8 * 8)()
            port_count = self._usb.libusb_get_port_numbers(dev, ports, 8)
            if port_count <= 0 or port_count > 8:
                continue
            usb_path = _format_usb_path(bus, tuple(int(ports[i]) for i in range(port_count)))
            if trace is not None:
                trace.phase = "DEVICE_SELECTION"
            serial = _serial_for_candidate(usb_path, descriptor)
            if serial != USB_DESCRIPTOR_SERIAL:
                continue
            if trace is not None:
                trace.target_candidates = _bounded_candidate_count(
                    int(trace.target_candidates) + 1)
            # Count the exact USB-serial identity before applying the remaining
            # signed descriptor fields, so duplicate serials fail closed even
            # when they appear at different USB paths.
            identity = _identity_from_sysfs(usb_path, descriptor)
            candidates.append(topology.Candidate(identity, dev))
        if seen != count or node:
            raise Refusal("libftdi enumeration count/list disagreement")
        if trace is not None:
            trace.target_candidates = _bounded_candidate_count(len(candidates))
            if not candidates:
                trace.code_override = "NO_TARGET_CANDIDATE"
            elif len(candidates) > 1:
                trace.code_override = "MULTIPLE_TARGET_CANDIDATES"
        self._eligible_candidates = tuple(candidates)
        return self._eligible_candidates

    def open_exact(self, candidate: topology.Candidate) -> None:
        trace = getattr(self, "_trace", None)
        if trace is not None:
            trace.phase = "DEVICE_OPEN"
        eligible = getattr(self, "_eligible_candidates", ())
        if (not any(candidate is row for row in eligible) or
                candidate.handle_token is None):
            raise Refusal("attempt to substitute a non-selected FTDI candidate")
        if candidate.identity.interface != FTDI_INTERFACE_NAME:
            raise Refusal("selected FTDI channel differs from fixed interface A")
        # Channel A is selected before opening, and the exact libusb_device
        # pointer from the descriptor-only list is passed to libftdi.
        rc = self._ftdi.ftdi_set_interface(self._ctx, FTDI_INTERFACE_A)
        if rc != 0:
            if trace is not None:
                trace.return_code = int(rc)
            raise Refusal("libftdi interface A selection failed")
        rc = self._ftdi.ftdi_usb_open_dev(self._ctx, candidate.handle_token)
        if rc != 0:
            if trace is not None:
                trace.return_code = int(rc)
            raise Refusal("libftdi exact-device open failed")
        self._opened = True
        if trace is not None:
            trace.device_opened = 1
            trace.advance("DEVICE_OPENED")

    def initialize_mpsse(self) -> None:
        trace = getattr(self, "_trace", None)
        if trace is not None:
            trace.phase = "MPSSE_INIT"
        if not self._opened:
            raise Refusal("MPSSE initialization before exact-device open")
        operations = (
            (lambda: self._ftdi.ftdi_set_bitmode(self._ctx, GPIO_MASK, BITMODE_RESET), "FTDI reset bitmode"),
            (lambda: self._ftdi.ftdi_set_bitmode(self._ctx, GPIO_MASK, BITMODE_MPSSE), "FTDI MPSSE bitmode"),
            (lambda: self._ftdi.ftdi_set_latency_timer(self._ctx, LATENCY_MS), "FTDI latency"),
            (lambda: self._ftdi.ftdi_read_data_set_chunksize(self._ctx, IO_CHUNK_SIZE), "FTDI read chunk"),
            (lambda: self._ftdi.ftdi_write_data_set_chunksize(self._ctx, IO_CHUNK_SIZE), "FTDI write chunk"),
            (lambda: self._ftdi.ftdi_tcioflush(self._ctx), "FTDI transport flush"),
        )
        for operation, phase in operations:
            rc = operation()
            if rc < 0:
                if trace is not None:
                    trace.return_code = int(rc)
                raise Refusal(phase + " failed")
        self.write_exact(topology.MPSSE_SYNC)
        if self.read_exact(2) != topology.MPSSE_SYNC_REPLY:
            raise Refusal("MPSSE synchronization response mismatch")
        self.write_exact(topology.MPSSE_SETUP)
        if trace is not None:
            trace.advance("MPSSE_READY")

    def write_exact(self, data: bytes) -> None:
        if not self._opened or not data:
            raise Refusal("FTDI write outside open transport or empty command")
        offset = 0
        trace = getattr(self, "_trace", None)
        while offset < len(data):
            # FTDI API accepts a buffer and byte count; require complete writes.
            part = (ctypes.c_ubyte * (len(data) - offset)).from_buffer_copy(data[offset:])
            written = self._ftdi.ftdi_write_data(self._ctx, part, len(data) - offset)
            if written <= 0 or written > len(data) - offset:
                if trace is not None:
                    trace.return_code = int(written)
                raise Refusal("short or invalid FTDI write")
            if trace is not None and trace.phase in ("SCAN_A_WRITE", "SCAN_B_WRITE") and written > 0:
                before = _mpsse_tcks_in_prefix(data, offset)
                after = _mpsse_tcks_in_prefix(data, min(len(data), offset + written))
                attr = "scan_a_tck_emitted" if trace.phase == "SCAN_A_WRITE" else "scan_b_tck_emitted"
                setattr(trace, attr, getattr(trace, attr) + max(0, after - before))
            offset += written

    def read_exact(self, size: int) -> bytes:
        if not self._opened or not 1 <= size <= 64 * 1024:
            raise Refusal("FTDI read outside open transport or outside fixed bounds")
        received = bytearray()
        while len(received) < size:
            remaining = size - len(received)
            buf = (ctypes.c_ubyte * remaining)()
            count = self._ftdi.ftdi_read_data(self._ctx, buf, remaining)
            if count <= 0 or count > remaining:
                trace = getattr(self, "_trace", None)
                if trace is not None:
                    trace.return_code = int(count)
                raise Refusal("short or invalid FTDI read")
            received.extend(bytes(buf[:count]))
        return bytes(received)

    def close_checked(self) -> None:
        if self._closed:
            return
        self._closed = True
        failed = False
        trace = getattr(self, "_trace", None)
        if self._opened:
            rc = self._ftdi.ftdi_usb_close(self._ctx)
            failed = rc < 0
            if failed and trace is not None:
                trace.return_code = int(rc)
            self._opened = False
        if self._list:
            self._ftdi.ftdi_list_free(ctypes.byref(self._list))
            self._list = _FtdiDeviceListPtr()
        if self._ctx:
            self._ftdi.ftdi_free(self._ctx)
            self._ctx = None
        for library in self._runtime.values():
            try:
                os.close(library.fd)
            except OSError:
                pass
        if not failed and trace is not None:
            trace.transport_closed = 1
        if failed:
            raise Refusal("libftdi close failed")


_NATIVE_BACKEND_TYPE = _NativeLibFtdi


def _execute_scan(backend: Any, commands: tuple[topology.Command, ...], scan: str,
                  trace: _AttemptTrace | None = None) -> bytes:
    byte_result = None
    final_result = None
    if trace is not None:
        if scan == "A":
            trace.scan_a_started = 1
            trace.advance("SCAN_A_ACTIVE")
        else:
            trace.scan_b_started = 1
            trace.advance("SCAN_B_ACTIVE")
    for command in commands:
        if trace is not None:
            if scan == "A":
                detail_state = {
                    "TMS_NO_READ": ("SCAN_A_NAV_WRITE" if trace.scan_a_tck_emitted < 9
                                    else "SCAN_A_EXIT_WRITE"),
                    "DR_A_INOUT_BYTE_LSB": "SCAN_A_BULK_WRITE",
                    "DR_A_FINAL_BIT_EXIT": "SCAN_A_FINAL_WRITE",
                }[command.label]
            else:
                detail_state = {
                    "TMS_NO_READ": ("SCAN_B_NAV_WRITE" if trace.scan_b_tck_emitted < 4
                                    else "SCAN_B_EXIT_WRITE"),
                    "DR_B_INOUT_BYTE_LSB": "SCAN_B_BULK_WRITE",
                    "DR_B_FINAL_BIT_EXIT": "SCAN_B_FINAL_WRITE",
                }[command.label]
            trace.advance(detail_state)
        if trace is not None:
            trace.phase = f"SCAN_{scan}_WRITE"
        backend.write_exact(command.write)
        if trace is not None:
            attr = "scan_a_tck_emitted" if scan == "A" else "scan_b_tck_emitted"
            if not isinstance(backend, _NATIVE_BACKEND_TYPE):
                setattr(trace, attr, getattr(trace, attr) + command.tck_count)
        if command.read_bytes:
            if trace is not None:
                trace.phase = f"SCAN_{scan}_READ"
                trace.advance("SCAN_A_BULK_READ" if scan == "A" and
                              command.label == "DR_A_INOUT_BYTE_LSB" else
                              "SCAN_A_FINAL_READ" if scan == "A" else
                              "SCAN_B_BULK_READ" if command.label == "DR_B_INOUT_BYTE_LSB" else
                              "SCAN_B_FINAL_READ")
            data = backend.read_exact(command.read_bytes)
            if not isinstance(data, bytes) or len(data) != command.read_bytes:
                raise Refusal("fixed scan returned a short/oversized FTDI read")
            if command.label == f"DR_{scan}_INOUT_BYTE_LSB":
                byte_result = data
            elif command.label == f"DR_{scan}_FINAL_BIT_EXIT":
                final_result = data
            else:
                raise Refusal("unexpected read point in fixed scan command plan")
    if byte_result is None or final_result is None:
        raise Refusal("fixed scan omitted a required TDO read")
    if trace is not None:
        trace.advance("SCAN_A_COMPLETE" if scan == "A" else "SCAN_B_COMPLETE")
    return byte_result + final_result


def _run_consumed_permit(permit: topology.DiscoveryPermit,
                          trace: _AttemptTrace | None = None,
                          request_raw: bytes | None = None) -> TransportObservation:
    if not isinstance(permit, topology.DiscoveryPermit) or type(request_raw) is not bytes:
        raise Refusal("physical transport requires a signed one-shot request")
    try:
        import phk2_fk0957_remote_topology_endpoint as endpoint
        if not endpoint.supervisor_capability_valid():
            raise Refusal("physical transport requires protected supervisor capability")
        issuers = endpoint._load_trust_config()
        context, _authorization_bytes, _authorization_id = endpoint._validate_request(request_raw, issuers)
        if (permit.descriptor_evidence_sha256 != context["descriptor_sha256"] or
                permit.nonce != context["permit_nonce"] or
                permit.authorization_id != context["authorization_id"]):
            raise Refusal("release authorization descriptor/nonce does not match permit")
        with topology._PERMIT_LOCK:
            active = topology._ACTIVE.get(permit._token)
            binding = (permit.descriptor_evidence_sha256, permit.identity, permit.nonce,
                       permit.issued_at, permit.expires_at, permit.trusted_signer_fingerprint,
                       permit.authorization_id)
            if active != binding or permit._token in topology._CONSUMED:
                raise Refusal("release authorization permit is not the original active token")
        # When launched through the protected root supervisor, the supervisor
        # consumes this exact signed authorization before creating the child
        # and supplies an inherited root-peer Unix socket capability. Direct
        # Python callers cannot fabricate that kernel peer credential.
        # The supervisor consumed this authorization before child launch.
    except Refusal:
        raise
    except Exception:
        raise Refusal("remote release authorization validation failed") from None
    # Keep the exact permit object issued from this signed request. Reissuing a
    # descriptor permit here would create a second token and disconnect result
    # validation from the token that passed the authorization gate.
    with topology._PERMIT_LOCK:
        active = topology._ACTIVE.get(permit._token)
        binding = (permit.descriptor_evidence_sha256, permit.identity, permit.nonce,
                   permit.issued_at, permit.expires_at, permit.trusted_signer_fingerprint,
                   permit.authorization_id)
        if active != binding or permit._token in topology._CONSUMED:
            raise Refusal("release authorization permit identity changed before consume")
    topology._consume(permit)
    if trace is not None:
        trace.permit_consumed = 1
        trace.advance("PERMIT_VALIDATED")
        trace.phase = "LIBRARY_PROVENANCE"
    # Always derive source identity here, immediately before native backend
    # construction. No caller-supplied digest can defer a mismatch until after
    # device access.
    source_sha = transport_source_sha256()
    backend = _NativeLibFtdi(trace)
    opened = False
    closed = False
    result = None
    failure: BaseException | None = None
    failure_phase = None
    selected_identity = None
    try:
        if trace is not None:
            trace.phase = "PRELIVE_VALIDATION"
        plan = topology.build_plan()
        if (plan.scan_a_tck_count, plan.scan_b_tck_count, plan.tck_count) != (
            EXPECTED_SCAN_A_TCK, EXPECTED_SCAN_B_TCK, EXPECTED_TOTAL_TCK):
            raise Refusal("fixed audited transaction count changed")
        if (plan.transaction_sha256 != GOLDEN_PLAN_SHA256 or
            plan.command_contract_sha256 != GOLDEN_COMMAND_CONTRACT_SHA256 or
            topology.MPSSE_SYNC != bytes.fromhex("aa") or
            topology.MPSSE_SYNC_REPLY != bytes.fromhex("fa aa") or
            topology.scan_transaction_sha256(plan.scan_a_commands) != GOLDEN_SCAN_A_SHA256 or
            topology.scan_transaction_sha256(plan.scan_b_commands) != GOLDEN_SCAN_B_SHA256 or
            hashlib.sha256(bytes(plan.tms_bits)).hexdigest() != GOLDEN_TMS_SHA256 or
            hashlib.sha256(bytes(plan.tdi_bits)).hexdigest() != GOLDEN_TDI_SHA256 or
            hashlib.sha256(bytes(plan.tdi_scans[0])).hexdigest() != GOLDEN_TDI_A_SHA256 or
            hashlib.sha256(bytes(plan.tdi_scans[1])).hexdigest() != GOLDEN_TDI_B_SHA256 or
            topology.MPSSE_SETUP != bytes.fromhex("97 8a 86 2b 01 85 80 08 0b")):
            raise Refusal("fixed audited transaction bytes changed")
        if trace is not None:
            trace.phase = "DEVICE_ENUMERATION"
            trace.advance("ENUMERATING")
        candidates = backend.enumerate_candidates()
        if trace is not None:
            trace.target_candidates = _bounded_candidate_count(len(candidates))
            trace.code_override = ("NO_TARGET_CANDIDATE" if len(candidates) == 0 else
                                   "MULTIPLE_TARGET_CANDIDATES" if len(candidates) > 1 else None)
            trace.phase = "DEVICE_SELECTION"
        selected = topology.validate_candidates(permit, candidates)
        selected_identity = selected.identity
        if trace is not None:
            trace.advance("DEVICE_SELECTED")
            trace.phase = "DEVICE_OPEN"
        backend.open_exact(selected)
        opened = True
        if trace is not None:
            trace.device_opened = 1
            trace.advance("DEVICE_OPENED")
            trace.phase = "MPSSE_INIT"
        backend.initialize_mpsse()
        if trace is not None:
            trace.advance("MPSSE_READY")
        raw_a = _execute_scan(backend, plan.scan_a_commands, "A", trace)
        raw_b = _execute_scan(backend, plan.scan_b_commands, "B", trace)
    except BaseException as exc:
        failure = exc
        failure_phase = trace.phase if trace is not None else None
    try:
        if trace is not None:
            trace.phase = "TRANSPORT_CLOSE"
            trace.begin_close()
        backend.close_checked()
        closed = True
        if trace is not None:
            trace.transport_closed = 1
            trace.finish_close()
    except BaseException as exc:
        if failure is None:
            failure = exc
            failure_phase = "TRANSPORT_CLOSE"
    if failure is not None:
        if trace is not None and failure_phase is not None:
            trace.phase = failure_phase
        if isinstance(failure, Refusal):
            raise failure
        raise Refusal("fixed topology transport failed; permit consumed and adapter closed") from failure
    if not opened or not closed or selected_identity is None:
        raise Refusal("transport lifecycle did not complete")
    if trace is not None:
        trace.phase = "LIBRARY_PROVENANCE"
    if transport_source_sha256() != source_sha:
        raise Refusal("transport source/native library bytes changed during operation")
    runtime = getattr(backend, "_runtime", None)
    if not isinstance(runtime, dict):
        raise Refusal("transport omitted approved loaded-library provenance")
    proof = object()
    runtime_provenance = tuple(
        (name, str(item.pin.path), item.pin.sha256, item.pin.build_id, item.pin.soname,
         item.pre_stat, item.post_stat, item.realpath)
        for name, item in runtime.items())
    result = TransportObservation(
        CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL, FTDI_INTERFACE_NAME,
        selected_identity.usb_path, f"{FTDI_VID:04x}", f"{FTDI_PID:04x}",
        selected_identity.manufacturer, selected_identity.product,
        permit.descriptor_evidence_sha256, permit.nonce,
        permit.authorization_id,
        topology.scan_transaction_sha256(plan.scan_a_commands), plan.scan_a_tck_count, raw_a,
        topology.scan_transaction_sha256(plan.scan_b_commands), plan.scan_b_tck_count, raw_b,
        plan.tck_count, source_sha, *_production_git_state(), runtime_provenance,
        1, 1, False, 0, 0, 0, proof)
    with _RESULT_LOCK:
        _SEALED_RESULTS[proof] = hashlib.sha256(_observation_payload(result)).hexdigest()
    return result


def run_fk0957_topology_discovery(authorized_permit: topology.DiscoveryPermit) -> TransportObservation:
    """Run exactly the reviewed two-scan topology census; accepts no overrides."""
    trace = _AttemptTrace()
    try:
        trace.phase = "PERMIT_VALIDATION"
        if not isinstance(authorized_permit, topology.DiscoveryPermit):
            raise Refusal("topology operation requires a verified release permit")
        with _REMOTE_AUTH_LOCK:
            request_raw = _REMOTE_AUTHORIZED_PERMITS.pop(authorized_permit._token, None)
        if request_raw is None:
            raise Refusal("topology operation requires authenticated release authorization")
        return _run_consumed_permit(authorized_permit, trace=trace, request_raw=request_raw)
    except BaseException as exc:
        with topology._PERMIT_LOCK:
            if isinstance(authorized_permit, topology.DiscoveryPermit):
                if authorized_permit._token in topology._CONSUMED:
                    trace.permit_consumed = 1
                elif authorized_permit._token in topology._ACTIVE:
                    trace.permit_consumed = 0
        raise _diagnostic_refusal(exc, trace) from None


def issue_fk0957_topology_permit(descriptor_evidence: bytes, expected_sha256: str,
                                  *, lifetime_seconds: int = 120,
                                  nonce: str | None = None,
                                  authorization_id: str | None = None) -> topology.DiscoveryPermit:
    """Verify the signed descriptor and issue its one-use topology permit."""
    trace = _AttemptTrace()
    trace.phase = "PERMIT_VALIDATION"
    trace.permit_consumed = 0
    try:
        return topology.issue_permit(descriptor_evidence, expected_sha256,
                                     lifetime_seconds=lifetime_seconds, nonce=nonce,
                                     authorization_id=authorization_id)
    except BaseException as exc:
        if isinstance(exc, identity_gate.Refusal):
            code, phase = "DESCRIPTOR_STALE", "PERMIT_VALIDATION"
        elif isinstance(exc, topology.Refusal):
            code, phase = "PERMIT_INVALID", "PERMIT_VALIDATION"
        else:
            code, phase = "INTERNAL_REFUSAL", "INTERNAL_REFUSAL"
        raise _diagnostic_refusal(exc, trace, code=code, phase=phase) from None


def _authorize_remote_permit(permit: topology.DiscoveryPermit, *, request_raw: bytes | None = None,
                             **untrusted_digests: Any) -> None:
    """Bind a permit only inside the protected supervisor-launched endpoint.

    Raw caller-supplied digests are not authority. This internal transport
    gate independently verifies the signed release request, handoff, target,
    manifest and freshness. The root supervisor has consumed the authorization
    ledger before launching this process and supplies the kernel peer capability.
    """
    if (not isinstance(permit, topology.DiscoveryPermit) or type(request_raw) is not bytes or
            untrusted_digests):
        raise Refusal("remote release authorization context is invalid")
    try:
        import phk2_fk0957_remote_topology_endpoint as endpoint
        if not endpoint.supervisor_capability_valid():
            raise Refusal("remote authorization requires protected supervisor capability")
        issuers = endpoint._load_trust_config()
        context, _, _ = endpoint._validate_request(request_raw, issuers)
        if (permit.descriptor_evidence_sha256 != context["descriptor_sha256"] or
                permit.nonce != context["permit_nonce"] or
                permit.authorization_id != context["authorization_id"]):
            raise Refusal("release authorization descriptor/nonce does not match permit")
        with topology._PERMIT_LOCK:
            active = topology._ACTIVE.get(permit._token)
            binding = (permit.descriptor_evidence_sha256, permit.identity, permit.nonce,
                       permit.issued_at, permit.expires_at, permit.trusted_signer_fingerprint,
                       permit.authorization_id)
            if active != binding or permit._token in topology._CONSUMED:
                raise Refusal("release authorization permit is not the original active token")
    except Refusal:
        raise
    except Exception:
        raise Refusal("remote release authorization validation failed") from None
    with _REMOTE_AUTH_LOCK:
        if permit._token in _REMOTE_AUTHORIZED_PERMITS:
            raise Refusal("remote release authorization context was already attached")
        _REMOTE_AUTHORIZED_PERMITS[permit._token] = request_raw


def _validate_transport_observation(permit: topology.DiscoveryPermit,
                                    result: TransportObservation) -> topology.ParsedTopology:
    if not isinstance(result, TransportObservation):
        raise Refusal("transport result type is not trusted")
    with _RESULT_LOCK:
        expected_proof = _SEALED_RESULTS.get(result._proof)
    if expected_proof is None or expected_proof != hashlib.sha256(_observation_payload(result)).hexdigest():
        raise Refusal("transport observation was not internally generated or was altered")
    plan = topology.build_plan()
    exact = (result.card_id, result.adapter_serial, result.usb_descriptor_serial,
             result.physical_interface, result.ftdi_vid, result.ftdi_pid,
             result.descriptor_evidence_sha256, result.permit_nonce, result.authorization_id,
             result.scan_a_transaction_sha256, result.scan_a_tck_count,
             result.scan_b_transaction_sha256, result.scan_b_tck_count,
             result.total_tck_count, result.transport_source_sha256,
             result.production_git_head, result.worktree_clean,
             result.runtime_library_provenance,
             result.matched_device_count, result.opened_device_count, result.second_device_opened,
             result.write_count, result.reset_count, result.program_count)
    expected = (CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL, "A", "0403", "6010",
                permit.descriptor_evidence_sha256, permit.nonce, permit.authorization_id,
                topology.scan_transaction_sha256(plan.scan_a_commands), 591,
                topology.scan_transaction_sha256(plan.scan_b_commands), 586,
                1177, transport_source_sha256(), *_production_git_state(),
                result.runtime_library_provenance,
                1, 1, False, 0, 0, 0)
    if exact != expected:
        raise Refusal("transport result binding, transaction, count, or mutation counter mismatch")
    expected_runtime = tuple(
        (pin.name, str(pin.path), pin.sha256, pin.build_id, pin.soname, None, None, str(pin.path))
        for pin in LIBRARY_PINS)
    if (len(result.runtime_library_provenance) != len(expected_runtime) or
        any((row[0], row[1], row[2], row[3], row[4], row[7]) !=
            (expected_runtime[i][0], expected_runtime[i][1], expected_runtime[i][2],
             expected_runtime[i][3], expected_runtime[i][4], expected_runtime[i][7]) or
            row[5] != row[6] or not isinstance(row[5], tuple) or len(row[5]) != 9
            for i, row in enumerate(result.runtime_library_provenance))):
        raise Refusal("loaded runtime library provenance is missing or inconsistent")
    with topology._PERMIT_LOCK:
        active_binding = topology._ACTIVE.get(permit._token)
        supplied_binding = (permit.descriptor_evidence_sha256, permit.identity, permit.nonce,
                            permit.issued_at, permit.expires_at,
                            permit.trusted_signer_fingerprint, permit.authorization_id)
        if (active_binding is None or active_binding != supplied_binding or
            permit._token not in topology._CONSUMED):
            raise Refusal("transport result lacks the original consumed descriptor permit")
    with _RESULT_LOCK:
        if permit._token in _SIGNED_PERMITS:
            raise Refusal("transport result permit was already signed")
    if topology._now() > datetime.fromisoformat(permit.expires_at):
        raise Refusal("descriptor-bound permit expired before local validation")
    bits_a = topology.raw_tdo_bits(result.scan_a_raw_tdo[:-1], result.scan_a_raw_tdo[-1:])
    bits_b = topology.raw_tdo_bits(result.scan_b_raw_tdo[:-1], result.scan_b_raw_tdo[-1:])
    parsed = topology.parse_raw_tdo(bits_a, bits_b, plan.tdi_scans[0], plan.tdi_scans[1])
    if parsed.status != "PARSED_RESET_DEFAULT_DR":
        raise Refusal("topology response is ambiguous or inconclusive")
    return parsed


def validate_transport_observation(permit: topology.DiscoveryPermit,
                                   result: TransportObservation) -> topology.ParsedTopology:
    trace = _AttemptTrace()
    trace.phase = "LOCAL_VALIDATION"
    trace.permit_consumed = _permit_consumption_state(permit)
    _trace_from_sealed_result(trace, result)
    try:
        parsed = _validate_transport_observation(permit, result)
        trace.advance("LOCAL_VALIDATED")
        return parsed
    except BaseException as exc:
        raise _diagnostic_refusal(exc, trace) from None
