"""Narrow FK0957 reset-default DR transport and local record gate.

The public transport operation accepts only a previously verified one-use
descriptor permit. Tests replace the private native-backend factory; no CLI,
network path, generic scan API, or caller-provided transaction exists.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import threading
from typing import Any

import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_orchestrator as orchestrator
import phk2_fk0957_topology_discovery as topology

CARD_ID = "FK0957"
ADAPTER_SERIAL = "153300000957A"
USB_DESCRIPTOR_SERIAL = "153300000957"
FTDI_VID = 0x0403
FTDI_PID = 0x6010
FTDI_INTERFACE_A = 1
FTDI_INTERFACE_NAME = "A"
SYSFS_USB_ROOT = Path("/sys/bus/usb/devices")
LIBFTDI_PATH = Path("/lib/x86_64-linux-gnu/libftdi1.so.2")
LIBUSB_PATH = Path("/lib/x86_64-linux-gnu/libusb-1.0.so.0")
LOCAL_SIGNING_KEY_PATH = Path(
    "/home/rmann/.local/share/sidecar/operator-keys/phk2-fk0957-evidence-20261111/"
    "phk2_fk0957_physical_evidence_ed25519_private.pem")
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


class Refusal(ValueError):
    pass


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
    scan_a_transaction_sha256: str
    scan_a_tck_count: int
    scan_a_raw_tdo: bytes
    scan_b_transaction_sha256: str
    scan_b_tck_count: int
    scan_b_raw_tdo: bytes
    total_tck_count: int
    transport_source_sha256: str
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
    return orchestrator.canonical(obj)


def _require_native_files() -> tuple[Path, Path]:
    paths = (LIBFTDI_PATH.resolve(strict=True), LIBUSB_PATH.resolve(strict=True))
    for path in paths:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > 100 * 1024 * 1024:
            raise Refusal("native FTDI transport library is not a bounded regular file")
    return paths


def transport_source_sha256() -> str:
    """Hash reviewed adapter/discovery sources plus the exact native libraries."""
    repo = Path(__file__).resolve().parents[2]
    source_files = (
        Path(__file__).resolve(),
        (repo / "tools/phk2_host/phk2_fk0957_topology_discovery.py").resolve(strict=True),
        (repo / "tools/phk2_host/phk2_fk0957_idcode_gate.py").resolve(strict=True),
        (repo / "tools/phk2_host/phk2_fk0957_remote_orchestrator.py").resolve(strict=True),
        (repo / "tools/phk1_raw_bscan/libftdi_io.cpp").resolve(strict=True),
        (repo / "tools/phk1_raw_bscan/mpsse_backend.cpp").resolve(strict=True),
        (repo / "tools/phk1_raw_bscan/usb_selection.cpp").resolve(strict=True),
        *_require_native_files(),
    )
    digest = hashlib.sha256()
    for path in source_files:
        st = path.stat()
        if not stat.S_ISREG(st.st_mode) or st.st_size > 100 * 1024 * 1024:
            raise Refusal("transport source input is not a bounded regular file")
        raw = path.read_bytes()
        digest.update(str(path).encode("utf-8") + b"\0")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


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
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise Refusal("sysfs descriptor is not UTF-8") from exc
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


class _NativeLibFtdi:
    """libftdi wrapper that enumerates without string-opening candidates."""
    def __init__(self):
        libftdi_path, libusb_path = _require_native_files()
        try:
            self._usb = ctypes.CDLL(str(libusb_path), mode=ctypes.RTLD_LOCAL)
            self._ftdi = ctypes.CDLL(str(libftdi_path), mode=ctypes.RTLD_LOCAL)
        except OSError as exc:
            raise Refusal("pinned native FTDI libraries could not be loaded") from exc
        self._bind_functions()
        self._ctx = self._ftdi.ftdi_new()
        if not self._ctx:
            raise Refusal("libftdi context allocation failed")
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
        count = self._ftdi.ftdi_usb_find_all(self._ctx, ctypes.byref(self._list), FTDI_VID, FTDI_PID)
        if count < 0:
            raise Refusal("libftdi descriptor enumeration failed")
        if count == 0:
            raise Refusal("no approved FTDI candidate found")
        # A second 0403:6010 device is a fail-closed ambiguity. Do not read its
        # strings and do not open it; enumeration is descriptor-only.
        if count != 1:
            raise Refusal("multiple FTDI devices present; refusing peer/second-device ambiguity")
        if not self._list:
            raise Refusal("libftdi enumeration count/list disagreement")
        node = self._list.contents
        if node.next:
            raise Refusal("libftdi enumeration count/list disagreement")
        dev = node.dev
        descriptor = _UsbDeviceDescriptor()
        if not dev or self._usb.libusb_get_device_descriptor(dev, ctypes.byref(descriptor)) != 0:
            raise Refusal("selected libusb descriptor unavailable")
        bus = int(self._usb.libusb_get_bus_number(dev))
        ports = (ctypes.c_uint8 * 8)()
        port_count = self._usb.libusb_get_port_numbers(dev, ports, 8)
        if port_count <= 0 or port_count > 8:
            raise Refusal("selected libusb topology path unavailable")
        usb_path = _format_usb_path(bus, tuple(int(ports[i]) for i in range(port_count)))
        identity = _identity_from_sysfs(usb_path, descriptor)
        candidate = topology.Candidate(identity, object())
        self._candidate = candidate
        self._selected_dev = dev
        return (candidate,)

    def open_exact(self, candidate: topology.Candidate) -> None:
        if candidate is not self._candidate or candidate.handle_token is None or not self._selected_dev:
            raise Refusal("attempt to substitute a non-selected FTDI candidate")
        if candidate.identity.interface != FTDI_INTERFACE_NAME:
            raise Refusal("selected FTDI channel differs from fixed interface A")
        # Channel A is selected before opening, and the exact libusb_device
        # pointer from the descriptor-only list is passed to libftdi.
        if self._ftdi.ftdi_set_interface(self._ctx, FTDI_INTERFACE_A) != 0:
            raise Refusal("libftdi interface A selection failed")
        if self._ftdi.ftdi_usb_open_dev(self._ctx, self._selected_dev) != 0:
            raise Refusal("libftdi exact-device open failed")
        self._opened = True

    def initialize_mpsse(self) -> None:
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
                raise Refusal(phase + " failed")
        self.write_exact(topology.MPSSE_SYNC)
        if self.read_exact(2) != topology.MPSSE_SYNC_REPLY:
            raise Refusal("MPSSE synchronization response mismatch")
        self.write_exact(topology.MPSSE_SETUP)

    def write_exact(self, data: bytes) -> None:
        if not self._opened or not data:
            raise Refusal("FTDI write outside open transport or empty command")
        offset = 0
        while offset < len(data):
            # FTDI API accepts a buffer and byte count; require complete writes.
            part = (ctypes.c_ubyte * (len(data) - offset)).from_buffer_copy(data[offset:])
            written = self._ftdi.ftdi_write_data(self._ctx, part, len(data) - offset)
            if written <= 0 or written > len(data) - offset:
                raise Refusal("short or invalid FTDI write")
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
                raise Refusal("short or invalid FTDI read")
            received.extend(bytes(buf[:count]))
        return bytes(received)

    def close_checked(self) -> None:
        if self._closed:
            return
        self._closed = True
        failed = False
        if self._opened:
            failed = self._ftdi.ftdi_usb_close(self._ctx) < 0
            self._opened = False
        if self._list:
            self._ftdi.ftdi_list_free(ctypes.byref(self._list))
            self._list = _FtdiDeviceListPtr()
        if self._ctx:
            self._ftdi.ftdi_free(self._ctx)
            self._ctx = None
        if failed:
            raise Refusal("libftdi close failed")


def _execute_scan(backend: Any, commands: tuple[topology.Command, ...], scan: str) -> bytes:
    byte_result = None
    final_result = None
    for command in commands:
        backend.write_exact(command.write)
        if command.read_bytes:
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
    return byte_result + final_result


def _make_observation(permit: topology.DiscoveryPermit, identity: topology.DescriptorIdentity,
                      raw_a: bytes, raw_b: bytes, plan: topology.DiscoveryPlan,
                      source_sha256: str) -> TransportObservation:
    proof = object()
    result = TransportObservation(
        CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL, FTDI_INTERFACE_NAME, identity.usb_path,
        f"{FTDI_VID:04x}", f"{FTDI_PID:04x}", identity.manufacturer, identity.product,
        permit.descriptor_evidence_sha256, permit.nonce,
        topology.scan_transaction_sha256(plan.scan_a_commands), plan.scan_a_tck_count, raw_a,
        topology.scan_transaction_sha256(plan.scan_b_commands), plan.scan_b_tck_count, raw_b,
        plan.tck_count, source_sha256, 1, 1, False, 0, 0, 0, proof)
    with _RESULT_LOCK:
        _SEALED_RESULTS[proof] = hashlib.sha256(_observation_payload(result)).hexdigest()
    return result


def _run_consumed_permit(permit: topology.DiscoveryPermit, backend: Any,
                          source_sha256_before: str | None = None) -> TransportObservation:
    opened = False
    closed = False
    result = None
    failure: BaseException | None = None
    selected_identity = None
    source_sha = source_sha256_before or transport_source_sha256()
    try:
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
        candidates = backend.enumerate_candidates()
        selected = topology.validate_candidates(permit, candidates)
        selected_identity = selected.identity
        backend.open_exact(selected)
        opened = True
        backend.initialize_mpsse()
        raw_a = _execute_scan(backend, plan.scan_a_commands, "A")
        raw_b = _execute_scan(backend, plan.scan_b_commands, "B")
    except BaseException as exc:
        failure = exc
    try:
        backend.close_checked()
        closed = True
    except BaseException as exc:
        if failure is None:
            failure = exc
    if failure is not None:
        if isinstance(failure, Refusal):
            raise failure
        raise Refusal("fixed topology transport failed; permit consumed and adapter closed") from failure
    if not opened or not closed or selected_identity is None:
        raise Refusal("transport lifecycle did not complete")
    if transport_source_sha256() != source_sha:
        raise Refusal("transport source/native library bytes changed during operation")
    result = _make_observation(permit, selected_identity, raw_a, raw_b, plan, source_sha)
    return result


def _run_with_backend(permit: topology.DiscoveryPermit, backend: Any) -> TransportObservation:
    topology._consume(permit)
    return _run_consumed_permit(permit, backend)


def run_fk0957_topology_discovery(authorized_permit: topology.DiscoveryPermit) -> TransportObservation:
    """Run exactly the reviewed two-scan topology census; accepts no overrides."""
    topology._consume(authorized_permit)
    source_sha = transport_source_sha256()
    backend = _NativeLibFtdi()
    return _run_consumed_permit(authorized_permit, backend, source_sha)


def validate_transport_observation(permit: topology.DiscoveryPermit,
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
             result.descriptor_evidence_sha256, result.permit_nonce,
             result.scan_a_transaction_sha256, result.scan_a_tck_count,
             result.scan_b_transaction_sha256, result.scan_b_tck_count,
             result.total_tck_count, result.transport_source_sha256,
             result.matched_device_count, result.opened_device_count, result.second_device_opened,
             result.write_count, result.reset_count, result.program_count)
    expected = (CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL, "A", "0403", "6010",
                permit.descriptor_evidence_sha256, permit.nonce,
                topology.scan_transaction_sha256(plan.scan_a_commands), 591,
                topology.scan_transaction_sha256(plan.scan_b_commands), 586,
                1177, transport_source_sha256(), 1, 1, False, 0, 0, 0)
    if exact != expected:
        raise Refusal("transport result binding, transaction, count, or mutation counter mismatch")
    if (permit._token not in topology._ACTIVE or permit._token not in topology._CONSUMED or
        permit._token in _SIGNED_PERMITS):
        raise Refusal("transport result lacks a live, unused authorized permit")
    if topology._now() > datetime.fromisoformat(permit.expires_at):
        raise Refusal("descriptor-bound permit expired before local validation")
    bits_a = topology.raw_tdo_bits(result.scan_a_raw_tdo[:-1], result.scan_a_raw_tdo[-1:])
    bits_b = topology.raw_tdo_bits(result.scan_b_raw_tdo[:-1], result.scan_b_raw_tdo[-1:])
    parsed = topology.parse_raw_tdo(bits_a, bits_b, plan.tdi_scans[0], plan.tdi_scans[1])
    if parsed.status != "PARSED_RESET_DEFAULT_DR":
        raise Refusal("topology response is ambiguous or inconclusive")
    return parsed


def _read_local_private_key(path: Path) -> bytes:
    parent_fd, name = orchestrator._open_path_parent(path)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(name, flags, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != 0o600):
                raise Refusal("local signing key must be regular, mode 0600, and single-link")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(16 * 1024 + 1)
                if len(raw) > 16 * 1024:
                    raise Refusal("local signing key file exceeds the bounded PEM size")
                return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def sign_local_discovery_record(permit: topology.DiscoveryPermit,
                                result: TransportObservation) -> dict[str, Any]:
    """Validate the complete raw observation, then sign locally on RGB only."""
    parsed = validate_transport_observation(permit, result)
    with _RESULT_LOCK:
        if permit._token in _SIGNED_PERMITS:
            raise Refusal("local topology record already signed for this permit")
        _SIGNED_PERMITS.add(permit._token)
    record = {
        "schema": "fk0957-topology-discovery-record-v1",
        "topology_discovery_only": True,
        "idcode_qualification_pass": False,
        "fpga_dna_observed": False,
        "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False,
        "card_id": result.card_id,
        "adapter_serial": result.adapter_serial,
        "usb_descriptor_serial": result.usb_descriptor_serial,
        "physical_interface": result.physical_interface,
        "descriptor_evidence_sha256": result.descriptor_evidence_sha256,
        "permit_nonce": result.permit_nonce,
        "permit_issued_at": permit.issued_at,
        "permit_expires_at": permit.expires_at,
        "observation_timestamp": datetime.now(timezone.utc).isoformat(),
        "usb_path": result.usb_path,
        "ftdi_vid": result.ftdi_vid,
        "ftdi_pid": result.ftdi_pid,
        "manufacturer": result.manufacturer,
        "product": result.product,
        "trusted_signer_fingerprint": permit.trusted_signer_fingerprint,
        "transport_source_sha256": result.transport_source_sha256,
        "scan_a_transaction_sha256": result.scan_a_transaction_sha256,
        "scan_a_tck_count": result.scan_a_tck_count,
        "scan_a_raw_tdo_hex": result.scan_a_raw_tdo.hex(),
        "scan_b_transaction_sha256": result.scan_b_transaction_sha256,
        "scan_b_tck_count": result.scan_b_tck_count,
        "scan_b_raw_tdo_hex": result.scan_b_raw_tdo.hex(),
        "total_tck_count": result.total_tck_count,
        "matched_device_count": result.matched_device_count,
        "opened_device_count": result.opened_device_count,
        "second_device_opened": result.second_device_opened,
        "aggregate_dr_length": parsed.aggregate_dr_length,
        "observed_taps_tdo_to_tdi": parsed.taps_tdo_to_tdi,
        "raw_tdo_scan_a_bits_lsb_first": parsed.raw_tdo_scan_a_bits,
        "raw_tdo_scan_b_bits_lsb_first": parsed.raw_tdo_scan_b_bits,
        "write_count": 0,
        "reset_count": 0,
        "program_count": 0,
    }
    raw_key = _read_local_private_key(LOCAL_SIGNING_KEY_PATH)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = serialization.load_pem_private_key(raw_key, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("not Ed25519")
        public_der = key.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        signer_fingerprint = hashlib.sha256(public_der).hexdigest()
        if signer_fingerprint != permit.trusted_signer_fingerprint:
            raise Refusal("local key does not match trusted descriptor signer")
        payload_bytes = orchestrator.canonical(record)
        signature = key.sign(payload_bytes)
        identity_gate._trusted_signer().verify(signature, payload_bytes)
    except Refusal:
        raise
    except Exception as exc:
        raise Refusal("local topology record signing or verification failed") from exc
    return {"payload": record, "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "signature_algorithm": "Ed25519", "signature_hex": signature.hex(),
            "signer_fingerprint": permit.trusted_signer_fingerprint}

