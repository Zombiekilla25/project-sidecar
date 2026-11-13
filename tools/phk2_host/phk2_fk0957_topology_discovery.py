"""Offline-only design for a descriptor-bound FK0957 reset-DR census.

There is intentionally no production USB/FTDI adapter or executable entry
point in this module.  The private transport seam exists only for mocks.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import threading
from pathlib import Path
from typing import Any, Iterable

import phk2_fk0957_idcode_gate as identity_gate

CARD_ID = "FK0957"
ADAPTER_SERIAL = "153300000957A"
USB_DESCRIPTOR_SERIAL = "153300000957"
VID = "0403"
PID = "6010"
MANUFACTURER = "Xilinx"
PRODUCT = "SQRL FK"
INTERFACE = "A"
TCK_IDLE = "LOW"
TDI_CHANGE_EDGE = "FALLING"
TDO_SAMPLE_EDGE = "RISING"
BIT_ORDER = "LSB_FIRST"
MAX_DEFAULT_DR_BITS = 512
DELAY_CONFIRM_BITS = 64
DEBRUIJN_ORDER = 10
CAPTURE_BITS = MAX_DEFAULT_DR_BITS + DELAY_CONFIRM_BITS + 1  # 577; final bit exits Shift-DR
MPSSE_SETUP = bytes.fromhex("97 8a 86 2b 01 85 80 08 0b")  # 100 kHz, TCK low, TDI low, TMS high
MPSSE_SYNC = bytes.fromhex("aa")
MPSSE_SYNC_REPLY = bytes.fromhex("fa aa")
IDLE_HIGH_CLAIM_CLASS = "MISTAKEN_GENERALIZATION_FROM_NONMATCHING_EDGE_OR_TRANSPORT CONTEXT"

_PERMIT_LOCK = threading.Lock()
_ACTIVE: dict[object, tuple[Any, ...]] = {}
_CONSUMED: set[object] = set()
_RESULTS: set[object] = set()
_COMPLETED: dict[object, "ParsedTopology"] = {}


class Refusal(ValueError):
    pass


@dataclass(frozen=True)
class DescriptorIdentity:
    card_id: str
    adapter_serial: str
    usb_descriptor_serial: str
    usb_path: str
    vid: str
    pid: str
    manufacturer: str
    product: str
    interface: str


@dataclass(frozen=True)
class Candidate:
    identity: DescriptorIdentity
    handle_token: Any


@dataclass(frozen=True)
class DiscoveryPermit:
    descriptor_evidence_sha256: str
    identity: DescriptorIdentity
    nonce: str
    issued_at: str
    expires_at: str
    trusted_signer_fingerprint: str
    _token: Any


@dataclass(frozen=True)
class Command:
    write: bytes
    read_bytes: int = 0
    tck_count: int = 0
    label: str = ""
    scan: str | None = None


@dataclass(frozen=True)
class DiscoveryPlan:
    commands: tuple[Command, ...]
    scan_a_commands: tuple[Command, ...]
    scan_b_commands: tuple[Command, ...]
    tdi_scans: tuple[tuple[int, ...], tuple[int, ...]]
    tms_bits: tuple[int, ...]
    tdi_bits: tuple[int, ...]
    scan_a_tck_count: int
    scan_b_tck_count: int
    tck_count: int
    transaction_sha256: str
    command_contract_sha256: str


@dataclass(frozen=True)
class ParsedTopology:
    raw_tdo_scan_a_bits: str
    raw_tdo_scan_a_packed_hex: str
    raw_tdo_scan_b_bits: str
    raw_tdo_scan_b_packed_hex: str
    aggregate_dr_length: int | None
    taps_tdo_to_tdi: tuple[dict[str, Any], ...] | None
    status: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue_permit(descriptor_evidence: bytes, expected_sha256: str,
                 *, lifetime_seconds: int = 120, nonce: str | None = None) -> DiscoveryPermit:
    """Verify the already signed descriptor with the embedded signer pin."""
    if nonce is not None and (type(nonce) is not str or len(nonce) != 64 or
                              any(char not in "0123456789abcdef" for char in nonce)):
        raise Refusal("invalid authorized topology nonce")
    base = identity_gate.authorize_descriptor(descriptor_evidence, expected_sha256=expected_sha256)
    # Retire the generic IDCODE-gate permit returned by descriptor validation;
    # only this separately scoped topology permit may authorize this operation.
    identity_gate._consume_permit(base)
    issued = _now()
    if issued.tzinfo is None or not 1 <= lifetime_seconds <= 120:
        raise Refusal("invalid permit time or lifetime")
    identity = DescriptorIdentity(base.card_id, base.adapter_serial, base.usb_descriptor_serial,
                                  base.usb_path, base.vid, base.pid, base.manufacturer,
                                  base.product, base.interface)
    token = object()
    if nonce is None:
        nonce = secrets.token_hex(32)
    permit = DiscoveryPermit(base.descriptor_evidence_sha256, identity,
                             nonce, issued.astimezone(timezone.utc).isoformat(),
                             (issued + timedelta(seconds=lifetime_seconds)).astimezone(timezone.utc).isoformat(),
                             identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256, token)
    with _PERMIT_LOCK:
        _ACTIVE[token] = (permit.descriptor_evidence_sha256, permit.identity, permit.nonce,
                          permit.issued_at, permit.expires_at, permit.trusted_signer_fingerprint)
    return permit


def _consume(permit: DiscoveryPermit, now: datetime | None = None) -> None:
    with _PERMIT_LOCK:
        if not isinstance(permit, DiscoveryPermit) or permit._token not in _ACTIVE or permit._token in _CONSUMED:
            raise Refusal("invalid or replayed topology permit")
        binding = (permit.descriptor_evidence_sha256, permit.identity, permit.nonce,
                   permit.issued_at, permit.expires_at, permit.trusted_signer_fingerprint)
        if binding != _ACTIVE[permit._token]:
            raise Refusal("altered topology permit")
        _CONSUMED.add(permit._token)  # consume before any device/transport operation
    current = now or _now()
    expires = datetime.fromisoformat(permit.expires_at)
    if current.tzinfo is None or current.astimezone(timezone.utc) > expires:
        raise Refusal("topology permit expired")
    i = permit.identity
    if (permit.trusted_signer_fingerprint != identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256 or
        permit.descriptor_evidence_sha256 == "" or
        (i.card_id, i.adapter_serial, i.usb_descriptor_serial, i.vid, i.pid,
         i.manufacturer, i.product, i.interface) !=
        (CARD_ID, ADAPTER_SERIAL, USB_DESCRIPTOR_SERIAL, VID, PID, MANUFACTURER, PRODUCT, INTERFACE)):
        raise Refusal("topology permit identity binding mismatch")


def validate_candidates(permit: DiscoveryPermit, candidates: Iterable[Candidate]) -> Candidate:
    """Require a sole FTDI candidate and exact signed-descriptor identity before open."""
    rows = tuple(candidates)
    if len(rows) != 1:
        raise Refusal("zero or multiple FTDI candidates; refusing peer/second-device ambiguity")
    if rows[0].identity != permit.identity:
        raise Refusal("candidate descriptor differs from signed FK0957 identity")
    return rows[0]


def _de_bruijn_binary(order: int) -> tuple[int, ...]:
    """Canonical binary de Bruijn cycle: each order-bit window occurs once."""
    a = [0] * (2 * order)
    out: list[int] = []

    def db(t: int, p: int) -> None:
        if t > order:
            if order % p == 0:
                out.extend(a[1:p + 1])
            return
        a[t] = a[t - p]
        db(t + 1, p)
        for j in range(a[t - p] + 1, 2):
            a[t] = j
            db(t + 1, t)

    db(1, 1)
    return tuple(out)


def tdi_pattern() -> tuple[int, ...]:
    cycle = _de_bruijn_binary(DEBRUIJN_ORDER)
    bits = cycle[:CAPTURE_BITS]
    if len(bits) != CAPTURE_BITS:
        raise AssertionError("internal topology TDI pattern is short")
    return bits


def tdi_pattern_b() -> tuple[int, ...]:
    # Complement makes the first capture sample differ across the two reset
    # scans. Captured IDCODE/BYPASS contents are stable across Test-Logic-Reset.
    return tuple(1 - bit for bit in tdi_pattern())


def _pack_lsb(bits: Iterable[int]) -> bytes:
    values = tuple(bits)
    out = bytearray((len(values) + 7) // 8)
    for index, bit in enumerate(values):
        if bit not in (0, 1):
            raise Refusal("scan vector contains a non-bit")
        out[index // 8] |= bit << (index % 8)
    return bytes(out)


def _tms_command(bits: tuple[int, ...], *, read: bool, scan: str | None = None) -> Command:
    if not 1 <= len(bits) <= 7 or any(bit not in (0, 1) for bit in bits):
        raise Refusal("invalid internal TMS segment")
    packed = sum(bit << index for index, bit in enumerate(bits))
    opcode = 0x6B if read else 0x4B
    payload = packed  # TDI is fixed low on all state-navigation clocks.
    return Command(bytes((opcode, len(bits) - 1, payload)), 1 if read else 0,
                   len(bits), "TMS_READ" if read else "TMS_NO_READ", scan)


def build_plan() -> DiscoveryPlan:
    """Build the sole bounded reset-default DR scan. It performs no IR update."""
    tdi_a, tdi_b = tdi_pattern(), tdi_pattern_b()
    # Unknown initial state -> five TMS-high clocks establish Test-Logic-Reset;
    # one low clock enters Idle; then Select-DR, Capture-DR, Shift-DR.
    entry = (1, 1, 1, 1, 1, 0, 1, 0, 0)
    nav: list[Command] = []
    for start in range(0, len(entry), 7):
        nav.append(_tms_command(entry[start:start + 7], read=False, scan="A"))
    commands: list[Command] = [Command(MPSSE_SYNC, 2, 0, "SYNC"),
                               Command(MPSSE_SETUP, 0, 0, "CONFIG")] + nav
    tms_full: list[int] = list(entry)
    tdi_full: list[int] = [0] * len(entry)

    def append_scan(pattern: tuple[int, ...], scan: str) -> None:
        body = _pack_lsb(pattern[:-1])
        if len(body) % 8:
            raise AssertionError("internal DR body must be byte aligned")
        byte_count = len(body)
        if not 1 <= byte_count <= 65536:
            raise AssertionError("internal MPSSE byte count is outside command bounds")
        encoded_count = byte_count - 1
        commands.append(Command(bytes((0x39, encoded_count & 0xff, encoded_count >> 8)) + body,
                                byte_count, len(pattern) - 1, f"DR_{scan}_INOUT_BYTE_LSB", scan))
        last = pattern[-1]
        commands.append(Command(bytes((0x6B, 0x00, 0x01 | (last << 7))), 1, 1,
                                f"DR_{scan}_FINAL_BIT_EXIT", scan))
        # Exit1-DR -> Update-DR -> Select-DR -> Select-IR -> Test-Logic-Reset.
        # This is TAP state synchronization; it does not reset/reconfigure FPGA logic.
        commands.append(_tms_command((1, 1, 1, 1, 1), read=False, scan=scan))
        tms_full.extend((0,) * (len(pattern) - 1) + (1,) + (1,) * 5)
        tdi_full.extend(pattern + (0,) * 5)

    append_scan(tdi_a, "A")
    # From Test-Logic-Reset: Idle, Select-DR, Capture-DR, Shift-DR.
    second_entry = (0, 1, 0, 0)
    commands.append(_tms_command(second_entry, read=False, scan="B"))
    tms_full.extend(second_entry)
    tdi_full.extend((0,) * len(second_entry))
    append_scan(tdi_b, "B")
    tck_count = sum(c.tck_count for c in commands)
    scan_a_commands = tuple(c for c in commands if c.scan == "A")
    scan_b_commands = tuple(c for c in commands if c.scan == "B")
    scan_a_tck_count = sum(c.tck_count for c in scan_a_commands)
    scan_b_tck_count = sum(c.tck_count for c in scan_b_commands)
    contract = hashlib.sha256(
        b"FTDI-AN108:MPSSE:idle-low;0x4b=tms-lsb-falling-no-read;"
        b"0x6b=tms-lsb-falling-in-rising;0x39=byte-lsb-out-falling-in-rising;"
        b"0x3b=bit-lsb-out-falling-in-rising;navigation-tdi-low;sample-rising;"
        b"setup=80-08-0b\n").hexdigest()
    tx_material = (b"tms=" + bytes(tms_full) + b"\ntdi=" + bytes(tdi_full) + b"\n" +
                   b"commands=" + b"".join(len(c.write).to_bytes(4, "big") + c.write for c in commands) +
                   b"\nclock=100000;idle=low;order=lsb;sample=rising;change=falling;dual-signature-scan")
    return DiscoveryPlan(tuple(commands), scan_a_commands, scan_b_commands, (tdi_a, tdi_b),
                         tuple(tms_full), tuple(tdi_full), scan_a_tck_count, scan_b_tck_count, tck_count,
                         hashlib.sha256(tx_material).hexdigest(), contract)


def scan_transaction_sha256(commands: tuple[Command, ...]) -> str:
    material = bytearray(b"FK0957-MPSSE-SCAN-MANIFEST-v1\0")
    for command in commands:
        label = command.label.encode("ascii")
        scan = (command.scan or "").encode("ascii")
        material.extend(len(command.write).to_bytes(4, "big"))
        material.extend(command.write)
        material.extend(command.read_bytes.to_bytes(4, "big"))
        material.extend(command.tck_count.to_bytes(4, "big"))
        material.extend(len(label).to_bytes(2, "big"))
        material.extend(label)
        material.extend(len(scan).to_bytes(2, "big"))
        material.extend(scan)
    return hashlib.sha256(bytes(material)).hexdigest()


def raw_tdo_bits(byte_reads: bytes, final_tms_read: bytes) -> str:
    """Decode only the fixed 72-byte plus one 0x6B return framing."""
    if not isinstance(byte_reads, bytes) or len(byte_reads) != (CAPTURE_BITS - 1) // 8:
        raise Refusal("short/long byte-mode TDO response")
    if not isinstance(final_tms_read, bytes) or len(final_tms_read) != 1:
        raise Refusal("missing/extra final TMS-read response")
    data_bits = "".join(f"{byte:08b}"[::-1] for byte in byte_reads)
    final_bit = (final_tms_read[0] >> 7) & 1  # 0x6B returns its single sample in bit 7.
    return data_bits + str(final_bit)


def _decode_topology(bits: str) -> tuple[dict[str, Any], ...] | None:
    taps: list[dict[str, Any]] = []
    offset = 0
    while offset < len(bits):
        bit = bits[offset]
        if bit == "0":
            taps.append({"kind": "BYPASS", "raw_bit": "0"})
            offset += 1
            continue
        if len(bits) - offset < 32:
            return None
        word_bits = bits[offset:offset + 32]
        word = sum(int(value) << index for index, value in enumerate(word_bits))
        if (word & 1) != 1:
            return None
        taps.append({"kind": "IDCODE", "idcode": f"0x{word:08x}",
                     "version": (word >> 28) & 0xf,
                     "part_number": (word >> 12) & 0xffff,
                     "manufacturer_code": (word >> 1) & 0x7ff,
                     "raw_bits_lsb_first": word_bits})
        offset += 32
    return tuple(taps)


def parse_raw_tdo(bits_a: str, bits_b: str, tdi_a: tuple[int, ...], tdi_b: tuple[int, ...], *,
                  sample_edge: str = TDO_SAMPLE_EDGE, bit_order: str = BIT_ORDER) -> ParsedTopology:
    if sample_edge != TDO_SAMPLE_EDGE or bit_order != BIT_ORDER:
        raise Refusal("capture convention differs from the pinned MPSSE contract")
    if (not isinstance(bits_a, str) or not isinstance(bits_b, str) or
        len(bits_a) != CAPTURE_BITS or len(bits_b) != CAPTURE_BITS or
        set(bits_a) - {"0", "1"} or set(bits_b) - {"0", "1"}):
        raise Refusal("raw TDO length or alphabet malformed")
    if tdi_a != tdi_pattern() or tdi_b != tdi_pattern_b():
        raise Refusal("TDI pattern differs from fixed discovery sequence")
    seq_a, seq_b = "".join(map(str, tdi_a)), "".join(map(str, tdi_b))
    matches = [delay for delay in range(1, MAX_DEFAULT_DR_BITS + 1)
               if bits_a[delay:] == seq_a[:len(bits_a) - delay]
               and bits_b[delay:] == seq_b[:len(bits_b) - delay]]
    packed_a = _pack_lsb(int(bit) for bit in bits_a).hex()
    packed_b = _pack_lsb(int(bit) for bit in bits_b).hex()
    if len(matches) != 1:
        return ParsedTopology(bits_a, packed_a, bits_b, packed_b, None, None,
                              "INCONCLUSIVE_DELAY_NOT_UNIQUE")
    length = matches[0]
    taps = _decode_topology(bits_a[:length])
    if taps is None:
        return ParsedTopology(bits_a, packed_a, bits_b, packed_b, length, None,
                              "INCONCLUSIVE_DR_PARTITION")
    if bits_b[:length] != bits_a[:length]:
        return ParsedTopology(bits_a, packed_a, bits_b, packed_b, length, None,
                              "INCONCLUSIVE_RESET_CAPTURE_CHANGED")
    return ParsedTopology(bits_a, packed_a, bits_b, packed_b, length, taps,
                          "PARSED_RESET_DEFAULT_DR")


def build_observation(permit: DiscoveryPermit, parsed: ParsedTopology,
                      *, tck_count: int) -> dict[str, Any]:
    """Return bounded unsigned raw evidence; it is never IDCODE qualification."""
    with _PERMIT_LOCK:
        if permit._token not in _ACTIVE or permit._token not in _CONSUMED or permit._token in _RESULTS:
            raise Refusal("permit unavailable or result already emitted")
        completed = _COMPLETED.get(permit._token)
        if completed is None or completed != parsed:
            raise Refusal("record input is not the internally retained transport result")
    if parsed.status not in ("PARSED_RESET_DEFAULT_DR", "INCONCLUSIVE_DELAY_NOT_UNIQUE",
                             "INCONCLUSIVE_DR_PARTITION", "INCONCLUSIVE_RESET_CAPTURE_CHANGED"):
        raise Refusal("unknown topology parse status")
    if (len(parsed.raw_tdo_scan_a_bits) != CAPTURE_BITS or
        len(parsed.raw_tdo_scan_b_bits) != CAPTURE_BITS or tck_count != build_plan().tck_count):
        raise Refusal("observation size/counter mismatch")
    checked = parse_raw_tdo(parsed.raw_tdo_scan_a_bits, parsed.raw_tdo_scan_b_bits,
                            tdi_pattern(), tdi_pattern_b())
    if checked != parsed:
        raise Refusal("parsed topology does not match preserved raw TDO")
    observed_at = _now()
    if observed_at.tzinfo is None or observed_at.astimezone(timezone.utc) > datetime.fromisoformat(permit.expires_at):
        raise Refusal("topology permit expired before record construction")
    record = {
        "schema": "fk0957-topology-discovery-raw-v1",
        "topology_discovery_only": True,
        "idcode_qualification_pass": False,
        "descriptor_evidence_sha256": permit.descriptor_evidence_sha256,
        "trusted_signer_fingerprint": permit.trusted_signer_fingerprint,
        "permit_nonce": permit.nonce,
        "permit_issued_at": permit.issued_at,
        "permit_expires_at": permit.expires_at,
        "observation_timestamp": observed_at.astimezone(timezone.utc).isoformat(),
        "card_id": CARD_ID,
        "adapter_serial": ADAPTER_SERIAL,
        "usb_descriptor_serial": USB_DESCRIPTOR_SERIAL,
        # No production transport adapter exists yet. Do not accept a caller
        # supplied hash and pretend it identifies one; this record is mock-only.
        "transport_source_sha256": None,
        "transport_adapter_integrated": False,
        "discovery_algorithm_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "transaction_sha256": build_plan().transaction_sha256,
        "mpsse_command_contract_sha256": build_plan().command_contract_sha256,
        "tck_count": tck_count,
        "scan_count": 2,
        "tap_state_reset_clocks": 10,
        "observed_tdo_scan_a_bits_lsb_first": parsed.raw_tdo_scan_a_bits,
        "observed_tdo_scan_a_packed_hex": parsed.raw_tdo_scan_a_packed_hex,
        "observed_tdo_scan_b_bits_lsb_first": parsed.raw_tdo_scan_b_bits,
        "observed_tdo_scan_b_packed_hex": parsed.raw_tdo_scan_b_packed_hex,
        "observed_aggregate_dr_length": parsed.aggregate_dr_length,
        "observed_taps_tdo_to_tdi": parsed.taps_tdo_to_tdi,
        "parse_status": parsed.status,
        "observed_ir_lengths": None,
        "observed_fpga_dna": None,
        "observed_loaded_image_identity": None,
        "fpga_dna_observed": False,
        "loaded_image_identity_observed": False,
        "bitstream_identity_observed": False,
        "device_handles_opened": 1,
        "second_device_opened": False,
        "fpga_write_count": 0,
        "fpga_reset_count": 0,
        "program_count": 0,
        "jtag_operation_count": 1,
    }
    with _PERMIT_LOCK:
        if permit._token in _RESULTS:
            raise Refusal("topology result replay")
        _RESULTS.add(permit._token)
    return record


def discover_fk0957_topology(*_args, **_kwargs):
    """Production entry point is deliberately unavailable pending FTDI adapter audit."""
    raise Refusal("narrow exact-device FTDI topology adapter is not implemented")


def _run_mock_transport(permit: DiscoveryPermit, transport: Any):
    """Private test seam. Consume first; exact candidate selection precedes open."""
    _consume(permit)
    candidates = transport.enumerate_candidates()
    selected = validate_candidates(permit, candidates)
    opened = transport.open_exact(selected.handle_token)
    try:
        byte_a, final_a, byte_b, final_b = opened.execute_fixed_plan(build_plan())
        bits_a = raw_tdo_bits(byte_a, final_a)
        bits_b = raw_tdo_bits(byte_b, final_b)
        parsed = parse_raw_tdo(bits_a, bits_b, tdi_pattern(), tdi_pattern_b())
    finally:
        opened.close()
    with _PERMIT_LOCK:
        _COMPLETED[permit._token] = parsed
    return parsed, (bits_a, bits_b)
