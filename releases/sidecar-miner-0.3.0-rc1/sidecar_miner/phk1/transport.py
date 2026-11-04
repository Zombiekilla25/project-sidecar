"""Minimal raw TAP and PHK1 USER1/2/3 protocol driver.

This module contains no device discovery and cannot open hardware. It drives a
caller-supplied pin backend, which makes the TAP behavior deterministic in
fixtures and prevents accidental wildcard hardware access.
"""
from __future__ import annotations

import hashlib
import time
from typing import Protocol, Sequence
from .frame_protocol import build_request, parse_response, parse_status, vector_transaction_id

USER_IR = {1: 0x02, 2: 0x03, 3: 0x22}
IR_BITS = 6
STATUS_READY = 1 << 4
STATUS_ERROR = 1 << 1
STATUS_RX_SPACE = 1 << 0
STATUS_TX_AVAILABLE = 1 << 2
STATUS_TX_FLUSH = 1 << 3
ABORT_WORD = 0x42414850  # PHAB, shifted LSB-first, UPDATE-DR
TILE_BYTES = 24_576
ALLOWED_OPERATIONS = frozenset({"identify", "hello", "operand-vector-001"})


def validate_operation(operation: str) -> None:
    if operation not in ALLOWED_OPERATIONS:
        raise ValueError("operation is outside the PHK1 canary allowlist")


def validate_chain_layout(device_count: int, target_index: int) -> None:
    """The current raw profile accepts only a serial-isolated single FPGA."""
    if device_count != 1 or target_index != 0:
        raise ValueError("chain padding is unqualified; require exactly one isolated FPGA")


class PinBackend(Protocol):
    """Raw JTAG pin clock. `clock` returns the TDO bit sampled for that edge."""

    def clock(self, tms: int, tdi: int) -> int: ...
    def close(self) -> None: ...


def pack_bits_lsb(bits: Sequence[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit not in (0, 1):
            raise ValueError("JTAG bits must be 0 or 1")
        out[i // 8] |= bit << (i % 8)
    return bytes(out)


def unpack_bits_lsb(data: bytes, count: int) -> list[int]:
    if count < 0 or len(data) * 8 < count:
        raise ValueError("short packed TDO buffer")
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(count)]


class Tap:
    """IEEE 1149.1 TAP sequencing over a raw TMS/TDI/TDO clock backend."""

    def __init__(self, backend: PinBackend, ir_bits: int = IR_BITS, *, device_count: int = 1, target_index: int = 0):
        if ir_bits != 6:
            raise ValueError("qualified PHK1 VU33P profile requires a 6-bit IR")
        validate_chain_layout(device_count, target_index)
        self.backend = backend
        self.ir_bits = ir_bits
        self.closed = False

    def _clock(self, tms: int, tdi: int = 0) -> int:
        if self.closed:
            raise RuntimeError("TAP is closed")
        value = self.backend.clock(int(bool(tms)), int(bool(tdi)))
        if value not in (0, 1):
            raise IOError("backend returned invalid TDO bit")
        return value

    def reset(self) -> None:
        for _ in range(5):
            self._clock(1)
        self._clock(0)  # Test-Logic-Reset -> Run-Test/Idle

    def shift_ir(self, value: int, bits: int | None = None) -> list[int]:
        bits = self.ir_bits if bits is None else bits
        if bits != self.ir_bits or value < 0 or value >= (1 << bits):
            raise ValueError("IR value/width outside qualified 6-bit range")
        for tms in (1, 1, 0, 0):  # Idle -> Select-DR -> Select-IR -> Capture -> Shift
            self._clock(tms)
        result = []
        for i in range(bits):
            result.append(self._clock(1 if i == bits - 1 else 0, (value >> i) & 1))
        self._clock(1)  # Update-IR
        self._clock(0)  # Idle
        return result

    def shift_dr(self, tdi_bits: Sequence[int]) -> list[int]:
        if not tdi_bits:
            raise ValueError("empty DR scans are not allowed")
        for tms in (1, 0, 0):  # Idle -> Select-DR -> Capture-DR -> Shift-DR
            self._clock(tms)
        result = []
        for i, bit in enumerate(tdi_bits):
            if bit not in (0, 1):
                raise ValueError("JTAG bits must be 0 or 1")
            result.append(self._clock(1 if i == len(tdi_bits) - 1 else 0, bit))
        self._clock(1)  # Update-DR
        self._clock(0)  # Idle
        return result

    def user_scan(self, chain: int, data: bytes) -> bytes:
        if chain not in USER_IR:
            raise ValueError("only PHK1 USER1/USER2/USER3 are permitted")
        if not data:
            raise ValueError("empty USER scans are not allowed")
        self.shift_ir(USER_IR[chain])
        tdi = [((byte >> bit) & 1) for byte in data for bit in range(8)]
        return pack_bits_lsb(self.shift_dr(tdi))[:len(data)]

    def close(self) -> None:
        if not self.closed:
            try:
                self.reset()
            finally:
                self.backend.close()
                self.closed = True


class PHK1RawTransport:
    """Restricted PHK1 protocol client over a qualified raw TAP backend.

    The class accepts only identify/HELLO and the frozen operand-vector-001.
    It does not accept arbitrary USER payloads or open/select a device.
    """

    def __init__(self, tap: Tap, timeout_s: float = 120.0):
        self.tap = tap
        self.timeout_s = timeout_s
        self.last_timings_ns: dict[str, int] = {}
        self.last_raw_result: bytes | None = None
        self.last_canonical_result: bytes | None = None

    def read_status_word(self) -> int:
        raw = self.tap.user_scan(3, b"\0" * 4)
        return int.from_bytes(raw, "little")

    def status(self) -> tuple[int, dict]:
        word = self.read_status_word()
        return word, parse_status(word)

    def hello(self) -> dict:
        # The first USER3 read releases the chain reset synchronizer. Prime
        # USER2 and USER1 once, then accept only the PHK1_READY signature.
        self.read_status_word()  # discarded reset-release scan
        deadline = time.monotonic() + self.timeout_s
        while True:
            word = self.read_status_word()
            if word & STATUS_READY:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("PHK1_READY did not assert during HELLO")
        info = parse_status(word)
        self.tap.user_scan(2, b"\0")
        self.tap.user_scan(1, b"\0")
        word = self.read_status_word()
        info = parse_status(word)
        if info["error"] or not info["rx_space"] or info["tx_available"] or info["tx_flush"]:
            raise RuntimeError("PHK1 HELLO status is not idle/ready")
        return {"status_word": f"0x{word:08x}", **info}

    def _abort(self) -> None:
        self.tap.user_scan(3, ABORT_WORD.to_bytes(4, "little"))

    def vector001(self, payload: bytes) -> tuple[bytes, bytes, dict]:
        self.last_timings_ns = {"host_pack": 0, "input_scan": 0, "status_scan": 0,
                                "output_scan": 0, "host_compose": 0, "verify": 0}
        if len(payload) != 196_608:
            raise ValueError("only the frozen operand-vector-001 payload is accepted")
        payload_sha = hashlib.sha256(payload).hexdigest()
        if payload_sha != "7f4b421e8611725432061254f56e70a78a2c51210104e6674bcf10aaebe77b4b":
            raise ValueError("operand-vector-001 identity mismatch")
        txid = vector_transaction_id("operand-vector-001", payload_sha)
        raw_frames: list[bytes] = []
        try:
            for tile in range(8):
                started = time.monotonic_ns()
                request = build_request(txid, tile, payload[tile*TILE_BYTES:(tile+1)*TILE_BYTES])
                self.last_timings_ns["host_pack"] += time.monotonic_ns() - started
                started = time.monotonic_ns()
                self.tap.user_scan(2, request)
                self.last_timings_ns["input_scan"] += time.monotonic_ns() - started
                deadline = time.monotonic() + self.timeout_s
                while True:
                    started = time.monotonic_ns()
                    word, info = self.status()
                    self.last_timings_ns["status_scan"] += time.monotonic_ns() - started
                    if info["error"]:
                        raise RuntimeError(f"PHK1 status error on tile {tile}: 0x{word:08x}")
                    if info["tx_available"]:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"PHK1 tile {tile} response deadline expired")
                started = time.monotonic_ns()
                response = self.tap.user_scan(1, b"\0" * 96)
                self.last_timings_ns["output_scan"] += time.monotonic_ns() - started
                parse_response(response, txid, tile)
                raw_frames.append(response)
        except Exception:
            self._abort()
            raise
        raw = b"".join(raw_frames)
        started = time.monotonic_ns()
        word_rows = [parse_response(frame, txid, tile) for tile, frame in enumerate(raw_frames)]
        combined = [0] * 16
        for row in word_rows:
            for index, word in enumerate(row):
                combined[index] ^= word
        canonical = b"".join(word.to_bytes(4, "little") for word in combined)
        self.last_raw_result = raw
        self.last_canonical_result = canonical
        self.last_timings_ns["host_compose"] = time.monotonic_ns() - started
        started = time.monotonic_ns()
        if hashlib.sha256(raw).hexdigest() != "7a1a4e48b6182144cb9a0ab7d11b80824b0b86194838feeccf106e62253f1eb0":
            raise RuntimeError("raw PHK1 result differs from frozen oracle")
        if hashlib.sha256(canonical).hexdigest() != "43dbc52a64ec00e4504328e6f900a6ddebbaadb166cf9e7a90f0f53e7f846ffa":
            raise RuntimeError("canonical PHK1 result differs from frozen oracle")
        self.last_timings_ns["verify"] = time.monotonic_ns() - started
        return raw, canonical, {"transaction_id": f"{txid:08x}", "tiles": 8}
