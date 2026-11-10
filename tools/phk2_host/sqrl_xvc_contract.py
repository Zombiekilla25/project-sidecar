"""Offline model of settck behavior in one statically reviewed SQRL bridge.

This is evidence about the pinned ELF below, not a transport implementation.
It must never be used to connect to XVC or infer a pin-measured rate.
"""
from __future__ import annotations

from dataclasses import dataclass


REVIEWED_ELF_SHA256 = "8c7230f0bf586e9297dc0e568bd19278aeeb7cff8dbb3dde150811f11393218a"
REVIEWED_ELF_BUILD_ID = "b0562d538761373e2f1025c8bc8d8188ff8a0c40"
SETTCK_COMMAND = b"settck:"
SETTCK_VALUE_BYTES = 4
NOMINAL_MPSSE_BASE_HZ = 30_000_000


class XvcProtocolError(ValueError):
    """Malformed synthetic XVC request."""


@dataclass(frozen=True)
class SettckAudit:
    request: bytes
    response: bytes
    requested_period_ns: int
    effective_period_changed: bool = False
    effective_tck_readback_trustworthy: bool = False


def model_reviewed_settck(request: bytes) -> SettckAudit:
    """Model reviewed handler: consume 11-byte request and echo its u32.

    The binary's handler copies the four request bytes to a local DWORD and
    writes those same four bytes back. It does not apply the value to MPSSE.
    The 32-bit field is interpreted as ns only by the XVC protocol contract;
    the examined handler itself treats it as opaque bytes.
    """
    if not isinstance(request, bytes) or len(request) != len(SETTCK_COMMAND) + SETTCK_VALUE_BYTES:
        raise XvcProtocolError("settck request must be 'settck:' followed by four bytes")
    if request[: len(SETTCK_COMMAND)] != SETTCK_COMMAND:
        raise XvcProtocolError("unexpected XVC command")
    value = request[len(SETTCK_COMMAND) :]
    return SettckAudit(
        request=request,
        response=value,
        requested_period_ns=int.from_bytes(value, "little", signed=False),
    )


def reviewed_binary_nominal_tck_hz(*, jcc4p_descriptor: bool = False) -> int:
    """Return the nominal configured clock derived from reviewed setup code.

    Generic branch passes 30 MHz to SQRLJtagCreate; JCC4P passes 20 MHz.
    The MPSSE setup divides 30 MHz by that request using integer division,
    then subtracts one. Both paths therefore select divisor zero (nominal
    30 MHz). This is binary configuration evidence, not pin measurement.
    """
    requested = 20_000_000 if jcc4p_descriptor else NOMINAL_MPSSE_BASE_HZ
    divisor = NOMINAL_MPSSE_BASE_HZ // requested - 1
    if divisor != 0:
        raise AssertionError("reviewed bridge clock model changed")
    return NOMINAL_MPSSE_BASE_HZ // (divisor + 1)
