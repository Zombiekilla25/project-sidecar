"""Fail-closed TCK policy checks; no transport or hardware access is performed."""
from __future__ import annotations
from dataclasses import dataclass

class TckContractRefusal(RuntimeError):
    pass

@dataclass(frozen=True)
class TckPolicy:
    proven: bool
    max_hz: int | None
    transport_id: str | None
    evidence_sha256: str | None

@dataclass(frozen=True)
class TckObservation:
    requested_hz: int | None
    measured_or_readback_hz: int | None
    verified: bool
    transport_id: str


def validate_tck(policy: TckPolicy, observed: TckObservation, *,
                 authorized_hz: int | None = None,
                 prior_session_hz: int | None = None,
                 reconnect: bool = False) -> int:
    """Accept only an attested, read-back rate within a proven policy ceiling.

    `measured_or_readback_hz` must be supplied by a future qualified adapter;
    a requested settck value alone is not verification. Values in tests are
    synthetic and do not establish the PHK2 contract.
    """
    if (policy.proven is not True or not isinstance(policy.max_hz, int) or
            policy.max_hz <= 0 or not policy.transport_id or
            not _is_sha256(policy.evidence_sha256)):
        raise TckContractRefusal("TCK ceiling lacks complete qualification evidence")
    if observed.transport_id != policy.transport_id:
        raise TckContractRefusal("TCK observation belongs to a different transport")
    requested = observed.requested_hz
    actual = observed.measured_or_readback_hz
    if not isinstance(requested, int) or requested <= 0 or actual is None:
        raise TckContractRefusal("TCK rate is unknown")
    if observed.verified is not True or actual != requested:
        raise TckContractRefusal("effective TCK rate was not verified")
    if actual > policy.max_hz:
        raise TckContractRefusal("TCK exceeds qualified maximum")
    if authorized_hz is not None and requested != authorized_hz:
        raise TckContractRefusal("TCK changed after authorization")
    if reconnect and prior_session_hz != actual:
        raise TckContractRefusal("TCK changed or is unknown after reconnect")
    return actual


def _is_sha256(value: str | None) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True
