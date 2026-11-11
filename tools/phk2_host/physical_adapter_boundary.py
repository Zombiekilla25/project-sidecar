"""Non-invoking policy/interface boundary for a future PHK2 physical adapter.

This module contains no endpoint discovery implementation and no physical I/O.
The selected endpoint is supplied by an eventual separately qualified adapter;
preflight policy runs before its transport methods may be called.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from board_protocol import ERROR, RESPONSE, HELLO_RESPONSE, Frame, Opcode, ProtocolError, request
from first_silicon_harness import decode_hello_payload
from tck_contract import TckObservation, TckPolicy, TckContractRefusal, validate_tck

class AdapterRefusal(RuntimeError):
    pass

@dataclass(frozen=True)
class QualificationGates:
    explicit_live: bool = False
    authorization_valid: bool = False
    image_qualified: bool = False
    protocol_qualified: bool = False
    one_card_only: bool = False
    target_lock_valid: bool = False
    rollback_ready: bool = False
    evidence_ready: bool = False
    peer_excluded: bool = False
    # Must only be set by a proof-backed adapter policy after it verifies the
    # effective rate. PHK2 currently has no such adapter/contract, so default
    # preflight fails closed.
    tck_contract_valid: bool = False

    def missing(self) -> tuple[str, ...]:
        return tuple(name for name, value in self.__dict__.items() if value is not True)

@dataclass(frozen=True)
class ExpectedIdentity:
    """Opaque target-lock identity and image binding; no hardware IDs invented."""
    target_identity_sha256: str
    candidate_image_sha256: str

@dataclass(frozen=True)
class EndpointIdentity:
    """Identity supplied by a selected-endpoint discovery provider.

    Discovery must be explicitly selected, bounded, and non-programming. The
    HELLO payload itself does not attest a physical serial or image digest.
    """
    target_identity_sha256: str
    candidate_image_sha256: str
    endpoint_token: str
    # Discovery metadata only. HELLO still independently confirms these.
    hello_capabilities: tuple[int, int, int, int, int, int, int] = (1, 0, 3, 112, 64, 112, 0x3f)

@dataclass(frozen=True)
class HelloCapabilities:
    major: int = 1
    minor: int = 0
    profile_id: int = 3
    descriptor_bytes: int = 112
    max_batch: int = 64
    result_bytes: int = 112
    feature_bits: int = 0x3f

EXPECTED_HELLO = HelloCapabilities()

@runtime_checkable
class SelectedEndpointDiscovery(Protocol):
    """Return only an already-selected endpoint; never scan hardware implicitly."""
    def selected_endpoint(self) -> EndpointIdentity | None: ...

@runtime_checkable
class PhysicalTransport(Protocol):
    """Future adapter seam. It intentionally has no implementation here."""
    def transact(self, framed_request: bytes, timeout_ms: int) -> bytes: ...
    def close(self) -> None: ...

def validate_capabilities(raw_payload: bytes, expected: HelloCapabilities = EXPECTED_HELLO) -> HelloCapabilities:
    decoded = decode_hello_payload(raw_payload)
    major, minor, profile, descriptor_bytes, max_batch, result_bytes, features = HELLO_RESPONSE.unpack(raw_payload)
    got = HelloCapabilities(major, minor, profile, descriptor_bytes, max_batch, result_bytes, features)
    if got != expected:
        raise AdapterRefusal(f"HELLO capabilities mismatch: got={got!r}")
    return got

def validate_preflight(gates: QualificationGates, expected: ExpectedIdentity,
                       endpoint: EndpointIdentity | None, *,
                       tck_policy: TckPolicy | None = None,
                       tck_observation: TckObservation | None = None,
                       authorized_tck_hz: int | None = None) -> EndpointIdentity:
    missing = gates.missing()
    if missing:
        raise AdapterRefusal("qualification gates missing: " + ",".join(missing))
    _validate_tck_gate(tck_policy, tck_observation, authorized_tck_hz)
    if endpoint is None:
        raise AdapterRefusal("no explicitly selected PHK2 endpoint")
    if (endpoint.target_identity_sha256 != expected.target_identity_sha256 or
            endpoint.candidate_image_sha256 != expected.candidate_image_sha256):
        raise AdapterRefusal("selected endpoint target/image identity mismatch")
    if not endpoint.endpoint_token:
        raise AdapterRefusal("selected endpoint token is missing")
    expected_caps=(EXPECTED_HELLO.major, EXPECTED_HELLO.minor, EXPECTED_HELLO.profile_id,
                   EXPECTED_HELLO.descriptor_bytes, EXPECTED_HELLO.max_batch,
                   EXPECTED_HELLO.result_bytes, EXPECTED_HELLO.feature_bits)
    if endpoint.hello_capabilities != expected_caps:
        raise AdapterRefusal("endpoint protocol/capability contract mismatch")
    return endpoint

def _validate_tck_gate(policy: TckPolicy | None, observation: TckObservation | None,
                       authorized_hz: int | None) -> None:
    if policy is None or observation is None:
        raise AdapterRefusal("proof-backed TCK policy and verified rate are required")
    try:
        validate_tck(policy, observation, authorized_hz=authorized_hz)
    except TckContractRefusal as exc:
        raise AdapterRefusal(f"TCK contract refused: {exc}") from exc

def prepare_physical_session(gates: QualificationGates, expected: ExpectedIdentity,
                             discovery: SelectedEndpointDiscovery,
                             timeout_ms: int = 2000, *,
                             tck_policy: TckPolicy | None = None,
                             tck_observation: TckObservation | None = None,
                             authorized_tck_hz: int | None = None) -> Any:
    """Legacy board-protocol seam; deliberately cannot open physical transport."""
    missing = gates.missing()
    if missing: raise AdapterRefusal("qualification gates missing: " + ",".join(missing))
    _validate_tck_gate(tck_policy, tck_observation, authorized_tck_hz)
    # The reviewed closure executor is returned directly by
    # master_pretransport_gate. This compatibility function has no factory,
    # permit, or executor-construction path.
    raise AdapterRefusal("transport/session construction is owned exclusively by master_pretransport_gate")

def make_hello_request(sequence: int = 0) -> bytes:
    """Exact existing board-protocol HELLO request (empty payload)."""
    return request(Opcode.HELLO, sequence, b"")

class GuardedPhysicalSession:
    """Disabled legacy constructor; the master gate returns a sealed executor."""
    def __init__(self, *_args, **_kwargs):
        raise AdapterRefusal("direct physical-session construction is disabled")
