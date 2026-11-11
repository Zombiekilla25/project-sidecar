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
                             discovery: SelectedEndpointDiscovery, transport_factory,
                             timeout_ms: int = 2000, *,
                             tck_policy: TckPolicy | None = None,
                             tck_observation: TckObservation | None = None,
                             authorized_tck_hz: int | None = None,
                             pretransport_permit=None) -> "GuardedPhysicalSession":
    """Resolve only a previously selected endpoint, then open after all gates.

    No discovery implementation is included. Gate failures happen before even
    asking the provider for its selected endpoint; identity/capability failures
    happen before the transport factory is called.
    """
    missing = gates.missing()
    if missing: raise AdapterRefusal("qualification gates missing: " + ",".join(missing))
    _validate_tck_gate(tck_policy, tck_observation, authorized_tck_hz)
    # Legacy boolean gates cannot authorize opening a physical transport.
    # The opaque permit is issued only after the closure master gate has
    # verified immutable qualification, signed authorization, peer/card
    # proofs, rollback and a durable PRE_TRANSPORT journal entry.
    from phk2_physical_close_guard import PreTransportPermit, open_transport_after_gate
    if not isinstance(pretransport_permit, PreTransportPermit):
        raise AdapterRefusal("master pre-transport closure permit required")
    endpoint = discovery.selected_endpoint()
    endpoint = validate_preflight(gates, expected, endpoint,
                                  tck_policy=tck_policy,
                                  tck_observation=tck_observation,
                                  authorized_tck_hz=authorized_tck_hz)
    try:
        transport = open_transport_after_gate(pretransport_permit, lambda: transport_factory(endpoint))
    except Exception as exc:
        raise AdapterRefusal(f"transport opening refused by master pre-transport gate: {exc}") from exc
    return GuardedPhysicalSession(transport, endpoint, timeout_ms,
                                  pretransport_permit=pretransport_permit)

def make_hello_request(sequence: int = 0) -> bytes:
    """Exact existing board-protocol HELLO request (empty payload)."""
    return request(Opcode.HELLO, sequence, b"")

class GuardedPhysicalSession:
    """Per-session guard for a separately supplied, already-open transport.

    Construction is only reachable after pure preflight passes. Any timeout,
    malformed/partial response, or disconnect poisons the session. No retry or
    reconnect is attempted. This wrapper does not discover or open endpoints.
    """
    def __init__(self, transport: PhysicalTransport, endpoint: EndpointIdentity,
                 timeout_ms: int = 2000, *, pretransport_permit=None):
        if timeout_ms <= 0: raise ValueError("timeout_ms must be positive")
        from phk2_physical_close_guard import PreTransportPermit
        if (not isinstance(pretransport_permit, PreTransportPermit) or
                not pretransport_permit._consumed or not pretransport_permit._opened):
            raise AdapterRefusal("a transport opened by the master pre-transport gate is required")
        self._transport = transport; self.endpoint = endpoint; self.timeout_ms = timeout_ms
        self._closed = False; self._hello_attempts = 0; self._sequence = 0
        self._abort_attempts = 0; self._seen_result_slots: set[tuple[int, int, int]] = set(); self._transaction_identity = None

    @property
    def hello_attempts(self): return self._hello_attempts
    @property
    def abort_attempts(self): return self._abort_attempts
    @property
    def closed(self): return self._closed

    def _exchange(self, raw: bytes) -> Frame:
        if self._closed: raise AdapterRefusal("stale/closed physical session")
        try:
            returned = self._transport.transact(raw, self.timeout_ms)
            frame = Frame.decode(returned)  # exact length, framing, reserved bits, CRC
            req = Frame.decode(raw)
            if frame.opcode != (req.opcode | 0x80) or frame.sequence != req.sequence or not frame.flags & RESPONSE:
                raise AdapterRefusal("response opcode/sequence/flags mismatch")
            if frame.flags & ERROR:
                raise AdapterRefusal("device returned protocol error")
            return frame
        except Exception:
            # A timeout, partial response, malformed frame, or disconnect makes
            # delivery state ambiguous; never replay this logical command.
            self.close()
            raise

    def hello_once(self) -> HelloCapabilities:
        if self._hello_attempts != 0: raise AdapterRefusal("HELLO budget exhausted")
        self._hello_attempts = 1
        frame = self._exchange(make_hello_request(self._sequence)); self._sequence += 1
        if frame.opcode != (int(Opcode.HELLO) | 0x80):
            self.close(); raise AdapterRefusal("not a HELLO response")
        try: return validate_capabilities(frame.payload)
        except Exception:
            self.close(); raise

    def accept_result_slot(self, generation: int, range_id: int, slot: int) -> None:
        if self._transaction_identity != (generation, range_id): raise AdapterRefusal("stale result transaction identity")
        key = (generation, range_id, slot)
        if key in self._seen_result_slots: raise AdapterRefusal("duplicate result slot")
        self._seen_result_slots.add(key)

    def bind_transaction(self, generation: int, range_id: int) -> None:
        if self._closed: raise AdapterRefusal("stale/closed physical session")
        if self._transaction_identity is not None: raise AdapterRefusal("transaction already bound")
        self._transaction_identity=(generation,range_id)

    def abort_once(self, encoded_abort_request: bytes) -> bytes:
        if self._transaction_identity is None: raise AdapterRefusal("ABORT requires an active transaction")
        if self._abort_attempts: raise AdapterRefusal("ABORT budget exhausted")
        req=Frame.decode(encoded_abort_request)
        if req.opcode != int(Opcode.ABORT): raise AdapterRefusal("abort_once requires frozen ABORT opcode")
        self._abort_attempts = 1
        response = self._exchange(encoded_abort_request)
        return response.payload

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try: self._transport.close()
            except Exception: pass
