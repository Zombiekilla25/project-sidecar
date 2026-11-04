"""PHK1 RAW_BSCAN backend boundary. No USB/JTAG dependency is imported here."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Protocol, Any
from datetime import datetime, timezone

from .contracts import BackendResult, WorkBatch
from .phk1.transport import PHK1RawTransport

VECTOR_ID = "operand-vector-001"
VECTOR_SHA256 = "7f4b421e8611725432061254f56e70a78a2c51210104e6674bcf10aaebe77b4b"
RAW_SHA256 = "7a1a4e48b6182144cb9a0ab7d11b80824b0b86194838feeccf106e62253f1eb0"
CANONICAL_SHA256 = "43dbc52a64ec00e4504328e6f900a6ddebbaadb166cf9e7a90f0f53e7f846ffa"
PHYSICAL_PROTOCOL_QUALIFIED = False
FK_TIMING_KEYS=("open_us","target_validation_us","hello_us","host_pack_us","input_stream_us",
                "fpga_compute_us","output_stream_us","host_compose_us","verify_us","total_us")


class FkState(str, Enum):
    UNINITIALIZED="UNINITIALIZED"; TARGET_BOUND="TARGET_BOUND"; READY="READY"
    BUSY="BUSY"; DEGRADED="DEGRADED"; FAILED="FAILED"; CLOSED="CLOSED"


@dataclass(frozen=True)
class Fk33TargetConfig:
    logical_fk_id: str
    usb_selector: str
    expected_idcode: int
    expected_dna: str | None
    target_lock_generation: int
    expected_bitstream_sha256: str | None = None
    protocol_version: int = 1
    jtag_clock_hz: int = 100_000

    def __post_init__(self):
        if not self.logical_fk_id or not self.usb_selector:
            raise ValueError("logical FK ID and runtime USB selector are required")
        if isinstance(self.expected_idcode,bool) or not 0 <= self.expected_idcode <= 0xffffffff:
            raise ValueError("expected IDCODE must be an unsigned 32-bit integer")
        if self.expected_dna is not None and not self.expected_dna:
            raise ValueError("DNA expectation must be absent or non-empty")
        if self.expected_bitstream_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}",self.expected_bitstream_sha256):
            raise ValueError("expected bitstream identity must be a lowercase SHA-256")
        if self.target_lock_generation < 0 or self.protocol_version != 1:
            raise ValueError("unsupported lock generation or PHK1 protocol version")
        if not 100_000 <= self.jtag_clock_hz <= 1_000_000:
            raise ValueError("JTAG clock outside offline-qualified range")


@dataclass(frozen=True)
class TargetLockEvidence:
    target_count: int
    idcode: int
    dna: str | None
    generation: int
    captured_monotonic: float
    peer_ambiguous: bool = False
    bitstream_sha256: str | None = None
    selector_fingerprint: str | None = None


@dataclass(frozen=True)
class RuntimeTargetSelector:
    """Physical selection values supplied at runtime and never serialized/logged."""
    vid: int
    pid: int
    serial: str
    usb_path: str
    manufacturer: str
    product: str
    interface_name: str = "A"
    def __post_init__(self):
        if not (0<=self.vid<=0xffff and 0<=self.pid<=0xffff):raise ValueError("USB VID/PID out of range")
        if any(not isinstance(x,str) or not x for x in
               (self.serial,self.usb_path,self.manufacturer,self.product,self.interface_name)):
            raise ValueError("runtime target selector is incomplete")
        if self.interface_name!="A":raise ValueError("qualified PHK1 path requires FTDI interface A")
    @property
    def fingerprint(self):
        payload=json.dumps({"vid":self.vid,"pid":self.pid,"serial":self.serial,"usb_path":self.usb_path,
            "manufacturer":self.manufacturer,"product":self.product,"interface":self.interface_name},sort_keys=True,separators=(",",":"))
        return hashlib.sha256(payload.encode()).hexdigest()


def load_runtime_target_lock(path: str | Path, config: Fk33TargetConfig,
                             selector: RuntimeTargetSelector, *, now: datetime | None=None) -> TargetLockEvidence:
    """Read and validate an operator-supplied private lock without retaining identity data."""
    try: lock_obj=json.loads(Path(path).read_text())
    except (OSError,ValueError) as exc:raise ValueError("target lock cannot be read/parsed") from exc
    if (lock_obj.get("schema")!="sidecar-raw-jtag-target-lock-v1" or lock_obj.get("status")!="PASS" or
        lock_obj.get("match_count")!=1 or lock_obj.get("peer_distinct") is not True or
        lock_obj.get("raw_device_handle_count")!=0 or lock_obj.get("peer_handle_open") is not False):
        raise ValueError("target lock is stale, ambiguous or has open handles")
    try:
        stamp=datetime.fromisoformat(lock_obj["captured_utc"].replace("Z","+00:00"))
        age=((now or datetime.now(timezone.utc))-stamp.astimezone(timezone.utc)).total_seconds()
        target=lock_obj["target"];peer=lock_obj["peer"]
        generation=int(lock_obj.get("target_lock_generation",lock_obj.get("generation")))
        idcode=int(str(target["idcode"]).lower().removeprefix("0x"),16)
    except (KeyError,TypeError,ValueError,AttributeError) as exc:raise ValueError("target lock identity/timestamp is malformed") from exc
    if age < -30 or age > 600:raise ValueError("target lock is stale or future dated")
    exact={"vid":f"{selector.vid:04x}","pid":f"{selector.pid:04x}","serial":selector.serial,
           "usb_path":selector.usb_path,"manufacturer":selector.manufacturer,"product":selector.product,
           "interface":selector.interface_name}
    if any(str(target.get(k,"" )).lower()!=str(v).lower() for k,v in exact.items()):
        raise ValueError("target lock does not match runtime target selector")
    if target.get("role")!="PHK1_CANARY" or idcode!=config.expected_idcode:
        raise ValueError("target lock role or IDCODE mismatch")
    if config.expected_dna is not None and target.get("dna")!=config.expected_dna:
        raise ValueError("DNA_MISMATCH")
    if config.expected_bitstream_sha256 and target.get("expected_phk1_bitstream_sha256")!=config.expected_bitstream_sha256:
        raise ValueError("target bitstream identity mismatch")
    if any(target.get(k)==peer.get(k) for k in ("ftdi_serial","usb_path","dna")):
        raise ValueError("target peer ambiguity")
    if generation!=config.target_lock_generation:raise ValueError("target-lock generation mismatch")
    dna=target.get("dna") if isinstance(target.get("dna"),str) else None
    return TargetLockEvidence(1,idcode,dna,generation,time.monotonic()-age,False,
                              target.get("expected_phk1_bitstream_sha256"),selector.fingerprint)


def validate_target_lock(config: Fk33TargetConfig, evidence: TargetLockEvidence,
                         now: float | None = None, max_age_s: float = 600.0) -> None:
    now = time.monotonic() if now is None else now
    age = now - evidence.captured_monotonic
    if evidence.target_count != 1 or evidence.peer_ambiguous:
        raise ValueError("target lock must bind exactly one unambiguous target")
    if evidence.idcode != config.expected_idcode:
        raise ValueError("target IDCODE mismatch")
    if config.expected_dna is not None and evidence.dna != config.expected_dna:
        raise ValueError("target DNA mismatch")
    if config.expected_bitstream_sha256 is not None and evidence.bitstream_sha256 != config.expected_bitstream_sha256:
        raise ValueError("target bitstream identity mismatch")
    if evidence.generation != config.target_lock_generation or age < 0 or age > max_age_s:
        raise ValueError("stale target-lock generation or age")


class RawBscanTransport(Protocol):
    """Private adapter boundary; callers outside fk33_backend see no scan API."""
    backend_id: str
    def open(self, config: Fk33TargetConfig) -> None: ...
    def user_scan(self, chain: int, payload: bytes) -> bytes: ...
    def health(self) -> bool: ...
    def close(self) -> None: ...


class LiveRawBscanTransport:
    """Lazy native binding. Qualification and target lock precede dlopen/USB."""
    backend_id="raw-bscan-native"
    def __init__(self, selector: RuntimeTargetSelector | None=None, *, target_lock_path: str | Path | None=None,
                 qualification_path: str | Path | None=None, native_library_path: str | Path | None=None,
                 live_enabled: bool=False, _boundary_factory=None, _qualification_loader=None):
        self.selector=selector;self.target_lock_path=Path(target_lock_path) if target_lock_path else None
        self.qualification_path=Path(qualification_path) if qualification_path else None
        self.native_library_path=Path(native_library_path) if native_library_path else None
        self.live_enabled=live_enabled;self._boundary_factory=_boundary_factory
        self._qualification_loader=_qualification_loader;self.boundary=None;self.opened=False
        self.config=None;self.last_error_category=None;self.qualification=None;self.calls=[]
    def open(self, config: Fk33TargetConfig) -> None:
        if self.opened:raise RuntimeError("native transport is already open")
        if not self.live_enabled:raise RuntimeError("live FK execution is not explicitly enabled")
        if not self.selector or not self.target_lock_path or not self.qualification_path or not self.native_library_path:
            raise RuntimeError("runtime target, lock, qualification artifact and native library are required")
        if not config.expected_bitstream_sha256:
            raise RuntimeError("runtime target config must bind the expected PHK1 bitstream")
        evidence=load_runtime_target_lock(self.target_lock_path,config,self.selector)
        validate_target_lock(config,evidence)
        if evidence.selector_fingerprint!=self.selector.fingerprint:
            raise RuntimeError("target lock selector fingerprint mismatch")
        from .qualification import pinned_source_hashes,validate_qualification_artifact
        runner_sha,backend_sha=pinned_source_hashes()
        loader=self._qualification_loader or validate_qualification_artifact
        qualification=loader(self.qualification_path,expected_runner_sha256=runner_sha,
            expected_backend_sha256=backend_sha,expected_bitstream_sha256=config.expected_bitstream_sha256)
        if not (qualification.hello_pass and qualification.vector001_pass and qualification.rollback_pass):
            raise RuntimeError("PHK1 physical qualification artifact is incomplete")
        if self._boundary_factory is None:
            # Importing/creating the ctypes boundary is delayed until all gates
            # pass. Its CDLL load remains delayed until boundary.open below.
            from .native_boundary import CtypesRawBscanBoundary
            factory=CtypesRawBscanBoundary
        else:factory=self._boundary_factory
        boundary=factory(self.native_library_path)
        try:boundary.open(self.selector,config.expected_idcode,config.jtag_clock_hz)
        except Exception:
            try:boundary.close()
            except Exception:pass
            raise
        self.boundary=boundary;self.config=config;self.qualification=qualification;self.opened=True
    def user_scan(self, chain: int, payload: bytes) -> bytes:
        if not self.opened or self.boundary is None:raise RuntimeError("native RAW_BSCAN is not open")
        try:
            response=self.boundary.user_scan(chain,payload)
            self.calls.append((chain,bytes(payload),bytes(response)))
            return response
        except Exception as exc:
            self.last_error_category=getattr(exc,"category","TRANSPORT_DISCONNECTED")
            raise
    def health(self) -> bool:
        return bool(self.opened and self.boundary is not None and not getattr(self.boundary,"closed",False))
    def close(self) -> None:
        try:
            if self.boundary is not None:self.boundary.close()
        finally:self.boundary=None;self.opened=False


class MockPhk1Transport:
    """Deterministic scan fixture transport. It never enumerates USB or opens hardware."""
    backend_id="phk1-mock-raw-bscan"
    def __init__(self, response_frames: bytes | None = None, fault: str | None = None):
        self.response_frames=response_frames
        self.fault=fault; self.opened=False; self.closed=False; self.calls=[]
        self._hello_status=0; self._hello_primed=False; self._pending=False; self._tile=0
    def open(self, config: Fk33TargetConfig) -> None:
        self.opened=True; self.closed=False
        if self.fault=="disconnect": raise ConnectionError("mock transport disconnected")
    def user_scan(self, chain: int, payload: bytes) -> bytes:
        if not self.opened or self.closed: raise ConnectionError("mock RAW_BSCAN is closed")
        data=bytes(payload)
        if self.fault=="timeout" and chain==3 and self._pending: raise TimeoutError("mock PHK1 response timeout")
        if chain==3:
            if self._pending:
                response=(0x15).to_bytes(4,"little")
            elif self.fault=="bad_hello" and self._hello_primed:response=(0x15).to_bytes(4,"little")
            # HELLO consists of reset-release, ready, then final idle status.
            else:
                self._hello_status+=1;response=(0x11).to_bytes(4,"little")
        elif chain==2:
            if len(payload)==1:
                self._hello_primed=True
                response=b"\0"  # documented USER2 prime
            else:
                if len(payload)!=24608: raise ValueError("mock received unexpected PHK1 request size")
                if self.fault=="wrong_target": raise RuntimeError("mock target identity rejected")
                self._pending=True;response=bytes(len(payload))
        elif chain==1:
            if len(payload)==1:response=b"\0"  # documented USER1 prime
            else:
                if len(payload)!=96: raise ValueError("mock received unexpected PHK1 response size")
                frames=self.response_frames
                if frames is None: raise RuntimeError("mock response fixture is unavailable")
                start=self._tile*96; response=frames[start:start+96]
                if self.fault=="truncated" and self._tile==0: response=response[:-1]
                if self.fault=="wrong_raw" and self._tile==0: response=bytes([response[0]^1])+response[1:]
                self._tile+=1; self._pending=False
        else: raise ValueError("unsupported PHK1 USER chain")
        self.calls.append((chain,data,response))
        return response
    def health(self) -> bool: return self.opened and not self.closed and self.fault not in {"disconnect"}
    def close(self) -> None: self.closed=True; self.opened=False


class Phk1ProtocolAdapter:
    """Narrow metadata adapter around the existing PHK1RawTransport logic."""
    def __init__(self, transport: RawBscanTransport, timeout_s: float=10.0):
        self.transport=transport
        self.client=PHK1RawTransport(transport,timeout_s=timeout_s)
    def hello(self) -> dict:
        calls=getattr(self.transport,"calls",[]);before=len(calls); started=time.monotonic()
        parsed=self.client.hello(); word=int(parsed["status_word"],16)
        transcript=b"".join(bytes((chain,))+len(tx).to_bytes(4,"little")+tx+
                             len(rx).to_bytes(4,"little")+rx
                             for chain,tx,rx in getattr(self.transport,"calls",[])[before:])
        info={"phk1_ready":parsed["phk1_ready"],"rx_space":parsed["rx_space"],
              "error":parsed["error"],"tx_available":parsed["tx_available"],"tx_flush":parsed["tx_flush"]}
        return {"protocol_version":1,"capabilities":["hello","operand-vector-001"],
                "status_word":f"0x{word:08x}","status":info,
                "raw_transcript_sha256":hashlib.sha256(transcript).hexdigest(),
                "timings_us":{key:None for key in FK_TIMING_KEYS}}
    def vector001(self,payload: bytes) -> tuple[bytes,bytes,dict]:
        raw,canonical,details=self.client.vector001(payload)
        details["timings_us"]={key:None for key in FK_TIMING_KEYS}
        return raw,canonical,details


@dataclass(frozen=True)
class Fk33VectorWork:
    payload: bytes
    vector_id: str = VECTOR_ID


@dataclass(frozen=True)
class Fk33VectorResult:
    raw: bytes
    canonical: bytes
    vector_id: str
    transaction_id: str
    job_fingerprint: str
    generation: int
    batch_id: str
    timing_source: str="mock-transport; hardware timing unknown"


def classify_fk_error(exc: Exception, operation: str) -> str:
    category=getattr(exc,"category",None)
    if category in {"TARGET_NOT_FOUND","TARGET_AMBIGUOUS","IDCODE_MISMATCH","DNA_MISMATCH",
                    "FTDI_OPEN_FAILED","MPSSE_SYNC_FAILED","TAP_FAILED","HELLO_FAILED",
                    "VECTOR_TIMEOUT","VECTOR_PROTOCOL_ERROR","RESULT_MISMATCH","TRANSPORT_DISCONNECTED"}:
        return category
    message=str(exc).lower()
    if isinstance(exc,TimeoutError):return "HELLO_FAILED" if operation=="hello" else "VECTOR_TIMEOUT"
    if "dna" in message:return "DNA_MISMATCH"
    if "idcode" in message:return "IDCODE_MISMATCH"
    if "ambiguous" in message or "duplicate" in message:return "TARGET_AMBIGUOUS"
    if "not found" in message:return "TARGET_NOT_FOUND"
    if "timeout" in message:return "HELLO_FAILED" if operation=="hello" else "VECTOR_TIMEOUT"
    if any(x in message for x in ("raw phk1 result","canonical phk1 result")):return "RESULT_MISMATCH"
    if "disconnect" in message or "closed" in message:return "TRANSPORT_DISCONNECTED"
    return "HELLO_FAILED" if operation=="hello" else "VECTOR_PROTOCOL_ERROR"


class RawBscanFk33Backend:
    def __init__(self, config: Fk33TargetConfig, transport: RawBscanTransport | None=None,
                 lock_evidence: TargetLockEvidence | None=None, response_fixture: Path | None=None):
        self.backend_id=config.logical_fk_id; self.config=config; self.transport=transport or LiveRawBscanTransport()
        self.lock_evidence=lock_evidence; self.response_fixture=response_fixture or Path(__file__).resolve().parents[1]/"fixtures/phk1/vector001-response-frames.bin"
        self.state=FkState.UNINITIALIZED; self.healthy=False; self.protocol=None; self.prepared=None
        self.last_hello=None; self.last_error=None; self._responses=None
        self.last_error_category=None
    def initialize(self) -> None:
        if self.state!=FkState.UNINITIALIZED: raise RuntimeError("backend initialize is only valid once")
        if self.lock_evidence is None: self.state=FkState.FAILED; self.last_error="target-lock evidence required"; raise RuntimeError(self.last_error)
        try: validate_target_lock(self.config,self.lock_evidence)
        except Exception as exc:
            self.state=FkState.FAILED; self.last_error=str(exc);self.last_error_category=classify_fk_error(exc,"open");raise
        self.state=FkState.TARGET_BOUND
        if not isinstance(self.transport,(MockPhk1Transport,LiveRawBscanTransport)):
            self.state=FkState.FAILED; self.last_error="unrecognized RAW_BSCAN transport implementation"; raise RuntimeError(self.last_error)
        try:
            self.transport.open(self.config)
            self._responses=None
            if isinstance(self.transport,MockPhk1Transport):
                manifest=json.loads(self.response_fixture.with_suffix('.json').read_text())
                response=self.response_fixture.read_bytes()
                if (manifest.get('schema')!='sidecar-phk1-vector001-mock-response-v1' or
                    manifest.get('version')!=1 or manifest.get('response_bytes')!=768 or
                    manifest.get('response_frames')!=8 or manifest.get('frame_bytes')!=96 or
                    manifest.get('response_sha256')!=RAW_SHA256 or
                    hashlib.sha256(response).hexdigest()!=manifest.get('response_sha256')):
                    raise ValueError('PHK1 mock response fixture manifest/hash mismatch')
                self._responses=response
            if isinstance(self.transport,MockPhk1Transport): self.transport.response_frames=self._responses
            self.protocol=Phk1ProtocolAdapter(self.transport)
            self.state=FkState.READY; self.healthy=True
        except Exception as exc:
            self.state=FkState.FAILED;self.healthy=False;self.last_error=str(exc)
            self.last_error_category=classify_fk_error(exc,"open")
            try:self.transport.close()
            except Exception:pass
            raise
    def health(self) -> dict:
        alive=self.transport.health() if self.state not in (FkState.UNINITIALIZED,FkState.CLOSED,FkState.FAILED) else False
        if not alive and self.state==FkState.READY: self.state=FkState.DEGRADED;self.healthy=False
        return {"state":self.state.value,"healthy":self.healthy and alive,"logical_fk_id":self.backend_id,
                "physical_protocol_qualified":PHYSICAL_PROTOCOL_QUALIFIED,"last_error":self.last_error}
    def hello(self) -> dict:
        if self.state!=FkState.READY or self.protocol is None: raise RuntimeError("FK33 backend is not READY")
        try:self.last_hello=self.protocol.hello();return self.last_hello
        except Exception as exc:
            self.state=FkState.DEGRADED;self.healthy=False;self.last_error=str(exc)
            self.last_error_category=classify_fk_error(exc,"hello");raise
    def prepare_job(self,job: Any) -> None:
        if self.state!=FkState.READY or self.last_hello is None: raise RuntimeError("HELLO must pass before preparing FK work")
        self.prepared=(job.fingerprint,job.generation)
    def execute_batch(self,batch: WorkBatch) -> BackendResult:
        if self.state!=FkState.READY or not self.healthy: raise RuntimeError("FK33 backend is not healthy")
        if self.prepared!=(batch.job_fingerprint,batch.generation): raise ValueError("batch job identity differs from prepared job")
        if not isinstance(batch.context,Fk33VectorWork): raise ValueError("PHK1 physical qualification currently supports only operand-vector-001 work")
        if batch.context.vector_id!=VECTOR_ID: raise ValueError("unsupported PHK1 vector")
        self.state=FkState.BUSY
        try:
            raw,canonical,details=self.protocol.vector001(batch.context.payload)
            # These correlation fields accompany the fixed PHK1 transaction;
            # the current frozen wire format has no PRL-job identity fields.
            result=Fk33VectorResult(raw,canonical,batch.context.vector_id,details["transaction_id"],
                                    batch.job_fingerprint,batch.generation,batch.batch_id)
            self.state=FkState.READY
            return BackendResult(batch.job_fingerprint,batch.generation,batch.batch_id,self.backend_id,
                hashlib.sha256(raw).hexdigest(),hashlib.sha256(canonical).hexdigest(),True,result,
                None,True,False,"raw-and-canonical-fixture-exact",details["timings_us"])
        except Exception as exc:
            self.state=FkState.DEGRADED;self.healthy=False;self.last_error=str(exc)
            self.last_error_category=classify_fk_error(exc,"vector")
            raise
    def close(self) -> None:
        if self.state==FkState.CLOSED:return
        try:self.transport.close()
        finally:self.state=FkState.CLOSED;self.healthy=False
