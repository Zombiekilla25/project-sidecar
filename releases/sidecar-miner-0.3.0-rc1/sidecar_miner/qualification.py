"""Shared, fail-closed backend qualification artifact schemas and loaders."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
SOURCE_MANIFEST=ROOT/"schemas/native-raw-bscan-source-v1.json"
PHK1_SCHEMA="sidecar-phk1-physical-qualification-v1"
SCHEMA=PHK1_SCHEMA
CUDA_SCHEMA="sidecar-cuda-qualification-v1"
ARTIFACT_TYPE="sidecar-backend-qualification"
PHK1_BACKEND="fk33-phk1"
CUDA_BACKEND="cuda-pearlhash"
PHK1_TRANSPORT_VERSION="raw-bscan-v1"
PHK1_PROTOCOL_VERSION=1
PHK1_VECTOR_ID="operand-vector-001"
CUDA_QUALIFICATION_SCHEMA=CUDA_SCHEMA


def pinned_source_hashes() -> tuple[str,str]:
    """Verify and return pinned protocol-runner and native-backend source hashes."""
    obj=json.loads(SOURCE_MANIFEST.read_text())
    def digest(group):
        parts=[]
        for row in obj[group]:
            path=ROOT/row["path"]
            actual=hashlib.sha256(path.read_bytes()).hexdigest()
            if actual!=row["sha256"]:raise RuntimeError(f"pinned native source changed: {row['path']}")
            parts.append(row["path"].encode()+b"\0"+bytes.fromhex(actual))
        return hashlib.sha256(b"".join(parts)).hexdigest()
    return digest("runner_sources"),digest("backend_sources")


def _read_json(path: str|Path) -> dict:
    def unique_object(pairs):
        obj={}
        for key,value in pairs:
            if key in obj:raise ValueError(f"duplicate JSON field: {key}")
            obj[key]=value
        return obj
    try:obj=json.loads(Path(path).read_text(encoding="utf-8"),object_pairs_hook=unique_object)
    except (OSError,UnicodeError,ValueError) as exc:raise ValueError("qualification artifact cannot be read/parsed") from exc
    if not isinstance(obj,dict):raise ValueError("qualification artifact must be a JSON object")
    return obj


def _hash(value: object, name: str) -> str:
    if not isinstance(value,str) or not re.fullmatch(r"[0-9a-f]{64}",value):
        raise ValueError(f"invalid {name}")
    return value


def _timestamp(value: object, *, now: datetime|None=None) -> str:
    if not isinstance(value,str):raise ValueError("qualification timestamp is invalid")
    try:
        stamp=datetime.fromisoformat(value.replace("Z","+00:00"))
        if stamp.tzinfo is None:raise ValueError()
        age=((now or datetime.now(timezone.utc))-stamp.astimezone(timezone.utc)).total_seconds()
    except (ValueError,TypeError,AttributeError) as exc:raise ValueError("qualification timestamp is invalid") from exc
    if age < -30 or age > 30*24*3600:raise ValueError("qualification timestamp is stale/future")
    return value

@dataclass(frozen=True)
class PhysicalQualification:
    bitstream_sha256: str
    runner_identity: str
    runner_sha256: str
    backend_identity: str
    backend_sha256: str
    qualified_at_utc: str
    hello_pass: bool
    vector001_pass: bool
    rollback_pass: bool
    qualification_sha256: str|None=None
    transport_version: str=PHK1_TRANSPORT_VERSION
    protocol_version: int=PHK1_PROTOCOL_VERSION
    vector_id: str=PHK1_VECTOR_ID
    raw_result_exact: bool=True
    canonical_result_exact: bool=True
    cpu_crosscheck: bool=True
    @property
    def qualified(self):return True
    @property
    def backend_type(self):return PHK1_BACKEND
    @property
    def qualification_timestamp(self):return self.qualified_at_utc

@dataclass(frozen=True)
class CudaQualification:
    library_sha256: str
    source_sha256: str
    fixture_sha256: str
    result_sha256: str
    device_name: str
    qualified_at_utc: str
    explicit_device_selection: bool
    qualification_sha256: str|None=None
    @property
    def qualified(self):return True
    @property
    def backend_type(self):return CUDA_BACKEND
    @property
    def qualification_timestamp(self):return self.qualified_at_utc


def validate_qualification_artifact(path: str|Path, *, expected_runner_sha256: str,
        expected_backend_sha256: str, expected_bitstream_sha256: str|None=None,
        expected_transport_version: str=PHK1_TRANSPORT_VERSION,
        expected_protocol_version: int=PHK1_PROTOCOL_VERSION,
        expected_vector_id: str=PHK1_VECTOR_ID, now: datetime|None=None) -> PhysicalQualification:
    obj=_read_json(path)
    required={"artifact_type","schema_version","backend_type","qualified","bitstream_sha256",
        "runner_identity","runner_sha256","backend_identity","backend_sha256","transport_version",
        "protocol_version","vector_id","raw_result_exact","canonical_result_exact","cpu_crosscheck",
        "rollback_verified","qualification_timestamp"}
    if set(obj)!=required:raise ValueError("PHK1 qualification artifact is incomplete or contains unsupported/private fields")
    if obj["artifact_type"]!=ARTIFACT_TYPE or obj["schema_version"]!=1:
        raise ValueError("unsupported PHK1 qualification schema version")
    if obj["backend_type"]!=PHK1_BACKEND:raise ValueError("qualification backend type mismatch")
    if obj["qualified"] is not True:raise ValueError("PHK1 artifact is not qualified")
    for key in ("bitstream_sha256","runner_sha256","backend_sha256"):_hash(obj[key],key)
    if obj["runner_sha256"]!=expected_runner_sha256 or obj["backend_sha256"]!=expected_backend_sha256:
        raise ValueError("qualification does not match pinned runner/backend sources")
    if expected_bitstream_sha256 and obj["bitstream_sha256"]!=expected_bitstream_sha256:
        raise ValueError("qualification bitstream identity mismatch")
    if not isinstance(obj["runner_identity"],str) or not obj["runner_identity"].strip():raise ValueError("runner identity is missing")
    if not isinstance(obj["backend_identity"],str) or not obj["backend_identity"].strip():raise ValueError("backend identity is missing")
    if obj["transport_version"]!=expected_transport_version:raise ValueError("qualification transport version mismatch")
    if obj["protocol_version"]!=expected_protocol_version:raise ValueError("qualification protocol version mismatch")
    if obj["vector_id"]!=expected_vector_id:raise ValueError("qualification Vector001 identity mismatch")
    for key in ("raw_result_exact","canonical_result_exact","cpu_crosscheck","rollback_verified"):
        if obj[key] is not True:raise ValueError(f"qualification gate failed: {key}")
    stamp=_timestamp(obj["qualification_timestamp"],now=now)
    return PhysicalQualification(
        bitstream_sha256=obj["bitstream_sha256"],runner_identity=obj["runner_identity"],
        runner_sha256=obj["runner_sha256"],backend_identity=obj["backend_identity"],
        backend_sha256=obj["backend_sha256"],qualified_at_utc=stamp,hello_pass=True,
        vector001_pass=True,rollback_pass=True,qualification_sha256=artifact_sha256(path),
        transport_version=obj["transport_version"],protocol_version=obj["protocol_version"],
        vector_id=obj["vector_id"],raw_result_exact=True,canonical_result_exact=True,cpu_crosscheck=True)


def validate_cuda_qualification_artifact(path: str|Path, *, expected_library_sha256: str,
        expected_source_sha256: str, expected_fixture_sha256: str,
        now: datetime|None=None) -> CudaQualification:
    obj=_read_json(path)
    required={"artifact_type","schema_version","backend_type","qualified","library_sha256","source_sha256",
        "fixture_sha256","result_sha256","device_name","qualification_timestamp","explicit_device_selection"}
    if set(obj)!=required:raise ValueError("CUDA qualification artifact is incomplete or contains unsupported fields")
    if obj["artifact_type"]!=ARTIFACT_TYPE or obj["schema_version"]!=1:raise ValueError("unsupported CUDA qualification schema version")
    if obj["backend_type"]!=CUDA_BACKEND:raise ValueError("CUDA qualification backend type mismatch")
    if obj["qualified"] is not True:raise ValueError("CUDA artifact is not qualified")
    for key in ("library_sha256","source_sha256","fixture_sha256","result_sha256"):_hash(obj[key],key)
    if (obj["library_sha256"]!=expected_library_sha256 or obj["source_sha256"]!=expected_source_sha256 or
            obj["fixture_sha256"]!=expected_fixture_sha256):raise ValueError("CUDA qualification identity mismatch")
    if not isinstance(obj["device_name"],str) or not obj["device_name"].strip():raise ValueError("CUDA device name is missing")
    if obj["explicit_device_selection"] is not True:raise ValueError("CUDA device selection was not explicitly qualified")
    stamp=_timestamp(obj["qualification_timestamp"],now=now)
    return CudaQualification(obj["library_sha256"],obj["source_sha256"],obj["fixture_sha256"],
        obj["result_sha256"],obj["device_name"],stamp,True,artifact_sha256(path))


def load_qualification_artifact(path: str|Path, *, expected_backend_type: str|None=None,
        expected_runner_sha256: str|None=None,expected_backend_sha256: str|None=None,
        expected_bitstream_sha256: str|None=None,expected_transport_version: str=PHK1_TRANSPORT_VERSION,
        expected_protocol_version: int=PHK1_PROTOCOL_VERSION,expected_vector_id: str=PHK1_VECTOR_ID,
        expected_library_sha256: str|None=None,expected_source_sha256: str|None=None,
        expected_fixture_sha256: str|None=None,now: datetime|None=None):
    """Single public loader dispatching only the versioned miner artifact format."""
    obj=_read_json(path);backend=obj.get("backend_type")
    if expected_backend_type and backend!=expected_backend_type:raise ValueError("qualification backend type mismatch")
    if backend==PHK1_BACKEND:
        if expected_runner_sha256 is None or expected_backend_sha256 is None:
            expected_runner_sha256,expected_backend_sha256=pinned_source_hashes()
        return validate_qualification_artifact(path,expected_runner_sha256=expected_runner_sha256,
            expected_backend_sha256=expected_backend_sha256,expected_bitstream_sha256=expected_bitstream_sha256,
            expected_transport_version=expected_transport_version,expected_protocol_version=expected_protocol_version,
            expected_vector_id=expected_vector_id,now=now)
    if backend==CUDA_BACKEND:
        return validate_cuda_qualification_artifact(path,expected_library_sha256=expected_library_sha256,
            expected_source_sha256=expected_source_sha256,expected_fixture_sha256=expected_fixture_sha256,now=now)
    raise ValueError("unknown qualification backend type")


def artifact_sha256(path: str|Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
