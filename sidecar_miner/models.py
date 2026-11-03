from __future__ import annotations
from dataclasses import dataclass, field
import hashlib, json, math, time

@dataclass(frozen=True)
class MiningJob:
    """Canonical PRL job. target is the pool's raw compact-target basis."""
    job_id: str
    sequence: int
    header: bytes
    target: int
    height: int
    cert_version: int
    difficulty: float | None = None
    received_at: float = field(default_factory=time.time, compare=False)
    clean: bool = False
    @classmethod
    def from_notify(cls, p: dict, sequence: int, difficulty=None):
        if not isinstance(p, dict): raise ValueError("notify params must be an object")
        required={"job_id","header","target","height","cert_version"}
        if not required.issubset(p): raise ValueError("notify missing required PRL fields: "+", ".join(sorted(required-set(p))))
        job_id=p["job_id"]
        if not isinstance(job_id,str) or not job_id or len(job_id)>256 or any(ord(c)<33 or ord(c)>126 for c in job_id): raise ValueError("invalid PRL job_id")
        header_hex=p["header"]; target_hex=p["target"]
        if not isinstance(header_hex,str) or len(header_hex)!=152: raise ValueError("PRL header must be 76-byte hex")
        if not isinstance(target_hex,str) or len(target_hex)!=64: raise ValueError("PRL target must be 32-byte hex")
        try: header=bytes.fromhex(header_hex); target=int(target_hex,16)
        except ValueError as e: raise ValueError("PRL header/target must be hexadecimal") from e
        if len(header)!=76 or not 0 < target < 1<<256: raise ValueError("invalid PRL header or target range")
        height=p["height"]; version=p["cert_version"]
        if isinstance(height,bool) or not isinstance(height,int) or not 0<=height<1<<64: raise ValueError("height outside uint64")
        if isinstance(version,bool) or not isinstance(version,int) or version not in (1,2,3): raise ValueError("unsupported cert_version")
        clean=p.get("clean",False)
        if not isinstance(clean,bool): raise ValueError("clean must be boolean when present")
        if difficulty is not None and (isinstance(difficulty,bool) or not isinstance(difficulty,(int,float)) or not math.isfinite(difficulty) or difficulty<=0): raise ValueError("invalid PRL difficulty state")
        return cls(job_id,sequence,header,target,height,version,float(difficulty) if difficulty is not None else None,time.time(),clean)
    def canonical(self):
        """Stable identity excludes arrival order/time and notification clean flag."""
        return json.dumps({"job_id":self.job_id,"header":self.header.hex(),"target":f"{self.target:064x}","height":self.height,"cert_version":self.cert_version},sort_keys=True,separators=(",",":"))
    @property
    def fingerprint(self): return hashlib.sha256(self.canonical().encode()).hexdigest()
    @property
    def generation(self): return self.sequence

@dataclass(frozen=True)
class GpuResult:
    job_fingerprint: str
    generation: int
    batch_id: str
    nonce: int
    candidate: object | None = None
    intermediate: object | None = None
    result_hash: int | None = None
    proof: object | None = None
    elapsed_seconds: float | None = None

@dataclass(frozen=True)
class Fk33Result:
    job_fingerprint: str
    generation: int
    batch_id: str
    raw_result_id: str
    canonical_result_id: str | None
    correctness: bool | None
    result: object | None = None
    elapsed_seconds: float | None = None
    backend_health: str = "unknown"

@dataclass(frozen=True)
class Candidate:
    job_id: str
    job_fingerprint: str
    proof: object
    result_hash: int  # backend-reported little-endian U256 digest; Rust oracle independently gates target
    nonce: int
    sigma: bytes
    b_seed: bytes
    generation: int
    gpu_result: GpuResult | None = None
    fk_results: tuple[Fk33Result,...] = ()
    backend_valid: bool = True

@dataclass(frozen=True)
class Share:
    job_id: str
    job_fingerprint: str
    candidate: Candidate
    submit_params: dict | None = None
