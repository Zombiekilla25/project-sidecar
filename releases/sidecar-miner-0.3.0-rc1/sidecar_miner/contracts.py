"""Canonical high-level contracts shared by the miner and its scheduler."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, Any
import hashlib, json, time

@dataclass(frozen=True)
class WorkBatch:
    job_fingerprint: str
    generation: int
    batch_id: str
    item_count: int
    input_identity: str
    input_sha256: str
    assignment: tuple[str,...] = ()
    deadline_monotonic: float|None = None
    created_monotonic: float = field(default_factory=time.monotonic)
    timings_us: dict[str,float|None] = field(default_factory=dict)
    context: Any = field(default=None,repr=False,compare=False)
    @classmethod
    def create(cls,job_fingerprint,generation,batch_id,payload:bytes,item_count,**kw):
        if not job_fingerprint or generation<0 or not batch_id or item_count<=0:raise ValueError('invalid batch identity/count')
        sha=hashlib.sha256(payload).hexdigest()
        return cls(job_fingerprint,generation,batch_id,item_count,sha,sha,**kw)
    def canonical(self):
        return json.dumps({'job_fingerprint':self.job_fingerprint,'generation':self.generation,'batch_id':self.batch_id,'item_count':self.item_count,'input_identity':self.input_identity,'input_sha256':self.input_sha256,'assignment':list(self.assignment)},sort_keys=True,separators=(',',':'))

@dataclass(frozen=True)
class BackendResult:
    job_fingerprint: str
    generation: int
    batch_id: str
    backend_id: str
    raw_result_identity: str
    canonical_result_identity: str|None
    correctness: bool|None
    payload: Any = None
    elapsed_us: float|None = None
    healthy: bool = True
    timed_out: bool = False
    verification_status: str = 'unverified'
    timings_us: dict[str,float|None] = field(default_factory=dict)

def raw_canonical_match(result:BackendResult)->bool:
    return bool(result.raw_result_identity and result.canonical_result_identity and result.raw_result_identity==result.canonical_result_identity)

class GpuBackend(Protocol):
    backend_id:str
    healthy:bool
    def prepare_job(self,job:Any)->None:...
    def compute_batch(self,batch:WorkBatch)->BackendResult:...

class Fk33Backend(Protocol):
    backend_id:str
    healthy:bool
    def prepare_job(self,job:Any)->None:...
    def execute_batch(self,batch:WorkBatch)->BackendResult:...

class ReferenceBackend(Protocol):
    def verify(self,job:Any,result:BackendResult)->bool:...
