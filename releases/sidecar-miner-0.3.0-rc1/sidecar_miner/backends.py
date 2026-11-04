from __future__ import annotations
import hashlib,time
from .models import MiningJob,Candidate,GpuResult
from .contracts import BackendResult,Fk33Backend,GpuBackend,ReferenceBackend,WorkBatch
from .cuda_backend import CudaPearlHashBackend
from .fk33_backend import RawBscanFk33Backend, MockPhk1Transport

class MockGpuBackend:
    """Offline mock; optional candidate_factory provides a reference proof candidate."""
    backend_id='gpu-mock';healthy=True
    def __init__(self,candidate_factory=None):self.prepared=None;self.batches=0;self.candidate_factory=candidate_factory
    def prepare_job(self,job):self.prepared=job
    def compute_batch(self,job_or_batch,batch_size=None):
        if not isinstance(job_or_batch,WorkBatch):
            job=job_or_batch
            if self.prepared is None or self.prepared.fingerprint!=job.fingerprint:raise RuntimeError('GPU job was not prepared')
            if batch_size is None or batch_size<1:raise ValueError('batch_size must be positive')
            self.batches+=1;return []
        batch=job_or_batch;job=self.prepared
        if job is None or job.fingerprint!=batch.job_fingerprint or job.generation!=batch.generation:raise RuntimeError('GPU batch belongs to an unprepared job')
        if self.candidate_factory is None:raise RuntimeError('GPU mock has no candidate factory for full offline mining')
        start=time.perf_counter();made=self.candidate_factory(job);self.batches+=1
        candidates=list(made) if isinstance(made,(list,tuple)) else [made]
        from dataclasses import replace
        for i,candidate in enumerate(candidates):
            result=GpuResult(batch.job_fingerprint,batch.generation,f'{batch.batch_id}-{i}',candidate.nonce,candidate,result_hash=candidate.result_hash,proof=candidate.proof,elapsed_seconds=time.perf_counter()-start)
            candidates[i]=replace(candidate,gpu_result=result)
        identity=hashlib.sha256(''.join(c.proof.to_base64() for c in candidates).encode()).hexdigest()
        payload=candidates[0] if len(candidates)==1 else tuple(candidates)
        return BackendResult(batch.job_fingerprint,batch.generation,batch.batch_id,self.backend_id,identity,identity,True,payload,(time.perf_counter()-start)*1e6,True,False,'candidate')

class MockFk33Backend:
    """Synthetic high-level FK result adapter; no hardware or transport I/O."""
    healthy=True
    def __init__(self,backend_id='fk-mock-0',fault=None,on_execute=None):self.backend_id=backend_id;self.fault=fault;self.on_execute=on_execute;self.prepared=None;self.batches=0
    def prepare_job(self,job):
        if self.fault=='disconnect':self.healthy=False;raise RuntimeError('mock FK disconnected')
        self.prepared=(job.fingerprint,job.generation)
    def execute_batch(self,batch:WorkBatch):
        start=time.perf_counter();self.batches+=1
        if self.on_execute:self.on_execute(batch)
        if self.fault=='timeout':return BackendResult(batch.job_fingerprint,batch.generation,batch.batch_id,self.backend_id,'timeout','timeout',False,None,None,True,True,'timeout')
        candidate=batch.context
        identity=hashlib.sha256(candidate.proof.to_base64().encode()).hexdigest()
        if self.fault=='stale':return BackendResult(batch.job_fingerprint,batch.generation-1,batch.batch_id,self.backend_id,'wrong','wrong',True,candidate,0,True,False,'invalid')
        correctness=self.fault!='wrong';canonical=identity if correctness else identity+'-wrong'
        return BackendResult(batch.job_fingerprint,batch.generation,batch.batch_id,self.backend_id,identity,canonical,correctness,candidate,(time.perf_counter()-start)*1e6,self.healthy,False,'raw-canonical-match' if correctness else 'mismatch')
    def prepare(self,job):return self.prepare_job(job)
    def execute(self,job,candidates):return [self.execute_batch(WorkBatch.create(job.fingerprint,job.generation,f'legacy-{i}',str(i).encode(),1)) for i,_ in enumerate(candidates)]

class UnavailableFk33Backend:
    backend_id='fk-unavailable';healthy=False
    def prepare_job(self,job):raise RuntimeError('FK33 backend unavailable')
    def execute_batch(self,batch):raise RuntimeError('FK33 backend unavailable')
    def prepare(self,job):return self.prepare_job(job)
    def execute(self,job,candidates):return self.execute_batch(None)

def timed_gpu_batch(backend,job,batch_size,telemetry):
    start=time.perf_counter()
    try:return backend.compute_batch(job,batch_size)
    finally:telemetry.record_stage('gpu_backend',time.perf_counter()-start)
def timed_fk_execute(backend,job,candidates,telemetry):
    start=time.perf_counter()
    try:return backend.execute(job,candidates)
    finally:telemetry.record_stage('fk_backend',time.perf_counter()-start)
