"""Joins PRL job handling, timing scheduler, typed backends, verification, and submission."""
from __future__ import annotations
from dataclasses import dataclass,replace
import hashlib,time
from sidecar_scheduler.contracts import BackendResult,WorkBatch
from sidecar_scheduler.fleet import assign_batches
from sidecar_scheduler.queueing import Backpressure
from sidecar_scheduler.runtime import FallbackController
from .models import MiningJob,Candidate,Fk33Result
from .integrated_scheduler import IntegratedScheduler
from .verification import verify_candidate
from .telemetry import Telemetry

@dataclass(frozen=True)
class IntegrationOutcome:
    choice:object
    gpu_results:tuple
    candidates:tuple[Candidate,...]
    verifications:tuple
    submissions:tuple

class IntegratedMiner:
    def __init__(self,scheduler:IntegratedScheduler,gpu_backend,reference_verify=None,telemetry=None,fk_timeout_us=None,current_job_provider=None,assignment_policy='least_loaded'):
        self.scheduler=scheduler;self.gpu=gpu_backend;self.reference_verify=reference_verify;self.telemetry=telemetry or Telemetry()
        self.fallback=FallbackController(max_latency_us=fk_timeout_us);self.queues=Backpressure(max_gpu_to_fk=8,max_fk_to_verify=8)
        self.current_job_provider=current_job_provider;self.current_job=None;self.assignment_policy=assignment_policy
    def on_job(self,job:MiningJob):
        if self.current_job is not None and job.generation<=self.current_job.generation:raise ValueError('job generation must increase')
        self.current_job=job
        if job.generation>self.queues.generation:self.queues.new_generation(job.generation)
        self.telemetry.current_job_id=job.job_id;self.telemetry.job_generation=job.generation;self.telemetry.job_received_at=job.received_at
    def _current(self,job):
        current=self.current_job_provider() if self.current_job_provider else self.current_job
        return current is not None and current.fingerprint==job.fingerprint and current.generation==job.generation
    def _encode_candidate_identity(self,candidate):
        raw=candidate.proof.to_base64().encode('ascii');return raw,hashlib.sha256(raw).hexdigest()
    def _reference_verify(self,job,candidate):return verify_candidate(job,candidate,self.reference_verify,self.telemetry)
    def _reference_adapter(self,job):
        outer=self
        class Adapter:
            def verify(inner,_job,result):
                candidate=result.payload
                return isinstance(candidate,Candidate) and outer._reference_verify(job,candidate).accepted
        return Adapter()
    def _gpu_candidates(self,result,job,expected_batch_id):
        if not isinstance(result,BackendResult) or not result.healthy or result.correctness is not True:return []
        if (result.job_fingerprint,result.generation)!=(job.fingerprint,job.generation) or result.batch_id!=expected_batch_id:return []
        payload=result.payload;candidates=list(payload) if isinstance(payload,(list,tuple)) else [payload]
        if not candidates or any(not isinstance(c,Candidate) or c.job_fingerprint!=job.fingerprint or c.generation!=job.generation for c in candidates):return []
        return candidates
    def process_job(self,job:MiningJob,batch_size=1,submitter=None):
        started_total=time.perf_counter()
        if self.current_job is None or job.generation>self.current_job.generation:self.on_job(job)
        if not self._current(job):self.telemetry.stale_shares+=1;self.telemetry.stale_results+=1;return IntegrationOutcome(None,(),(),(),())
        choice=self.scheduler.choose(job);self.telemetry.mode=choice.mode;self.telemetry.scheduler_decision=choice.decision.value
        self.telemetry.backend_health={getattr(b,'backend_id',f'fk-{i}'):'healthy' if getattr(b,'healthy',True) else 'unhealthy' for i,b in enumerate(self.scheduler.fk_backends)}
        self.telemetry.backend_health[getattr(self.gpu,'backend_id','gpu')]='healthy' if getattr(self.gpu,'healthy',True) else 'unhealthy'
        if self.scheduler.mode=='sidecar' and not self.scheduler.healthy_fks():raise RuntimeError('sidecar mode requires a healthy FK backend')
        self.gpu.prepare_job(job);self.telemetry.gpu_jobs+=1
        batch_id=f'{job.generation}-gpu-0';gpu_batch=WorkBatch.create(job.fingerprint,job.generation,batch_id,job.header,batch_size,assignment=(getattr(self.gpu,'backend_id','gpu'),),context=job)
        if choice.mode=='sidecar' and not self.queues.enqueue_gpu(gpu_batch):raise RuntimeError('GPU→FK queue is full')
        started=time.perf_counter()
        try:gpu_result=self.gpu.compute_batch(gpu_batch)
        except Exception:self.telemetry.rejected_shares+=1;raise
        finally:
            elapsed=time.perf_counter()-started;self.telemetry.record_stage('gpu_backend',elapsed);self.telemetry.gpu_seconds+=elapsed;self.telemetry.gpu_batches+=1
        gpu_candidates=self._gpu_candidates(gpu_result,job,gpu_batch.batch_id)
        if not gpu_candidates:
            self.telemetry.backend_health[getattr(self.gpu,'backend_id','gpu')]='unhealthy';self.telemetry.rejected_shares+=1;return IntegrationOutcome(choice,(gpu_result,),(),(),())
        if not self._current(job):self.telemetry.stale_shares+=1;self.telemetry.stale_results+=1;return IntegrationOutcome(choice,(gpu_result,),(),(),())
        final_candidates=[]
        if choice.mode=='sidecar':
            queued=self.queues.take_fk()
            if queued is None or queued.job_fingerprint!=job.fingerprint or queued.generation!=job.generation:
                self.telemetry.stale_results+=1;self.telemetry.fallback_count+=1;final_candidates=list(gpu_candidates)
            else:
                healthy=self.scheduler.healthy_fks();assignments=assign_batches(len(gpu_candidates),len(healthy),self.assignment_policy);used_indices=set()
                for fk_index,indices in enumerate(assignments):
                    if not indices:continue
                    backend=healthy[fk_index]
                    for candidate_index in indices:
                        candidate=gpu_candidates[candidate_index]
                        try:
                            backend.prepare_job(job);proof_bytes,_=self._encode_candidate_identity(candidate)
                            fk_batch=WorkBatch.create(job.fingerprint,job.generation,f'{job.generation}-{backend.backend_id}-{candidate_index}',proof_bytes,1,assignment=(backend.backend_id,),deadline_monotonic=time.monotonic()+5.0,context=candidate)
                            if not self.queues.start_active(fk_batch):raise RuntimeError('FK batch is stale before dispatch')
                            self.telemetry.fk_jobs+=1;self.telemetry.fk_batches+=1
                            started_fk=time.perf_counter();fk_result=backend.execute_batch(fk_batch);elapsed=time.perf_counter()-started_fk
                            self.telemetry.record_stage('fk_backend',elapsed);self.telemetry.fk_seconds+=elapsed
                            known=fk_result.timings_us
                            if known.get('input_stream_us') is not None and known.get('output_stream_us') is not None:self.telemetry.fk_transfer_seconds=(self.telemetry.fk_transfer_seconds or 0.0)+(known['input_stream_us']+known['output_stream_us'])/1e6
                            if known.get('fpga_compute_us') is not None:self.telemetry.fk_compute_seconds=(self.telemetry.fk_compute_seconds or 0.0)+known['fpga_compute_us']/1e6
                            if time.monotonic()>fk_batch.deadline_monotonic and not fk_result.timed_out:fk_result=replace(fk_result,timed_out=True)
                            active_ok=self.queues.accepts_active(fk_batch.batch_id,fk_result.generation)
                            self.queues.finish_active(fk_batch.batch_id)
                            if not self._current(job):self.telemetry.stale_shares+=1;self.telemetry.stale_results+=1;self.telemetry.fallback_count+=1;return IntegrationOutcome(choice,(gpu_result,fk_result),(),(),())
                            if not active_ok:
                                backend.healthy=False;self.fallback.unhealthy.add(backend.backend_id);self.telemetry.backend_health=self.telemetry.backend_health or {};self.telemetry.backend_health[backend.backend_id]='unhealthy';self.telemetry.stale_results+=1;self.telemetry.fallback_count+=1;continue
                            payload_candidate=fk_result.payload
                            identity_matches=isinstance(payload_candidate,Candidate) and self._encode_candidate_identity(payload_candidate)[1]==self._encode_candidate_identity(candidate)[1]
                            if fk_result.batch_id!=fk_batch.batch_id or fk_result.backend_id!=backend.backend_id or not identity_matches:fk_result=replace(fk_result,correctness=False)
                            ok,_reason=self.fallback.accept_fk_result(job.fingerprint,job.generation,fk_result,self._reference_adapter(job))
                            if ok and self.queues.enqueue_verify(fk_result):
                                verified_result=self.queues.take_verify();candidate_out=verified_result.payload
                                fkmark=Fk33Result(verified_result.job_fingerprint,verified_result.generation,verified_result.batch_id,verified_result.raw_result_identity,verified_result.canonical_result_identity,True,verified_result.payload,elapsed,backend_health='healthy')
                                final_candidates.append(replace(candidate_out,fk_results=candidate_out.fk_results+(fkmark,)));used_indices.add(candidate_index)
                            else:
                                backend.healthy=False;self.fallback.unhealthy.add(backend.backend_id);self.telemetry.backend_health=self.telemetry.backend_health or {};self.telemetry.backend_health[backend.backend_id]='unhealthy';self.telemetry.fallback_count+=1
                        except Exception:
                            backend.healthy=False;self.fallback.unhealthy.add(backend.backend_id);self.telemetry.backend_health=self.telemetry.backend_health or {};self.telemetry.backend_health[backend.backend_id]='unhealthy';self.fallback.fallback_count+=1;self.telemetry.fallback_count+=1
                for i,candidate in enumerate(gpu_candidates):
                    if i not in used_indices:final_candidates.append(candidate)
        else:final_candidates=list(gpu_candidates)
        verifications=[];submissions=[]
        for candidate in final_candidates:
            if not self._current(job):self.telemetry.stale_shares+=1;self.telemetry.stale_results+=1;continue
            result=self._reference_verify(job,candidate);verifications.append(result);self.telemetry.verification_seconds+=result.elapsed_seconds
            if result.accepted and submitter is not None:
                if not self._current(job):self.telemetry.stale_shares+=1;self.telemetry.stale_results+=1;continue
                submissions.append(submitter.submit(result))
        self.telemetry.end_to_end_seconds+=time.perf_counter()-started_total
        return IntegrationOutcome(choice,(gpu_result,),tuple(final_candidates),tuple(verifications),tuple(submissions))
