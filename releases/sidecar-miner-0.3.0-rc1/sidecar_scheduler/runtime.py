from __future__ import annotations
from dataclasses import dataclass,field
from .contracts import BackendResult, ReferenceBackend, verify_accelerator_result

@dataclass
class FallbackController:
    max_latency_us:float|None=None
    unhealthy:set[str]=field(default_factory=set)
    fallback_count:int=0
    def eligible(self,backend_id):return backend_id not in self.unhealthy
    def accept_fk_result(self,job_fingerprint,generation,result:BackendResult,reference:ReferenceBackend):
        reason=None
        if result.timed_out:reason='timeout'
        elif not result.healthy:reason='backend_unhealthy'
        elif self.max_latency_us is not None and (result.elapsed_us is None or result.elapsed_us>self.max_latency_us):reason='slow_response'
        elif not verify_accelerator_result(job_fingerprint,generation,result,reference):reason='incorrect_or_stale_result'
        if reason:
            self.unhealthy.add(result.backend_id);self.fallback_count+=1
            return False,reason
        return True,'verified'
    def route_or_fallback(self,job_fingerprint,generation,result,gpu_candidates,reference):
        ok,reason=self.accept_fk_result(job_fingerprint,generation,result,reference)
        return (result.payload,'fk_verified') if ok else (gpu_candidates,'gpu_fallback:'+reason)
    def remaining_fleet(self,backend_ids):return [x for x in backend_ids if self.eligible(x)]
    def gpu_fallback_required(self,backend_ids):return not self.remaining_fleet(backend_ids)
