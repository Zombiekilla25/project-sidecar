from __future__ import annotations
from dataclasses import dataclass, field
import time
from .models import MiningJob, Candidate, Share
from .target import effective_share_target, compare_result

_VERIFICATION_SEAL=object()
@dataclass(frozen=True)
class Verification:
    accepted: bool
    reason: str
    share: Share | None = None
    computed_result: int | None = None
    target: int | None = None
    meets_share_target: bool = False
    candidate_valid: bool = False
    expected_digest: int | None = None
    actual_digest: int | None = None
    backend_reported_result: int | None = None
    elapsed_seconds: float = 0.0
    _seal: object = field(default=None,repr=False,compare=False)
    @property
    def authentic(self): return self._seal is _VERIFICATION_SEAL

def verify_candidate(job: MiningJob,candidate: Candidate,reference_verify=None,telemetry=None) -> Verification:
    if reference_verify is None:
        from .pearlhash import PearlHashCpuVerifier
        reference_verify=PearlHashCpuVerifier().verify
    start=time.perf_counter()
    def result(ok,reason,**kw):
        elapsed=time.perf_counter()-start
        if telemetry is not None:
            telemetry.record_stage("verification",elapsed)
            if not ok: telemetry.rejected_shares+=1
        return Verification(ok,reason,elapsed_seconds=elapsed,**kw)
    if not isinstance(candidate,Candidate): return result(False,"malformed-candidate")
    if candidate.job_id!=job.job_id or candidate.job_fingerprint!=job.fingerprint or candidate.generation!=job.generation:
        return result(False,"stale-or-mismatched-job")
    if not candidate.backend_valid or (candidate.gpu_result is not None and (candidate.gpu_result.job_fingerprint!=job.fingerprint or candidate.gpu_result.generation!=job.generation or candidate.gpu_result.nonce!=candidate.nonce or candidate.gpu_result.result_hash!=candidate.result_hash)) or any(x.correctness is not True or not x.raw_result_id or not x.canonical_result_id or x.job_fingerprint!=job.fingerprint or x.generation!=job.generation for x in candidate.fk_results):
        return result(False,"backend-invalid")
    if not isinstance(candidate.sigma,bytes) or len(candidate.sigma)!=32 or not isinstance(candidate.b_seed,bytes) or len(candidate.b_seed)!=32 or isinstance(candidate.nonce,bool) or not isinstance(candidate.nonce,int) or not 0<=candidate.nonce<1<<64:
        return result(False,"malformed-candidate")
    if isinstance(candidate.result_hash,bool) or not isinstance(candidate.result_hash,int) or not 0<=candidate.result_hash<1<<256:
        return result(False,"invalid-result-hash")
    try: ref=reference_verify(job,candidate)
    except Exception as e: return result(False,"reference-verification-error",actual_digest=candidate.result_hash)
    valid=bool(getattr(ref,"valid",ref))
    digest=getattr(ref,"digest",None)
    if digest is not None and digest!=candidate.result_hash:
        return result(False,"reference-digest-mismatch",computed_result=digest,actual_digest=candidate.result_hash,candidate_valid=False)
    # Candidate contract's PearlHash work factor follows the proof's tile dimensions and k.
    proof=candidate.proof
    try: factor=getattr(ref,"work_factor",None) or int(proof.k)*len(proof.a.row_indices)*len(proof.bt.row_indices)
    except Exception: return result(False,"malformed-proof",actual_digest=candidate.result_hash)
    try: target=effective_share_target(job.target,factor); meets=compare_result(candidate.result_hash,target)
    except ValueError: return result(False,"invalid-share-target",actual_digest=candidate.result_hash)
    if not valid: return result(False,"reference-verification-failed",computed_result=digest,target=target,meets_share_target=meets,candidate_valid=False,actual_digest=candidate.result_hash)
    if not meets: return result(False,"above-share-target",computed_result=digest,target=target,meets_share_target=False,candidate_valid=True,actual_digest=candidate.result_hash)
    share=Share(job.job_id,job.fingerprint,candidate)
    return result(True,"verified",share=share,computed_result=digest,target=target,meets_share_target=True,candidate_valid=True,expected_digest=digest,actual_digest=None,backend_reported_result=candidate.result_hash,_seal=_VERIFICATION_SEAL)
