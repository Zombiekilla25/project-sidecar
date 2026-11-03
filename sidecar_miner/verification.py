from __future__ import annotations
from dataclasses import dataclass, field
from .models import MiningJob, Candidate, Share

_VERIFICATION_SEAL = object()

@dataclass(frozen=True)
class Verification:
    accepted: bool
    reason: str
    share: Share | None = None
    _seal: object = field(default=None, repr=False, compare=False)
    @property
    def authentic(self): return self._seal is _VERIFICATION_SEAL

def verify_candidate(job: MiningJob, candidate: Candidate, reference_verify) -> Verification:
    if candidate.job_id != job.job_id or candidate.job_fingerprint != job.fingerprint:
        return Verification(False, "stale-or-mismatched-job")
    if not 0 <= candidate.result_hash < 1 << 256: return Verification(False, "invalid-result-hash")
    try: valid = bool(reference_verify(job, candidate))
    except Exception: valid = False
    if not valid: return Verification(False, "reference-verification-failed")
    if candidate.result_hash > job.target: return Verification(False, "above-share-target")
    return Verification(True, "verified", Share(job.job_id, job.fingerprint, candidate.proof, candidate.result_hash, candidate.submit_params), _VERIFICATION_SEAL)
