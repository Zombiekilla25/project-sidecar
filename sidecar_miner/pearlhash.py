"""Adapter for the authoritative local py-pearl-mining CPU consensus verifier."""
from __future__ import annotations
from dataclasses import dataclass
from .models import MiningJob,Candidate
from .target import target_to_compact,effective_share_target
from .pearlhash_fields import proof_context

@dataclass(frozen=True)
class ReferenceResult:
    valid: bool
    digest: int | None
    message: str
    work_factor: int | None = None

class PearlHashCpuVerifier:
    def __init__(self, oracle=None): self.oracle=oracle
    def _oracle(self):
        if self.oracle is None:
            try: import pearl_mining as pm
            except ImportError as e: raise RuntimeError("py-pearl-mining is required for CPU verification") from e
            self.oracle=pm
        return self.oracle
    def verify(self,job: MiningJob,candidate: Candidate) -> ReferenceResult:
        pm=self._oracle(); proof=candidate.proof
        if isinstance(proof,str): proof=pm.PlainProof.from_base64(proof)
        if not hasattr(proof,"to_base64") or not hasattr(proof,"a") or not hasattr(proof,"bt"):
            return ReferenceResult(False,None,"candidate is not a canonical PearlHash PlainProof")
        if proof.k<=0 or proof.noise_rank<=0 or not proof.a.row_indices or not proof.bt.row_indices:
            return ReferenceResult(False,None,"malformed PlainProof dimensions or tile")
        _,_,sigma,b_seed,factor=proof_context(job,proof,pm)
        if candidate.sigma!=sigma or candidate.b_seed!=b_seed: return ReferenceResult(False,None,"candidate seed fields mismatch PlainProof roots")
        bound=effective_share_target(job.target,factor)
        if candidate.result_hash>bound: return ReferenceResult(False,None,"reported PearlHash result exceeds scaled pool target",factor)
        compact=target_to_compact(job.target); header=pm.IncompleteBlockHeader.from_bytes(job.header)
        try: ok,msg=pm.verify_plain_proof_for_cert_version(job.cert_version,header,proof,nbits_override=compact)
        except AttributeError:
            fn=getattr(pm,f"verify_plain_proof_v{job.cert_version}",None)
            if fn is None: return ReferenceResult(False,None,"oracle lacks certificate-version verifier")
            ok,msg=fn(header,proof,nbits_override=compact)
        return ReferenceResult(bool(ok),None,str(msg),factor)
