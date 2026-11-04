from .contracts import BackendResult, ReferenceBackend, verify_accelerator_result

class ExactReference:
    """Test/adapter reference. Production passes the PearlHash CPU verifier adapter."""
    def __init__(self, verifier): self.verifier=verifier
    def verify(self,job,result):return bool(self.verifier(job,result))

def candidate_eligible(job_fingerprint,generation,result,reference):
    return verify_accelerator_result(job_fingerprint,generation,result,reference)
