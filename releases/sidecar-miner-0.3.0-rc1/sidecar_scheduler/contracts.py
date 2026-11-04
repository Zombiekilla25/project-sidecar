"""Compatibility exports for the miner's canonical contracts."""
from sidecar_miner.contracts import BackendResult, Fk33Backend, GpuBackend, ReferenceBackend, WorkBatch, raw_canonical_match

def verify_accelerator_result(job_fingerprint,generation,result,reference):
    if result.timed_out or not result.healthy or result.correctness is not True:return False
    if result.job_fingerprint!=job_fingerprint or result.generation!=generation:return False
    if not raw_canonical_match(result):return False
    try:return bool(reference.verify({'fingerprint':job_fingerprint,'generation':generation},result))
    except Exception:return False

__all__=['BackendResult','WorkBatch','GpuBackend','Fk33Backend','ReferenceBackend','raw_canonical_match','verify_accelerator_result']
