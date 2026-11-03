import pearl_mining as pm
from sidecar_miner.models import MiningJob,Candidate
from sidecar_miner.pearlhash_fields import proof_context
COMPACT_EASY=0x2100ffff
def fixture_job(target=None,sequence=1,job_id='offline-job'):
    raw=pm.IncompleteBlockHeader(0,b'\0'*32,b'1'*32,0x66666666,COMPACT_EASY).to_bytes()
    target=target if target is not None else (0xffff<<240)
    return MiningJob(job_id,sequence,raw,target,12345,2)
def canonical_proof(job):
    rows=pm.PeriodicPattern.from_list(list(range(16)))
    config=pm.MiningConfiguration(2048,128,pm.MMAType.Int7xInt7ToInt32,rows,rows)
    return pm.mine(256,256,2048,pm.IncompleteBlockHeader.from_bytes(job.header),config,cert_version=job.cert_version)
def candidate_for(job,proof,nonce=1,result_hash=0,**kw):
    _,_,sigma,b_seed,_=proof_context(job,proof,pm)
    return Candidate(job.job_id,job.fingerprint,proof,result_hash,nonce,sigma,b_seed,job.generation,**kw)
