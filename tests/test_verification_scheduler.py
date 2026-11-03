import unittest
from types import SimpleNamespace
from sidecar_miner.models import Candidate,GpuResult,Fk33Result
from sidecar_miner.verification import verify_candidate,Verification
from sidecar_miner.backends import MockGpuBackend,UnavailableFk33Backend
from sidecar_miner.scheduler import Scheduler
from tests.reference_support import fixture_job

class VerificationPipelineTests(unittest.TestCase):
    def setUp(self):
        self.job=fixture_job(target=100)
        self.proof=SimpleNamespace(k=4,noise_rank=2,a=SimpleNamespace(row_indices=list(range(2)),root=b'0'*32),bt=SimpleNamespace(row_indices=list(range(2)),root=b'1'*32),moe=None)
        self.candidate=Candidate(self.job.job_id,self.job.fingerprint,self.proof,0,1,b'a'*32,b'b'*32,self.job.generation)
    def test_valid_candidate_gets_submission_eligibility(self):
        v=verify_candidate(self.job,self.candidate,lambda *_:SimpleNamespace(valid=True,digest=None))
        self.assertTrue(v.accepted); self.assertTrue(v.authentic); self.assertEqual(v.target,100*16); self.assertTrue(v.meets_share_target)
    def test_stale_unknown_malformed_or_target_miss_rejected(self):
        cases=[Candidate('unknown',self.job.fingerprint,self.proof,0,1,b'a'*32,b'b'*32,1),Candidate(self.job.job_id,'wrong',self.proof,0,1,b'a'*32,b'b'*32,1),Candidate(self.job.job_id,self.job.fingerprint,self.proof,0,1,b'a',b'b'*32,1),Candidate(self.job.job_id,self.job.fingerprint,self.proof,1<<20,1,b'a'*32,b'b'*32,1)]
        for c in cases:
            with self.subTest(c=c): self.assertFalse(verify_candidate(self.job,c,lambda *_:True).accepted)
    def test_reference_and_backend_gates(self):
        self.assertEqual(verify_candidate(self.job,self.candidate,lambda *_:False).reason,'reference-verification-failed')
        invalid=Candidate(self.job.job_id,self.job.fingerprint,self.proof,0,1,b'a'*32,b'b'*32,1,backend_valid=False)
        self.assertEqual(verify_candidate(self.job,invalid,lambda *_:True).reason,'backend-invalid')
        old_gpu=GpuResult(self.job.fingerprint,0,'batch',1)
        badgpu=Candidate(self.job.job_id,self.job.fingerprint,self.proof,0,1,b'a'*32,b'b'*32,1,gpu_result=old_gpu)
        self.assertEqual(verify_candidate(self.job,badgpu,lambda *_:True).reason,'backend-invalid')
        badfk=Fk33Result(self.job.fingerprint,1,'batch','raw','canonical',False)
        candidate=Candidate(self.job.job_id,self.job.fingerprint,self.proof,0,1,b'a'*32,b'b'*32,1,fk_results=(badfk,))
        self.assertEqual(verify_candidate(self.job,candidate,lambda *_:True).reason,'backend-invalid')
    def test_gpu_only_fk_failure_and_many_backend_contracts(self):
        gpu=MockGpuBackend(); gpu.prepare_job(self.job); self.assertEqual(gpu.compute_batch(self.job,1),[])
        sched=Scheduler('sidecar'); self.assertEqual(sched.run_fk_or_fallback(UnavailableFk33Backend(),self.job,[]),[])
        self.assertEqual((sched.mode,sched.fallback_count),('gpu-only',1))
        class B:
            def prepare(self,j): self.j=j
            def execute(self,j,c): return (j.fingerprint,len(c))
        s=Scheduler('sidecar'); self.assertEqual(s.run_fk_backends([B(),B()],self.job,[1]),[(self.job.fingerprint,1)]*2)
