import unittest
from sidecar_miner.models import MiningJob,Candidate
from sidecar_miner.verification import verify_candidate
from sidecar_miner.backends import MockGpuBackend,UnavailableFk33Backend
from sidecar_miner.scheduler import Scheduler

def job(): return MiningJob.from_notify({'job_id':'j','header':bytes(76).hex(),'target':f'{1<<250:064x}'},1)
def candidate(j,h=1,fp=None): return Candidate(j.job_id,fp or j.fingerprint,{'fixture':True},h,{'job_id':j.job_id,'type':'v2','plain_proof':'fixture'})

class VerificationTests(unittest.TestCase):
    def test_verified_candidate_becomes_share(self):
        j=job(); r=verify_candidate(j,candidate(j),lambda *_:True)
        self.assertTrue(r.accepted); self.assertEqual(r.share.job_fingerprint,j.fingerprint)
    def test_unverified_stale_and_above_target_blocked(self):
        j=job()
        self.assertFalse(verify_candidate(j,candidate(j,fp='wrong'),lambda *_:True).accepted)
        self.assertFalse(verify_candidate(j,candidate(j),lambda *_:False).accepted)
        self.assertEqual(verify_candidate(j,candidate(j,1<<251),lambda *_:True).reason,'above-share-target')

class GpuFallbackTests(unittest.TestCase):
    def test_gpu_only_and_fk_failure_fallback(self):
        j=job(); gpu=MockGpuBackend(); gpu.prepare_job(j); self.assertEqual(gpu.compute_batch(j,1),[])
        sched=Scheduler('sidecar'); self.assertEqual(sched.run_fk_or_fallback(UnavailableFk33Backend(),j,[]),[])
        self.assertEqual((sched.mode,sched.fallback_count),('gpu-only',1))
