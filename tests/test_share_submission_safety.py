import unittest
from dataclasses import replace
from sidecar_miner.verification import verify_candidate
from sidecar_miner.share_encoder import build_prl_submit_params
from sidecar_miner.stratum import StratumClient,StratumError
from sidecar_miner.pearlhash import PearlHashCpuVerifier
from tests.reference_support import fixture_job,canonical_proof,candidate_for

class ShareSubmissionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.job=fixture_job(); self.proof=canonical_proof(self.job); self.candidate=candidate_for(self.job,self.proof)
    def test_verified_only_boundary_and_exact_fields(self):
        c=StratumClient('127.0.0.1',1,'fixture',timeout=.01); c.current_job=self.job
        rejected=verify_candidate(self.job,self.candidate,lambda *_:False)
        with self.assertRaises(StratumError): c.submit(rejected)
        verified=verify_candidate(self.job,self.candidate,PearlHashCpuVerifier().verify)
        self.assertTrue(verified.accepted,verified.reason)
        params=build_prl_submit_params(self.job,self.candidate)
        self.assertEqual(params['job_id'],self.job.job_id)
    def test_stale_job_and_job_fingerprint_mismatch_rejected(self):
        v=verify_candidate(self.job,self.candidate,PearlHashCpuVerifier().verify); self.assertTrue(v.accepted)
        c=StratumClient('127.0.0.1',1,'fixture'); c.current_job=replace(self.job,sequence=2)
        with self.assertRaises(StratumError): c.submit(v)
        with self.assertRaises(ValueError): build_prl_submit_params(replace(self.job,job_id='other'),self.candidate)
    def test_invalid_backend_unknown_job_and_malformed_candidate_rejected(self):
        c=StratumClient('127.0.0.1',1,'fixture'); c.current_job=self.job
        for bad in (replace(self.candidate,backend_valid=False),replace(self.candidate,job_id='unknown'),replace(self.candidate,nonce=1<<64)):
            v=verify_candidate(self.job,bad,PearlHashCpuVerifier().verify)
            self.assertFalse(v.accepted)
            with self.assertRaises(StratumError): c.submit(v)
    def test_target_miss_is_rejected_by_cpu_oracle(self):
        low=fixture_job(target=1); proof=canonical_proof(low); candidate=candidate_for(low,proof)
        v=verify_candidate(low,candidate,PearlHashCpuVerifier().verify)
        self.assertFalse(v.accepted)
