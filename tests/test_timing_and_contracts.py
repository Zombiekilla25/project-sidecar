import unittest
from sidecar_miner.models import GpuResult,Fk33Result
from sidecar_miner.backends import MockGpuBackend,timed_gpu_batch,timed_fk_execute
from sidecar_miner.telemetry import Telemetry
from sidecar_miner.scheduler import Scheduler
from tests.reference_support import fixture_job

class BackendResultAndTimingContracts(unittest.TestCase):
    def test_timing_hooks_for_gpu_and_fk(self):
        job=fixture_job(); telemetry=Telemetry(); gpu=MockGpuBackend(); gpu.prepare_job(job)
        timed_gpu_batch(gpu,job,1,telemetry)
        class Fk:
            def execute(self,job,candidates): return candidates
        timed_fk_execute(Fk(),job,[],telemetry)
        self.assertGreaterEqual(telemetry.stage_seconds['gpu_backend'],0)
        self.assertGreaterEqual(telemetry.stage_seconds['fk_backend'],0)
    def test_gpu_and_fk_results_carry_job_generation_and_identity(self):
        gpu=GpuResult('fp',3,'batch',7,candidate='candidate',intermediate={'phase':1},result_hash=5,proof='proof',elapsed_seconds=.01)
        fk=Fk33Result('fp',3,'batch','raw-id','canonical-id',True,result='result',elapsed_seconds=.02,backend_health='healthy')
        self.assertEqual((gpu.job_fingerprint,gpu.generation,gpu.batch_id,gpu.nonce,gpu.result_hash),('fp',3,'batch',7,5))
        self.assertEqual((fk.raw_result_id,fk.canonical_result_id,fk.correctness,fk.backend_health),('raw-id','canonical-id',True,'healthy'))
