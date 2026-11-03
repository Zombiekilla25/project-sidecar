import unittest
from sidecar_miner.models import MiningJob
from sidecar_miner.config import Config

def payload(job_id='fixture-1', target=(1<<255)):
    return {'job_id':job_id,'header':bytes(range(76)).hex(),'target':f'{target:064x}','height':123,'cert_version':2}

class JobModelTests(unittest.TestCase):
    def test_fingerprint_stable_and_sequence_sensitive(self):
        a=MiningJob.from_notify(payload(),1,2.0); b=MiningJob.from_notify(payload(),1,2.0); c=MiningJob.from_notify(payload(),2,2.0)
        self.assertEqual(a.fingerprint,b.fingerprint); self.assertNotEqual(a.fingerprint,c.fingerprint)
        self.assertEqual(MiningJob.from_notify(payload(),1).header,bytes(range(76)))
    def test_invalid_prl_job_rejected(self):
        with self.assertRaises(ValueError): MiningJob.from_notify({'job_id':'x','header':'00','target':'ff'},1)

class ConfigTests(unittest.TestCase):
    def test_environment_overrides_local_config(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        with TemporaryDirectory() as d:
            p=Path(d)/'c.json'; p.write_text('{"pool":"fixture:1","worker":"json-worker"}')
            c=Config.load(str(p),{'SIDECAR_WALLET':'local-only','SIDECAR_MODE':'sidecar'})
        self.assertEqual((c.pool,c.wallet,c.worker,c.mode),('fixture:1','local-only','json-worker','sidecar'))
    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError): Config.load(environ={'SIDECAR_MODE':'unsafe'})
