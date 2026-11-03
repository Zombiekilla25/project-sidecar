import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from sidecar_miner.config import Config
class ConfigTests(unittest.TestCase):
    def test_local_env_settings_and_gpu_selection(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'c.json'; p.write_text('{"pool":"127.0.0.1:19000","worker":"local","gpu":"0,1"}')
            c=Config.load(str(p),{'SIDECAR_WALLET':'fixture-wallet','SIDECAR_MODE':'sidecar'})
        self.assertEqual((c.wallet,c.worker,c.gpu,c.mode),('fixture-wallet','local','0,1','sidecar'))
    def test_invalid_mode(self):
        with self.assertRaises(ValueError): Config.load(environ={'SIDECAR_MODE':'unsafe'})
