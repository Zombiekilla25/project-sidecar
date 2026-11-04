import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tools.phk1_raw_bscan.create_raw_target_lock import LockError,create_lock
from tools.phk1_raw_bscan.phk1_live_runner import AUTHORITATIVE_MAP_PATH,BITSTREAM_SHA

class RawLockTests(unittest.TestCase):
    def test_lock_created_from_fresh_log_and_readonly_sysfs(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"ops").mkdir(); (root/"evidence/run-1").mkdir(parents=True)
            (root/"ops/map.json").write_text(AUTHORITATIVE_MAP_PATH.read_text())
            xbt=root/"rollback-xbt.bit"; xbt.write_bytes(b"known-good-xbt-fixture")
            import hashlib
            binding={"phk1_bitstream_sha256":BITSTREAM_SHA,
                     "rollback_image_path":str(xbt),
                     "rollback_image_sha256":hashlib.sha256(xbt.read_bytes()).hexdigest()}
            (root/"binding.json").write_text(json.dumps(binding))
            image=root/"PHK1_FK33_CANARY.bit"; image.write_bytes(b"fixture")
            authority=json.loads((root/"ops/map.json").read_text())
            target=authority["phk1_canary_physical_id"]
            peer=authority["phk1_peer_physical_id"]
            cards=(authority["card_a"],authority["card_b"])
            tc=next(c for c in cards if c["ftdi_serial"]==target["ftdi_serial"])
            pc=next(c for c in cards if c["ftdi_serial"]==peer["ftdi_serial"])
            log=root/"evidence/run-1/phk1-single.log"
            log.write_text(f"Bitstream Loaded {image}\n{tc['sqrl_jtag_serial']}\nIDCODE(04b69093)\nDNA: 4000000001295d813c80a445\n")
            sysfs=root/"sys"; sysfs.mkdir()
            entries=[("1-9.3","153300000957"),("1-9.4","153300000711")]
            for i,(name,serial) in enumerate(entries,1):
                dev=sysfs/name; dev.mkdir()
                for key,value in {"serial":serial,"idVendor":"0403","idProduct":"6010",
                                  "busnum":str(i),"devnum":str(10+i)}.items():
                    (dev/key).write_text(value)
            def no_handles(argv,**kwargs): return SimpleNamespace(returncode=1,stdout="")
            lock=create_lock(log,root=root,map_path=root/"ops/map.json",binding_path=root/"binding.json",
                             sysfs=sysfs,lsof=no_handles,now=dt.datetime.now(dt.timezone.utc))
            self.assertEqual(lock["status"],"PASS")
            self.assertEqual(lock["run_id"],"run-1")
            self.assertEqual(lock["match_count"],1)
            self.assertEqual(lock["raw_device_handle_count"],0)
            self.assertEqual(lock["target"]["expected_phk1_bitstream_sha256"],BITSTREAM_SHA)
            required={"usb_path","ftdi_serial","vid","pid","interface","idcode","dna","bridge_endpoint","miner_binding"}
            self.assertTrue(required.issubset(lock["peer"]))
            self.assertEqual(lock["peer"]["interface"],pc["ftdi_interface"])
            self.assertEqual(lock["peer"]["bridge_endpoint"],pc["bridge_endpoint"])
            self.assertEqual(lock["peer"]["miner_binding"],pc["miner_binding"])
            self.assertEqual(lock["target"]["interface"],tc["ftdi_interface"])
            baseline_log=root/"evidence/run-1/baseline-xbt.log"
            baseline_log.write_text(f"Bitstream Loaded {xbt}\n{tc['sqrl_jtag_serial']}\nIDCODE(04b69093)\nDNA: 4000000001295d813c80a445\n")
            baseline=create_lock(baseline_log,root=root,map_path=root/"ops/map.json",
                                 binding_path=root/"binding.json",sysfs=sysfs,lsof=no_handles,
                                 now=dt.datetime.now(dt.timezone.utc),image_kind="xbt")
            self.assertEqual(baseline["loaded_image_kind"],"xbt")
            self.assertEqual(baseline["loaded_image_sha256"],binding["rollback_image_sha256"])
            self.assertEqual(baseline["target"]["expected_phk1_bitstream_sha256"],BITSTREAM_SHA)
            target=authority["phk1_canary_physical_id"]; peer=authority["phk1_peer_physical_id"]
            cards=(authority["card_a"],authority["card_b"])
            tc=next(c for c in cards if c["ftdi_serial"]==target["ftdi_serial"])
            pc=next(c for c in cards if c["ftdi_serial"]==peer["ftdi_serial"])
            identity_log=root/"evidence/run-1/bridge.log"
            identity_log.write_text(f"{tc['sqrl_jtag_serial']}\\n{pc['sqrl_jtag_serial']}\\nIDCODE({target['idcode']})\\nIDCODE({peer['idcode']})\\nDNA: {target['dna']}\\nDNA: {peer['dna']}\\n")
            identity=create_lock(identity_log,root=root,map_path=root/"ops/map.json",
                                 binding_path=root/"binding.json",sysfs=sysfs,lsof=no_handles,
                                 now=dt.datetime.now(dt.timezone.utc),image_kind="identity")
            self.assertIsNone(identity["loaded_image_sha256"])
            self.assertEqual(identity["target"]["role"],"PHK1_CANARY")
            self.assertTrue(required.issubset(identity["peer"]))

    def test_lock_fails_if_usb_or_owner_state_is_ambiguous(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); (root/"ops").mkdir(); (root/"evidence/run-1").mkdir(parents=True)
            (root/"ops/map.json").write_text(AUTHORITATIVE_MAP_PATH.read_text())
            (root/"binding.json").write_text(json.dumps({"phk1_bitstream_sha256":BITSTREAM_SHA}))
            image=root/"PHK1_FK33_CANARY.bit"; image.write_bytes(b"x")
            log=root/"evidence/run-1/phk1-single.log"
            log.write_text(f"Bitstream Loaded {image}\nIDCODE(04b69093)\nDNA: 4000000001295d813c80a445\n")
            sysfs=root/"sys"; sysfs.mkdir()
            # A missing serial match must fail before a lock is issued.
            with self.assertRaises(LockError):
                create_lock(log,root=root,map_path=root/"ops/map.json",binding_path=root/"binding.json",sysfs=sysfs)

if __name__=="__main__": unittest.main(verbosity=2)
