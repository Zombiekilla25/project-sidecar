from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from tools.phk1_raw_bscan.create_raw_target_lock import LockError, complete_peer_identity
from tools.phk1_raw_bscan.live_target_lock_v2 import physical_from_identity_lock, V2LockError
from tools.phk1_raw_bscan.phk1_live_runner import AUTHORITATIVE_MAP_PATH

PROJECT=Path(__file__).resolve().parents[2]
ATTEMPT=Path(os.environ.get("PHK1_V2_ATTEMPT_EVIDENCE",
    str(PROJECT/"sidecar-evidence/phk1-patched-live-canary-20261104/20261104T191344Z")))
REQUIRED={"usb_path","ftdi_serial","vid","pid","interface","idcode","dna","bridge_endpoint","miner_binding"}


class PeerIdentityHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.authority=json.loads(AUTHORITATIVE_MAP_PATH.read_text())
        cls.failed=json.loads((ATTEMPT/"FRESH_PHYSICAL_TARGET_LOCK.json").read_text())

    def test_exact_failed_input_and_authoritative_completion(self):
        peer=self.failed["peer"]
        self.assertEqual(REQUIRED-set(peer),
            {"vid","pid","interface","bridge_endpoint","miner_binding"})
        current=dict(self.failed); current["captured_utc"]=datetime.now(timezone.utc).isoformat()
        with self.assertRaises(V2LockError):
            physical_from_identity_lock(current)
        completed=complete_peer_identity(peer,self.authority)
        self.assertTrue(REQUIRED.issubset(completed))
        current["peer"]={**completed,"role":"PEER"}
        target,peer_v2=physical_from_identity_lock(current)
        self.assertNotEqual(target,peer_v2)
        mapped=self.authority["phk1_peer_physical_id"]
        card=next(c for c in (self.authority["card_a"],self.authority["card_b"])
                  if c["ftdi_serial"]==mapped["ftdi_serial"])
        self.assertEqual(completed["vid"],card["vid"].lower())
        self.assertEqual(completed["pid"],card["pid"].lower())
        self.assertEqual(completed["interface"],card["ftdi_interface"])
        self.assertEqual(completed["bridge_endpoint"],card["bridge_endpoint"])
        self.assertEqual(completed["miner_binding"],card["miner_binding"])

    def test_wrong_peer_identity_inputs_fail_closed(self):
        source=self.failed["peer"]
        cases=[]
        for key,value in (("ftdi_serial","wrong-serial"),("usb_path","9-9.9"),
                          ("idcode","00000000"),("dna","wrong-dna"),
                          ("vid","ffff"),("miner_binding","stale-workload-binding")):
            altered=deepcopy(source); altered[key]=value
            cases.append((key,altered,deepcopy(self.authority)))
        missing=deepcopy(source); missing.pop("dna")
        cases.append(("missing-dna",missing,deepcopy(self.authority)))
        bad_map=deepcopy(self.authority)
        peer_card=next(c for c in (bad_map["card_a"],bad_map["card_b"])
                       if c["ftdi_serial"]==bad_map["phk1_peer_physical_id"]["ftdi_serial"])
        peer_card.pop("ftdi_interface")
        cases.append(("missing-mapped-interface",deepcopy(source),bad_map))
        target_as_peer=deepcopy(self.authority)
        target_as_peer["phk1_peer_physical_id"]=deepcopy(target_as_peer["phk1_canary_physical_id"])
        target_values=self.failed["target"]
        same={"usb_path":target_values["usb_path"],"ftdi_serial":target_values["ftdi_serial"],
              "idcode":target_values["idcode"],"dna":target_values["dna"],
              "vid":target_values["vid"],"pid":target_values["pid"]}
        cases.append(("peer-equals-target",same,target_as_peer))
        passed=0
        for label,observed,authority in cases:
            with self.subTest(case=label), self.assertRaises(LockError):
                complete_peer_identity(observed,authority)
            passed+=1
        self.assertEqual(passed,9)


if __name__=="__main__": unittest.main(verbosity=2)
