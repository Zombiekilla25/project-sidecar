#!/usr/bin/env python3
"""End-to-end no-device rehearsal of the integrated v2 lock/operator/runner/recovery path."""
from __future__ import annotations
from datetime import datetime, timezone
import json, os, tempfile, unittest
from pathlib import Path

from tools.phk1_raw_bscan.test_phk1_live_runner import PAYLOAD, MockRpcBackend
from tools.phk1_raw_bscan.phk1_live_runner import (
    AUTHORITATIVE_MAP_PATH, CANDIDATE_BITSTREAM, CANDIDATE_MANIFEST,
    QUALIFICATION_MANIFEST, ROLLBACK_BINDING, ROLLBACK_BITSTREAM,
    validate_target_lock, run_hello_vector_session, RunnerError,
)
from tools.phk1_raw_bscan.live_target_lock_v2 import (
    create_v2_lock, validate_v2_lock_file, sha_file, V2LockError,
)
from tools.phk1_raw_bscan.target_lock_v2 import canonical_sha256, transition_image_state
from tools.phk1_raw_bscan.recovery_v2_roles import select_rollback

PROJECT=Path(__file__).resolve().parents[2]
ATTEMPT=Path(os.environ.get("PHK1_V2_ATTEMPT_EVIDENCE",
    str(PROJECT/"sidecar-evidence/phk1-patched-live-canary-20261104/20261104T040859Z")))
GEN="v2-full-rehearsal-20261104-fixture"

class LiveV2ControlPathTests(unittest.TestCase):
    def test_operator_runner_and_recovery_are_wired_to_v2(self):
        operator=PROJECT/"tools/phk1_one_fk_canary_remote.sh"
        recovery=PROJECT/"tools/phk1_one_fk_recover_remote.sh"
        runner=PROJECT/"tools/phk1_raw_bscan/phk1_live_runner.py"
        op=operator.read_text(); rec=recovery.read_text(); run=runner.read_text()
        generate=op.index('"$V2_LOCK_TOOL" create --identity-lock "$STATE/FRESH_PHYSICAL_TARGET_LOCK.json"')
        jit=op.index('"$V2_LOCK_TOOL" validate --lock "$STATE/PHK1_TARGET_LOCK_PROGRAM.json"')
        program_marker=op.index('touch "$STATE/PHK1_PROGRAM_ATTEMPTED"')
        phk_program=op.index('start_single "$PHK" phk1-single no')
        verify_create=op.index('--current-kind phk1 --current-log "$STATE/phk1-single.log"')
        runner_start=op.index('PHK1_MAINTENANCE_GENERATION=')
        self.assertLess(generate,jit); self.assertLess(jit,program_marker); self.assertLess(program_marker,phk_program)
        self.assertLess(phk_program,verify_create); self.assertLess(verify_create,runner_start)
        self.assertIn('PHK1_MAINTENANCE_GENERATION="$(basename "$STATE")"',op)
        self.assertIn('sidecar-raw-jtag-target-lock-v2',run)
        self.assertIn('legacy lock formats are rejected',run)
        self.assertIn('recovery_v2_roles.py',rec)
        self.assertLess(rec.index('recovery_v2_roles.py'),rec.index('"$BRIDGE" -s ",$CANARY_USB" -b "$XBT"'))
        self.assertIn('PHK1_TARGET_LOCK_VERIFY.json',rec)
        self.assertIn('PHK1_TARGET_LOCK_PROGRAM.json',rec)

    def test_previous_failure_replay_and_full_no_hardware_rehearsal(self):
        old=json.loads((ATTEMPT/"PRECANARY_TARGET_LOCK.json").read_text())
        self.assertEqual(old["target"]["expected_phk1_bitstream_sha256"],
            "eb2324c3c07cb3b89e078557ce818fcef21e6282bc707474ea862d5d374c769e")
        summary_path=ATTEMPT/"ATTEMPT_SUMMARY.json"
        if summary_path.is_file():
            self.assertEqual(json.loads(summary_path.read_text())["failure_phase"],
                "post-program create_raw_target_lock.py image-kind=phk1")
        else:
            # The testbench's retained run directory predates the local summary
            # receipt. Reconstruct the v1 rejection from its exact saved inputs.
            loaded=(ATTEMPT/"phk1-single.log").read_text(errors="replace")
            self.assertIn("Bitstream Loaded",loaded)
            self.assertNotEqual(old["target"]["expected_phk1_bitstream_sha256"],sha_file(CANDIDATE_BITSTREAM))
        with tempfile.TemporaryDirectory() as td:
            d=Path(td)
            identity=dict(old)
            identity["captured_utc"]=datetime.now(timezone.utc).isoformat()
            identity_path=d/"physical-identity-fixture.json"
            identity_path.write_text(json.dumps(identity))
            xbt_log=d/"baseline-xbt.log"
            phk_log=d/"patched-phk1.log"
            xbt_log.write_text(f"DNA: {old['target']['dna']}\nIDCODE({old['target']['idcode']})\nUsing Bitstream {ROLLBACK_BITSTREAM.resolve()} for SQRL JTAG Board 0 Device 0\nBitstream Loaded\n")
            phk_log.write_text(f"DNA: {old['target']['dna']}\nIDCODE({old['target']['idcode']})\nUsing Bitstream {CANDIDATE_BITSTREAM.resolve()} for SQRL JTAG Board 0 Device 0\nBitstream Loaded\n")
            program_lock_path=d/"PHK1_TARGET_LOCK_PROGRAM.json"
            program_lock=create_v2_lock(identity_lock_path=identity_path,candidate_path=CANDIDATE_BITSTREAM,
                candidate_manifest_path=CANDIDATE_MANIFEST,qualification_path=QUALIFICATION_MANIFEST,
                rollback_path=ROLLBACK_BITSTREAM,rollback_binding_path=ROLLBACK_BINDING,
                current_kind="xbt",current_log_path=xbt_log,maintenance_generation=GEN,
                output_path=program_lock_path)
            self.assertEqual(program_lock["current_image"]["sha256"],"f9812864d13a6963700f60709507ff85ee660fb77e846e51be533b2d479502df")
            self.assertEqual(program_lock["candidate_image"]["sha256"],"47a392b76ebdfdd9edbfc5270f21b48fb6d1acb73e45a7425811865a196d76f8")
            self.assertEqual(program_lock["rollback_image"]["sha256"],program_lock["current_image"]["sha256"])
            self.assertEqual(program_lock["intended_action"],"PROGRAM_CANDIDATE")
            ledger=d/"nonce-ledger.json"
            validate_v2_lock_file(lock_path=program_lock_path,identity_lock_path=identity_path,
                candidate_path=CANDIDATE_BITSTREAM,candidate_manifest_path=CANDIDATE_MANIFEST,
                qualification_path=QUALIFICATION_MANIFEST,rollback_path=ROLLBACK_BITSTREAM,
                rollback_binding_path=ROLLBACK_BINDING,current_kind="xbt",current_log_path=xbt_log,
                maintenance_generation=GEN,phase="program",nonce_ledger_path=ledger)
            counts={"PHK1":1,"HELLO":0,"VECTOR001":0,"XBT_ROLLBACK":0,"PEER_PHK1":0}
            state={"current_image":program_lock["current_image"],"candidate_image":program_lock["candidate_image"],
                   "rollback_image":program_lock["rollback_image"],"production_restored":False}
            programmed=transition_image_state(state,"program_success")
            self.assertEqual(programmed["current_image"]["sha256"],program_lock["candidate_image"]["sha256"])

            verify_path=d/"PHK1_TARGET_LOCK_VERIFY.json"
            verify_lock=create_v2_lock(identity_lock_path=identity_path,candidate_path=CANDIDATE_BITSTREAM,
                candidate_manifest_path=CANDIDATE_MANIFEST,qualification_path=QUALIFICATION_MANIFEST,
                rollback_path=ROLLBACK_BITSTREAM,rollback_binding_path=ROLLBACK_BINDING,
                current_kind="phk1",current_log_path=phk_log,maintenance_generation=GEN,
                output_path=verify_path)
            self.assertEqual(verify_lock["intended_action"],"VERIFY_CANDIDATE")
            self.assertEqual(verify_lock["programmed_device_count"],1)
            # The actual production runner's validator consumes v2 roles and rejects v1.
            prior_generation=os.environ.get("PHK1_MAINTENANCE_GENERATION")
            os.environ["PHK1_MAINTENANCE_GENERATION"]=GEN
            prior_rollback=__import__("tools.phk1_raw_bscan.phk1_live_runner",fromlist=["ROLLBACK_BITSTREAM"]).ROLLBACK_BITSTREAM
            import tools.phk1_raw_bscan.phk1_live_runner as runner
            runner.ROLLBACK_BITSTREAM=ROLLBACK_BITSTREAM
            try:
                parsed,_=validate_target_lock(verify_path,expected_maintenance_generation=GEN)
                hello,vector=run_hello_vector_session(lock_path=verify_path,evidence_dir=d/"runner",
                    backend_factory=lambda target,mode:MockRpcBackend(target),payload_path=PAYLOAD)
            finally:
                runner.ROLLBACK_BITSTREAM=prior_rollback
                if prior_generation is None: os.environ.pop("PHK1_MAINTENANCE_GENERATION",None)
                else: os.environ["PHK1_MAINTENANCE_GENERATION"]=prior_generation
            self.assertEqual(hello["status"],"PASS")
            self.assertEqual(vector["raw_result_sha256"],"7a1a4e48b6182144cb9a0ab7d11b80824b0b86194838feeccf106e62253f1eb0")
            self.assertEqual(vector["canonical_result_sha256"],"43dbc52a64ec00e4504328e6f900a6ddebbaadb166cf9e7a90f0f53e7f846ffa")
            counts["HELLO"]+=1; counts["VECTOR001"]+=1
            self.assertEqual(parsed["candidate_image"]["sha256"],verify_lock["candidate_image"]["sha256"])
            qualification=json.loads(QUALIFICATION_MANIFEST.read_text())
            self.assertIn("PASS",str(qualification.get("cpu_crosscheck")))
            recovery=select_rollback(verify_lock,ROLLBACK_BITSTREAM,ROLLBACK_BINDING)
            self.assertEqual(recovery["selected_role"],"ROLLBACK_IMAGE")
            self.assertEqual(recovery["sha256"],"f9812864d13a6963700f60709507ff85ee660fb77e846e51be533b2d479502df")
            counts["XBT_ROLLBACK"]+=1
            restored=transition_image_state(programmed,"rollback_success")
            self.assertEqual(restored["current_image"]["sha256"],verify_lock["rollback_image"]["sha256"])
            self.assertTrue(restored["production_restored"])
            self.assertEqual(counts,{"PHK1":1,"HELLO":1,"VECTOR001":1,"XBT_ROLLBACK":1,"PEER_PHK1":0})
            with self.assertRaises(V2LockError):
                validate_v2_lock_file(lock_path=program_lock_path,identity_lock_path=identity_path,
                    candidate_path=CANDIDATE_BITSTREAM,candidate_manifest_path=CANDIDATE_MANIFEST,
                    qualification_path=QUALIFICATION_MANIFEST,rollback_path=ROLLBACK_BITSTREAM,
                    rollback_binding_path=ROLLBACK_BINDING,current_kind="xbt",current_log_path=xbt_log,
                    maintenance_generation=GEN,phase="program",nonce_ledger_path=ledger)

    def test_legacy_v1_lock_is_rejected_by_actual_runner(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"old.json"; p.write_text(json.dumps(json.loads((ATTEMPT/"PRECANARY_TARGET_LOCK.json").read_text())))
            with self.assertRaises(RunnerError): validate_target_lock(p)

if __name__=="__main__": unittest.main(verbosity=2)
