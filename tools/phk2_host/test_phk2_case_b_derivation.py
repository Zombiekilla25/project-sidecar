"""Offline USER3 RTL contract simulation against immutable v5.1 source."""
from __future__ import annotations

import io
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from phk2_physical_close_guard import verify_immutable_v51
from phk2_case_b_method import TAP_NEXT


ROOT = Path(__file__).resolve().parents[2]
TB = ROOT / "tests/phk2_board/tb_phk2_case_b_user3_status_contract.sv"
CANDIDATE = ROOT / "ops/phk2/PHK2_FK0957_CASE_B_CANDIDATE_METHOD.json"
VIVADO_JTAG_MODEL = Path("/home/rmann/Xilinx/2026.1/Vivado/data/verilog/src/unisims/JTAG_SIME2.v")


class CaseBDerivationSimulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binding = verify_immutable_v51(ROOT)

    def test_immutable_source_user3_status_snapshot_shift_contract(self):
        if not shutil.which("iverilog") or not shutil.which("vvp"):
            self.skipTest("Icarus Verilog is required for the offline RTL contract simulation")
        source_commit = self.binding.source_commit
        archive = subprocess.run(
            ["git", "-C", str(ROOT), "archive", source_commit,
             "rtl/phk2_board", "tests/phk2_board/bscan_stub.sv"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with tempfile.TemporaryDirectory(prefix="phk2-case-b-user3-") as tmp:
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as tar:
                tar.extractall(tmp, filter="data")
            source_root = Path(tmp)
            rtl_files = sorted((source_root / "rtl/phk2_board").rglob("*.sv"))
            stub = source_root / "tests/phk2_board/bscan_stub.sv"
            output = Path(tmp) / "user3-contract.vvp"
            subprocess.run(
                ["iverilog", "-g2012", "-DPHK2_SIM", "-s",
                 "tb_phk2_case_b_user3_status_contract", "-o", str(output),
                 str(stub), *(str(path) for path in rtl_files), str(TB)],
                cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = subprocess.run(["vvp", str(output)], cwd=ROOT, check=True,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertIn("PHK2_USER3_STATUS_CONTRACT=PASS snapshots=64 shifts_per_snapshot=32", result.stdout)
        self.assertIn("TAP_SEQUENCE_TESTED=NO PHYSICAL_EXPECTED_RESPONSE=NONE", result.stdout)

    def test_candidate_tms_path_resets_from_any_state_and_returns_to_idle(self):
        record = json.loads(CANDIDATE.read_text())
        tap = record["candidate_tap_shape"]
        vector = tap["candidate_complete_tms_vector"]
        self.assertEqual(len(vector), tap["candidate_cycle_count"])
        self.assertEqual(tap["candidate_cycle_count"], 55)
        self.assertEqual(vector[:5], "11111")
        for initial in TAP_NEXT:
            state = initial
            for bit in vector[:5]:
                state = TAP_NEXT[state][int(bit)]
            self.assertEqual(state, "TEST_LOGIC_RESET")
            for bit in vector[5:]:
                state = TAP_NEXT[state][int(bit)]
            self.assertEqual(state, "RUN_TEST_IDLE")
        state = "TEST_LOGIC_RESET"
        observed = []
        for bit in vector[5:]:
            state = TAP_NEXT[state][int(bit)]
            observed.append(state)
        expected = (["RUN_TEST_IDLE", "SELECT_DR_SCAN", "SELECT_IR_SCAN", "CAPTURE_IR", "SHIFT_IR"] +
                    ["SHIFT_IR"] * 5 + ["EXIT1_IR", "UPDATE_IR", "RUN_TEST_IDLE"] +
                    ["SELECT_DR_SCAN", "CAPTURE_DR", "SHIFT_DR"] +
                    ["SHIFT_DR"] * 31 + ["EXIT1_DR", "UPDATE_DR", "RUN_TEST_IDLE"])
        self.assertEqual(observed, expected)
        self.assertIsNone(tap["tap_initial_state_before_reset"])
        self.assertIsNone(tap["expected_transition_table"])
        self.assertFalse(record["approved"])
        self.assertFalse(record["execution_allowed"])

    def test_candidate_has_provenance_and_keeps_unknowns_unapproved(self):
        record = json.loads(CANDIDATE.read_text())
        self.assertEqual(record["status"], "CANDIDATE")
        self.assertEqual(record["authoritative_fields_derived_count"],
                         len(record["authoritative_fields_derived"]))
        self.assertEqual(record["case_binding"]["case_id"], "33")
        self.assertEqual(record["case_binding"]["matrix_result"], "UNRESOLVED")
        self.assertEqual(record["design_binding"]["source_commit"],
                         self.binding.source_commit)
        self.assertEqual(record["design_binding"]["routed_dcp_sha256"],
                         self.binding.routed_dcp_sha256)
        self.assertIsNone(record["candidate_tap_shape"]["tap_initial_state_before_reset"])
        self.assertIsNone(record["candidate_tap_shape"]["tdi_vector"])
        self.assertIsNone(record["candidate_tap_shape"]["expected_transition_table"])
        self.assertIsNone(record["candidate_observation"]["expected_response_relationship"]
                          ["fixed_expected_tdo_constant"])
        self.assertFalse(record["approved"])
        self.assertFalse(record["execution_allowed"])
        trace = record["derivation_trace"]
        self.assertEqual(trace["tap_vector_derivation"]["fsm_symbol"], "TAP_NEXT")
        self.assertEqual(trace["routed_clock_evidence"]["clock_object"], "bscan_tck")
        self.assertGreaterEqual(len(record["method_element_evidence"]), 12)
        self.assertTrue(all(row["source_file"] and row["source_lines_or_symbol"] and
                            row["source_commit"] and row["test"] and row["confidence_status"]
                            for row in record["method_element_evidence"]))
        self.assertEqual(record["operation_side_effect_scope"]["allowed_design_state_change"],
                         "stat_shift only: loaded on USER3 CAPTURE and shifted on USER3 SHIFT")

    def test_vu33p_vendor_model_derives_user3_opcode(self):
        if not VIVADO_JTAG_MODEL.is_file():
            self.skipTest("local Vivado 2026.1 JTAG simulation model is unavailable")
        data = VIVADO_JTAG_MODEL.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "d936b7af7b7a923e794141aec5cc79f76392f566b6381aa8dc45e23ade5eecd5")
        source = data.decode()
        prefix = source[source.index("localparam IRLength ="):]
        six_bit_branch = prefix[:prefix.index("? 6 :")]
        self.assertIn('PART_NAME == "XCVU33P"', six_bit_branch)
        import re
        match = re.search(r"USER3_INSTR\s*=\s*24'b([01]{24})", source)
        self.assertIsNotNone(match)
        opcode24 = int(match.group(1), 2)
        opcode6 = (opcode24 >> 18) & 0x3f
        self.assertEqual(opcode6, 0x22)
        self.assertEqual("".join(str((opcode6 >> bit) & 1) for bit in range(6)), "010001")


if __name__ == "__main__":
    unittest.main()
