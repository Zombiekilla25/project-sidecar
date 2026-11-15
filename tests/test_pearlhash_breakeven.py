import importlib.util
import pathlib
import unittest

PATH = pathlib.Path(__file__).resolve().parents[1] / "tools" / "pearlhash_breakeven.py"
SPEC = importlib.util.spec_from_file_location("pearlhash_breakeven", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BreakEvenTests(unittest.TestCase):
    def test_default_work_and_baseline_time(self):
        result = MODULE.analyze()
        self.assertEqual(result["work_unit"]["macs"], 70_368_744_177_664)
        self.assertAlmostEqual(result["gpu_reference"]["equivalent_baseline_seconds_per_work_unit"], 0.9325943, places=6)
        self.assertTrue(result["gpu_reference"]["is_measurement"])
        self.assertEqual(result["gpu_reference"]["source"], "RETAINED_OFFLINE_MEASUREMENT")
        custom = MODULE.analyze(gpu_tmacs=50)
        self.assertEqual(custom["gpu_reference"]["source"], "USER_INPUT")
        self.assertFalse(custom["gpu_reference"]["is_measurement"])

    def test_transfer_budget_reduces_compute_allowance(self):
        no_transfer = MODULE.analyze()
        one_gib = MODULE.analyze(pcie_bytes=1 << 30)
        self.assertGreater(no_transfer["targets"]["cycles_per_accelerator_available_after_transfer"], one_gib["targets"]["cycles_per_accelerator_available_after_transfer"])
        self.assertGreater(one_gib["estimated_transport"]["required_fpga_compute_tmacs"], 75.45483)

    def test_transcript_volume_exceeds_live_deadline(self):
        result = MODULE.analyze(gpu_tmacs=81.24666666666667, pcie_bytes=4 << 30)
        self.assertFalse(result["estimated_transport"]["target_feasible_with_transport"])

    def test_margin_raises_target_rate(self):
        base = MODULE.analyze()
        margin = MODULE.analyze(margin_percent=10)
        self.assertAlmostEqual(margin["targets"]["required_end_to_end_tmacs"], base["targets"]["required_end_to_end_tmacs"] * 1.1)

    def test_measured_cycle_input_includes_link_overhead(self):
        result = MODULE.analyze(measured_cycles=100_000_000, cycle_evidence="MEASURED", pcie_bytes=1 << 30)
        measured = result["optional_fpga_cycle_result"]
        self.assertGreater(measured["end_to_end_seconds"], measured["fpga_compute_seconds"])
        self.assertTrue(measured["is_measurement"])
        estimate = MODULE.analyze(measured_cycles=100_000_000, cycle_evidence="ESTIMATE")
        self.assertFalse(estimate["optional_fpga_cycle_result"]["is_measurement"])

    def test_bad_inputs_refuse(self):
        for values in ({"work_macs": True}, {"pcie_bytes": -1}, {"fpga_count": 0}, {"gpu_tmacs": float("nan")}, {"margin_percent": -1}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                MODULE.analyze(**values)
        with self.assertRaises(ValueError):
            MODULE.analyze(measured_cycles=1)
        with self.assertRaises(ValueError):
            MODULE.analyze(cycle_evidence="MEASURED")
        with self.assertRaises(ValueError):
            MODULE.analyze(gpu_rate_source="UNTRUSTED")
        with self.assertRaises(ValueError):
            MODULE.analyze(gpu_rate_source=[])
        with self.assertRaises(ValueError):
            MODULE.analyze(measured_cycles=1, cycle_evidence=[])

    def test_cpu_stage_measurements_are_preserved_and_classified(self):
        result = MODULE.analyze(cpu_stage_ms={"operand_generation": 1.2, "final_hash": 0.3}, cpu_stage_evidence="MEASURED")
        cpu = result["optional_cpu_stage_timings"]
        self.assertEqual(cpu["sum_ms"], 1.5)
        self.assertEqual(cpu["completeness"], "PARTIAL_OR_UNAVAILABLE")
        with self.assertRaises(ValueError):
            MODULE.analyze(cpu_stage_ms={"noisy_gemm": float("nan")}, cpu_stage_evidence="MEASURED")
        with self.assertRaises(ValueError):
            MODULE.analyze(cpu_stage_ms={"noisy_gemm": 1.0})


if __name__ == "__main__":
    unittest.main()
