from __future__ import annotations
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from raw_identity_runner import EXIT, PHASE_EXIT
from raw_identity_runner import RunnerFailure, validate_lock

RUNNER = Path(__file__).with_name("raw_identity_runner.py")


def fixture_lock() -> dict:
    return {
        "schema": "sidecar-raw-jtag-target-lock-v1", "status": "PASS",
        "captured_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "match_count": 1, "peer_distinct": True,
        "raw_device_handle_count": 0, "peer_handle_open": False,
        "target": {"role": "PHK1_CANARY", "usb_path": "3-2.1", "ftdi_serial": "FIXTURE-TARGET",
                   "vid": "0403", "pid": "6010", "interface": "A", "idcode": "04b69093", "dna": "FIXTURE-DNA"},
        "peer": {"role": "PEER", "usb_path": "3-2.2", "ftdi_serial": "FIXTURE-PEER"},
    }


class RawIdentityRunnerTests(unittest.TestCase):
    def invoke(self, root: Path, lock_path: Path, inject: str | None = None):
        outdir = root / ("out-" + (inject or "success"))
        cmd = [sys.executable, str(RUNNER), "--lock", str(lock_path), "--output-dir", str(outdir), "--backend", "mock"]
        if inject:
            cmd += ["--inject", inject]
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        return p, outdir

    def test_mock_runner_success_and_capture(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); lock = root / "lock.json"; lock.write_text(json.dumps(fixture_lock()))
            p, outdir = self.invoke(root, lock)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("OUTPUT_CAPTURE=PASS", p.stdout)
            self.assertTrue((outdir / "stdout.log").is_file())
            self.assertTrue((outdir / "stderr.log").is_file())
            self.assertTrue((outdir / "transcript.log").is_file())
            self.assertEqual(json.loads((outdir / "status.json").read_text())["exit_code"], 0)
            self.assertEqual(json.loads((outdir / "last-phase.json").read_text())["current_phase"], "P17_COMPLETE")
            transcript = (outdir / "transcript.log").read_text()
            for phase in ("P00_START", "P01_PARSE_ARGS", "P02_LOAD_TARGET_LOCK", "P03_VALIDATE_TARGET_LOCK",
                          "P04_ENUMERATE_USB", "P05_MATCH_FTDI_DEVICE", "P06_OPEN_FTDI",
                          "P07_SELECT_INTERFACE_A", "P08_INIT_MPSSE", "P09_MPSSE_SYNC",
                          "P10_SET_JTAG_CLOCK", "P11_TAP_RESET", "P12_READ_CHAIN",
                          "P13_PARSE_CHAIN", "P14_VERIFY_IDCODE", "P15_DNA_VERIFY",
                          "P16_CLOSE_FTDI", "P17_COMPLETE"):
                self.assertIn("PHASE=" + phase, transcript)

    def test_expected_failure_phases(self):
        cases = [
            ("missing-lock", "missing", "P02_LOAD_TARGET_LOCK", 3),
            ("bad-json", "badjson", "P02_LOAD_TARGET_LOCK", 3),
            ("stale-lock", "stale", "P03_VALIDATE_TARGET_LOCK", 3),
            ("wrong-serial", "WRONG_SERIAL", "P05_MATCH_FTDI_DEVICE", 4),
            ("wrong-usb-path", "WRONG_USB_PATH", "P05_MATCH_FTDI_DEVICE", 4),
            ("no-ftdi-device", "NO_FTDI_DEVICE", "P04_ENUMERATE_USB", 4),
            ("multiple-matches", "MULTIPLE_MATCHES", "P05_MATCH_FTDI_DEVICE", 4),
            ("open-failure", "OPEN_FAILURE", "P06_OPEN_FTDI", 5),
            ("wrong-interface", "WRONG_INTERFACE", "P07_SELECT_INTERFACE_A", 5),
            ("sync-failure", "MPSSE_SYNC_FAILURE", "P09_MPSSE_SYNC", 6),
            ("clock-failure", "CLOCK_SETUP_FAILURE", "P10_SET_JTAG_CLOCK", 6),
            ("tap-reset-failure", "TAP_RESET_FAILURE", "P11_TAP_RESET", 7),
            ("short-tdo", "SHORT_TDO", "P12_READ_CHAIN", 7),
            ("bad-chain", "BAD_CHAIN", "P13_PARSE_CHAIN", 7),
            ("bad-idcode", "WRONG_IDCODE", "P14_VERIFY_IDCODE", 8),
            ("close-failure", "CLOSE_FAILURE", "P16_CLOSE_FTDI", 9),
        ]
        passed = 0
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for label, injection, phase, code in cases:
                lock = root / (label + ".json")
                d = fixture_lock()
                if injection == "missing":
                    lock = root / "absent.json"
                elif injection == "badjson":
                    lock.write_text("{")
                elif injection == "stale":
                    d["captured_utc"] = "2000-01-01T00:00:00+00:00"
                    lock.write_text(json.dumps(d))
                else:
                    lock.write_text(json.dumps(d))
                p, outdir = self.invoke(root, lock, injection if injection not in ("missing", "badjson", "stale") else None)
                status = json.loads((outdir / "status.json").read_text())
                self.assertEqual(p.returncode, code, label)
                self.assertEqual(status["failed_phase"], phase, label)
                failure_text = (outdir / "stderr.log").read_text()
                self.assertIn("FAILED_PHASE=" + phase, failure_text, label)
                for field in ("FAILED_OPERATION", "FAILED_ERRNO", "FAILED_LIBFTDI_CODE", "FAILED_MESSAGE"):
                    self.assertIn(field + "=", failure_text, label)
                self.assertEqual(json.loads((outdir / "last-phase.json").read_text())["current_phase"], phase)
                passed += 1
        self.assertEqual(passed, len(cases))

    def test_exit_code_model(self):
        self.assertEqual(EXIT, {"success": 0, "arguments": 2, "target_lock": 3, "usb_enumeration": 4,
                               "device_open": 5, "mpsse": 6, "jtag_scan": 7, "identity_mismatch": 8,
                               "cleanup": 9, "internal": 10})
        self.assertEqual(PHASE_EXIT["P14_VERIFY_IDCODE"], 8)

    def test_target_lock_negative_cases(self):
        mutations = [
            lambda d: d.update(match_count=2),
            lambda d: d.update(peer_distinct=False),
            lambda d: d.update(raw_device_handle_count=1),
            lambda d: d["target"].update(role="PEER"),
            lambda d: d["target"].update(interface="B"),
            lambda d: d["target"].pop("dna"),
            lambda d: d.update(captured_utc="2000-01-01T00:00:00+00:00"),
        ]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "lock.json"
            for mutate in mutations:
                data = fixture_lock(); mutate(data); p.write_text(json.dumps(data))
                with self.assertRaises(RunnerFailure) as got:
                    validate_lock(p, lambda _: None)
                self.assertEqual(got.exception.phase, "P03_VALIDATE_TARGET_LOCK")


if __name__ == "__main__":
    unittest.main()
