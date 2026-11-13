from __future__ import annotations

from pathlib import Path
import io
import tempfile
import unittest
from unittest import mock

import phk2_fk0957_topology_rgb_cli as cli


class RGBCLIEndToEndTests(unittest.TestCase):
    def test_remote_unsigned_path_validates_signs_then_atomically_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = root / "request.json"
            output = root / "evidence.json"
            request.write_bytes(b"canonical request")
            signed = {"payload": {"schema": "signed"}}
            unsigned = {"status": "ACQUIRED", "scan_a_raw_tdo_hex": "00",
                        "scan_b_raw_tdo_hex": "00"}
            events = []
            def acquire(raw):
                events.append(("acquire", raw))
                return signed
            def verify(value):
                events.append(("verify", value))
                return unsigned
            def summary(payload, destination, digest):
                events.append(("summary", payload, destination, digest))
                return {"status": "SIGNED"}
            def publish(destination, data, state):
                events.append(("publish", destination, data))
                destination.write_bytes(data)
                state[0] = "EVIDENCE_PUBLISHED"
            with mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=acquire), \
                 mock.patch.object(cli, "_verify_signed_remote_result", side_effect=verify), \
                 mock.patch.object(cli.evidence_cli, "_success_summary", side_effect=summary), \
                 mock.patch.object(cli.evidence_cli, "_publish_evidence_atomic", side_effect=publish):
                report, status, published = cli.run_once(request, output)
            self.assertEqual(status, 0)
            self.assertTrue(published)
            self.assertTrue(output.exists())
            self.assertEqual([event[0] for event in events], ["acquire", "verify", "summary", "publish"])
            self.assertEqual(events[0][1], b"canonical request")
            self.assertEqual(report, b'{"status":"SIGNED"}')

    def test_remote_refusal_never_signs_or_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request, output = root / "request.json", root / "evidence.json"
            request.write_bytes(b"canonical request")
            with mock.patch.object(cli.rgb, "acquire_validate_sign_once", side_effect=ValueError("raw secret text")) as acquire, \
                 mock.patch.object(cli.evidence_cli, "_publish_evidence_atomic") as publish:
                report, status, published = cli.run_once(request, output)
            self.assertEqual(status, 2)
            self.assertFalse(published)
            self.assertFalse(output.exists())
            self.assertIn(b"REMOTE_RGB_FLOW_FAILED", report)
            self.assertNotIn(b"raw secret text", report)
            acquire.assert_called_once()
            publish.assert_not_called()

    def test_cli_has_no_host_or_scan_override_arguments(self):
        output = io.BytesIO()
        with mock.patch.object(cli, "run_once", return_value=(b"done\n", 0, True)) as run, \
             mock.patch.object(cli.sys, "stdout", type("Stdout", (), {"buffer": output})()):
            self.assertEqual(cli.main(["--authorization-request", "/request",
                                      "--output", "/evidence"]), 0)
        self.assertEqual(output.getvalue(), b"done\n")
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
