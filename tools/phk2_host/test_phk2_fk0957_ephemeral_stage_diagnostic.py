from __future__ import annotations

import base64
import hashlib
import io
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_ephemeral_stage_diagnostic as diagnostic
import phk2_fk0957_remote_orchestrator as orchestrator


def _ssh_string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _known_hosts_line():
    blob = _ssh_string(b"ssh-ed25519") + _ssh_string(b"A" * 32)
    return f"192.168.1.173 ssh-ed25519 {base64.b64encode(blob).decode()}\n"


class FakeDiagnosticSSH:
    def __init__(self, *, returncode=0, corrupt_bundle=False):
        self.returncode = returncode
        self.corrupt_bundle = corrupt_bundle
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.returncode:
            return subprocess.CompletedProcess(cmd, self.returncode, b"", b"simulated transport refusal")
        args = shlex.split(cmd[-1])
        code = args[args.index("-c") + 1]
        argv = args[args.index("-c") + 2:]
        payload = kwargs["input"]
        if self.corrupt_bundle:
            payload = payload[:-1] + bytes((payload[-1] ^ 1,))
        return subprocess.run([sys.executable, "-I", "-S", "-c", code, *argv], input=payload,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


class EphemeralStageDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.kh = Path(self.temp.name) / "known_hosts"
        self.kh.write_text(_known_hosts_line())
        self.kh.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_stages_verify_bundle_and_pins_without_invoking_collector(self):
        fake = FakeDiagnosticSSH()
        output = io.StringIO()
        result = diagnostic.run_diagnostic(self.kh, runner=fake, output=output)
        text = output.getvalue()
        self.assertEqual(result["failure_phase"], "none")
        self.assertRegex(text, r"(?m)^BUNDLE_CONSTRUCTED=YES$")
        self.assertRegex(text, r"(?m)^BUNDLE_SHA256=[0-9a-f]{64}$")
        self.assertRegex(text, r"(?m)^SSH_STDIN_SENT=YES$")
        for phase in ("REMOTE_RUNNER_STARTED", "REMOTE_BUNDLE_RECEIVED",
                      "REMOTE_BUNDLE_HASH_VERIFIED", "REMOTE_BUNDLE_MANIFEST_VERIFIED",
                      "COLLECTOR_SOURCE_VERIFIED",
                      "BACKEND_SOURCE_VERIFIED"):
            self.assertRegex(text, rf"(?m)^{phase}=YES$")
        self.assertRegex(text, r"(?m)^COLLECTOR_INVOKED=NO$")
        self.assertRegex(text, r"(?m)^USB_ACCESS=NO$")
        self.assertRegex(text, r"(?m)^HARDWARE_ACCESS=NO$")
        cmd, kwargs = fake.calls[0]
        self.assertEqual(cmd[-2], "rmann@192.168.1.173")
        self.assertIn("StrictHostKeyChecking=yes", cmd)
        self.assertIn("GlobalKnownHostsFile=/dev/null", cmd)
        self.assertTrue(any(x.startswith("UserKnownHostsFile=/tmp/fk0957-stage-pin-") for x in cmd))
        self.assertIn("-I", cmd[-1])
        self.assertIn("-S", cmd[-1])
        self.assertNotIn("--remote-repo", cmd[-1])
        self.assertNotIn("--signing-key", " ".join(cmd))
        self.assertEqual(hashlib.sha256(kwargs["input"]).hexdigest(), result["bundle_sha256"])
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                                          "LC_ALL": "C", "LANG": "C"})

    def test_bad_received_bundle_stops_before_source_verification(self):
        fake = FakeDiagnosticSSH(corrupt_bundle=True)
        output = io.StringIO()
        result = diagnostic.run_diagnostic(self.kh, runner=fake, output=output)
        text = output.getvalue()
        self.assertEqual(result["failure_phase"], "REMOTE_BUNDLE_HASH_VERIFIED")
        self.assertRegex(text, r"(?m)^REMOTE_BUNDLE_RECEIVED=YES$")
        self.assertRegex(text, r"(?m)^REMOTE_BUNDLE_HASH_VERIFIED=NO$")
        self.assertNotRegex(text, r"(?m)^COLLECTOR_SOURCE_VERIFIED=YES$")
        self.assertRegex(text, r"(?m)^COLLECTOR_INVOKED=NO$")

    def test_transport_refusal_is_reported_before_remote_runner(self):
        fake = FakeDiagnosticSSH(returncode=255)
        output = io.StringIO()
        result = diagnostic.run_diagnostic(self.kh, runner=fake, output=output)
        text = output.getvalue()
        self.assertEqual(result["failure_phase"], "SSH_TRANSPORT")
        self.assertRegex(text, r"(?m)^BUNDLE_CONSTRUCTED=YES$")
        self.assertRegex(text, r"(?m)^SSH_STDIN_SENT=NO$")
        self.assertNotRegex(text, r"(?m)^REMOTE_RUNNER_STARTED=YES$")
        self.assertRegex(text, r"(?m)^COLLECTOR_INVOKED=NO$")


if __name__ == "__main__":
    unittest.main()
