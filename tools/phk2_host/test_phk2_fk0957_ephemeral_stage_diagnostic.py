from __future__ import annotations

import base64
import hashlib
import io
import os
import re
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


def _known_hosts_line(keyseed=b"A" * 32):
    blob = _ssh_string(b"ssh-ed25519") + _ssh_string(keyseed)
    return f"192.168.1.173 ssh-ed25519 {base64.b64encode(blob).decode()}\n"


class FakeDiagnosticSSH:
    def __init__(self, *, returncode=0, corrupt_bundle=False):
        self.returncode = returncode
        self.corrupt_bundle = corrupt_bundle
        self.calls = []
        self.pin_bytes = None
        self.pin_mode = None
        self.pin_nlink = None
        self.pin_parent_mode = None
        self.pin_path = None

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        pin_option = next(x for x in cmd if x.startswith("UserKnownHostsFile="))
        pin_path = Path(pin_option.split("=", 1)[1])
        self.pin_path = pin_path
        self.pin_bytes = pin_path.read_bytes()
        self.pin_mode = pin_path.stat().st_mode & 0o777
        self.pin_nlink = pin_path.stat().st_nlink
        self.pin_parent_mode = pin_path.parent.stat().st_mode & 0o777
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
        pin_option = next(x for x in cmd if x.startswith("UserKnownHostsFile="))
        copied_path = Path(pin_option.split("=", 1)[1])
        source_bytes = self.kh.read_bytes()
        self.assertEqual(fake.pin_bytes, source_bytes)
        self.assertEqual(hashlib.sha256(fake.pin_bytes).digest(), hashlib.sha256(source_bytes).digest())
        self.assertEqual(orchestrator._parse_pinned_host_key(fake.pin_bytes),
                         orchestrator._parse_pinned_host_key(source_bytes))
        self.assertEqual(fake.pin_mode, 0o600)
        self.assertEqual(fake.pin_nlink, 1)
        self.assertEqual(fake.pin_parent_mode, 0o700)
        self.assertNotEqual(copied_path.parent.name, "fk0957-stage-pin-")
        self.assertRegex(copied_path.parent.name, r"^fk0957-stage-pin-[A-Za-z0-9_]{8,}$")
        self.assertFalse(copied_path.is_symlink())
        self.assertFalse(copied_path.exists(), "temporary pin should be cleaned after success")

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
        self.assertIsNotNone(fake.pin_path)
        self.assertFalse(fake.pin_path.exists(), "temporary pin should be cleaned after SSH failure")

    def test_known_hosts_temp_symlink_and_hardlink_are_refused_without_touching_target(self):
        fake = FakeDiagnosticSSH()
        with tempfile.TemporaryDirectory(prefix="fk0957-stage-pin-") as d:
            target = Path(d) / "target"
            target.write_bytes(b"preserve")
            (Path(d) / "known_hosts").symlink_to(target)
            class ExistingTemp:
                name = d
                def cleanup(self):
                    pass
            with self.assertRaises(FileExistsError):
                diagnostic.run_diagnostic(self.kh, runner=fake, temp_factory=lambda **_: ExistingTemp())
            self.assertEqual(target.read_bytes(), b"preserve")
            self.assertEqual(fake.calls, [])

        with tempfile.TemporaryDirectory(prefix="fk0957-stage-pin-") as d:
            target = Path(d) / "target"
            target.write_bytes(b"preserve")
            os.link(target, Path(d) / "known_hosts")
            class ExistingHardlinkTemp:
                name = d
                def cleanup(self):
                    pass
            with self.assertRaises(FileExistsError):
                diagnostic.run_diagnostic(self.kh, runner=fake,
                    temp_factory=lambda **_: ExistingHardlinkTemp())
            self.assertEqual(target.read_bytes(), b"preserve")
            self.assertEqual(fake.calls, [])

    def test_symlinked_temp_directory_and_unsafe_permissions_refuse(self):
        fake = FakeDiagnosticSSH()
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir(mode=0o700)
            link = Path(tempfile.mkdtemp(prefix="fk0957-stage-pin-", dir="/tmp"))
            link.rmdir()
            link.symlink_to(target, target_is_directory=True)
            class LinkedTemp:
                name = str(link)
                def cleanup(self):
                    link.unlink()
            with self.assertRaises(RuntimeError):
                diagnostic.run_diagnostic(self.kh, runner=fake, temp_factory=lambda **_: LinkedTemp())
            self.assertEqual(list(target.iterdir()), [])
        with tempfile.TemporaryDirectory(prefix="fk0957-stage-pin-") as d:
            os.chmod(d, 0o755)
            class UnsafeModeTemp:
                name = d
                def cleanup(self):
                    pass
            with self.assertRaises(RuntimeError):
                diagnostic.run_diagnostic(self.kh, runner=fake, temp_factory=lambda **_: UnsafeModeTemp())
        self.assertEqual(fake.calls, [])

    def test_unsafe_temp_parent_and_pin_creation_permission_failure_refuse(self):
        fake = FakeDiagnosticSSH()
        with tempfile.TemporaryDirectory(prefix="fk0957-stage-pin-") as d:
            unsafe = Path(d) / "child" / ".." / "fk0957-stage-pin-reused"
            class UnsafeParentTemp:
                name = str(unsafe)
                def cleanup(self):
                    pass
            with self.assertRaises(RuntimeError):
                diagnostic.run_diagnostic(self.kh, runner=fake,
                    temp_factory=lambda **_: UnsafeParentTemp())
        real = tempfile.TemporaryDirectory(prefix="fk0957-stage-pin-", dir="/tmp")
        cleaned = []
        class TrackingTemp:
            name = real.name
            def cleanup(self):
                cleaned.append(True)
                real.cleanup()
        from unittest import mock
        try:
            with mock.patch.object(diagnostic, "_write_private_pin", side_effect=PermissionError("denied")):
                with self.assertRaises(PermissionError):
                    diagnostic.run_diagnostic(self.kh, runner=fake,
                        temp_factory=lambda **_: TrackingTemp())
            self.assertEqual(cleaned, [True])
        finally:
            if Path(real.name).exists():
                real.cleanup()
        self.assertEqual(fake.calls, [])

    def test_changed_temp_copy_after_validation_refuses_before_ssh(self):
        fake = FakeDiagnosticSSH()
        original = orchestrator._read_pinned_known_hosts
        seen = 0
        def mutate_copy(path):
            nonlocal seen
            result = original(path)
            if (Path(path).name == "known_hosts" and
                    Path(path).parent.name.startswith("fk0957-stage-pin-")):
                seen += 1
                if seen == 1:
                    Path(path).write_text(_known_hosts_line(b"B" * 32))
            return result
        from unittest import mock
        with mock.patch.object(orchestrator, "_read_pinned_known_hosts", side_effect=mutate_copy):
            with self.assertRaises(RuntimeError):
                diagnostic.run_diagnostic(self.kh, runner=fake)
        self.assertGreaterEqual(seen, 2)
        self.assertEqual(fake.calls, [])

    def test_changed_original_pin_after_validation_refuses_before_ssh(self):
        fake = FakeDiagnosticSSH()
        original = diagnostic._safe_source_pin
        calls = 0
        def mutate_source(path):
            nonlocal calls
            result = original(path)
            calls += 1
            if calls == 1:
                self.kh.write_text(_known_hosts_line(b"B" * 32))
                self.kh.chmod(0o600)
            return result
        from unittest import mock
        with mock.patch.object(diagnostic, "_safe_source_pin", side_effect=mutate_source):
            with self.assertRaises(RuntimeError):
                diagnostic.run_diagnostic(self.kh, runner=fake)
        self.assertEqual(fake.calls, [])

    def test_wrong_fingerprint_multiple_keys_and_malformed_pin_refuse_before_ssh(self):
        fake = FakeDiagnosticSSH()
        cases = (_known_hosts_line().replace("192.168.1.173", "192.168.1.174").encode(),
                 (_known_hosts_line() + _known_hosts_line()).encode(), b"malformed\n")
        for data in cases:
            with self.subTest(data=data):
                self.kh.write_bytes(data)
                self.kh.chmod(0o600)
                with self.assertRaises(RuntimeError):
                    diagnostic.run_diagnostic(self.kh, runner=fake)
        self.assertEqual(fake.calls, [])

    def test_cleanup_failure_fails_closed_and_ssh_settings_are_fixed(self):
        from unittest import mock
        real = tempfile.TemporaryDirectory(prefix="fk0957-stage-pin-", dir="/tmp")
        class BadCleanup:
            name = real.name
            def cleanup(self):
                real.cleanup()
                raise OSError("simulated cleanup failure")
        fake = FakeDiagnosticSSH()
        hostile = {"SSH_OPTIONS": "-o StrictHostKeyChecking=no", "SSH_CONFIG": "/tmp/evil",
                   "SSH_AUTH_SOCK": "/tmp/agent", "HOME": "/tmp/evil"}
        output = io.StringIO()
        try:
            with mock.patch.dict(os.environ, hostile, clear=False):
                with self.assertRaises(OSError):
                    diagnostic.run_diagnostic(self.kh, runner=fake,
                        temp_factory=lambda **_: BadCleanup(), output=output)
            self.assertNotIn("FAILURE_PHASE=none", output.getvalue())
            cmd, kwargs = fake.calls[0]
            self.assertEqual(cmd[0], orchestrator.SSH_BINARY)
            self.assertEqual(cmd[1:3], ["-F", "/dev/null"])
            self.assertIn("StrictHostKeyChecking=yes", cmd)
            self.assertIn("GlobalKnownHostsFile=/dev/null", cmd)
            self.assertNotIn("StrictHostKeyChecking=no", cmd)
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
                                              "LC_ALL": "C", "LANG": "C"})
        finally:
            if Path(real.name).exists():
                real.cleanup()


if __name__ == "__main__":
    unittest.main()
