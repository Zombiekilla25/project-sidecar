from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_remote_orchestrator as remote


def unsigned(collector_hash=None, backend_hash=None, session_nonce="0" * 64):
    return {
        "schema": "fk0957-unsigned-descriptor-evidence", "version": 1,
        "target_selector": "FK0957", "collector_source_sha256": collector_hash or remote.COLLECTOR_PIN,
        "session_nonce": session_nonce,
        "backend_source_sha256": backend_hash or "a189556093b915d1ab1d3f93ebcc3ef9af44f4f11c3d67d649798cbe6cb20196",
        "source_commit": "e2feedcfde44563854a3cf41fe4526c231ed385b", "remote_hostname": "testbox",
        "acquisition_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "ftdi_vid": "0403", "ftdi_pid": "6010", "manufacturer": "Xilinx", "product": "SQRL FK",
        "interface": "A", "usb_path": "1-2.3", "adapter_serial": "153300000957A",
        "fk0957_mapping": "153300000957", "WRITE_COUNT": 0, "RESET_COUNT": 0,
        "PROGRAM_COUNT": 0, "JTAG_OPERATIONS": 0,
    }


def wire(value):
    return remote.canonical(value) + b"\n"


class FakeSSH:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if callable(self.response):
            response = self.response(cmd)
        else:
            response = self.response
        return subprocess.CompletedProcess(cmd, 0, response, b"")


class RemoteOrchestratorTests(unittest.TestCase):
    def test_fake_remote_acquisition_signs_locally_with_no_key_material_sent(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory() as d:
            key_path = Path(d) / "signer.pem"
            key = Ed25519PrivateKey.generate()
            key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
            key_path.write_bytes(key_bytes)
            fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1])))
            result = remote.acquire_and_sign(key_path, runner=fake, expected_hostname="testbox", remote_repo="/remote repo")
            cmd, kwargs = fake.calls[0]
            self.assertEqual(cmd[-2], "rmann@192.168.1.173")
            self.assertIn("ForwardAgent=no", cmd)
            self.assertRegex(cmd[-1], rf"^cd -- '/remote repo' && FK0957_TARGET=FK0957 python3 - {remote.COLLECTOR_PIN} [0-9a-f]{{64}}$")
            self.assertEqual(kwargs["input"], remote.COLLECTOR.read_bytes())
            self.assertNotIn(key_bytes, kwargs["input"])
            self.assertNotIn(str(key_path), " ".join(cmd))
            canonical = remote.canonical(result["payload"])
            key.public_key().verify(bytes.fromhex(result["signature_hex"]), canonical)

    def test_wrong_target_counters_extra_fields_and_stale_data_refuse(self):
        base = unsigned()
        for change in ({"target_selector": "FK0958"}, {"WRITE_COUNT": 1},
                       {"extra": "no"}, {"adapter_serial": "wrong"},
                       {"source_commit": ""}):
            bad = dict(base, **change)
            with self.subTest(change=change), self.assertRaises(remote.Refusal):
                remote.validate_unsigned(wire(bad), collector_hash=remote.COLLECTOR_PIN,
                                         backend_hash=base["backend_source_sha256"], expected_hostname="testbox",
                                         session_nonce="0" * 64)
        stale = dict(base, acquisition_timestamp="2020-01-01T00:00:00Z")
        with self.assertRaises(remote.Refusal):
            remote.validate_unsigned(wire(stale), collector_hash=remote.COLLECTOR_PIN,
                                     backend_hash=base["backend_source_sha256"], expected_hostname="testbox",
                                     session_nonce="0" * 64)

    def test_noncanonical_json_hostname_and_hash_mismatch_refuse(self):
        base = unsigned()
        raw = json.dumps(base).encode() + b"\n"
        with self.assertRaises(remote.Refusal):
            remote.validate_unsigned(raw, collector_hash=remote.COLLECTOR_PIN,
                                     backend_hash=base["backend_source_sha256"], expected_hostname="testbox",
                                     session_nonce="0" * 64)
        with self.assertRaises(remote.Refusal):
            remote.validate_unsigned(wire(base), collector_hash=remote.COLLECTOR_PIN,
                                     backend_hash=base["backend_source_sha256"], expected_hostname="wrong",
                                     session_nonce="0" * 64)
        with self.assertRaises(remote.Refusal):
            remote.validate_unsigned(wire(base), collector_hash="0" * 64,
                                     backend_hash=base["backend_source_sha256"], expected_hostname="testbox",
                                     session_nonce="0" * 64)

    def test_duplicate_keys_nonfinite_float_and_truncation_refuse(self):
        base = unsigned()
        good = wire(base)
        duplicate = good[:-2] + b',"WRITE_COUNT":0}\n'
        variants = [duplicate, good.replace(b'"WRITE_COUNT":0', b'"WRITE_COUNT":NaN'),
                    good.replace(b'"WRITE_COUNT":0', b'"WRITE_COUNT":Infinity'),
                    good.replace(b'"WRITE_COUNT":0', b'"WRITE_COUNT":0.0'), good[:len(good) // 2]]
        for raw in variants:
            with self.subTest(raw=raw[-50:]), self.assertRaises(remote.Refusal):
                remote.validate_unsigned(raw, collector_hash=remote.COLLECTOR_PIN,
                                         backend_hash=base["backend_source_sha256"], expected_hostname="testbox",
                                         session_nonce="0" * 64)

    def test_missing_and_reordered_fields_refuse(self):
        base = unsigned()
        missing = dict(base)
        missing.pop("usb_path")
        reordered = b"{" + b",".join(
            remote.canonical({k: base[k]})[1:-1] for k in reversed(list(base))) + b"}\n"
        for raw in (wire(missing), reordered):
            with self.assertRaises(remote.Refusal):
                remote.validate_unsigned(raw, collector_hash=remote.COLLECTOR_PIN,
                                         backend_hash=base["backend_source_sha256"], expected_hostname="testbox",
                                         session_nonce="0" * 64)

    def test_host_injection_unicode_huge_and_nonce_replay_refuse(self):
        base = unsigned()
        cases = [(base, "testbox; touch /tmp/pwned", "0" * 64),
                 (dict(base, remote_hostname="testbox"), "testbox", "1" * 64),
                 (dict(base, adapter_serial="153300000957A;id"), "testbox", "0" * 64),
                 (dict(base, usb_path="界" * 100000), "testbox", "0" * 64),
                 (dict(base, remote_hostname="testbox\u202e"), "testbox\u202e", "0" * 64)]
        for value, hostname, nonce in cases:
            with self.subTest(hostname=hostname[:20]), self.assertRaises(remote.Refusal):
                remote.validate_unsigned(wire(value), collector_hash=remote.COLLECTOR_PIN,
                                         backend_hash=base["backend_source_sha256"], expected_hostname=hostname,
                                         session_nonce=nonce)

    def test_signed_tampering_wrong_key_and_invalid_signature_refuse(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        wrong = Ed25519PrivateKey.generate()
        u = unsigned()
        payload = {"schema": "fk0957-signed-identity-evidence", "version": 1,
                   "unsigned_evidence": u,
                   "provenance": {"ssh_target": remote.HOST, "remote_hostname": u["remote_hostname"],
                                  "collector_source_sha256": u["collector_source_sha256"],
                                  "backend_source_sha256": u["backend_source_sha256"],
                                  "source_commit": u["source_commit"],
                                  "acquisition_timestamp": u["acquisition_timestamp"],
                                  "session_nonce": u["session_nonce"],
                                  "raw_unsigned_sha256": remote.sha(wire(u))}}
        encoded = remote.canonical(payload)
        signed = {"payload": payload, "payload_sha256": remote.sha(encoded), "signature_algorithm": "Ed25519",
                  "signature_hex": key.sign(encoded).hex()}
        self.assertTrue(remote.verify_signed(signed, key.public_key()))
        mutated = dict(signed, payload={"schema": "altered"})
        for candidate, pub in ((mutated, key.public_key()), (signed, wrong.public_key()),
                               (dict(signed, signature_hex="00"), key.public_key())):
            with self.subTest(candidate=candidate), self.assertRaises(remote.Refusal):
                remote.verify_signed(candidate, pub)

    def test_remote_environment_and_stdin_never_contain_key_reference(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory() as d:
            key_path = Path(d) / "SECRET_KEY_FILE.pem"
            key = Ed25519PrivateKey.generate()
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1])))
            remote.acquire_and_sign(key_path, runner=fake, expected_hostname="testbox", remote_repo="/remote repo")
            cmd, kwargs = fake.calls[0]
            self.assertEqual(set(kwargs), {"input", "stdout", "stderr", "check", "timeout", "env"})
            self.assertTrue(set(kwargs["env"]).issubset({"PATH", "HOME"}))
            self.assertNotIn(b"SECRET_KEY_FILE", kwargs["input"])
            self.assertNotIn("SECRET_KEY_FILE", repr(cmd) + repr(kwargs))

    def test_remote_repository_metacharacters_are_shell_quoted(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory() as d:
            key_path = Path(d) / "key.pem"
            key = Ed25519PrivateKey.generate()
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            remote_path = "/tmp/$(touch pwn);'repo"
            fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1])))
            with self.assertRaises(remote.Refusal):
                # This deliberately returns a wrong hostname; we only need to
                # inspect that the path traveled as inert quoted shell text.
                remote.acquire_and_sign(key_path, runner=fake, expected_hostname="wrong",
                                        remote_repo=remote_path)
            command = fake.calls[0][0][-1]
            self.assertTrue(command.startswith(f"cd -- {shlex.quote(remote_path)} && "))
            self.assertEqual(fake.calls[0][0][-2], "rmann@192.168.1.173")

    def test_private_key_unavailable_fails_after_validation_without_exposure(self):
        fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1])))
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("/definitely/not/a/key"), runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(len(fake.calls), 1)

    def test_invalid_remote_output_refuses_before_attempting_key_read(self):
        fake = FakeSSH(b'{"schema":"partial"}\n')
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), runner=fake, expected_hostname="testbox", remote_repo="/remote")

    def test_collector_is_stdlib_only_and_has_no_mutation_surface(self):
        source = remote.COLLECTOR.read_text()
        for forbidden in ("cryptography", "ftdi_write", "ftdi_set_bitmode", "libusb_claim_interface",
                          "mpsse", "shift_ir", "shift_dr"):
            self.assertNotIn(forbidden, source)
        self.assertIn("select_exact", source)
        self.assertIn("open_selected", source)

    def test_deterministic_schema_fuzz_mutations_fail_closed(self):
        base = unsigned()
        for index, field in enumerate(sorted(base)):
            changed = dict(base)
            changed[field] = "attacker-controlled-" + str(index)
            with self.subTest(field=field), self.assertRaises(remote.Refusal):
                remote.validate_unsigned(wire(changed), collector_hash=remote.COLLECTOR_PIN,
                                         backend_hash=base["backend_source_sha256"], expected_hostname="testbox",
                                         session_nonce="0" * 64)

    def test_pins_are_checked_before_ssh(self):
        with mock.patch.object(remote, "COLLECTOR_PIN", "0" * 64):
            fake = FakeSSH(b"")
            with self.assertRaises(remote.Refusal):
                remote.acquire_and_sign(Path("missing-key"), runner=fake, expected_hostname="testbox", remote_repo="/remote")
            self.assertEqual(fake.calls, [])


if __name__ == "__main__":
    unittest.main()
