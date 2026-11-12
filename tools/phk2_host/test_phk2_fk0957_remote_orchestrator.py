from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import base64
import hmac
import json
import shlex
import os
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


def ssh_string(value):
    return len(value).to_bytes(4, "big") + value


def hostkey_line(host="192.168.1.173", keyseed=b"A" * 32):
    blob = ssh_string(b"ssh-ed25519") + ssh_string(keyseed)
    return f"{host} ssh-ed25519 {base64.b64encode(blob).decode()}\n"


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
    def setUp(self):
        self.pin_dir = tempfile.TemporaryDirectory()
        self.known_hosts_path = Path(self.pin_dir.name) / "testbench.known_hosts"
        self.known_hosts_path.write_text(hostkey_line())
        self.known_hosts_path.chmod(0o600)

    def tearDown(self):
        self.pin_dir.cleanup()

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
            result = remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path, runner=fake, expected_hostname="testbox", remote_repo="/remote repo")
            cmd, kwargs = fake.calls[0]
            self.assertEqual(cmd[-2], "rmann@192.168.1.173")
            self.assertEqual(cmd[0], "/usr/bin/ssh")
            self.assertIn("-F", cmd)
            self.assertIn("BatchMode=yes", cmd)
            self.assertIn("StrictHostKeyChecking=yes", cmd)
            self.assertIn("GlobalKnownHostsFile=/dev/null", cmd)
            self.assertIn("HostKeyAlias=192.168.1.173", cmd)
            self.assertTrue(any(x.startswith("UserKnownHostsFile=/proc/self/fd/") for x in cmd))
            self.assertIn("ForwardAgent=no", cmd)
            self.assertRegex(cmd[-1], rf"^cd -- '/remote repo' && FK0957_TARGET=FK0957 python3 - {remote.COLLECTOR_PIN} [0-9a-f]{{64}}$")
            self.assertEqual(kwargs["input"], remote.COLLECTOR.read_bytes())
            self.assertNotIn(key_bytes, kwargs["input"])
            self.assertNotIn(str(key_path), " ".join(cmd))
            prov = result["payload"]["provenance"]
            self.assertEqual(prov["ssh_destination"], remote.SSH_DESTINATION)
            self.assertEqual(prov["ssh_host_key_algorithm"], "ssh-ed25519")
            self.assertTrue(prov["ssh_host_key_sha256"].startswith("SHA256:"))
            self.assertEqual(prov["pinned_known_hosts_sha256"], remote.sha(self.known_hosts_path.read_bytes()))
            self.assertEqual(prov["collector_reported_hostname_SELF_REPORTED"], "testbox")
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
                   "provenance": {"ssh_destination": remote.SSH_DESTINATION,
                                  "ssh_host_key_algorithm": "ssh-ed25519",
                                  "ssh_host_key_sha256": "SHA256:" + base64.b64encode(hashlib.sha256(
                                      base64.b64decode(hostkey_line().split()[2])).digest()).decode().rstrip("="),
                                  "pinned_known_hosts_sha256": remote.sha(hostkey_line().encode()),
                                  "collector_reported_hostname_SELF_REPORTED": u["remote_hostname"],
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
            remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path, runner=fake, expected_hostname="testbox", remote_repo="/remote repo")
            cmd, kwargs = fake.calls[0]
            self.assertEqual(set(kwargs), {"input", "stdout", "stderr", "check", "timeout", "env", "pass_fds"})
            self.assertEqual(set(kwargs["env"]), {"PATH", "HOME", "LC_ALL", "LANG"})
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
                remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path, runner=fake, expected_hostname="wrong",
                                        remote_repo=remote_path)
            command = fake.calls[0][0][-1]
            self.assertTrue(command.startswith(f"cd -- {shlex.quote(remote_path)} && "))
            self.assertEqual(fake.calls[0][0][-2], "rmann@192.168.1.173")

    def test_private_key_unavailable_fails_after_validation_without_exposure(self):
        fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1])))
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("/definitely/not/a/key"), known_hosts_path=self.known_hosts_path, runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(len(fake.calls), 1)

    def test_signing_key_symlink_and_hardlink_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            key = root / "key.pem"
            key.write_bytes(b"not a key")
            alias = root / "alias.pem"
            alias.symlink_to(key)
            with self.assertRaises(OSError):
                remote._read_signing_key(alias)
            hard = root / "hard.pem"
            hard.hardlink_to(key)
            with self.assertRaises(remote.Refusal):
                remote._read_signing_key(key)

    def test_signing_key_through_symlinked_parent_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            real = root / "real"
            real.mkdir()
            (real / "key.pem").write_bytes(b"secret")
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError):
                remote._read_signing_key(alias / "key.pem")

    def test_atomic_evidence_write_refuses_symlink_without_touching_target(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "target"
            target.write_bytes(b"preserve")
            output = root / "evidence.json"
            output.symlink_to(target)
            with self.assertRaises(remote.Refusal):
                remote.write_evidence_atomic(output, b"evidence\n")
            self.assertTrue(output.is_symlink())
            self.assertEqual(target.read_bytes(), b"preserve")

    def test_atomic_evidence_write_refuses_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(OSError):
                remote.write_evidence_atomic(alias / "evidence.json", b"evidence\n")
            self.assertFalse((real / "evidence.json").exists())

    def test_atomic_evidence_write_creates_and_replaces_regular_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            output = root / "evidence.json"
            remote.write_evidence_atomic(output, b"first\n")
            self.assertEqual(output.read_bytes(), b"first\n")
            remote.write_evidence_atomic(output, b"second\n")
            self.assertEqual(output.read_bytes(), b"second\n")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["evidence.json"])

    def test_output_replaced_with_symlink_during_write_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "target"
            target.write_bytes(b"preserve")
            output = root / "evidence.json"
            output.write_bytes(b"previous evidence")
            original_fsync = remote.os.fsync
            def replace_during_fsync(fd):
                original_fsync(fd)
                output.unlink()
                output.symlink_to(target)
            with mock.patch.object(remote.os, "fsync", side_effect=replace_during_fsync):
                with self.assertRaises(remote.Refusal):
                    remote.write_evidence_atomic(output, b"evidence\n")
            self.assertTrue(output.is_symlink())
            self.assertEqual(target.read_bytes(), b"preserve")
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["evidence.json", "target"])

    def test_parent_directory_replaced_during_write_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            parent = root / "out"
            parent.mkdir()
            output = parent / "evidence.json"
            original_fsync = remote.os.fsync
            def replace_parent_during_fsync(fd):
                original_fsync(fd)
                parent.rename(root / "moved-out")
                parent.mkdir()
            with mock.patch.object(remote.os, "fsync", side_effect=replace_parent_during_fsync):
                with self.assertRaises(remote.Refusal):
                    remote.write_evidence_atomic(output, b"evidence\n")
            self.assertFalse(output.exists())
            self.assertEqual(list((root / "moved-out").iterdir()), [])
            self.assertEqual(list(parent.iterdir()), [])

    def test_invalid_remote_output_refuses_before_attempting_key_read(self):
        fake = FakeSSH(b'{"schema":"partial"}\n')
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path, runner=fake, expected_hostname="testbox", remote_repo="/remote")

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
                remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path, runner=fake, expected_hostname="testbox", remote_repo="/remote")
            self.assertEqual(fake.calls, [])

    def test_host_key_entry_must_match_fixed_ip_and_be_unambiguous(self):
        fake = FakeSSH(b"")
        self.known_hosts_path.write_text(hostkey_line("192.168.1.174"))
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(fake.calls, [])
        self.known_hosts_path.write_text(hostkey_line() + hostkey_line(keyseed=b"B" * 32))
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(fake.calls, [])

    def test_ssh_rejection_of_wrong_presented_host_key_never_signs(self):
        class WrongHostKeySSH:
            def __call__(self, cmd, **kwargs):
                # Model OpenSSH StrictHostKeyChecking=yes rejecting a server key
                # that does not match the one-key local pin.
                return subprocess.CompletedProcess(cmd, 255, b"", b"Host key verification failed")
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                runner=WrongHostKeySSH(), expected_hostname="testbox", remote_repo="/remote")

    def test_hashed_known_hosts_entry_is_supported(self):
        salt = b"hashed-salt"
        digest = hmac.new(salt, b"192.168.1.173", hashlib.sha1).digest()
        token = "|1|" + base64.b64encode(salt).decode() + "|" + base64.b64encode(digest).decode()
        self.known_hosts_path.write_text(hostkey_line(token))
        fd, material, identity = remote._read_pinned_known_hosts(self.known_hosts_path)
        os.close(fd)
        self.assertEqual(material, self.known_hosts_path.read_bytes())
        self.assertEqual(identity["algorithm"], "ssh-ed25519")

    def test_symlink_missing_malformed_and_unsafe_pin_refuse(self):
        fake = FakeSSH(b"")
        linked = self.known_hosts_path.with_name("linked.known_hosts")
        linked.symlink_to(self.known_hosts_path)
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=linked,
                                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path.with_name("absent"),
                                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.known_hosts_path.write_text("not a known_hosts entry\n")
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(fake.calls, [])

    def test_open_ssh_options_environment_and_config_are_fail_closed(self):
        fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1])))
        hostile = {"SSH_OPTIONS": "-o StrictHostKeyChecking=no", "SSH_CONFIG": "/tmp/evil",
                   "SSH_AUTH_SOCK": "/tmp/agent", "GIT_SSH_COMMAND": "evil", "HOME": "/tmp/evil"}
        with mock.patch.dict(os.environ, hostile, clear=False):
            with tempfile.TemporaryDirectory() as d:
                key_path = Path(d) / "key.pem"
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                key = Ed25519PrivateKey.generate()
                key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path, runner=fake,
                                        expected_hostname="testbox", remote_repo="/remote")
        cmd, kwargs = fake.calls[0]
        self.assertEqual(cmd[0], remote.SSH_BINARY)
        self.assertEqual(cmd[1:3], ["-F", "/dev/null"])
        self.assertEqual(cmd.count("StrictHostKeyChecking=yes"), 1)
        self.assertEqual(cmd.count("GlobalKnownHostsFile=/dev/null"), 1)
        self.assertNotIn("StrictHostKeyChecking=no", cmd)
        self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "LANG": "C"})
        self.assertNotIn("shell", kwargs)

    def test_destination_and_host_alias_cannot_be_overridden_by_module_aliases(self):
        fake = FakeSSH(b"{}\n")
        with mock.patch.object(remote, "SSH_DESTINATION", "attacker@203.0.113.9"), \
             mock.patch.object(remote, "SSH_IP", "203.0.113.9"):
            with self.assertRaises(remote.Refusal):
                remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        cmd = fake.calls[0][0]
        self.assertEqual(cmd[-2], "rmann@192.168.1.173")
        self.assertIn("HostKeyAlias=192.168.1.173", cmd)

    def test_group_or_world_readable_known_hosts_refuses(self):
        self.known_hosts_path.chmod(0o644)
        with self.assertRaises(remote.Refusal):
            remote._read_pinned_known_hosts(self.known_hosts_path)

    def test_changed_path_and_symlink_swap_cannot_change_invoked_pin(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory() as d:
            key_path = Path(d) / "key.pem"
            key = Ed25519PrivateKey.generate()
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            original = self.known_hosts_path.read_bytes()
            def mutate_after_exec(cmd, **kwargs):
                self.known_hosts_path.unlink()
                self.known_hosts_path.symlink_to(Path(d) / "attacker")
                inherited = Path(f"/proc/self/fd/{kwargs['pass_fds'][0]}").read_bytes()
                self.assertEqual(inherited, original)
                return subprocess.CompletedProcess(cmd, 0, wire(unsigned(session_nonce=cmd[-1].split()[-1])), b"")
            signed = remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path,
                runner=mutate_after_exec, expected_hostname="testbox", remote_repo="/remote")
            self.assertEqual(signed["payload"]["provenance"]["pinned_known_hosts_sha256"], remote.sha(original))

    def test_pin_changed_between_validation_and_invocation_refuses(self):
        fake = FakeSSH(b"")
        original_read = remote._read_pinned_known_hosts
        calls = 0
        def mutate_between_reads(path):
            nonlocal calls
            calls += 1
            result = original_read(path)
            if calls == 1:
                self.known_hosts_path.write_text(hostkey_line(keyseed=b"C" * 32))
                self.known_hosts_path.chmod(0o600)
            return result
        with mock.patch.object(remote, "_read_pinned_known_hosts", side_effect=mutate_between_reads):
            with self.assertRaises(remote.Refusal):
                remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(fake.calls, [])

    def test_wrong_reported_hostname_refuses_before_signing(self):
        fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1], collector_hash=remote.COLLECTOR_PIN)))
        with tempfile.TemporaryDirectory() as d:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            key_path = Path(d) / "key.pem"
            key = Ed25519PrivateKey.generate()
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            def spoof(cmd):
                value = unsigned(session_nonce=cmd[-1].split()[-1])
                value["remote_hostname"] = "spoofed-testbox"
                return wire(value)
            fake.response = spoof
            with self.assertRaises(remote.Refusal):
                remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path, runner=fake,
                    expected_hostname="testbox", remote_repo="/remote")


if __name__ == "__main__":
    unittest.main()
