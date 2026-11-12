from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import base64
import hmac
import io
import json
import shlex
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_remote_orchestrator as remote
import phk2_fk0957_ephemeral_bundle as bundle_tools
import phk2_fk0957_ephemeral_runner as bundle_runner


def unsigned(collector_hash=None, backend_hash=None, session_nonce="0" * 64):
    return {
        "schema": "fk0957-unsigned-descriptor-evidence", "version": 1,
        "target_selector": "FK0957", "collector_source_sha256": collector_hash or remote.COLLECTOR_PIN,
        "session_nonce": session_nonce,
        "backend_source_sha256": backend_hash or remote.sha(remote.BACKEND.read_bytes()),
        "source_commit": "e2feedcfde44563854a3cf41fe4526c231ed385b", "remote_hostname": "testbox",
        "acquisition_timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "ftdi_vid": "0403", "ftdi_pid": "6010", "manufacturer": "Xilinx", "product": "SQRL FK",
        "interface": "A", "usb_path": "1-2.3", "adapter_serial": "153300000957A",
        "usb_descriptor_serial": "153300000957",
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
    def __init__(self, response, *, stderr=b"", returncode=0):
        self.response = response
        self.stderr = stderr
        self.returncode = returncode
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if callable(self.response):
            response = self.response(cmd)
        else:
            response = self.response
        return subprocess.CompletedProcess(cmd, self.returncode, response, self.stderr)


class RemoteOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.pin_dir = tempfile.TemporaryDirectory()
        self.known_hosts_path = Path(self.pin_dir.name) / "testbench.known_hosts"
        self.known_hosts_path.write_text(hostkey_line())
        self.known_hosts_path.chmod(0o600)

    def tearDown(self):
        self.pin_dir.cleanup()

    def make_bundle(self, nonce="1" * 64, runner_bytes=None):
        collector = remote.COLLECTOR.read_bytes()
        backend = remote.BACKEND.read_bytes()
        observer_bytes = remote.observer.OBSERVER_PATH.read_bytes()
        return bundle_tools.deterministic_bundle(
            source_commit=subprocess.run(["git", "-C", str(remote.REPO), "rev-parse", "HEAD"],
                                          check=True, capture_output=True, text=True).stdout.strip(),
            session_nonce=nonce, source_root=remote.REPO, collector_pin=remote.sha(collector),
            backend_pin=remote.sha(backend), observer_pin=remote.sha(observer_bytes),
            runner_bytes=(runner_bytes if runner_bytes is not None else
                          (remote.HERE / "phk2_fk0957_ephemeral_runner.py").read_bytes()))

    def test_fake_remote_acquisition_signs_locally_with_no_key_material_sent(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory() as d:
            key_path = Path(d) / "signer.pem"
            key = Ed25519PrivateKey.generate()
            key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
            key_path.write_bytes(key_bytes)
            seen_pin = {}
            def inspect_pin_during_ssh(cmd):
                pin_option = next(x for x in cmd if x.startswith("UserKnownHostsFile="))
                active_pin = Path(pin_option.split("=", 1)[1])
                seen_pin.update(path=active_pin, data=active_pin.read_bytes(),
                                mode=active_pin.stat().st_mode & 0o777,
                                links=active_pin.stat().st_nlink,
                                parent_mode=active_pin.parent.stat().st_mode & 0o777)
                return wire(unsigned(session_nonce=cmd[-1].split()[-1]))
            fake = FakeSSH(inspect_pin_during_ssh)
            result = remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path, runner=fake, expected_hostname="testbox", remote_repo="/remote repo")
            cmd, kwargs = fake.calls[0]
            self.assertEqual(cmd[-2], "rmann@192.168.1.173")
            self.assertEqual(cmd[0], "/usr/bin/ssh")
            self.assertIn("-F", cmd)
            self.assertIn("BatchMode=yes", cmd)
            self.assertIn("StrictHostKeyChecking=yes", cmd)
            self.assertIn("GlobalKnownHostsFile=/dev/null", cmd)
            self.assertNotIn("HostKeyAlias=192.168.1.173", cmd)
            pin_path = seen_pin["path"]
            self.assertEqual(seen_pin["data"], self.known_hosts_path.read_bytes())
            self.assertEqual(seen_pin["mode"], 0o600)
            self.assertEqual(seen_pin["links"], 1)
            self.assertEqual(seen_pin["parent_mode"], 0o700)
            self.assertIn("ForwardAgent=no", cmd)
            self.assertRegex(cmd[-1], rf"^cd -- '/remote repo' && FK0957_TARGET=FK0957 python3 - {remote.COLLECTOR_PIN} [0-9a-f]{{64}}$")
            self.assertEqual(kwargs["input"], remote.COLLECTOR.read_bytes())
            self.assertNotIn(key_bytes, kwargs["input"])
            self.assertNotIn(str(key_path), " ".join(cmd))
            prov = result["payload"]["provenance"]
            self.assertEqual(prov["ssh_destination"], remote.SSH_DESTINATION)
            self.assertEqual(prov["ssh_host_key_algorithm"], "ssh-ed25519")
            self.assertTrue(prov["ssh_host_key_sha256"].startswith("SHA256:"))
            self.assertFalse(pin_path.exists())
            self.assertEqual(prov["pinned_known_hosts_sha256"], remote.sha(self.known_hosts_path.read_bytes()))
            self.assertEqual(prov["collector_reported_hostname_SELF_REPORTED"], "testbox")
            canonical = remote.canonical(result["payload"])
            key.public_key().verify(bytes.fromhex(result["signature_hex"]), canonical)

    def test_wrong_target_counters_extra_fields_and_stale_data_refuse(self):
        base = unsigned()
        for change in ({"target_selector": "FK0958"}, {"WRITE_COUNT": 1},
                       {"extra": "no"}, {"adapter_serial": "wrong"},
                       {"usb_descriptor_serial": "153300000957A"},
                       {"usb_descriptor_serial": "0957"},
                       {"usb_descriptor_serial": "153300000958"},
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

    def test_evidence_schema_keeps_adapter_and_usb_descriptor_serial_distinct(self):
        base = unsigned()
        self.assertEqual(base["adapter_serial"], "153300000957A")
        self.assertEqual(base["usb_descriptor_serial"], "153300000957")
        self.assertIn("usb_descriptor_serial", remote.EXPECTED_FIELDS)
        for bad in (
                {k: v for k, v in base.items() if k != "usb_descriptor_serial"},
                dict(base, usb_descriptor_serial="153300000957A"),
                dict(base, adapter_serial="153300000957"),
                dict(base, fpga_dna="4000000001295d813c80a445")):
            with self.subTest(record=bad), self.assertRaises(remote.Refusal):
                remote.validate_unsigned(wire(bad), collector_hash=remote.COLLECTOR_PIN,
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
                                  "execution_mode": "REMOTE_CHECKOUT",
                                  "execution_source_commit": None,
                                  "execution_bundle_sha256": None,
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
            self.assertEqual(set(kwargs), {"input", "stdout", "stderr", "check", "timeout", "env"})
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
        self.assertNotIn("HostKeyAlias=192.168.1.173", cmd)
        self.assertTrue(any(x.startswith("UserKnownHostsFile=/tmp/fk0957-known-hosts-") for x in cmd))

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
                pin_arg = next(x for x in cmd if x.startswith("UserKnownHostsFile="))
                pinned_copy = Path(pin_arg.split("=", 1)[1]).read_bytes()
                self.assertEqual(pinned_copy, original)
                return subprocess.CompletedProcess(cmd, 0, wire(unsigned(session_nonce=cmd[-1].split()[-1])), b"")
            signed = remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path,
                runner=mutate_after_exec, expected_hostname="testbox", remote_repo="/remote")
            self.assertEqual(signed["payload"]["provenance"]["pinned_known_hosts_sha256"], remote.sha(original))

    def test_pin_changed_between_validation_and_invocation_refuses(self):
        fake = FakeSSH(b"")
        original_read = remote._read_pinned_source
        calls = 0
        def mutate_between_reads(path):
            nonlocal calls
            calls += 1
            result = original_read(path)
            if calls == 1:
                self.known_hosts_path.write_text(hostkey_line(keyseed=b"C" * 32))
                self.known_hosts_path.chmod(0o600)
            return result
        with mock.patch.object(remote, "_read_pinned_source", side_effect=mutate_between_reads):
            with self.assertRaises(remote.Refusal):
                remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(fake.calls, [])

    def test_private_temp_pin_tampering_before_ssh_refuses(self):
        fake = FakeSSH(b"")
        original_validate = remote._validate_private_pin
        calls = 0
        def tamper_second_validation(path, material, identity, dir_identity, file_identity):
            nonlocal calls
            calls += 1
            if calls == 2:
                Path(path).write_bytes(material + b"# changed\\n")
                Path(path).chmod(0o600)
            return original_validate(path, material, identity, dir_identity, file_identity)
        with mock.patch.object(remote, "_validate_private_pin", side_effect=tamper_second_validation):
            with self.assertRaises(remote.Refusal):
                remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                    runner=fake, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(fake.calls, [])

    def test_private_temp_pin_is_cleaned_when_ssh_runner_raises(self):
        observed = {}
        def raise_after_observing(cmd, **kwargs):
            option = next(x for x in cmd if x.startswith("UserKnownHostsFile="))
            path = Path(option.split("=", 1)[1])
            observed["path"] = path
            observed["bytes"] = path.read_bytes()
            raise OSError("simulated SSH launch error")
        with self.assertRaises(OSError):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                runner=raise_after_observing, expected_hostname="testbox", remote_repo="/remote")
        self.assertEqual(observed["bytes"], self.known_hosts_path.read_bytes())
        self.assertFalse(observed["path"].exists())

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

    def test_ephemeral_bundle_is_deterministic_minimal_and_pinned(self):
        first, metadata = self.make_bundle()
        second, metadata2 = self.make_bundle()
        self.assertEqual(first, second)
        self.assertEqual(metadata, metadata2)
        self.assertEqual(set(metadata["files"]), set(bundle_tools.PAYLOAD_RELS))
        self.assertEqual(len(metadata["files"]), 3)
        parsed, members = bundle_tools.inspect_bundle(
            first, expected_bundle_sha256=metadata["bundle_sha256"],
            expected_source_commit=metadata["source_commit"],
            expected_collector_sha256=metadata["collector_source_sha256"],
            expected_backend_sha256=metadata["backend_source_sha256"],
            expected_nonce=metadata["session_nonce"])
        self.assertEqual(parsed["session_nonce"], "1" * 64)
        self.assertEqual(set(members), {*bundle_tools.PAYLOAD_RELS, "runner.py"})

    def test_ephemeral_bundle_rejects_modified_truncated_extra_and_wrong_nonce(self):
        raw, m = self.make_bundle()
        args = dict(expected_source_commit=m["source_commit"],
                    expected_collector_sha256=m["collector_source_sha256"],
                    expected_backend_sha256=m["backend_source_sha256"], expected_nonce=m["session_nonce"])
        with self.assertRaises(bundle_tools.BundleRefusal):
            bundle_tools.inspect_bundle(raw[:-9], expected_bundle_sha256=hashlib.sha256(raw[:-9]).hexdigest(), **args)
        changed_stream = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(changed_stream, "w") as target:
            for item in source.infolist():
                data = source.read(item.filename)
                if item.filename == bundle_tools.COLLECTOR_REL:
                    data = bytes([data[0] ^ 1]) + data[1:]
                target.writestr(item, data)
        changed = changed_stream.getvalue()
        with self.assertRaises(bundle_tools.BundleRefusal):
            bundle_tools.inspect_bundle(bytes(changed), expected_bundle_sha256=hashlib.sha256(changed).hexdigest(), **args)
        extra_stream = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(extra_stream, "w") as target:
            for item in source.infolist():
                target.writestr(item, source.read(item.filename))
            target.writestr("unexpected.py", b"print('unexpected')")
        extra = extra_stream.getvalue()
        with self.assertRaises(bundle_tools.BundleRefusal):
            bundle_tools.inspect_bundle(extra, expected_bundle_sha256=hashlib.sha256(extra).hexdigest(), **args)
        with self.assertRaises(bundle_tools.BundleRefusal):
            bundle_tools.inspect_bundle(raw, expected_bundle_sha256=m["bundle_sha256"],
                                        expected_source_commit=m["source_commit"],
                                        expected_collector_sha256=m["collector_source_sha256"],
                                        expected_backend_sha256=m["backend_source_sha256"],
                                        expected_nonce="2" * 64)
        with self.assertRaises(bundle_tools.BundleRefusal):
            bundle_tools.inspect_bundle(raw, expected_bundle_sha256=m["bundle_sha256"],
                                        expected_source_commit="f" * 40,
                                        expected_collector_sha256=m["collector_source_sha256"],
                                        expected_backend_sha256=m["backend_source_sha256"],
                                        expected_nonce=m["session_nonce"])

    def test_ephemeral_command_uses_isolated_python_and_no_remote_checkout(self):
        raw, m = self.make_bundle()
        command = bundle_tools.remote_command(bundle_sha256=m["bundle_sha256"],
            source_commit=m["source_commit"], collector_sha256=m["collector_source_sha256"],
            backend_sha256=m["backend_source_sha256"], session_nonce=m["session_nonce"])
        self.assertIn("/usr/bin/python3 -I -S -c ", command)
        self.assertIn("FK0957_TARGET=FK0957", command)
        self.assertIn(m["bundle_sha256"], command)
        self.assertNotIn("remote-repo", command)
        with self.assertRaises(bundle_tools.BundleRefusal):
            bundle_tools.remote_command(bundle_sha256="0" * 62 + ";id", source_commit=m["source_commit"],
                collector_sha256=m["collector_source_sha256"], backend_sha256=m["backend_source_sha256"],
                session_nonce=m["session_nonce"])

    def test_isolated_python_ignores_hostile_pythonpath_customization_and_cwd_modules(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            marker = root / "customization-ran"
            hostile = ("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('bad')\n")
            for name in ("sitecustomize.py", "usercustomize.py", "json.py", "socket.py"):
                (root / name).write_text(hostile)
            user_site = (root / "user-base" / "lib" /
                         f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")
            user_site.mkdir(parents=True)
            (user_site / "userpoison.py").write_text(hostile)
            proc = subprocess.run([sys.executable, "-I", "-S", "-c",
                                   "import importlib.util, json; print(json.__file__); print(importlib.util.find_spec('userpoison'))"], cwd=root,
                                  env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                                       "PYTHONPATH": str(root), "PYTHONHOME": str(root / "hostile-pythonhome"),
                                       "PYTHONUSERBASE": str(root / "user-base")},
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn(str(root), proc.stdout)
            self.assertTrue(proc.stdout.rstrip().endswith("None"))
            self.assertFalse(marker.exists())

    def test_isolated_bootstrap_verifies_bundle_before_exec_with_hostile_environment(self):
        bundle, metadata = self.make_bundle(runner_bytes=b"import sys\nsys.stdout.write('BUNDLE_OK')\n")
        command = bundle_tools.remote_command(bundle_sha256=metadata["bundle_sha256"],
            source_commit=metadata["source_commit"], collector_sha256=metadata["collector_source_sha256"],
            backend_sha256=metadata["backend_source_sha256"], session_nonce=metadata["session_nonce"])
        argv = shlex.split(command)
        self.assertEqual(argv[0], "FK0957_TARGET=FK0957")
        with tempfile.TemporaryDirectory() as d:
            poison = Path(d)
            marker = poison / "ran"
            (poison / "sitecustomize.py").write_text("from pathlib import Path; Path(" + repr(str(marker)) + ").write_text('x')")
            (poison / "zipfile.py").write_text("raise RuntimeError('shadowed stdlib')")
            proc = subprocess.run(argv[1:], input=bundle, cwd=poison,
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(poison)},
                capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, b"BUNDLE_OK")
            self.assertFalse(marker.exists())
            altered = bundle[:-1] + bytes([bundle[-1] ^ 1])
            bad = subprocess.run(argv[1:], input=altered, cwd=poison,
                env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(poison)},
                capture_output=True, timeout=10)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stdout, b"")
            self.assertIn(b"FK0957_DIAG REMOTE_PHASE=BUNDLE_RECEIVED", bad.stderr)
            self.assertIn(b"FK0957_DIAG SSH_ERROR_CLASS=BUNDLE_HASH_FAILED", bad.stderr)
            self.assertNotIn(b"COLLECTOR_STARTED", bad.stderr)

    def test_ephemeral_remote_stderr_and_partial_stdout_refuse(self):
        key = Path(self.pin_dir.name) / "not-read.pem"
        raw, m = self.make_bundle()
        common = dict(known_hosts_path=self.known_hosts_path, expected_hostname="testbox", ephemeral=True)
        for fake in (FakeSSH(b"", stderr=b"injected stderr"), FakeSSH(b'{"partial":')):
            with self.subTest(stderr=fake.stderr), self.assertRaises(remote.Refusal):
                remote.acquire_and_sign(key, runner=fake, **common)
            self.assertTrue(fake.calls[0][1]["input"].startswith(b"PK\x03\x04"))

    def test_remote_failure_diagnostics_retain_rc_phase_and_redact_raw_stderr(self):
        secret = b"credential=never-print-this"
        fake = FakeSSH(b"", stderr=b"Permission denied (publickey); " + secret, returncode=255)
        with self.assertRaises(remote.Refusal) as caught:
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                runner=fake, expected_hostname="testbox", ephemeral=True)
        message = str(caught.exception)
        self.assertIn("SSH_RETURN_CODE=255", message)
        self.assertIn("SSH_ERROR_CLASS=SSH_AUTH_FAILED", message)
        self.assertNotIn(secret.decode(), message)

        stderr = (b"FK0957_DIAG REMOTE_RUNNER_STARTED=YES\n"
                  b"FK0957_DIAG BUNDLE_RECEIVED=YES\n"
                  b"FK0957_DIAG BUNDLE_HASH_VERIFIED=YES\n"
                  b"FK0957_DIAG MANIFEST_VERIFIED=YES\n"
                  b"FK0957_DIAG COLLECTOR_SOURCE_VERIFIED=YES\n"
                  b"FK0957_DIAG BACKEND_SOURCE_VERIFIED=YES\n"
                  b"FK0957_DIAG COLLECTOR_STARTED=YES\n"
                  b"FK0957_DIAG COLLECTOR_RETURNED=YES\n"
                  b"FK0957_DIAG COLLECTOR_REFUSAL_CODE=NO_MATCHING_TARGET\n"
                  b"FK0957_DIAG REMOTE_PHASE=COLLECTOR_RETURNED\n"
                  b"FK0957_DIAG SSH_ERROR_CLASS=COLLECTOR_REFUSED\n")
        failure = remote.canonical({"status": "REFUSED", "phase": "COLLECTOR",
            "refusal_code": "NO_MATCHING_TARGET", "cards_opened": 0,
            "second_card_opened": False, "write_count": 0, "reset_count": 0,
            "program_count": 0, "jtag_operations": 0}) + b"\n"
        fake = FakeSSH(failure, stderr=stderr, returncode=2)
        with self.assertRaises(remote.Refusal) as caught:
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                runner=fake, expected_hostname="testbox", ephemeral=True)
        self.assertIn("SSH_RETURN_CODE=2", str(caught.exception))
        self.assertIn("REMOTE_PHASE=COLLECTOR_RETURNED", str(caught.exception))
        self.assertIn("SSH_ERROR_CLASS=COLLECTOR_REFUSED", str(caught.exception))
        self.assertIn("COLLECTOR_REFUSAL_CODE=NO_MATCHING_TARGET", str(caught.exception))
        self.assertEqual(len(fake.calls), 1)

    def test_every_collector_refusal_code_is_strictly_validated(self):
        for code in sorted(remote.COLLECTOR_REFUSAL_CODES):
            record = {"status": "REFUSED", "phase": "COLLECTOR", "refusal_code": code,
                      "cards_opened": 0, "second_card_opened": False,
                      "write_count": 0, "reset_count": 0, "program_count": 0,
                      "jtag_operations": 0}
            with self.subTest(code=code):
                raw = remote.canonical(record) + b"\n"
                self.assertEqual(remote._parse_collector_failure_envelope(raw, returncode=2), record)
                self.assertIsNone(remote._parse_collector_failure_envelope(raw, returncode=0))

    def test_collector_failure_envelopes_fail_closed_on_all_invalid_forms(self):
        base = {"status": "REFUSED", "phase": "COLLECTOR", "refusal_code": "INTERNAL_REFUSAL",
                "cards_opened": 0, "second_card_opened": False,
                "write_count": 0, "reset_count": 0, "program_count": 0,
                "jtag_operations": 0}
        attacks = {
            "forged_PASS": remote.canonical(unsigned()) + b"\n",
            "unknown_code": remote.canonical(dict(base, refusal_code="EXECUTE_COMMAND")) + b"\n",
            "lowercase_code": remote.canonical(dict(base, refusal_code="internal_refusal")) + b"\n",
            "array_code": remote.canonical(dict(base, refusal_code=[])) + b"\n",
            "object_code": remote.canonical(dict(base, refusal_code={"code": "INTERNAL_REFUSAL"})) + b"\n",
            "extra_field": remote.canonical(dict(base, arbitrary="secret")) + b"\n",
            "missing_field": remote.canonical({k: v for k, v in base.items() if k != "phase"}) + b"\n",
            "duplicate_json_key": b'{"cards_opened":0,"jtag_operations":0,"phase":"COLLECTOR","program_count":0,"refusal_code":"INTERNAL_REFUSAL","reset_count":0,"second_card_opened":false,"status":"REFUSED","status":"REFUSED","write_count":0}\n',
            "control_character": b'{"status":"REFUSED","phase":"COLLECTOR","refusal_code":"INTERNAL_REFUSAL","cards_opened":0,"second_card_opened":false,"write_count":0,"reset_count":0,"program_count":0,"jtag_operations":0}\x01\n',
            "malformed_json": b"{not-json}\n",
            "conflicting_cards": remote.canonical(dict(base, cards_opened=1)) + b"\n",
            "string_counter": remote.canonical(dict(base, cards_opened="0")) + b"\n",
            "bool_counter": remote.canonical(dict(base, write_count=True)) + b"\n",
            "negative_counter": remote.canonical(dict(base, reset_count=-1)) + b"\n",
            "huge_counter": remote.canonical(dict(base, program_count=10**100)) + b"\n",
            "write_nonzero": remote.canonical(dict(base, write_count=1)) + b"\n",
            "reset_nonzero": remote.canonical(dict(base, reset_count=1)) + b"\n",
            "program_nonzero": remote.canonical(dict(base, program_count=1)) + b"\n",
            "jtag_nonzero": remote.canonical(dict(base, jtag_operations=1)) + b"\n",
            "multiple_records": remote.canonical(base) + b"\n" + remote.canonical(base) + b"\n",
            "partial_record": remote.canonical(base)[:-1],
        }
        for label, raw in attacks.items():
            with self.subTest(label=label):
                self.assertIsNone(remote._parse_collector_failure_envelope(raw, returncode=2))
        self.assertIsNone(remote._parse_collector_failure_envelope(
            remote.canonical(base) + b"\n", returncode=0))

    def test_unhashable_refusal_code_is_rejected_by_both_envelope_parsers(self):
        for code in ([], {}):
            record = {"status": "REFUSED", "phase": "COLLECTOR", "refusal_code": code,
                      "cards_opened": 0, "second_card_opened": False,
                      "write_count": 0, "reset_count": 0, "program_count": 0,
                      "jtag_operations": 0}
            raw = remote.canonical(record) + b"\n"
            with self.subTest(code=code):
                self.assertIsNone(remote._parse_collector_failure_envelope(raw, returncode=2))
                self.assertIsNone(bundle_runner.parse_collector_failure_envelope(raw, returncode=2))

    def test_collector_failure_envelope_requires_matching_ordered_diagnostics_and_is_never_evidence(self):
        record = {"status": "REFUSED", "phase": "COLLECTOR", "refusal_code": "DESCRIPTOR_READ_FAILED",
                  "cards_opened": 0, "second_card_opened": False,
                  "write_count": 0, "reset_count": 0, "program_count": 0,
                  "jtag_operations": 0}
        stdout = remote.canonical(record) + b"\n"
        markers = ["REMOTE_RUNNER_STARTED", "BUNDLE_RECEIVED", "BUNDLE_HASH_VERIFIED",
                   "MANIFEST_VERIFIED", "COLLECTOR_SOURCE_VERIFIED", "BACKEND_SOURCE_VERIFIED",
                   "COLLECTOR_STARTED", "COLLECTOR_RETURNED"]
        stderr = b"".join(f"FK0957_DIAG {name}=YES\n".encode() for name in markers)
        stderr += (b"FK0957_DIAG COLLECTOR_REFUSAL_CODE=DESCRIPTOR_READ_FAILED\n"
                   b"FK0957_DIAG REMOTE_PHASE=COLLECTOR_RETURNED\n"
                   b"FK0957_DIAG SSH_ERROR_CLASS=COLLECTOR_REFUSED\n")
        message = remote._remote_failure_message(2, stderr, stdout)
        self.assertIn("COLLECTOR_REFUSAL_CODE=DESCRIPTOR_READ_FAILED", message)
        self.assertIn("SSH_RETURN_CODE=2", message)
        self.assertIsNone(remote._parse_collector_failure_envelope(stdout, returncode=0))

        forged = remote.canonical(unsigned()) + b"\n"
        message = remote._remote_failure_message(2, stderr, forged)
        self.assertIn("SSH_ERROR_CLASS=UNEXPECTED_REMOTE_EXIT", message)
        self.assertNotIn("COLLECTOR_REFUSAL_CODE=", message)

        injected = stderr + b"secret=must-not-appear\n"
        message = remote._remote_failure_message(2, injected, stdout)
        self.assertNotIn("secret=must-not-appear", message)
        self.assertNotIn("COLLECTOR_REFUSAL_CODE=", message)

    def test_forged_or_malformed_phase_markers_are_discarded(self):
        attacks = (
            # A later marker without the preceding verified phases.
            b"FK0957_DIAG COLLECTOR_RETURNED=YES\n"
            b"FK0957_DIAG REMOTE_PHASE=COLLECTOR_RETURNED\n"
            b"FK0957_DIAG SSH_ERROR_CLASS=COLLECTOR_REFUSED\n",
            # Out-of-order phases cannot establish collector access.
            b"FK0957_DIAG REMOTE_RUNNER_STARTED=YES\n"
            b"FK0957_DIAG BUNDLE_HASH_VERIFIED=YES\n"
            b"FK0957_DIAG BUNDLE_RECEIVED=YES\n"
            b"FK0957_DIAG REMOTE_PHASE=BUNDLE_RECEIVED\n"
            b"FK0957_DIAG SSH_ERROR_CLASS=BUNDLE_HASH_FAILED\n",
            # A valid-looking prefix followed by untrusted text invalidates
            # the whole stream; do not retain its claimed phase.
            b"FK0957_DIAG REMOTE_RUNNER_STARTED=YES\n"
            b"FK0957_DIAG BUNDLE_RECEIVED=YES\n"
            b"FK0957_DIAG REMOTE_PHASE=BUNDLE_RECEIVED\n"
            b"FK0957_DIAG SSH_ERROR_CLASS=BUNDLE_HASH_FAILED\n"
            b"forged phase COLLECTOR_RETURNED",
        )
        for stderr in attacks:
            with self.subTest(stderr=stderr):
                records, clean = remote._parse_remote_diagnostics(stderr)
                self.assertFalse(clean)
                self.assertEqual(records, {})
                message = remote._remote_failure_message(2, stderr)
                self.assertNotIn("REMOTE_PHASE=COLLECTOR_RETURNED", message)
                self.assertNotIn("COLLECTOR_RETURNED=YES", message)
                self.assertNotIn("forged phase", message)

    def test_precollector_bundle_failure_refuses_before_evidence_validation_or_signing(self):
        stderr = (b"FK0957_DIAG REMOTE_RUNNER_STARTED=YES\n"
                  b"FK0957_DIAG BUNDLE_RECEIVED=YES\n"
                  b"FK0957_DIAG REMOTE_PHASE=BUNDLE_RECEIVED\n"
                  b"FK0957_DIAG SSH_ERROR_CLASS=BUNDLE_HASH_FAILED\n")
        fake = FakeSSH(b"", stderr=stderr, returncode=2)
        with mock.patch.object(remote, "validate_unsigned", side_effect=AssertionError("evidence validation reached")), \
             mock.patch.object(remote, "_read_signing_key", side_effect=AssertionError("signing reached")):
            with self.assertRaises(remote.Refusal) as caught:
                remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                    runner=fake, expected_hostname="testbox", ephemeral=True)
        self.assertIn("REMOTE_PHASE=BUNDLE_RECEIVED", str(caught.exception))
        self.assertEqual(len(fake.calls), 1)
        self.assertTrue(fake.calls[0][1]["input"].startswith(b"PK\x03\x04"))

    def test_malformed_remote_stdout_fails_closed_with_bounded_diagnostic(self):
        fake = FakeSSH(b"not-json\n")
        with mock.patch.object(remote, "_read_signing_key", side_effect=AssertionError("signing reached")):
            with self.assertRaises(remote.Refusal) as caught:
                remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                    runner=fake, expected_hostname="testbox", ephemeral=True)
        self.assertIn("SSH_ERROR_CLASS=JSON_PARSE_FAILED", str(caught.exception))
        self.assertIn("REMOTE_PHASE=STDOUT_RECORD_RECEIVED", str(caught.exception))

    def test_main_never_writes_a_collector_failure_to_the_evidence_path(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            with mock.patch.object(remote, "acquire_and_sign",
                                   side_effect=remote.Refusal("SSH_RETURN_CODE=2 SSH_ERROR_CLASS=COLLECTOR_REFUSED")), \
                 mock.patch.object(remote, "write_evidence_atomic") as write_atomic:
                with self.assertRaises(SystemExit):
                    remote.main(["--signing-key", "unused.pem", "--known-hosts", str(self.known_hosts_path),
                                 "--output", str(output), "--expected-hostname", "testbox", "--ephemeral"])
            write_atomic.assert_not_called()
            self.assertFalse(output.exists())

    def test_ephemeral_signing_binds_bundle_hash_commit_nonce_and_local_key_only(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory() as d:
            key_path = Path(d) / "RGB_ONLY_SIGNING_KEY.pem"
            key = Ed25519PrivateKey.generate()
            key_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
            key_path.write_bytes(key_bytes)
            diagnostic_stderr = b"".join(
                f"FK0957_DIAG {phase}=YES\n".encode() for phase in (
                    "REMOTE_RUNNER_STARTED", "BUNDLE_RECEIVED", "BUNDLE_HASH_VERIFIED",
                    "MANIFEST_VERIFIED", "COLLECTOR_SOURCE_VERIFIED", "BACKEND_SOURCE_VERIFIED",
                    "COLLECTOR_STARTED", "COLLECTOR_RETURNED", "STDOUT_RECORD_RECEIVED"))
            fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1],
                                                      collector_hash=remote.COLLECTOR_PIN)),
                           stderr=diagnostic_stderr)
            signed = remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path, runner=fake,
                expected_hostname="testbox", ephemeral=True)
            cmd, kwargs = fake.calls[0]
            self.assertIn("-I -S -c", cmd[-1])
            self.assertTrue(kwargs["input"].startswith(b"PK\x03\x04"))
            prov = signed["payload"]["provenance"]
            self.assertEqual(prov["execution_mode"], "EPHEMERAL_REVIEWED_BUNDLE")
            self.assertEqual(prov["execution_bundle_sha256"], hashlib.sha256(kwargs["input"]).hexdigest())
            self.assertEqual(prov["execution_source_commit"], self.make_bundle()[1]["source_commit"])
            self.assertNotIn(key_bytes, kwargs["input"])
            self.assertNotIn(str(key_path), " ".join(cmd))
            key.public_key().verify(bytes.fromhex(signed["signature_hex"]),
                                    remote.canonical(signed["payload"]))

    def test_ephemeral_source_commit_ignores_git_environment_redirects(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            evil_repo = root / "evil-repo"
            subprocess.run(["git", "init", str(evil_repo)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(evil_repo), "-c", "user.name=Audit",
                            "-c", "user.email=audit@example.invalid", "commit", "--allow-empty", "-m", "evil"],
                           check=True, capture_output=True)
            evil_commit = subprocess.run(["git", "-C", str(evil_repo), "rev-parse", "HEAD"],
                                         check=True, capture_output=True, text=True).stdout.strip()
            key_path = root / "key.pem"
            key = Ed25519PrivateKey.generate()
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce=cmd[-1].split()[-1],
                                                      collector_hash=remote.COLLECTOR_PIN)))
            hostile_env = {"GIT_DIR": str(evil_repo / ".git"),
                           "GIT_WORK_TREE": str(root), "GIT_CONFIG_COUNT": "1",
                           "GIT_CONFIG_KEY_0": "core.worktree", "GIT_CONFIG_VALUE_0": str(root)}
            with mock.patch.dict(os.environ, hostile_env, clear=False):
                signed = remote.acquire_and_sign(key_path, known_hosts_path=self.known_hosts_path,
                    runner=fake, expected_hostname="testbox", ephemeral=True)
            recorded = signed["payload"]["provenance"]["execution_source_commit"]
            self.assertNotEqual(recorded, evil_commit)
            self.assertEqual(recorded, subprocess.run(["git", "-C", str(remote.REPO), "rev-parse", "HEAD"],
                check=True, capture_output=True, text=True).stdout.strip())

    def test_ephemeral_remote_rejects_wrong_nonce_and_stderr_before_signing(self):
        fake = FakeSSH(lambda cmd: wire(unsigned(session_nonce="0" * 64)))
        with self.assertRaises(remote.Refusal):
            remote.acquire_and_sign(Path("missing-key"), known_hosts_path=self.known_hosts_path,
                                    runner=fake, expected_hostname="testbox", ephemeral=True)
        self.assertEqual(len(fake.calls), 1)

    def test_remote_temp_path_symlink_attack_refuses_without_following_target(self):
        raw_bundle, metadata = self.make_bundle()
        manifest, members = bundle_tools.inspect_bundle(raw_bundle,
            expected_bundle_sha256=metadata["bundle_sha256"], expected_source_commit=metadata["source_commit"],
            expected_collector_sha256=metadata["collector_source_sha256"],
            expected_backend_sha256=metadata["backend_source_sha256"], expected_nonce=metadata["session_nonce"])
        members.pop("runner.py")
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir(mode=0o700)
            link = Path("/tmp") / ("fk0957-link-" + remote.secrets.token_hex(8))
            link.symlink_to(target, target_is_directory=True)
            class LinkedTemp:
                name = str(link)
                def cleanup(self):
                    link.unlink()
            with self.assertRaises(RuntimeError):
                bundle_runner.run_payload(manifest, members, expected_commit=metadata["source_commit"],
                    collector_hash=metadata["collector_source_sha256"], backend_hash=metadata["backend_source_sha256"],
                    session_nonce=metadata["session_nonce"], temp_factory=lambda **_: LinkedTemp(),
                    process_runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, b'{"ok":true}\n', b""))
            self.assertEqual(list(target.iterdir()), [])

    def test_bundle_precollector_failure_does_not_start_collector_process(self):
        raw, metadata = self.make_bundle()
        manifest, members = bundle_tools.inspect_bundle(raw,
            expected_bundle_sha256=metadata["bundle_sha256"],
            expected_source_commit=metadata["source_commit"],
            expected_collector_sha256=metadata["collector_source_sha256"],
            expected_backend_sha256=metadata["backend_source_sha256"],
            expected_nonce=metadata["session_nonce"])
        members.pop("runner.py")
        members[bundle_tools.BACKEND_REL] += b"# tampered"
        invoked = []
        with self.assertRaises(RuntimeError):
            bundle_runner.run_payload(manifest, members,
                expected_commit=metadata["source_commit"],
                collector_hash=metadata["collector_source_sha256"],
                backend_hash=metadata["backend_source_sha256"],
                session_nonce=metadata["session_nonce"],
                process_runner=lambda *a, **k: invoked.append((a, k)))
        self.assertEqual(invoked, [])

    def test_collector_refusal_diagnostic_does_not_forward_remote_stderr(self):
        import contextlib
        raw, metadata = self.make_bundle()
        manifest, members = bundle_tools.inspect_bundle(raw,
            expected_bundle_sha256=metadata["bundle_sha256"],
            expected_source_commit=metadata["source_commit"],
            expected_collector_sha256=metadata["collector_source_sha256"],
            expected_backend_sha256=metadata["backend_source_sha256"],
            expected_nonce=metadata["session_nonce"])
        members.pop("runner.py")
        envelope = remote.canonical({"status": "REFUSED", "phase": "COLLECTOR",
            "refusal_code": "INTERNAL_REFUSAL", "cards_opened": 0,
            "second_card_opened": False, "write_count": 0, "reset_count": 0,
            "program_count": 0, "jtag_operations": 0}) + b"\n"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            with self.assertRaises(bundle_runner.RemoteDiagnosticError) as caught:
                bundle_runner.run_payload(manifest, members,
                    expected_commit=metadata["source_commit"],
                    collector_hash=metadata["collector_source_sha256"],
                    backend_hash=metadata["backend_source_sha256"],
                    session_nonce=metadata["session_nonce"],
                    process_runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                        argv, 2, envelope, b""))
        self.assertEqual(caught.exception.phase, "COLLECTOR_RETURNED")
        self.assertEqual(caught.exception.error_class, "COLLECTOR_REFUSED")
        self.assertEqual(caught.exception.refusal_code, "INTERNAL_REFUSAL")
        self.assertNotIn("collection refused:", captured.getvalue())
        self.assertIn("FK0957_DIAG COLLECTOR_STARTED=YES", captured.getvalue())
        self.assertIn("FK0957_DIAG COLLECTOR_RETURNED=YES", captured.getvalue())

    def test_runner_accepts_each_canonical_collector_refusal_code_only_on_nonzero_exit(self):
        import contextlib
        raw, metadata = self.make_bundle()
        manifest, members = bundle_tools.inspect_bundle(raw,
            expected_bundle_sha256=metadata["bundle_sha256"],
            expected_source_commit=metadata["source_commit"],
            expected_collector_sha256=metadata["collector_source_sha256"],
            expected_backend_sha256=metadata["backend_source_sha256"],
            expected_nonce=metadata["session_nonce"])
        members.pop("runner.py")
        for code in sorted(bundle_runner.COLLECTOR_REFUSAL_CODES):
            envelope = remote.canonical({"status": "REFUSED", "phase": "COLLECTOR",
                "refusal_code": code, "cards_opened": 0, "second_card_opened": False,
                "write_count": 0, "reset_count": 0, "program_count": 0,
                "jtag_operations": 0}) + b"\n"
            with self.subTest(code=code), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(bundle_runner.RemoteDiagnosticError) as caught:
                    bundle_runner.run_payload(manifest, members,
                        expected_commit=metadata["source_commit"],
                        collector_hash=metadata["collector_source_sha256"],
                        backend_hash=metadata["backend_source_sha256"],
                        session_nonce=metadata["session_nonce"],
                        process_runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                            argv, 2, envelope, b""))
                self.assertEqual(caught.exception.error_class, "COLLECTOR_REFUSED")
                self.assertEqual(caught.exception.refusal_code, code)
                self.assertEqual(caught.exception.failure_envelope, envelope)
            self.assertIsNone(bundle_runner.parse_collector_failure_envelope(envelope, returncode=0))

    def test_runner_rejects_forged_malformed_conflicting_and_injected_failure_records(self):
        valid = {"status": "REFUSED", "phase": "COLLECTOR", "refusal_code": "INTERNAL_REFUSAL",
                 "cards_opened": 0, "second_card_opened": False,
                 "write_count": 0, "reset_count": 0, "program_count": 0,
                 "jtag_operations": 0}
        forged_pass = remote.canonical(unsigned()) + b"\n"
        variants = [
            forged_pass,
            remote.canonical(dict(valid, refusal_code="UNKNOWN_CODE")) + b"\n",
            remote.canonical(dict(valid, refusal_code=[])) + b"\n",
            remote.canonical(dict(valid, refusal_code={"code": "INTERNAL_REFUSAL"})) + b"\n",
            remote.canonical(dict(valid, extra="value")) + b"\n",
            b"{malformed}\n",
            b'{"cards_opened":0,"jtag_operations":0,"phase":"COLLECTOR","program_count":0,"refusal_code":"INTERNAL_REFUSAL","reset_count":0,"second_card_opened":false,"status":"REFUSED","status":"REFUSED","write_count":0}\n',
            remote.canonical(dict(valid, cards_opened=1)) + b"\n",
            remote.canonical(dict(valid, write_count=1)) + b"\n",
            remote.canonical(dict(valid, reset_count=1)) + b"\n",
            remote.canonical(dict(valid, program_count=1)) + b"\n",
            remote.canonical(dict(valid, jtag_operations=1)) + b"\n",
            remote.canonical(valid) + b"\n" + remote.canonical(valid) + b"\n",
            remote.canonical(valid)[:-1],
        ]
        for index, raw in enumerate(variants):
            with self.subTest(index=index):
                self.assertIsNone(bundle_runner.parse_collector_failure_envelope(
                    raw, returncode=2, stderr=b""))
        secret = b"remote-secret-must-not-escape"
        encoded = remote.canonical(valid) + b"\n"
        self.assertIsNone(bundle_runner.parse_collector_failure_envelope(
            encoded, returncode=2, stderr=secret))

    def test_collector_temp_replacement_cannot_change_executed_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            marker_verified = root / "verified-ran"
            marker_replacement = root / "replacement-ran"
            collector_rel = bundle_tools.COLLECTOR_REL
            backend_rel = bundle_tools.BACKEND_REL
            observer_rel = bundle_tools.OBSERVER_REL
            collector_bytes = ("from pathlib import Path\nPath(" + repr(str(marker_verified)) +
                              ").write_text('verified')\nprint('{\\\"source\\\":\\\"verified\\\"}')\n").encode()
            backend_bytes, observer_bytes = b"pinned-backend", b"pinned-observer"
            nonce, commit = "a" * 64, "b" * 40
            files = {collector_rel: collector_bytes, backend_rel: backend_bytes,
                     observer_rel: observer_bytes}
            hashes = {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}
            manifest = {"source_commit": commit, "session_nonce": nonce,
                        "collector_source_sha256": hashes[collector_rel],
                        "backend_source_sha256": hashes[backend_rel], "files": hashes}
            real_run = subprocess.run

            def replace_before_exec(argv, **kwargs):
                bundle_root = Path(kwargs["env"]["FK0957_BUNDLE_ROOT"])
                collector_path = bundle_root / collector_rel
                collector_path.write_text(
                    "from pathlib import Path\nPath(" + repr(str(marker_replacement)) +
                    ").write_text('replacement')\nprint('{\\\"source\\\":\\\"replacement\\\"}')\n")
                self.assertEqual(argv[3], "-c")
                self.assertEqual(kwargs["input"], collector_bytes)
                return real_run(argv, **kwargs)

            raw = bundle_runner.run_payload(manifest, files, expected_commit=commit,
                collector_hash=hashes[collector_rel], backend_hash=hashes[backend_rel],
                session_nonce=nonce, process_runner=replace_before_exec)
            self.assertEqual(json.loads(raw), {"source": "verified"})
            self.assertTrue(marker_verified.exists())
            self.assertFalse(marker_replacement.exists())

    def test_collector_bundle_directory_does_not_shadow_stdlib_imports(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative in bundle_tools.PAYLOAD_RELS:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((remote.REPO / relative).read_bytes())
            marker = root / "shadow-import-ran"
            (root / "tools/phk2_host/dataclasses.py").write_text(
                "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('shadow')\n"
                "raise RuntimeError('bundle path shadowed dataclasses')\n")
            collector = root / bundle_tools.COLLECTOR_REL
            proc = subprocess.run([sys.executable, "-I", "-S", "-c",
                "import sys; exec(compile(sys.stdin.buffer.read(), '<collector-test>', 'exec'))",
                remote.COLLECTOR_PIN, "c" * 64], input=collector.read_bytes(), cwd=root,
                env={"PATH": "/usr/bin:/bin", "FK0957_TARGET": "", "FK0957_BUNDLE_ROOT": str(root)},
                capture_output=True, timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(marker.exists())

    def test_remote_temp_cleanup_failure_emits_no_stdout(self):
        raw_bundle, metadata = self.make_bundle()
        manifest, members = bundle_tools.inspect_bundle(raw_bundle,
            expected_bundle_sha256=metadata["bundle_sha256"], expected_source_commit=metadata["source_commit"],
            expected_collector_sha256=metadata["collector_source_sha256"],
            expected_backend_sha256=metadata["backend_source_sha256"], expected_nonce=metadata["session_nonce"])
        members.pop("runner.py")
        real_temp = tempfile.TemporaryDirectory()
        class BadCleanup:
            name = real_temp.name
            def cleanup(self):
                real_temp.cleanup()
                raise OSError("injected cleanup failure")
        out = io.BytesIO()
        with self.assertRaises(RuntimeError):
            bundle_runner.run_payload(manifest, members, expected_commit=metadata["source_commit"],
                collector_hash=metadata["collector_source_sha256"], backend_hash=metadata["backend_source_sha256"],
                session_nonce=metadata["session_nonce"], temp_factory=lambda **_: BadCleanup(),
                process_runner=lambda *a, **k: subprocess.CompletedProcess(a[0], 0, b'{"ok":true}\n', b""),
                stdout=out)
        self.assertEqual(out.getvalue(), b"")

    def test_unexpected_import_is_refused_and_bundle_contains_no_mutator_api(self):
        with self.assertRaises(bundle_tools.BundleRefusal):
            bundle_tools._check_import_surface({bundle_tools.COLLECTOR_REL: b"import sitecustomize\n"})
        backend = remote.BACKEND.read_text()
        for forbidden in ("ftdi_write_data", "ftdi_set_bitmode", "libusb_claim_interface"):
            self.assertNotIn(forbidden, backend)

    def test_changed_collector_or_backend_mutation_capability_cannot_be_bundled(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for relative in bundle_tools.PAYLOAD_RELS:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((remote.REPO / relative).read_bytes())
            collector_path = root / bundle_tools.COLLECTOR_REL
            collector_path.write_bytes(collector_path.read_bytes() + b"\ndef program(): pass\n")
            with self.assertRaises(bundle_tools.BundleRefusal):
                bundle_tools.deterministic_bundle(source_commit="1" * 40, session_nonce="2" * 64,
                    source_root=root, collector_pin=remote.COLLECTOR_PIN,
                    backend_pin=remote.sha(remote.BACKEND.read_bytes()), observer_pin=remote.OBSERVER_PIN,
                    runner_bytes=(remote.HERE / "phk2_fk0957_ephemeral_runner.py").read_bytes())


if __name__ == "__main__":
    unittest.main()
