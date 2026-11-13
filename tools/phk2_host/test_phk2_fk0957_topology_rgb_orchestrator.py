from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_topology_rgb_orchestrator as rgb
import phk2_fk0957_remote_orchestrator as ssh_policy
import phk2_fk0957_topology_discovery as topology
import phk2_fk0957_topology_signing as signing
import phk2_fk0957_topology_transport as transport
import phk2_fk0957_idcode_gate as identity_gate
import phk2_fk0957_remote_topology_endpoint as endpoint


def response(pattern):
    captured = "".join(str((0x04B69093 >> i) & 1) for i in range(32))
    bits = captured + "".join(map(str, pattern[:-32]))
    packed = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        packed[index // 8] |= int(bit) << (index % 8)
    return bytes(packed[:-1]), bytes(((packed[-1] & 1) << 7,))


class RGBTopologyOrchestratorTests(unittest.TestCase):
    def test_pinned_ssh_keeps_agent_local_and_disables_forwarding(self):
        captured = {}
        def runner(command, **kwargs):
            captured["command"] = command
            captured.update(kwargs)
            return SimpleNamespace(returncode=0, stdout=b"canonical placeholder\n", stderr=b"remote-secret")
        known = b"approved host-key pin\n"
        host = {"algorithm": "ssh-ed25519", "fingerprint": "SHA256:" + "A" * 43}
        with mock.patch.object(ssh_policy, "_read_pinned_source", return_value=(known, host, (1, 2))), \
             mock.patch.object(ssh_policy, "_validated_local_ssh_auth_sock", return_value=("/run/user/1000/agent.sock", (3, 4))), \
             mock.patch.object(ssh_policy, "_probe_local_ssh_agent") as probe, \
             mock.patch.object(ssh_policy, "_revalidate_local_ssh_auth_sock") as revalidate, \
             mock.patch.object(ssh_policy, "_validate_private_pin"):
            output, provenance = rgb._pinned_ssh(b'{"request":"only"}\n', runner=runner)
        command = captured["command"]
        self.assertEqual(output, b"canonical placeholder\n")
        self.assertIn("ForwardAgent=no", command)
        self.assertIn("ClearAllForwardings=yes", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("GlobalKnownHostsFile=/dev/null", command)
        self.assertEqual(command[-2:], [ssh_policy._AUTHORIZED_SSH_DESTINATION,
                                       rgb.REMOTE_ENDPOINT_COMMAND])
        self.assertEqual(captured["input"], b'{"request":"only"}\n')
        self.assertEqual(captured["env"]["SSH_AUTH_SOCK"], "/run/user/1000/agent.sock")
        self.assertNotIn("SSH_AUTH_SOCK", command)
        self.assertEqual(captured["stderr"], subprocess.PIPE)
        self.assertNotIn(b"remote-secret", output)
        self.assertTrue(provenance["local_agent_available_to_ssh_client"])
        self.assertFalse(provenance["remote_agent_forwarding"])
        self.assertEqual(provenance["remote_process_state"], "REMOTE_PROCESS_CONFIRMED_EXITED")
        probe.assert_called_once(); revalidate.assert_called_once()

    def test_timeout_is_unknown_and_never_retried(self):
        calls = []
        def runner(*_args, **_kwargs):
            calls.append(1)
            raise subprocess.TimeoutExpired("ssh", 150)
        host = {"algorithm": "ssh-ed25519", "fingerprint": "SHA256:" + "A" * 43}
        with mock.patch.object(ssh_policy, "_read_pinned_source", return_value=(b"pin\n", host, (1, 2))), \
             mock.patch.object(ssh_policy, "_validated_local_ssh_auth_sock", return_value=("/agent", (3, 4))), \
             mock.patch.object(ssh_policy, "_probe_local_ssh_agent"), \
             mock.patch.object(ssh_policy, "_revalidate_local_ssh_auth_sock"), \
             mock.patch.object(ssh_policy, "_validate_private_pin"):
            with self.assertRaisesRegex(rgb.Refusal, "process state unknown") as caught:
                rgb._pinned_ssh(b"request", runner=runner)
        self.assertEqual(caught.exception.remote_state, "REMOTE_STATE_UNKNOWN")
        self.assertEqual(len(calls), 1)

    def test_endpoint_refusal_exit_confirms_process_exit_without_exposing_stderr(self):
        refusal = endpoint.canonical({"schema": "fk0957-remote-acquisition-v1",
                                      "status": "REFUSED", "phase": "DEVICE_OPEN",
                                      "code": "DEVICE_OPEN_FAILED"})
        host = {"algorithm": "ssh-ed25519", "fingerprint": "SHA256:" + "A" * 43}
        def runner(*_args, **_kwargs):
            return SimpleNamespace(returncode=2, stdout=refusal, stderr=b"secret /path")
        with mock.patch.object(ssh_policy, "_read_pinned_source", return_value=(b"pin\n", host, (1, 2))), \
             mock.patch.object(ssh_policy, "_validated_local_ssh_auth_sock", return_value=("/agent", (3, 4))), \
             mock.patch.object(ssh_policy, "_probe_local_ssh_agent"), \
             mock.patch.object(ssh_policy, "_revalidate_local_ssh_auth_sock"), \
             mock.patch.object(ssh_policy, "_validate_private_pin"):
            with self.assertRaisesRegex(rgb.Refusal, "DEVICE_OPEN_FAILED") as caught:
                rgb._pinned_ssh(b"request", runner=runner)
        self.assertEqual(caught.exception.remote_state, "REMOTE_PROCESS_CONFIRMED_EXITED")
        self.assertNotIn("secret", str(caught.exception))

    def test_ssh_255_never_confirms_remote_exit_even_with_refusal_bytes(self):
        refusal = endpoint.canonical({"schema": "fk0957-remote-acquisition-v1",
                                      "status": "REFUSED", "phase": "DEVICE_OPEN",
                                      "code": "DEVICE_OPEN_FAILED"})
        host = {"algorithm": "ssh-ed25519", "fingerprint": "SHA256:" + "A" * 43}
        def runner(*_args, **_kwargs):
            return SimpleNamespace(returncode=255, stdout=refusal, stderr=b"connection lost")
        with mock.patch.object(ssh_policy, "_read_pinned_source", return_value=(b"pin\n", host, (1, 2))), \
             mock.patch.object(ssh_policy, "_validated_local_ssh_auth_sock", return_value=("/agent", (3, 4))), \
             mock.patch.object(ssh_policy, "_probe_local_ssh_agent"), \
             mock.patch.object(ssh_policy, "_revalidate_local_ssh_auth_sock"), \
             mock.patch.object(ssh_policy, "_validate_private_pin"):
            with self.assertRaisesRegex(rgb.Refusal, "state unknown after SSH loss") as caught:
                rgb._pinned_ssh(b"request", runner=runner)
        self.assertEqual(caught.exception.remote_state, "REMOTE_STATE_UNKNOWN")

    def test_ssh_255_requires_fresh_supervisor_terminal_receipt(self):
        operation = "a" * 32
        auth_id = "b" * 64
        manifest_payload = {"schema": "test-manifest", "production_head": "f" * 40,
                            "transaction_profile_sha256": "9" * 64}
        request = endpoint.canonical({
            "operation_id": operation,
            "release_authorization": {"payload": {"authorization_id": auth_id}},
            "handoff": {"payload": {"handoff_id": "c" * 64}},
            "runtime_manifest": {"payload": manifest_payload},
        })
        handoff_payload = {"handoff_id": "c" * 64}
        result_record = endpoint.canonical({"schema": "unused-test-result"})
        status = endpoint.canonical({
            "schema": "fk0957-supervisor-status-v1", "operation_id": operation,
            "authorization_id": auth_id, "authorization_sha256": hashlib.sha256(
                endpoint.canonical({"authorization_id": auth_id})).hexdigest(),
            "handoff_sha256": hashlib.sha256(endpoint.canonical(handoff_payload)).hexdigest(),
            "manifest_sha256": hashlib.sha256(endpoint.canonical(manifest_payload)).hexdigest(),
            "production_head": manifest_payload.get("production_head"),
            "transaction_profile_sha256": manifest_payload.get("transaction_profile_sha256"),
            "target": "FK0957", "one_shot": True,
            "state": "EXITED_SUCCESS", "exit_code": 0, "reaped_ns": 123,
            "process": {"operation_id": operation, "authorization_id": auth_id,
                        "pid": 100, "parent_pid": 50, "start_identity": "12345",
                        "executable_sha256": "1" * 64, "argv_sha256": "2" * 64,
                        "executable": "/usr/local/bin/fk0957-safe-launcher"},
            "result_b64": __import__("base64").b64encode(result_record).decode(),
        })
        calls = []
        def runner(command, **_kwargs):
            calls.append(command)
            if len(calls) == 1:
                return SimpleNamespace(returncode=255, stdout=b"partial", stderr=b"private")
            return SimpleNamespace(returncode=0, stdout=status, stderr=b"private")
        host = {"algorithm": "ssh-ed25519", "fingerprint": "SHA256:" + "A" * 43}
        with mock.patch.object(ssh_policy, "_read_pinned_source", return_value=(b"pin\n", host, (1, 2))), \
             mock.patch.object(ssh_policy, "_validated_local_ssh_auth_sock", return_value=("/agent", (3, 4))), \
             mock.patch.object(ssh_policy, "_probe_local_ssh_agent"), \
             mock.patch.object(ssh_policy, "_revalidate_local_ssh_auth_sock"), \
             mock.patch.object(ssh_policy, "_validate_private_pin"):
            output, provenance = rgb._pinned_ssh(request, runner=runner)
        self.assertEqual(output, result_record)
        self.assertEqual(len(calls), 2)  # one acquisition, one read-only status query
        self.assertIn(operation, calls[1][-1])
        self.assertEqual(provenance["remote_process_state"], "REMOTE_PROCESS_CONFIRMED_EXITED")

    def test_rejected_or_malformed_remote_output_never_reaches_signing(self):
        context = {"operation_id": "1" * 32}
        with mock.patch.object(rgb, "_validated_local_context", return_value=context), \
             mock.patch.object(rgb, "_consume_local_auth") as consume, \
             mock.patch.object(rgb, "_pinned_ssh", return_value=(endpoint.canonical({
                 "schema": "fk0957-remote-acquisition-v1", "status": "REFUSED",
                 "phase": "DEVICE_OPEN", "code": "DEVICE_OPEN_FAILED"}), {})), \
             mock.patch.object(signing, "_sign_validated_remote_record") as sign:
            with self.assertRaisesRegex(rgb.Refusal, "remote refusal DEVICE_OPEN/DEVICE_OPEN_FAILED"):
                rgb.acquire_validate_sign_once(b"request")
        consume.assert_called_once_with(context)
        sign.assert_not_called()

    def test_unsigned_record_is_reparsed_from_raw_tdo_and_rejects_mutations(self):
        plan = topology.build_plan()
        raw_a = b"".join(response(plan.tdi_scans[0]))
        raw_b = b"".join(response(plan.tdi_scans[1]))
        bits_a = topology.raw_tdo_bits(raw_a[:-1], raw_a[-1:])
        bits_b = topology.raw_tdo_bits(raw_b[:-1], raw_b[-1:])
        parsed = topology.parse_raw_tdo(bits_a, bits_b, plan.tdi_scans[0], plan.tdi_scans[1])
        now = datetime.now(timezone.utc)
        context = {
            "operation_id": "1" * 32, "authorization_id": "2" * 64,
            "authorization_sha256": "3" * 64, "handoff_sha256": "4" * 64,
            "manifest_sha256": "5" * 64, "production_head": "a" * 40,
            "transaction_profile_sha256": endpoint._profile_hash(),
            "descriptor_sha256": "6" * 64, "permit_nonce": "7" * 64,
            "expires_at": (now + timedelta(minutes=2)).isoformat(),
        }
        record = {
            "schema": "fk0957-unsigned-topology-acquisition-v1", "status": "ACQUIRED",
            **{k: context[k] for k in ("operation_id", "authorization_id", "authorization_sha256",
                "handoff_sha256", "manifest_sha256", "production_head", "transaction_profile_sha256")},
            "card_id": "FK0957", "adapter_serial": "153300000957A",
            "usb_descriptor_serial": "153300000957", "physical_interface": "A",
            "descriptor_evidence_sha256": context["descriptor_sha256"], "permit_nonce": "8" * 64,
            "trusted_signer_fingerprint": identity_gate.TRUSTED_SIGNER_FINGERPRINT_SHA256,
            "observation_timestamp": now.isoformat(), "transport_source_sha256": "9" * 64,
            "worktree_clean": True,
            "runtime_library_provenance": [
                {"logical_name": pin.name, "approved_path": str(pin.path), "expected_sha256": pin.sha256,
                 "expected_build_id": pin.build_id, "soname": pin.soname,
                 "loaded_object_realpath": str(pin.path)} for pin in transport.LIBRARY_PINS],
            "scan_a_transaction_sha256": topology.scan_transaction_sha256(plan.scan_a_commands),
            "scan_a_tck_count": 591, "scan_a_raw_tdo_hex": raw_a.hex(),
            "scan_b_transaction_sha256": topology.scan_transaction_sha256(plan.scan_b_commands),
            "scan_b_tck_count": 586, "scan_b_raw_tdo_hex": raw_b.hex(), "total_tck_count": 1177,
            "matched_device_count": 1, "opened_device_count": 1, "second_device_opened": False,
            "aggregate_dr_length": parsed.aggregate_dr_length,
            "observed_taps_tdo_to_tdi": list(parsed.taps_tdo_to_tdi or ()),
            "raw_tdo_scan_a_bits_lsb_first": parsed.raw_tdo_scan_a_bits,
            "raw_tdo_scan_b_bits_lsb_first": parsed.raw_tdo_scan_b_bits,
            "write_count": 0, "reset_count": 0, "program_count": 0,
            "jtag_operation_count": 1, "topology_discovery_only": True,
            "idcode_qualification_pass": False, "fpga_dna_observed": False,
            "loaded_image_identity_observed": False, "bitstream_identity_observed": False,
        }
        with mock.patch.object(transport, "transport_source_sha256", return_value="9" * 64):
            accepted = rgb._validate_unsigned_record(endpoint.canonical(record), context)
            self.assertEqual(accepted, record)
            for field, value in (("write_count", 1), ("scan_a_tck_count", 592),
                                 ("card_id", "FK0958"), ("idcode_qualification_pass", True)):
                changed = dict(record); changed[field] = value
                with self.subTest(field=field), self.assertRaises(rgb.Refusal):
                    rgb._validate_unsigned_record(endpoint.canonical(changed), context)


if __name__ == "__main__":
    unittest.main()
