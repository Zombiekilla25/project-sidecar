from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_idcode_gate as gate
import phk2_fk0957_remote_orchestrator as remote
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def signed_descriptor(key: Ed25519PrivateKey, now: datetime) -> bytes:
    stamp = now.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    unsigned = {
        "schema": "fk0957-unsigned-descriptor-evidence", "version": 1,
        "target_selector": "FK0957", "collector_source_sha256": "a" * 64,
        "backend_source_sha256": "b" * 64, "session_nonce": "c" * 64,
        "source_commit": "d" * 40, "remote_hostname": "testbench", "acquisition_timestamp": stamp,
        "ftdi_vid": "0403", "ftdi_pid": "6010", "manufacturer": "Xilinx", "product": "SQRL FK",
        "interface": "A", "usb_path": "1-9.3", "adapter_serial": gate.ADAPTER_SERIAL,
        "usb_descriptor_serial": gate.USB_DESCRIPTOR_SERIAL, "fk0957_mapping": "153300000957",
        "WRITE_COUNT": 0, "RESET_COUNT": 0, "PROGRAM_COUNT": 0, "JTAG_OPERATIONS": 0,
    }
    unsigned_raw = remote.canonical(unsigned) + b"\n"
    provenance = {
        "ssh_destination": "rmann@192.168.1.173", "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_sha256": "SHA256:" + "A" * 43, "pinned_known_hosts_sha256": "e" * 64,
        "collector_reported_hostname_SELF_REPORTED": "testbench",
        "collector_source_sha256": unsigned["collector_source_sha256"],
        "backend_source_sha256": unsigned["backend_source_sha256"],
        "execution_mode": "EPHEMERAL_REVIEWED_BUNDLE", "execution_source_commit": "f" * 40,
        "execution_bundle_sha256": "1" * 64, "source_commit": unsigned["source_commit"],
        "acquisition_timestamp": stamp, "session_nonce": unsigned["session_nonce"],
        "raw_unsigned_sha256": remote.sha(unsigned_raw),
    }
    payload = {"schema": "fk0957-signed-identity-evidence", "version": 1,
               "unsigned_evidence": unsigned, "provenance": provenance}
    encoded = remote.canonical(payload)
    document = {"payload": payload, "payload_sha256": remote.sha(encoded),
                "signature_algorithm": "Ed25519", "signature_hex": key.sign(encoded).hex()}
    return remote.canonical(document)


def good_result(permit: gate.ReadPermit) -> dict:
    identity = {"card_id": gate.CARD_ID, "adapter_serial": gate.ADAPTER_SERIAL,
                "usb_descriptor_serial": gate.USB_DESCRIPTOR_SERIAL, "usb_path": permit.usb_path}
    return {
        "schema": "fk0957-fixed-idcode-observation-v1",
        "descriptor_evidence_sha256": permit.descriptor_evidence_sha256,
        "operation": permit.operation, **identity,
        "before_identity": identity.copy(), "after_identity": identity.copy(),
        "candidate_count": 1, "device_handles_opened": 1, "second_card_opened": False,
        "tap_reset_tms": [1, 1, 1, 1, 1, 0], "ir_opcode": 9, "ir_bits": 6,
        "dr_bits": 64, "tck_cycles": 87, "tap_state_after": "RUN_TEST_IDLE",
        "chain_words": [0x04B69093, 0], "idcode": "04b69093",
        "target_part_family": "xcvu33p", "write_count": 0, "reset_count": 0,
        "program_count": 0, "jtag_operations": 0,
    }


class FakeTransport:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def read_fk0957_idcode_once(self, permit):
        self.calls.append(permit)
        return self.result


class IdcodeGateTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.raw = signed_descriptor(self.key, self.now)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.permit = gate.authorize_descriptor(self.raw, expected_sha256=self.digest,
                                                public_key=self.key.public_key(), now=self.now)

    def test_signed_descriptor_authorizes_fixed_idcode_only_and_single_call(self):
        transport = FakeTransport(good_result(self.permit))
        result = gate.read_once(self.permit, transport)
        self.assertEqual(result["idcode"], "04b69093")
        self.assertEqual(result["target_part_family"], "xcvu33p")
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0].descriptor_evidence_sha256, self.digest)
        self.assertEqual(transport.calls[0].ir_opcode, 0x09)
        self.assertEqual(transport.calls[0].dr_bits, 64)
        self.assertEqual(transport.calls[0].tck_cycle_limit, 87)

    def test_descriptor_digest_signature_target_counters_and_freshness_are_required(self):
        with self.assertRaises(gate.Refusal):
            gate.authorize_descriptor(self.raw, expected_sha256="0" * 64,
                                      public_key=self.key.public_key(), now=self.now)
        stale = signed_descriptor(self.key, self.now.replace(year=self.now.year - 1))
        with self.assertRaises(gate.Refusal):
            gate.authorize_descriptor(stale, expected_sha256=hashlib.sha256(stale).hexdigest(),
                                      public_key=self.key.public_key(), now=self.now)

    def test_unexpected_idcode_topology_or_identity_refuses(self):
        for field, value in (("idcode", "04b69092"), ("chain_words", [0x04B69093, 0x1234]),
                             ("candidate_count", 2), ("second_card_opened", True),
                             ("tck_cycles", 88), ("write_count", 1),
                             ("usb_descriptor_serial", "153300000957A")):
            result = good_result(self.permit)
            result[field] = value
            with self.subTest(field=field), self.assertRaises(gate.Refusal):
                gate.validate_observation(self.permit, result)

    def test_before_after_identity_must_match_and_schema_is_closed(self):
        result = good_result(self.permit)
        result["after_identity"] = dict(result["after_identity"], usb_path="1-10")
        with self.assertRaises(gate.Refusal):
            gate.validate_observation(self.permit, result)

    def test_manually_constructed_or_modified_permit_is_not_authorized(self):
        transport = FakeTransport(good_result(self.permit))
        forged = gate.ReadPermit(self.digest, gate.CARD_ID, gate.ADAPTER_SERIAL,
                                 gate.USB_DESCRIPTOR_SERIAL, "1-9.3", "0403", "6010",
                                 ir_opcode=0x02)
        with self.assertRaises(gate.Refusal):
            gate.read_once(forged, transport)
        self.assertEqual(transport.calls, [])
        result = good_result(self.permit)
        result["arbitrary_ir"] = 0x02
        with self.assertRaises(gate.Refusal):
            gate.validate_observation(self.permit, result)


if __name__ == "__main__":
    unittest.main()
