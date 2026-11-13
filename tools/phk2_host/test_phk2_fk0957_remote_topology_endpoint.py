from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import phk2_fk0957_remote_topology_endpoint as endpoint
import phk2_fk0957_topology_transport as transport

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class RemoteTopologyEndpointTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.release_key = Ed25519PrivateKey.generate()
        self.handoff_key = Ed25519PrivateKey.generate()
        self.issuers = {
            "release": self.release_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            "handoff": self.handoff_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        }
        self.operation = "1" * 32
        self.auth_id = "2" * 64
        self.nonce = "3" * 64
        self.descriptor = b"signed descriptor fixture bytes"
        self.descriptor_sha = hashlib.sha256(self.descriptor).hexdigest()
        self.profile_sha = endpoint._profile_hash()
        self.manifest = {
            "schema": "fk0957-runtime-source-manifest-v1", "version": 1,
            "production_head": "a" * 40, "worktree_clean": True,
            "source_hashes": {
                path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                for path in (
                    "tools/phk2_host/phk2_fk0957_remote_topology_endpoint.py",
                    "tools/phk2_host/phk2_fk0957_topology_transport.py",
                    "tools/phk2_host/phk2_fk0957_topology_discovery.py",
                    "tools/phk2_host/phk2_fk0957_idcode_gate.py",
                )},
            "native_runtime_hashes": {pin.name: pin.sha256 for pin in transport.LIBRARY_PINS},
            "transaction_profile_sha256": self.profile_sha,
            "issued_at": self.now.isoformat(),
        }
        self.manifest_sha = hashlib.sha256(endpoint.canonical(self.manifest)).hexdigest()
        self.handoff = {
            "schema": "fk0957-maintenance-handoff-v1", "version": 1,
            "handoff_id": "4" * 64, "operation_id": self.operation,
            "authorization_id": self.auth_id, "permit_sha256": self.descriptor_sha,
            "target": dict(endpoint.EXPECTED_TARGET), "bridge_executable_sha256": "5" * 64,
            "bridge_config_sha256": "6" * 64, "expected_clients": ["client-a"],
            "expected_lanes": ["lane-a"], "bridge_release_state": "RELEASED",
            "usbfs_ownership": "EXCLUSIVE", "production_head": self.manifest["production_head"],
            "manifest_sha256": self.manifest_sha,
            "transaction_profile_sha256": self.profile_sha,
            "issued_at": self.now.isoformat(),
            "expires_at": (self.now + timedelta(seconds=90)).isoformat(),
        }
        self.handoff_sha = hashlib.sha256(endpoint.canonical(self.handoff)).hexdigest()
        self.authorization = {
            "schema": "fk0957-release-authorization-v1", "version": 1,
            "authorization_id": self.auth_id, "operation_id": self.operation,
            "permit_sha256": self.descriptor_sha, "handoff_sha256": self.handoff_sha,
            "target": dict(endpoint.EXPECTED_TARGET),
            "production_head": self.manifest["production_head"],
            "manifest_sha256": self.manifest_sha,
            "transaction_profile_sha256": self.profile_sha,
            "issued_at": self.now.isoformat(),
            "expires_at": (self.now + timedelta(seconds=90)).isoformat(), "nonce": self.nonce,
        }
        self.request = {
            "schema": endpoint.SCHEMA, "version": 1, "operation_id": self.operation,
            "descriptor_evidence_b64": base64.b64encode(self.descriptor).decode("ascii"),
            "descriptor_evidence_sha256": self.descriptor_sha,
            "handoff": self._sign(self.handoff, self.handoff_key, "FK0957_MAINTENANCE_AUTHORITY"),
            "release_authorization": self._sign(self.authorization, self.release_key, "FK0957_RELEASE_AUTHORITY"),
            "runtime_manifest": self._sign(self.manifest, self.release_key, "FK0957_RELEASE_AUTHORITY"),
        }

    @staticmethod
    def _sign(payload, key, issuer):
        encoded = endpoint.canonical(payload)
        return {"payload": payload, "payload_sha256": hashlib.sha256(encoded).hexdigest(),
                "signature_algorithm": "Ed25519", "signature_hex": key.sign(encoded).hex(),
                "issuer": issuer}

    def request_bytes(self):
        return endpoint.canonical(self.request)

    def test_valid_signed_request_binds_target_handoff_and_runtime(self):
        with mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)):
            context, authorization_bytes, auth_id = endpoint._validate_request(
                self.request_bytes(), self.issuers, now=self.now)
        self.assertEqual(auth_id, self.auth_id)
        self.assertEqual(context["operation_id"], self.operation)
        self.assertEqual(context["descriptor_sha256"], self.descriptor_sha)
        self.assertEqual(context["transaction_profile_sha256"], self.profile_sha)
        self.assertEqual(hashlib.sha256(authorization_bytes).hexdigest(), context["authorization_sha256"])

    def test_missing_production_trust_pins_refuse_before_transport(self):
        with mock.patch.object(endpoint, "TRUST_CONFIG_SHA256", ""), \
             mock.patch.object(transport, "run_fk0957_topology_discovery") as run:
            with self.assertRaises(endpoint.Refusal) as caught:
                endpoint.execute_request(self.request_bytes())
        self.assertEqual(caught.exception.code, "ISSUER_PINS_NOT_PROVISIONED")
        run.assert_not_called()

    def test_endpoint_has_no_signing_key_or_signing_module_import(self):
        source = Path(endpoint.__file__).read_text()
        self.assertNotIn("phk2_fk0957_topology_signing", source)
        self.assertNotIn("phk2_fk0957_remote_orchestrator", source)
        self.assertNotIn("LOCAL_SIGNING_KEY_PATH", source)
        self.assertNotIn("Ed25519PrivateKey", source)
        self.assertNotIn("def sign", source)

    def test_runtime_manifest_checks_exact_source_native_pins_head_and_clean_state(self):
        with mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)):
            endpoint._verify_runtime_manifest(self.manifest, self.profile_sha)
            with self.assertRaisesRegex(endpoint.Refusal, "RUNTIME_SOURCE_SET_INVALID"):
                endpoint._verify_runtime_manifest({**self.manifest,
                    "source_hashes": {**self.manifest["source_hashes"], "extra.py": "f" * 64}},
                    self.profile_sha)
            with self.assertRaisesRegex(endpoint.Refusal, "NATIVE_RUNTIME_MANIFEST_MISMATCH"):
                endpoint._verify_runtime_manifest({**self.manifest,
                    "native_runtime_hashes": {**self.manifest["native_runtime_hashes"], "libc": "0" * 64}},
                    self.profile_sha)
        with mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, False)):
            with self.assertRaisesRegex(endpoint.Refusal, "RUNTIME_GIT_STATE_MISMATCH"):
                endpoint._verify_runtime_manifest(self.manifest, self.profile_sha)

    def test_execute_consumes_before_one_physical_run_and_returns_unsigned_record(self):
        events = []
        parsed = SimpleNamespace(aggregate_dr_length=33, taps_tdo_to_tdi=(),
                                 raw_tdo_scan_a_bits="0", raw_tdo_scan_b_bits="1")
        result = SimpleNamespace(
            card_id="FK0957", adapter_serial="153300000957A", usb_descriptor_serial="153300000957",
            physical_interface="A", descriptor_evidence_sha256=self.descriptor_sha, permit_nonce="7" * 64,
            trusted_signer_fingerprint="f" * 64,
            transport_source_sha256="8" * 64, worktree_clean=True,
            runtime_library_provenance=(), scan_a_transaction_sha256="9" * 64,
            scan_a_tck_count=591, scan_a_raw_tdo=b"a", scan_b_transaction_sha256="a" * 64,
            scan_b_tck_count=586, scan_b_raw_tdo=b"b", total_tck_count=1177,
            matched_device_count=1, opened_device_count=1, second_device_opened=False,
            write_count=0, reset_count=0, program_count=0)
        with mock.patch.object(endpoint, "_load_trust_config", return_value=self.issuers), \
             mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)), \
             mock.patch.object(endpoint, "_consume_authorization", side_effect=lambda *_: events.append("consume")), \
             mock.patch.object(transport, "issue_fk0957_topology_permit",
                               side_effect=lambda *_a, **_k: events.append("permit") or SimpleNamespace(
                                   trusted_signer_fingerprint="f" * 64)), \
             mock.patch.object(transport, "run_fk0957_topology_discovery",
                               side_effect=lambda *_: events.append("physical") or result) as run, \
             mock.patch.object(transport, "validate_transport_observation",
                               side_effect=lambda *_: events.append("validate") or parsed):
            raw = endpoint.execute_request(self.request_bytes())
        record = json.loads(raw)
        self.assertEqual(events, ["consume", "permit", "physical", "validate"])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(record["status"], "ACQUIRED")
        self.assertNotIn("signature_hex", record)
        self.assertNotIn("signature_algorithm", record)
        self.assertEqual((record["scan_a_tck_count"], record["scan_b_tck_count"],
                          record["total_tck_count"]), (591, 586, 1177))
        with mock.patch.object(transport, "_production_git_state", return_value=("b" * 40, True)):
            with self.assertRaisesRegex(endpoint.Refusal, "RUNTIME_GIT_STATE_MISMATCH"):
                endpoint._verify_runtime_manifest(self.manifest, self.profile_sha)

    def test_target_manifest_or_handoff_tampering_refuses(self):
        attacks = []
        changed = json.loads(json.dumps(self.request)); changed["operation_id"] = "9" * 32; attacks.append(changed)
        changed = json.loads(json.dumps(self.request)); changed["descriptor_evidence_sha256"] = "0" * 64; attacks.append(changed)
        changed = json.loads(json.dumps(self.request)); changed["handoff"]["payload"]["usbfs_ownership"] = "UNKNOWN"; attacks.append(changed)
        changed = json.loads(json.dumps(self.request)); changed["runtime_manifest"]["payload"]["worktree_clean"] = False; attacks.append(changed)
        for index, request in enumerate(attacks):
            with self.subTest(index=index), mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)):
                with self.assertRaises(endpoint.Refusal):
                    endpoint._validate_request(endpoint.canonical(request), self.issuers, now=self.now)

    def test_expired_and_wrong_signature_records_refuse(self):
        expired = dict(self.authorization)
        expired["issued_at"] = (self.now - timedelta(minutes=5)).isoformat()
        expired["expires_at"] = (self.now - timedelta(minutes=3)).isoformat()
        self.request["release_authorization"] = self._sign(expired, self.release_key, "FK0957_RELEASE_AUTHORITY")
        with mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)):
            with self.assertRaisesRegex(endpoint.Refusal, "EXPIRED_OR_STALE"):
                endpoint._validate_request(self.request_bytes(), self.issuers, now=self.now)
        self.request["release_authorization"] = self._sign(self.authorization, self.handoff_key, "FK0957_RELEASE_AUTHORITY")
        with self.assertRaisesRegex(endpoint.Refusal, "SIGNATURE_INVALID"):
            endpoint._verify_signed(self.request["release_authorization"],
                expected_issuer="FK0957_RELEASE_AUTHORITY", public_key_raw=self.issuers["release"],
                payload_fields=endpoint.AUTH_FIELDS, schema="fk0957-release-authorization-v1")

    def test_duplicate_noncanonical_and_unhashable_fields_fail_closed(self):
        for raw in (b'{"schema":"x","schema":"y"}\n', b'{ "schema":"x" }\n'):
            with self.assertRaises(endpoint.Refusal):
                endpoint._parse_canonical(raw, endpoint.MAX_REQUEST_BYTES)
        malformed = json.loads(self.request_bytes())
        malformed["handoff"]["payload"]["expected_clients"] = [["nested"]]
        with mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)):
            with self.assertRaises(endpoint.Refusal):
                endpoint._validate_request(endpoint.canonical(malformed), self.issuers, now=self.now)

    def test_authorization_ledger_is_durable_single_use_and_parallel_safe(self):
        with tempfile.TemporaryDirectory(prefix="fk0957-auth-ledger-") as raw:
            root = Path(raw) / "consumed"
            root.mkdir(mode=0o700); root.chmod(0o700)
            with mock.patch.object(endpoint, "CONSUMED_AUTHORIZATION_DIR", root):
                def consume(_):
                    try:
                        endpoint._consume_authorization(self.auth_id, b"auth")
                        return "CONSUMED"
                    except endpoint.Refusal as exc:
                        return exc.code
                with ThreadPoolExecutor(max_workers=12) as pool:
                    statuses = list(pool.map(consume, range(24)))
            self.assertEqual(statuses.count("CONSUMED"), 1)
            self.assertEqual(statuses.count("AUTHORIZATION_REPLAY"), 23)
            self.assertEqual((root / (self.auth_id + ".consumed")).read_text(),
                             hashlib.sha256(b"auth").hexdigest() + "\n")


if __name__ == "__main__":
    unittest.main()
