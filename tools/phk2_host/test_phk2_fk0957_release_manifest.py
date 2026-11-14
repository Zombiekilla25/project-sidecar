from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import phk2_fk0957_remote_topology_endpoint as endpoint
import phk2_fk0957_topology_transport as transport
import verify_fk0957_runtime_manifest as verifier


class SignedManifestVerifierTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()  # TEST_ONLY; never installed or provisioned.
        self.wrong_key = Ed25519PrivateKey.generate()  # TEST_ONLY.
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.wrong_public = self.wrong_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.now = datetime.now(timezone.utc)
        self.payload = {
            "schema": "fk0957-runtime-source-manifest-v1", "version": 1,
            "production_head": "a" * 40, "worktree_clean": True,
            "source_hashes": {"tools/phk2_host/phk2_fk0957_topology_live_cli.py": "b" * 64},
            "source_inventory": [{"relative_path": "tools/phk2_host/phk2_fk0957_topology_live_cli.py",
                                  "absolute_install_path": "/usr/local/lib/sidecar/fk0957/tools/phk2_host/phk2_fk0957_topology_live_cli.py",
                                  "sha256": "b" * 64}],
            "native_runtime_hashes": {"libc": "c" * 64},
            "runtime_inventory": [{"logical_name": "libc", "path": "/lib/libc.so.6",
                                   "sha256": "c" * 64, "build_id": "d" * 40,
                                   "package": "libc6", "package_version": "1"}],
            "trust_config_sha256": "e" * 64,
            "transaction_profile_sha256": "f" * 64,
            "issued_at": self.now.isoformat(),
        }

    def signed(self, payload=None):
        value = self.payload if payload is None else payload
        raw = endpoint.canonical(value)
        return {"payload": value, "payload_sha256": hashlib.sha256(raw).hexdigest(),
                "signature_algorithm": "Ed25519", "signature_hex": self.key.sign(raw).hex(),
                "issuer": "FK0957_RELEASE_AUTHORITY"}

    def test_signed_exact_head_manifest_verifies_and_checks_runtime_binding(self):
        with mock.patch.object(endpoint, "_verify_runtime_manifest") as check, \
             mock.patch.object(endpoint, "_profile_hash", return_value="f" * 64):
            result = verifier.verify_document(self.signed(), issuers={"release": self.public}, now=self.now)
        self.assertEqual(result, self.payload)
        check.assert_called_once_with(self.payload, "f" * 64)

    def test_modified_covered_byte_and_wrong_key_refuse(self):
        with self.assertRaisesRegex(endpoint.Refusal, "SIGNED_RECORD_SIGNATURE_INVALID"):
            verifier.verify_document(self.signed(), issuers={"release": self.wrong_public}, now=self.now)
        document = self.signed()
        document["payload"]["source_hashes"] = {"changed": "0" * 64}
        with self.assertRaisesRegex(endpoint.Refusal, "SIGNED_RECORD_DIGEST_INVALID"):
            verifier.verify_document(document, issuers={"release": self.public}, now=self.now)
        with self.assertRaisesRegex(endpoint.Refusal, "SIGNED_RECORD_SIGNATURE_INVALID"):
            document = self.signed()
            document["signature_hex"] = self.wrong_key.sign(endpoint.canonical(self.payload)).hex()
            verifier.verify_document(document, issuers={"release": self.public}, now=self.now)

    def test_stale_manifest_refuses_before_source_acceptance(self):
        old = dict(self.payload)
        old["issued_at"] = (self.now - timedelta(days=2)).isoformat()
        with mock.patch.object(endpoint, "_verify_runtime_manifest") as check, \
             mock.patch.object(endpoint, "_profile_hash", return_value="f" * 64):
            with self.assertRaisesRegex(endpoint.Refusal, "RUNTIME_MANIFEST_STALE"):
                verifier.verify_document(self.signed(old), issuers={"release": self.public}, now=self.now)
        check.assert_not_called()

    def test_signed_mutations_of_head_paths_hashes_native_ids_and_issuer_refuse(self):
        with mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)):
            exact = endpoint.build_unsigned_runtime_manifest(Path.cwd())

        def verify(payload):
            with mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)):
                return verifier.verify_document(self.signed(payload),
                                                issuers={"release": self.public},
                                                now=datetime.now(timezone.utc) + timedelta(seconds=1))

        verify(exact)
        cases = []
        head = dict(exact)
        head["production_head"] = "b" * 40
        cases.append((head, "RUNTIME_GIT_STATE_MISMATCH"))

        file_hash = json_clone(exact)
        key = "tools/phk2_host/phk2_fk0957_topology_live_cli.py"
        file_hash["source_hashes"][key] = "0" * 64
        next(row for row in file_hash["source_inventory"] if row["relative_path"] == key)["sha256"] = "0" * 64
        cases.append((file_hash, "RUNTIME_SOURCE_HASH_MISMATCH"))

        path = json_clone(exact)
        path["source_inventory"][0]["absolute_install_path"] = "/attacker/cli.py"
        cases.append((path, "RUNTIME_SOURCE_INVENTORY_INVALID"))

        native = json_clone(exact)
        native["native_runtime_hashes"]["libc"] = "0" * 64
        cases.append((native, "NATIVE_RUNTIME_MANIFEST_MISMATCH"))

        build_id = json_clone(exact)
        next(row for row in build_id["runtime_inventory"]
             if row["logical_name"] == "libc")["build_id"] = "0" * 40
        cases.append((build_id, "RUNTIME_INVENTORY_MISMATCH"))

        trust = dict(exact)
        trust["trust_config_sha256"] = "0" * 64
        cases.append((trust, "TRUST_CONFIG_MANIFEST_MISMATCH"))

        for payload, expected_code in cases:
            with self.subTest(code=expected_code), self.assertRaisesRegex(endpoint.Refusal, expected_code):
                verify(payload)

        envelope = self.signed(exact)
        envelope["issuer"] = "UNAPPROVED_ISSUER"
        with self.assertRaisesRegex(endpoint.Refusal, "SIGNED_RECORD_ISSUER_INVALID"):
            verifier.verify_document(envelope, issuers={"release": self.public}, now=self.now)

        envelope = self.signed(exact)
        envelope["signature_hex"] = "0" * 128
        with self.assertRaisesRegex(endpoint.Refusal, "SIGNED_RECORD_SIGNATURE_INVALID"):
            verifier.verify_document(envelope, issuers={"release": self.public}, now=self.now)


def json_clone(value):
    return __import__("json").loads(__import__("json").dumps(value))


if __name__ == "__main__":
    unittest.main()
