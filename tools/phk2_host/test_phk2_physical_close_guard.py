"""Synthetic-only regressions for immutable PHK2 physical-closure gates."""
from __future__ import annotations

import base64
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import struct
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from physical_tck_preflight import Refusal
import phk2_physical_close_guard as guard
from phk2_physical_close_guard import *
from phk2_physical_close_guard import _canonical, _sha
from physical_adapter_boundary import (AdapterRefusal, EndpointIdentity, ExpectedIdentity,
                                       GuardedPhysicalSession, QualificationGates,
                                       prepare_physical_session)
from board_protocol import Frame, Opcode, ProtocolError, RESPONSE, request
from tck_contract import TckObservation, TckPolicy
from board_transport import PhysicalBscanTransport


def signed(payload, key, key_id="fixture-key"):
    return {"schema": "PHK2-SIGNED-PHYSICAL-EVIDENCE-v1", "payload": payload,
            "signature": {"algorithm": "Ed25519", "key_id": key_id,
                          "value_b64": base64.b64encode(key.sign(_canonical(payload))).decode()}}


def wave_csv(periods=12):
    # 0.5 ns digital sampling of an ideal 20 ns / 50% square wave.
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["sample_index", "timestamp_ns", "logic_level"])
    for i in range(periods * 40 + 1):
        t = i * 0.5
        writer.writerow([i, f"{t:.3f}", int((t % 20.0) < 10.0)])
    return out.getvalue().encode()


def tap_json(idcode="04b69093"):
    records = []
    word = int(idcode, 16)
    for i, (tms, tdi) in enumerate(zip(TAP_TMS, TAP_TDI)):
        tdo = ((word >> (i - 21)) & 1) if 21 <= i < 53 else 0
        records.append({"seq": i, "timestamp_ns": i * 100.0,
                        "tms": tms, "tdi": tdi, "tdo": tdo})
    return json.dumps({"schema": "PHK2-TAP-TRACE-v1", "sequence": "RESET_IDCODE_87_CYCLES",
                       "cycles": records, "derived_final_state": "RUN_TEST_IDLE"}).encode()


class FakeTransport:
    def __init__(self, counter, abort_response=False): self.counter = counter; self.closed = False; self.abort_response=abort_response
    def transact(self, raw, _timeout):
        self.counter["transact"] += 1
        if self.abort_response:
            req=Frame.decode(raw)
            return Frame(req.opcode | 0x80, RESPONSE, req.sequence, struct.pack("<QH",1,1)).encode()
        return b""
    def close(self): self.closed = True


class TestTransportFactory:
    def __init__(self, abort_response=False): self.calls=0;self.counter={"transact":0};self.abort_response=abort_response
    def __call__(self, _target_identity, _image_sha):
        self.calls+=1
        return FakeTransport(self.counter,self.abort_response)


def issue_capability(repo: Path, journal_path: Path, *, abort_response=False):
    """Exercise the actual gate with synthetic proof providers and no I/O."""
    binding = SimpleNamespace(
        source_commit=V51_SOURCE_COMMIT, source_tree_hash=V51_SOURCE_TREE_HASH,
        routed_dcp_sha256=V51_ROUTED_DCP_SHA256,
        qualification_record_sha256=V51_QUALIFICATION_RECORD_SHA256,
        qualified_physical_envelope_available=True,
        expected_card_id="153300000957", expected_adapter_id="153300000957A",
        expected_idcode="04b69093")
    now = datetime.now(timezone.utc).isoformat()
    peer_payload = {"schema": "PHK2-PEER-EXCLUSION-PROOF-v1", "captured_utc": now,
        "server": {"pid": 100, "exe_path": "/sqrl/xvc", "sha256": PINNED_REVIEWED_BRIDGE_SHA256,
            "build_id": PINNED_REVIEWED_BUILD_ID, "service_unit": "sqrl.service",
            "service_config_sha256": "c" * 64, "port": 2542},
        "listener": {"pid": 100, "port": 2542, "state": "LISTEN"},
        "existing_foreign_clients": [], "competing_xvc_jtag_processes": [],
        "runner_pid": 200, "local_lock": {"held": True, "owner_pid": 200,
            "lock_key": "d" * 64, "path": "/tmp/phk2.lock"}}
    card_payload = {"schema": "PHK2-CARD-ADAPTER-IDENTITY-v1", "captured_utc": now,
        "expected_card_id": binding.expected_card_id, "observed_card_id": binding.expected_card_id,
        "expected_adapter_id": binding.expected_adapter_id, "observed_adapter_id": binding.expected_adapter_id,
        "bridge_sha256": PINNED_REVIEWED_BRIDGE_SHA256, "one_card_scope": True,
        "observed_idcode": binding.expected_idcode}
    peer_expectation = {"pid": 100, "exe_path": "/sqrl/xvc", "sha256": PINNED_REVIEWED_BRIDGE_SHA256,
        "build_id": PINNED_REVIEWED_BUILD_ID, "service_unit": "sqrl.service",
        "service_config_sha256": "c" * 64, "port": 2542, "lock_key": "d" * 64}
    card_expectation = {"expected_card_id": binding.expected_card_id,
        "expected_adapter_id": binding.expected_adapter_id, "expected_idcode": binding.expected_idcode,
        "bridge_sha256": PINNED_REVIEWED_BRIDGE_SHA256}
    auth_wrapper = {"fixture_signed_auth": "metadata-only-test"}
    auth_payload = {"authorization_id": "auth-1", "operator_id": "operator-1"}
    auth_status_payload = {"schema": "PHK2-AUTHORIZATION-STATUS-v1", "status": "ACTIVE",
        "authorization_id": "auth-1", "authorization_sha256": _sha(_canonical(auth_wrapper))}
    rollback_expectation = {"rollback_manifest_sha256": ROLLBACK_SHA256}
    transport_factory = TestTransportFactory(abort_response)
    capture_expectation = {"backend_id": "fixture-backend", "backend_sha256": "b" * 64,
                           "backend_version": "test", "capture_device_id": "fixture-scope",
                           "transport_factory_sha256": transport_factory_identity_sha256(transport_factory)}
    capture_payload = {**capture_expectation, "status": "READY", "synthetic_fixture": False}
    rollback_payload = {**rollback_expectation, "status": "READY", "synthetic_fixture": False}
    peer_wrapper = {"schema": "test"}
    card_wrapper = {"schema": "test"}
    manifest = {"qualification_record_sha256": V51_QUALIFICATION_RECORD_SHA256}
    runtime = {}

    def live_state(): return {**runtime, "authorization_status_wrapper": {"fixture": "active"}}
    capture_expectation["state_revalidator_sha256"] = guard.callable_identity_sha256(
        live_state, "live-state revalidator")
    capture_payload["state_revalidator_sha256"] = capture_expectation["state_revalidator_sha256"]
    def verified_doc(_wrapper, _keys, role, **_kw):
        return peer_payload if role == "peer" else card_payload
    def readiness(_wrapper, _keys, *, role, **_kw):
        return rollback_payload if role == "rollback" else capture_payload
    def verify_auth(*_args, **_kwargs): return auth_payload
    real_check = guard._check_runtime_claims
    def seed_runtime(record, expected=None):
        if expected is not None:
            runtime.clear(); runtime.update(expected)
        return real_check(record, expected)

    td_obj = tempfile.TemporaryDirectory()
    actual_journal = Path(td_obj.name) / journal_path.name
    patches = ExitStack()
    patches.enter_context(mock.patch.object(guard, "PINNED_TRUST_STORE_SHA256", "fixture-pinned"))
    patches.enter_context(mock.patch.object(guard, "verify_immutable_v51", return_value=binding))
    patches.enter_context(mock.patch.object(guard, "validate_case_manifest"))
    patches.enter_context(mock.patch.object(guard, "verify_signed_document", side_effect=verified_doc))
    patches.enter_context(mock.patch.object(guard, "validate_peer_proof", return_value="a" * 64))
    patches.enter_context(mock.patch.object(guard, "validate_card_identity", return_value={
        "OBSERVED_CARD_ID": binding.expected_card_id, "OBSERVED_ADAPTER_ID": binding.expected_adapter_id}))
    patches.enter_context(mock.patch.object(guard, "validate_readiness_attestation", side_effect=readiness))
    patches.enter_context(mock.patch.object(guard, "validate_signed_authorization", side_effect=verify_auth))
    patches.enter_context(mock.patch.object(guard, "validate_authorization_status", return_value=auth_status_payload))
    patches.enter_context(mock.patch.object(guard, "_check_runtime_claims", side_effect=seed_runtime))
    cap = guard.master_pretransport_gate(
        repo=repo, closure_manifest=manifest, signed_authorization=auth_wrapper,
        signed_authorization_status={"fixture": "active"},
        trusted_keys=guard.TrustedKeyStore({}, verified_sha256="fixture-pinned"),
        peer_proof={"_signature_wrapper": peer_wrapper}, peer_expectation=peer_expectation,
        signed_card_identity=card_wrapper, card_expectation=card_expectation,
        signed_rollback_attestation={}, signed_capture_backend_attestation={},
        rollback_expectation=rollback_expectation, capture_backend_expectation=capture_expectation,
        transport_factory=transport_factory,
        tck_envelope_qualified=True, journal_path=actual_journal,
        session_nonce="session-1", qualification_hash=V51_QUALIFICATION_RECORD_SHA256,
        bridge_sha256=PINNED_REVIEWED_BRIDGE_SHA256,
        endpoint_target_identity_sha256="e" * 64, candidate_image_sha256="f" * 64,
        state_revalidator=live_state)
    return cap, runtime, actual_journal, binding, td_obj, patches, transport_factory


class PhysicalCloseGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Path(__file__).resolve().parents[2]
        cls.binding = verify_immutable_v51(cls.repo)

    def test_01_exact_immutable_cases_and_envelope_binding(self):
        b = self.binding
        self.assertEqual((b.case_a["case_id"], b.case_a["case"]), ("40", CASE_A_NAME))
        self.assertEqual((b.case_b["case_id"], b.case_b["case"]), ("33", CASE_B_NAME))
        self.assertFalse(b.qualified_physical_envelope_available)
        self.assertEqual(b.tck_envelope["routed_dcp_sha256"], V51_ROUTED_DCP_SHA256)
        self.assertEqual(b.tck_envelope["qualification_record_sha256"], V51_QUALIFICATION_RECORD_SHA256)

    def test_02_arbitrary_reordered_or_foreign_case_and_route_manifest_refuse(self):
        manifest = {"TCK_INDEPENDENT_PASS": 38, "TCK_INDEPENDENT_FAIL": 0,
                    "v5_1_identity": {"source_commit": self.binding.source_commit,
                        "source_tree_hash": self.binding.source_tree_hash,
                        "routed_dcp_sha256": self.binding.routed_dcp_sha256,
                        "qualification_record_sha256": self.binding.qualification_record_sha256,
                        "matrix_sha256": self.binding.matrix_sha256,
                        "evidence_commit": self.binding.evidence_commit},
                    "qualification_matrix": {"sha256": self.binding.matrix_sha256,
                        "commit": MATRIX_COMMIT, "path": MATRIX_PATH},
                    "tck_dependent_cases": [
                        {"case_id": CASE_A_ID, "case": CASE_A_NAME, "kind": "PHYSICAL_TCK_WAVEFORM",
                         "matrix_detail": "Physical host maximum TCK frequency/duty contract not qualified"},
                        {"case_id": CASE_B_ID, "case": CASE_B_NAME, "kind": "BSCAN_CLOCK_INTERACTION",
                         "matrix_detail": self.binding.case_b["detail"]}],
                    "TCK_ENVELOPE_SHA256": self.binding.tck_envelope_sha256,
                    "TCK_ANALYSIS_REFERENCE": self.binding.tck_envelope,
                    "artifacts": {"routed_dcp": {"sha256": self.binding.routed_dcp_sha256}}}
        validate_case_manifest(manifest, self.binding)
        for mutate in (
            lambda m: m["tck_dependent_cases"].__setitem__(0, {**m["tck_dependent_cases"][0], "case_id": "SYNTH-A"}),
            lambda m: m["tck_dependent_cases"].reverse(),
            lambda m: m["TCK_ANALYSIS_REFERENCE"].update(source_commit="f" * 40),
            lambda m: m["artifacts"]["routed_dcp"].update(sha256="0" * 64),
        ):
            bad = json.loads(json.dumps(manifest)); mutate(bad)
            with self.assertRaises(Refusal): validate_case_manifest(bad, self.binding)

    def test_03_waveform_is_parsed_and_summary_independently_checked(self):
        raw = wave_csv()
        result = parse_waveform_csv(raw)
        self.assertAlmostEqual(result["MEASURED_TCK_HZ"], 50_000_000)
        self.assertAlmostEqual(result["MEASURED_HIGH_NS"], 10)
        self.assertAlmostEqual(result["MEASURED_LOW_NS"], 10)
        self.assertEqual(result["SAMPLE_COUNT"], 481)
        parse_waveform_csv(raw, result)
        for bad in (b"", b"garbage", b"sample_index,timestamp_ns,logic_level\n0,0,0\n"):
            with self.assertRaises(Refusal): parse_waveform_csv(bad)
        good = raw.decode().splitlines()
        good[3] = "2,0.25,1"  # timestamp regresses
        with self.assertRaises(Refusal): parse_waveform_csv("\n".join(good).encode())
        with self.assertRaises(Refusal): parse_waveform_csv(raw, {**result, "MEASURED_TCK_HZ": 1})

    def test_04_tap_transcript_semantics_and_prohibited_instruction_refuse(self):
        parsed = parse_tap_transcript(tap_json(), self.binding.expected_idcode)
        self.assertEqual(parsed["instruction_value"], 0x09)
        self.assertEqual(parsed["after_state"], "RUN_TEST_IDLE")
        doc = json.loads(tap_json()); doc["cycles"][10]["tdi"] = 1 - doc["cycles"][10]["tdi"]
        with self.assertRaises(Refusal): parse_tap_transcript(json.dumps(doc).encode(), self.binding.expected_idcode)
        doc = json.loads(tap_json()); doc["cycles"][21]["tdo"] = 1 - doc["cycles"][21]["tdo"]
        with self.assertRaises(Refusal): parse_tap_transcript(json.dumps(doc).encode(), self.binding.expected_idcode)
        with self.assertRaises(Refusal): parse_tap_transcript(b"{\"tap_pass\":true}", self.binding.expected_idcode)

    def test_05_signed_peer_and_card_content_must_match(self):
        now = datetime.now(timezone.utc)
        expected_peer = {"pid": 100, "exe_path": "/opt/sqrl/xvc", "sha256": "a" * 64,
                         "build_id": "b" * 40, "service_unit": "sqrl.service",
                         "service_config_sha256": "c" * 64, "port": 2542, "lock_key": "d" * 64}
        peer = {"schema": "PHK2-PEER-EXCLUSION-PROOF-v1", "captured_utc": now.isoformat(),
                "server": {k: expected_peer[k] for k in ("pid", "exe_path", "sha256", "build_id", "service_unit", "service_config_sha256", "port")},
                "listener": {"pid": 100, "port": 2542, "state": "LISTEN"},
                "existing_foreign_clients": [], "competing_xvc_jtag_processes": [],
                "runner_pid": 200, "local_lock": {"held": True, "owner_pid": 200,
                   "lock_key": expected_peer["lock_key"], "path": "/run/user/1/phk2.lock"}}
        self.assertEqual(validate_peer_proof(peer, expected_peer, now=now), _sha(_canonical(peer)))
        bad_peer = json.loads(json.dumps(peer)); bad_peer["existing_foreign_clients"] = [{"pid": 9}]
        with self.assertRaises(Refusal): validate_peer_proof(bad_peer, expected_peer, now=now)
        bad_peer = json.loads(json.dumps(peer)); bad_peer["captured_utc"] = (now - timedelta(hours=1)).isoformat()
        with self.assertRaises(Refusal): validate_peer_proof(bad_peer, expected_peer, now=now)
        expected_card = {"expected_card_id": self.binding.expected_card_id,
                         "expected_adapter_id": self.binding.expected_adapter_id,
                         "bridge_sha256": "e" * 64, "expected_idcode": self.binding.expected_idcode}
        card = {"schema": "PHK2-CARD-ADAPTER-IDENTITY-v1",
                "captured_utc": now.isoformat(),
                "expected_card_id": self.binding.expected_card_id, "observed_card_id": self.binding.expected_card_id,
                "expected_adapter_id": self.binding.expected_adapter_id, "observed_adapter_id": self.binding.expected_adapter_id,
                "bridge_sha256": "e" * 64, "one_card_scope": True, "observed_idcode": self.binding.expected_idcode}
        validate_card_identity(card, expected_card)
        card["observed_card_id"] = "wrong"
        with self.assertRaises(Refusal): validate_card_identity(card, expected_card)

    def test_06_boolean_authorization_and_fake_physical_real_refuse(self):
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        roots = {"fixture-key": {"roles": ["authorization", "capture"],
                                 "public_key_b64": base64.b64encode(pub).decode()}}
        with self.assertRaises(Refusal): verify_signed_document({"AUTHORIZED": True}, roots, "authorization")
        fabricated = {"schema": "PHK2-SIGNED-PHYSICAL-EVIDENCE-v1", "payload": {
            "provenance": "PHYSICAL_REAL", "synthetic_fixture": False,
            "case_id": CASE_A_ID, "raw_capture_b64": base64.b64encode(b"fabricated").decode()}}
        with self.assertRaises(Refusal): validate_signed_capture(fabricated, {}, expected_role="capture",
              expected_case_id=CASE_A_ID, expected_record_sha256=V51_QUALIFICATION_RECORD_SHA256)
        wrapper = signed({"provenance": "PHYSICAL_REAL", "captured_utc": datetime.now(timezone.utc).isoformat(),
                          "synthetic_fixture": False, "qualification_record_sha256": V51_QUALIFICATION_RECORD_SHA256,
                          "case_id": CASE_A_ID, "raw_capture_b64": base64.b64encode(b"fabricated").decode(),
                          "raw_capture_sha256": _sha(b"fabricated")}, key)
        payload, raw = validate_signed_capture(wrapper, roots, expected_role="capture",
              expected_case_id=CASE_A_ID, expected_record_sha256=V51_QUALIFICATION_RECORD_SHA256)
        self.assertEqual(raw, b"fabricated")
        wrapper["signature"]["value_b64"] = base64.b64encode(b"0" * 64).decode()
        with self.assertRaises(Refusal): validate_signed_capture(wrapper, roots, expected_role="capture",
              expected_case_id=CASE_A_ID, expected_record_sha256=V51_QUALIFICATION_RECORD_SHA256)

        now = datetime.now(timezone.utc)
        auth_payload = {"authorized_operation": "PHK2_PHYSICAL_TCK_CLOSURE", "card_scope": 1,
            "card_id": self.binding.expected_card_id,
            "qualification_record_sha256": V51_QUALIFICATION_RECORD_SHA256,
            "bridge_sha256": "e" * 64, "session_nonce": "nonce-1", "case_ids": [CASE_A_ID, CASE_B_ID],
            "operator_id": "operator-1", "authorization_id": "auth-1",
            "issued_utc": now.isoformat(), "expires_utc": (now + timedelta(minutes=10)).isoformat()}
        valid_auth = signed(auth_payload, key)
        validate_signed_authorization(valid_auth, roots, qualification_hash=V51_QUALIFICATION_RECORD_SHA256,
            bridge_sha256="e" * 64, card_id=self.binding.expected_card_id, nonce="nonce-1", now=now)
        with self.assertRaises(Refusal):
            validate_signed_authorization(valid_auth, roots, qualification_hash=V51_QUALIFICATION_RECORD_SHA256,
                bridge_sha256="0" * 64, card_id=self.binding.expected_card_id, nonce="nonce-1", now=now)

    def test_07_journal_initializes_durable_pretransport_entry_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "journal.jsonl"
            j = PreTransportJournal(p, "fixture-nonce")
            j.initialize({"qualification_record_sha256": V51_QUALIFICATION_RECORD_SHA256})
            row = json.loads(p.read_text().splitlines()[0])
            self.assertEqual(row["event"], "PRE_TRANSPORT")
            self.assertEqual(row["sequence"], 0)
            for event in ("TRANSPORT_OPEN_REQUESTED", "TRANSPORT_OPENED", "CASE_A_CAPTURED",
                          "CASE_B_CAPTURED", "CASE_A_RESULT", "CASE_B_RESULT", "FINAL_IDLE_CLOSE"):
                j.append(event, {"ok": True})
            self.assertEqual(verify_pretransport_journal(p.read_bytes())["event_count"], 8)
            with self.assertRaises(Refusal): PreTransportJournal(p, "second").initialize({})

    def test_08_empty_trust_store_and_unqualified_physical_envelope_remain_closed(self):
        with tempfile.TemporaryDirectory() as td:
            fake_store = {"schema": "PHK2-TRUSTED-SIGNERS-v1", "keys": [{
                "key_id": "attacker-chosen", "algorithm": "Ed25519", "roles": ["authorization"],
                "public_key_b64": base64.b64encode(b"x" * 32).decode()}]}
            p = Path(td) / "trust.json"; p.write_text(json.dumps(fake_store))
            with self.assertRaises(Refusal): load_trust_store(p)
        self.assertFalse(self.binding.qualified_physical_envelope_available)

    def _issue(self, **kwargs):
        return issue_capability(self.repo, Path("phk2-journal.jsonl"), **kwargs)

    @staticmethod
    def _open(cap, runtime, *, nonce="session-1", target="e" * 64, image="f" * 64, calls=None):
        calls = calls if calls is not None else []
        result = open_transport_after_gate(cap,
            session_nonce=nonce, endpoint_target_identity_sha256=target,
            candidate_image_sha256=image)
        calls.append("opened")
        return result, calls

    def test_09_forged_deserialized_and_direct_factory_attempts_refuse(self):
        cap, _runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        calls = []
        with self.assertRaises(Refusal): TransportCapability()
        forged = object.__new__(TransportCapability)
        with self.assertRaises(Refusal):
            open_transport_after_gate(forged,
                session_nonce="session-1", endpoint_target_identity_sha256="e" * 64,
                candidate_image_sha256="f" * 64)
        serialized = json.loads(json.dumps(capability_audit_metadata(cap)))
        with self.assertRaises(Refusal):
            open_transport_after_gate(serialized,
                session_nonce="session-1", endpoint_target_identity_sha256="e" * 64,
                candidate_image_sha256="f" * 64)
        with self.assertRaises(TypeError): __import__("copy").copy(cap)
        with self.assertRaises(Refusal):
            open_transport_after_gate(None,
                session_nonce="session-1", endpoint_target_identity_sha256="e" * 64,
                candidate_image_sha256="f" * 64)
        with self.assertRaises(TypeError):
            open_transport_after_gate(cap, transport_factory=factory,
                session_nonce="session-1", endpoint_target_identity_sha256="e" * 64,
                candidate_image_sha256="f" * 64)
        with self.assertRaises(RuntimeError): PhysicalBscanTransport()
        self.assertEqual(calls, [])
        self.assertEqual(factory.calls, 0)

    def test_10_only_master_issued_capability_opens_once_and_is_session_bound(self):
        cap, runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        claims = capability_audit_metadata(cap)
        opened, calls = self._open(cap, runtime)
        self.assertEqual(calls, ["opened"])
        self.assertEqual(factory.calls, 1)
        endpoint = EndpointIdentity("e" * 64, "f" * 64, "selected")
        session = GuardedPhysicalSession(opened, endpoint, transport_capability=cap)
        with self.assertRaises(Refusal): self._open(cap, runtime)
        session.close()
        self.assertEqual(claims["case_ids"], (CASE_A_ID, CASE_B_ID))
        self.assertTrue(opened.closed)

    def test_11_wrong_nonce_card_or_artifact_invalidates_before_factory(self):
        for kwargs in ({"nonce": "copied-nonce"}, {"target": "0" * 64}, {"image": "0" * 64}):
            cap, _runtime, _path, _binding, tmp, patches, factory = self._issue()
            calls = []
            with self.assertRaises(Refusal): self._open(cap, {}, calls=calls, **kwargs)
            self.assertEqual(calls, [])
            self.assertEqual(factory.calls, 0)
            patches.close(); tmp.cleanup()

    def test_12_peer_card_route_authorization_and_backend_changes_stale_capability(self):
        mutations = ("peer_state_sha256", "card_identity_sha256", "routed_dcp_sha256",
                     "authorization_artifact_sha256", "capture_backend_identity_sha256",
                     "state_revalidator_sha256", "transport_factory_sha256")
        for field in mutations:
            cap, runtime, _path, _binding, tmp, patches, factory = self._issue()
            runtime[field] = "0" * 64
            calls = []
            with self.assertRaises(Refusal): self._open(cap, runtime, calls=calls)
            self.assertEqual(calls, [])
            self.assertEqual(factory.calls, 0)
            patches.close(); tmp.cleanup()

    def test_13_authorization_expiry_or_revocation_invalidates_capability(self):
        cap, runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        runtime["authorization_status_sha256"] = "0" * 64
        calls = []
        with self.assertRaises(Refusal): self._open(cap, runtime, calls=calls)
        self.assertEqual(calls, [])
        self.assertEqual(factory.calls, 0)

        cap, _runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        patches.enter_context(mock.patch.object(guard, "validate_signed_authorization",
                                                side_effect=Refusal("authorization expired/revoked")))
        calls = []
        with self.assertRaises(Refusal): self._open(cap, {}, calls=calls)
        self.assertEqual(calls, [])

    def test_14_journal_failure_invalidates_capability_before_transport(self):
        cap, _runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        record = guard._CAPABILITY_REGISTRY[cap]
        os.close(record.journal.fd); record.journal.fd = None
        calls = []
        with self.assertRaises(Refusal): self._open(cap, {}, calls=calls)
        self.assertEqual(calls, [])
        with self.assertRaises(Refusal): self._open(cap, {})

    def test_15_internal_session_constructor_and_cli_helpers_cannot_bypass_gate(self):
        counter = {"transact": 0}
        endpoint = EndpointIdentity("e" * 64, "f" * 64, "selected")
        transport = FakeTransport(counter)
        with self.assertRaises(AdapterRefusal): GuardedPhysicalSession(transport, endpoint)
        self.assertEqual(counter["transact"], 0)

        from first_silicon_cli import run_authorized_live, recover
        class Trap:
            def __getattr__(self, name): raise AssertionError(f"plugin method reached: {name}")
        for call in (lambda: run_authorized_live(Trap(), None, None, None, None, None, None, None, None),
                     lambda: recover(Trap(), None)):
            with self.assertRaises(RuntimeError): call()

        good = QualificationGates(True, True, True, True, True, True, True, True, True, True)
        identity = ExpectedIdentity("e" * 64, "f" * 64)
        policy = TckPolicy(True, 100_000, "fixture-transport", "a" * 64)
        observed = TckObservation(100_000, 100_000, True, "fixture-transport")
        class TrapDiscovery:
            calls = 0
            def selected_endpoint(self):
                self.calls += 1
                return EndpointIdentity("e" * 64, "f" * 64, "selected")
        discovery = TrapDiscovery()
        with self.assertRaises(AdapterRefusal):
            prepare_physical_session(good, identity, discovery, tck_policy=policy,
                                     tck_observation=observed, authorized_tck_hz=100_000)
        self.assertEqual(discovery.calls, 0)

    def test_16_journal_is_fsynced_before_capability_is_issued(self):
        cap, _runtime, path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        record = guard._CAPABILITY_REGISTRY[cap]
        rows = path.read_text().splitlines()
        self.assertEqual(json.loads(rows[0])["event"], "PRE_TRANSPORT")
        self.assertEqual(record.journal.sequence, 1)
        self.assertTrue(record.journal.fd is not None)

    def test_17_abort_invalidates_capability_after_the_single_abort(self):
        cap, runtime, _path, _binding, tmp, patches, factory = self._issue(abort_response=True)
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        endpoint = EndpointIdentity("e" * 64, "f" * 64, "selected")
        opened, _ = self._open(cap, runtime)
        transport=opened
        session = GuardedPhysicalSession(transport, endpoint, transport_capability=cap)
        session.bind_transaction(1, 1)
        result = session.abort_once(request(Opcode.ABORT, 0, b"fixture"))
        self.assertEqual(result, struct.pack("<QH", 1, 1))
        self.assertEqual(factory.counter["transact"], 1)
        with self.assertRaises(Refusal): guard.assert_transport_capability_live(cap)
        session.close()

    def test_18_no_importable_secret_or_mint_helper(self):
        self.assertFalse(hasattr(guard, "_PERMIT_SECRET"))
        self.assertFalse(hasattr(guard, "_issue_capability"))

    def test_19_protocol_failure_poison_session_and_capability(self):
        cap, runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        transport, _ = self._open(cap, runtime)
        endpoint = EndpointIdentity("e" * 64, "f" * 64, "selected")
        session = GuardedPhysicalSession(transport, endpoint, transport_capability=cap)
        with self.assertRaises((AdapterRefusal, ProtocolError)): session.hello_once()
        self.assertTrue(session.closed)
        self.assertEqual(factory.counter["transact"], 1)
        with self.assertRaises(AdapterRefusal): session.hello_once()
        with self.assertRaises(Refusal): guard.assert_transport_capability_live(cap)
        self.assertEqual(factory.counter["transact"], 1)

    def test_20_capability_cannot_be_paired_with_another_transport_object(self):
        cap, runtime, _path, _binding, tmp, patches, _factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        _opened, _ = self._open(cap, runtime)
        substitute = FakeTransport({"transact": 0})
        endpoint = EndpointIdentity("e" * 64, "f" * 64, "selected")
        with self.assertRaises(AdapterRefusal):
            GuardedPhysicalSession(substitute, endpoint, transport_capability=cap)
        self.assertEqual(substitute.counter["transact"], 0)


if __name__ == "__main__":
    unittest.main()
