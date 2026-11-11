"""Synthetic-only regressions for immutable PHK2 physical-closure gates."""
from __future__ import annotations

import base64
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from physical_tck_preflight import Refusal
from phk2_physical_close_guard import *
from phk2_physical_close_guard import _canonical, _sha
from phk2_physical_close_guard import _PERMIT_SECRET


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

    def test_09_transport_factory_cannot_be_called_without_master_permit(self):
        calls = []
        with self.assertRaises(Refusal):
            open_transport_after_gate(None, lambda: calls.append("opened"))
        self.assertEqual(calls, [])
        # A journal object that was never successfully initialized also
        # refuses before invoking the supplied transport factory.
        journal = PreTransportJournal("/tmp/phk2-never-created-journal.jsonl", "nonce")
        permit = PreTransportPermit(_PERMIT_SECRET, "f" * 64, "nonce", journal)
        with self.assertRaises(Refusal):
            open_transport_after_gate(permit, lambda: calls.append("opened"))
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
