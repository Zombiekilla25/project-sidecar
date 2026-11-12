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


def canary_wave_csv(*, rising_edges=87, pretrigger_ns=1_000, posttrigger_ns=20_000,
                    omit_final_fall=False, extra_edge=False, reorder=False,
                    duplicate_timestamp=False, malformed_level=False,
                    final_rise_offset_ns=None, idle_tail_ns=1_000):
    """Sparse edge-event fixture with explicit pretrigger and idle tail."""
    rows = [[0, pretrigger_ns * -1, 0]]
    for edge in range(rising_edges):
        rise = (edge * 20 if edge != rising_edges - 1 or final_rise_offset_ns is None
                else final_rise_offset_ns)
        rows.append([len(rows), rise, 1])
        if not (omit_final_fall and edge == rising_edges - 1):
            rows.append([len(rows), rise + 10, 0])
    if extra_edge:
        rows.extend([[len(rows), rising_edges * 20, 1],
                     [len(rows) + 1, rising_edges * 20 + 10, 0]])
    last_fall = next((row[1] for row in reversed(rows) if row[2] == 0), 0)
    final_time = max(posttrigger_ns, last_fall + idle_tail_ns)
    rows.append([len(rows), final_time, 0 if not omit_final_fall else 1])
    if reorder and len(rows) > 3:
        rows[2], rows[3] = rows[3], rows[2]
    if duplicate_timestamp and len(rows) > 2:
        rows[2][1] = rows[1][1]
    if malformed_level:
        rows[2][2] = 2
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["sample_index", "timestamp_ns", "logic_level"])
    writer.writerows(rows)
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


def issue_executor(repo: Path, journal_path: Path, *, abort_response=False):
    """Exercise the master gate with synthetic proof providers and no I/O."""
    binding = SimpleNamespace(
        source_commit=V51_SOURCE_COMMIT, source_tree_hash=V51_SOURCE_TREE_HASH,
        routed_dcp_sha256=V51_ROUTED_DCP_SHA256,
        qualification_record_sha256=V51_QUALIFICATION_RECORD_SHA256,
        qualified_physical_envelope_available=True,
        tck_envelope={"physical_waveform_limits": {
            "minimum_tck_hz": 49_000_000, "maximum_tck_hz": 51_000_000,
            "minimum_high_ns": 9.0, "maximum_high_ns": 11.0,
            "minimum_low_ns": 9.0, "maximum_low_ns": 11.0,
            "minimum_duty_cycle_percent": 45.0, "maximum_duty_cycle_percent": 55.0,
            "minimum_jitter_ns": 0.0, "maximum_jitter_ns": 1.0}},
        expected_card_id="153300000957", expected_adapter_id="153300000957A",
        expected_idcode="04b69093", expected_fpga_dna="4000000001295d813c80a445",
        expected_target_part="xcvu33p-fsvh2104-2-e")
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
        "expected_fpga_dna": binding.expected_fpga_dna, "observed_fpga_dna": binding.expected_fpga_dna,
        "expected_target_part": binding.expected_target_part, "observed_target_part": binding.expected_target_part,
        "observed_idcode": binding.expected_idcode}
    peer_expectation = {"pid": 100, "exe_path": "/sqrl/xvc", "sha256": PINNED_REVIEWED_BRIDGE_SHA256,
        "build_id": PINNED_REVIEWED_BUILD_ID, "service_unit": "sqrl.service",
        "service_config_sha256": "c" * 64, "port": 2542, "lock_key": "d" * 64}
    card_expectation = {"expected_card_id": binding.expected_card_id,
        "expected_adapter_id": binding.expected_adapter_id, "expected_idcode": binding.expected_idcode,
        "expected_fpga_dna": binding.expected_fpga_dna,
        "expected_target_part": binding.expected_target_part,
        "bridge_sha256": PINNED_REVIEWED_BRIDGE_SHA256}
    auth_wrapper = {"fixture_signed_auth": "metadata-only-test"}
    auth_payload = {"authorization_id": "auth-1", "operator_id": "operator-1"}
    auth_status_payload = {"schema": "PHK2-AUTHORIZATION-STATUS-v1", "status": "ACTIVE",
        "authorization_id": "auth-1", "authorization_sha256": _sha(_canonical(auth_wrapper))}
    rollback_expectation = {"rollback_manifest_sha256": ROLLBACK_SHA256}
    transport = TestTransportFactory(abort_response)
    def fake_open(_target_identity, _image_sha):
        transport.calls += 1
        return FakeTransport(transport.counter, abort_response)
    factory_identity = transport_factory_identity_sha256(fake_open)
    capture_expectation = {"backend_id": "fixture-backend", "backend_sha256": "b" * 64,
        "backend_version": "test", "capture_device_id": "fixture-scope",
        "transport_factory_sha256": factory_identity}
    capture_payload = {**capture_expectation, "status": "READY", "synthetic_fixture": False}
    rollback_payload = {**rollback_expectation, "status": "READY", "synthetic_fixture": False}
    peer_wrapper = {"schema": "test"}; card_wrapper = {"schema": "test"}
    manifest = {"qualification_record_sha256": V51_QUALIFICATION_RECORD_SHA256}
    runtime = {}
    def live_state(): return {**runtime, "authorization_status_wrapper": {"fixture": "active"}}
    revalidator_digest = guard.callable_identity_sha256(live_state, "live-state revalidator")
    capture_expectation["state_revalidator_sha256"] = revalidator_digest
    capture_payload["state_revalidator_sha256"] = revalidator_digest
    status_digest = _sha(_canonical({key: auth_status_payload[key] for key in (
        "schema", "status", "authorization_id", "authorization_sha256")}))
    runtime.update({
        "routed_dcp_sha256": binding.routed_dcp_sha256,
        "card_identity_sha256": guard._card_runtime_digest(card_payload),
        "peer_state_sha256": guard._peer_runtime_digest(peer_payload),
        "authorization_status_sha256": status_digest,
        "capture_backend_identity_sha256": guard._backend_runtime_digest(capture_payload),
        "transport_factory_sha256": factory_identity,
        "state_revalidator_sha256": revalidator_digest,
        "endpoint_target_identity_sha256": "e" * 64,
        "candidate_image_sha256": "f" * 64})
    def verified_doc(_wrapper, _keys, role, **_kw):
        return peer_payload if role == "peer" else card_payload
    def readiness(_wrapper, _keys, *, role, **_kw):
        return rollback_payload if role == "rollback" else capture_payload
    def verify_auth(*_args, **_kwargs): return auth_payload
    td_obj = tempfile.TemporaryDirectory()
    actual_journal = Path(td_obj.name) / journal_path.name
    patches = ExitStack()
    patches.enter_context(mock.patch.object(guard, "PINNED_TRUST_STORE_SHA256", "fixture-pinned"))
    patches.enter_context(mock.patch.object(guard, "transport_factory_identity_sha256", return_value=factory_identity))
    patches.enter_context(mock.patch.object(guard, "verify_immutable_v51", return_value=binding))
    patches.enter_context(mock.patch.object(guard, "validate_case_manifest"))
    patches.enter_context(mock.patch.object(guard, "verify_signed_document", side_effect=verified_doc))
    patches.enter_context(mock.patch.object(guard, "validate_peer_proof", return_value="a" * 64))
    patches.enter_context(mock.patch.object(guard, "validate_card_identity", return_value={
        "OBSERVED_CARD_ID": binding.expected_card_id, "OBSERVED_ADAPTER_ID": binding.expected_adapter_id}))
    patches.enter_context(mock.patch.object(guard, "validate_readiness_attestation", side_effect=readiness))
    patches.enter_context(mock.patch.object(guard, "validate_signed_authorization", side_effect=verify_auth))
    patches.enter_context(mock.patch.object(guard, "validate_authorization_status", return_value=auth_status_payload))
    patches.enter_context(mock.patch.object(guard, "_create_physical_transport", side_effect=fake_open))
    executor = guard.master_pretransport_gate(
        repo=repo, closure_manifest=manifest, signed_authorization=auth_wrapper,
        signed_authorization_status={"fixture": "active"},
        trusted_keys=guard.TrustedKeyStore({}, verified_sha256="fixture-pinned"),
        peer_proof={"_signature_wrapper": peer_wrapper}, peer_expectation=peer_expectation,
        signed_card_identity=card_wrapper, card_expectation=card_expectation,
        signed_rollback_attestation={}, signed_capture_backend_attestation={},
        rollback_expectation=rollback_expectation, capture_backend_expectation=capture_expectation,
        tck_envelope_qualified=True, journal_path=actual_journal,
        session_nonce="session-1", qualification_hash=V51_QUALIFICATION_RECORD_SHA256,
        bridge_sha256=PINNED_REVIEWED_BRIDGE_SHA256,
        endpoint_target_identity_sha256="e" * 64, candidate_image_sha256="f" * 64,
        state_revalidator=live_state)
    return executor, runtime, actual_journal, binding, td_obj, patches, transport


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

    def test_03b_canary_requires_complete_exact_87_edge_capture_and_idle_tail(self):
        raw = canary_wave_csv()
        result = parse_waveform_csv(raw, expected_rising_edges=87)
        self.assertEqual(result["RISING_EDGE_COUNT"], 87)
        self.assertEqual(result["FINAL_HIGH_NS"], 10)
        self.assertGreaterEqual(result["PRETRIGGER_NS"], 1_000)
        self.assertGreaterEqual(result["POSTTRIGGER_NS"], 20_000)
        self.assertGreaterEqual(result["IDLE_TAIL_NS"], 1_000)
        invalid = (
            canary_wave_csv(rising_edges=86),                         # truncated edge sequence
            canary_wave_csv(extra_edge=True),                        # extra pulse
            canary_wave_csv(omit_final_fall=True),                    # truncated final pulse
            canary_wave_csv(posttrigger_ns=0),                        # no valid posttrigger window
            canary_wave_csv(pretrigger_ns=999),                       # inadequate pretrigger
            canary_wave_csv(reorder=True),                            # reordered transitions
            canary_wave_csv(duplicate_timestamp=True),                # duplicate timestamp
            canary_wave_csv(malformed_level=True),                    # malformed logic level
            canary_wave_csv(final_rise_offset_ns=19_500, idle_tail_ns=999),  # insufficient idle tail
        )
        for bad in invalid:
            with self.subTest(capture=bad[:100]):
                with self.assertRaises(Refusal):
                    parse_waveform_csv(bad, expected_rising_edges=87)

    def test_04_tap_transcript_semantics_and_prohibited_instruction_refuse(self):
        parsed = parse_tap_transcript(tap_json(), self.binding.expected_idcode)
        self.assertEqual(parsed["instruction_value"], 0x09)
        self.assertEqual(parsed["after_state"], "RUN_TEST_IDLE")
        doc = json.loads(tap_json()); doc["cycles"][10]["tdi"] = 1 - doc["cycles"][10]["tdi"]
        with self.assertRaises(Refusal): parse_tap_transcript(json.dumps(doc).encode(), self.binding.expected_idcode)
        doc = json.loads(tap_json()); doc["cycles"][21]["tdo"] = 1 - doc["cycles"][21]["tdo"]
        with self.assertRaises(Refusal): parse_tap_transcript(json.dumps(doc).encode(), self.binding.expected_idcode)
        with self.assertRaises(Refusal): parse_tap_transcript(b"{\"tap_pass\":true}", self.binding.expected_idcode)

    def test_case_evidence_requires_87_edges_correlation_bytes_and_session_nonce(self):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        roots = {"fixture-key": {"roles": ["capture"], "public_key_b64": base64.b64encode(public).decode()}}
        now = datetime.now(timezone.utc).isoformat()
        nonce = "current-session"
        wave = canary_wave_csv()
        wave_summary = parse_waveform_csv(wave, expected_rising_edges=87)
        corr = b'{"correlation":"fixture evidence"}'
        native = b"synthetic native instrument payload"
        instrument = {"instrument_model": "fixture", "instrument_serial": "fixture-1", "probe_id": "probe-1",
                     "calibration_certificate_sha256": "a" * 64,
                     "calibration_valid_until_utc": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                     "bandwidth_hz": 1_000_000, "sample_rate_hz": 10_000_000, "voltage_threshold_v": 1.2,
                     "coupling": "DC", "channel": "CH1", "timebase": "1us/div", "trigger": "rising TCK",
                     "capture_window": "1us pre, 20us post", "software_version": "fixture",
                     "measurement_uncertainty_ns": 0.1}

        def capture(case_id, raw, **extra):
            payload = {"provenance": "PHYSICAL_REAL", "synthetic_fixture": False,
                       "captured_utc": now, "qualification_record_sha256": self.binding.qualification_record_sha256,
                       "case_id": case_id, "session_nonce": nonce,
                       "raw_capture_b64": base64.b64encode(raw).decode(),
                       "raw_capture_sha256": _sha(raw), **extra}
            return signed(payload, key)

        wave_wrapper = capture(CASE_A_ID, wave, summary=wave_summary,
            native_acquisition_b64=base64.b64encode(native).decode(),
            native_acquisition_sha256=_sha(native), instrument_metadata=instrument)
        tap_extra = {"physical_clock_correlation_b64": base64.b64encode(corr).decode(),
                     "physical_clock_correlation_sha256": _sha(corr),
                     "fpga_programming": False, "workload_changed": False,
                     "settck_used_as_measurement": False,
                     "final_close": {"transport_closed": True, "tap_idle": True, "peer_count_after": 0}}
        tap_wrapper = capture(CASE_B_ID, tap_json(), **tap_extra)
        with self.assertRaisesRegex(Refusal, "no immutable matrix-approved"):
            validate_physical_capture_package(
                trusted_keys=roots, waveform_wrapper=wave_wrapper, tap_wrapper=tap_wrapper,
                binding=self.binding, expected_idcode=self.binding.expected_idcode,
                expected_session_nonce=nonce, now=datetime.fromisoformat(now))

        short_raw = wave_csv(periods=12)
        short_wave = capture(CASE_A_ID, short_raw, summary=parse_waveform_csv(short_raw),
            native_acquisition_b64=base64.b64encode(native).decode(),
            native_acquisition_sha256=_sha(native), instrument_metadata=instrument)
        with self.assertRaisesRegex(Refusal, "87|edge sequence"):
            validate_physical_capture_package(trusted_keys=roots, waveform_wrapper=short_wave,
                tap_wrapper=tap_wrapper, binding=self.binding, expected_idcode=self.binding.expected_idcode,
                expected_session_nonce=nonce, now=datetime.fromisoformat(now))

        missing_native = capture(CASE_A_ID, wave, summary=wave_summary)
        with self.assertRaisesRegex(Refusal, "native instrument acquisition"):
            validate_physical_capture_package(trusted_keys=roots, waveform_wrapper=missing_native,
                tap_wrapper=tap_wrapper, binding=self.binding, expected_idcode=self.binding.expected_idcode,
                expected_session_nonce=nonce, now=datetime.fromisoformat(now))

        missing_corr = capture(CASE_B_ID, tap_json(), **{k: v for k, v in tap_extra.items()
            if k != "physical_clock_correlation_b64"})
        with self.assertRaisesRegex(Refusal, "no immutable matrix-approved"):
            validate_physical_capture_package(trusted_keys=roots, waveform_wrapper=wave_wrapper,
                tap_wrapper=missing_corr, binding=self.binding, expected_idcode=self.binding.expected_idcode,
                expected_session_nonce=nonce, now=datetime.fromisoformat(now))

        replayed = capture(CASE_B_ID, tap_json(), **tap_extra)
        replayed["payload"]["session_nonce"] = "old-session"
        replayed = signed(replayed["payload"], key)
        with self.assertRaisesRegex(Refusal, "current authorized session"):
            validate_physical_capture_package(trusted_keys=roots, waveform_wrapper=wave_wrapper,
                tap_wrapper=replayed, binding=self.binding, expected_idcode=self.binding.expected_idcode,
                expected_session_nonce=nonce, now=datetime.fromisoformat(now))

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
                         "bridge_sha256": "e" * 64, "expected_idcode": self.binding.expected_idcode,
                         "expected_fpga_dna": self.binding.expected_fpga_dna,
                         "expected_target_part": self.binding.expected_target_part}
        card = {"schema": "PHK2-CARD-ADAPTER-IDENTITY-v1",
                "captured_utc": now.isoformat(),
                "expected_card_id": self.binding.expected_card_id, "observed_card_id": self.binding.expected_card_id,
                "expected_adapter_id": self.binding.expected_adapter_id, "observed_adapter_id": self.binding.expected_adapter_id,
                "bridge_sha256": "e" * 64, "one_card_scope": True,
                "expected_fpga_dna": self.binding.expected_fpga_dna,
                "observed_fpga_dna": self.binding.expected_fpga_dna,
                "expected_target_part": self.binding.expected_target_part,
                "observed_target_part": self.binding.expected_target_part,
                "observed_idcode": self.binding.expected_idcode}
        validate_card_identity(card, expected_card)
        card["observed_card_id"] = "wrong"
        with self.assertRaises(Refusal): validate_card_identity(card, expected_card)
        card["observed_card_id"] = self.binding.expected_card_id
        card["observed_fpga_dna"] = "0" * 24
        with self.assertRaises(Refusal): validate_card_identity(card, expected_card)
        card["observed_fpga_dna"] = self.binding.expected_fpga_dna
        card["observed_target_part"] = "xcvu33p-fsvh2104-1-e"
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
        return issue_executor(self.repo, Path("phk2-journal.jsonl"), **kwargs)

    def test_09_old_authority_types_and_transport_seams_are_absent(self):
        self.assertFalse(hasattr(guard, "TransportCapability"))
        self.assertFalse(hasattr(guard, "_CapabilityRecord"))
        self.assertFalse(hasattr(guard, "_CAPABILITY_REGISTRY"))
        self.assertFalse(hasattr(guard, "open_transport_after_gate"))
        self.assertFalse(hasattr(guard, "register_capability"))
        self.assertFalse(hasattr(guard, "_issue_capability"))
        with self.assertRaises(TypeError):
            guard.master_pretransport_gate(transport_factory=lambda *_: self.fail("factory reached"))
        with self.assertRaises(RuntimeError): PhysicalBscanTransport()

    def test_10_registry_forgery_and_audit_metadata_are_inert(self):
        executor, _runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        forged = object()
        guard._CAPABILITY_REGISTRY = {forged: {"issued": True, "session_nonce": "session-1"}}
        self.assertFalse(hasattr(forged, "open_transport"))
        self.assertEqual(executor.state, "OPEN")
        metadata = json.loads(json.dumps(executor.audit_metadata()))
        self.assertEqual(metadata["session_nonce"], "session-1")
        self.assertFalse(hasattr(metadata, "run_case_a"))
        self.assertEqual(factory.calls, 1)
        del guard._CAPABILITY_REGISTRY

    def test_11_executor_construction_copy_pickle_and_cross_session_forgery_refuse(self):
        import copy, pickle
        executor, _runtime, _path, _binding, tmp, patches, _factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        with self.assertRaises(Refusal): type(executor)(object())
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises((TypeError, Refusal)): operation(executor)
        metadata = executor.audit_metadata()
        with self.assertRaises((TypeError, Refusal)):
            type(executor)(metadata)
        second, _runtime2, _path2, _binding2, tmp2, patches2, _factory2 = self._issue()
        self.addCleanup(patches2.close); self.addCleanup(tmp2.cleanup)
        self.assertIsNot(executor, second)
        self.assertEqual(executor.state, "OPEN")
        self.assertEqual(second.state, "OPEN")

    def test_12_gate_opens_exactly_once_and_executor_has_no_factory_or_open_method(self):
        executor, _runtime, path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        self.assertEqual(factory.calls, 1)
        self.assertEqual(executor.state, "OPEN")
        self.assertFalse(hasattr(executor, "open_transport"))
        self.assertFalse(hasattr(executor, "transport_factory"))
        self.assertEqual(json.loads(path.read_text().splitlines()[0])["event"], "PRE_TRANSPORT")
        self.assertEqual(json.loads(path.read_text().splitlines()[1])["event"], "TRANSPORT_OPEN_REQUESTED")

    def test_13_peer_card_route_authorization_and_backend_changes_abort_before_capture(self):
        for field in ("peer_state_sha256", "card_identity_sha256", "routed_dcp_sha256",
                      "authorization_status_sha256", "capture_backend_identity_sha256",
                      "state_revalidator_sha256", "transport_factory_sha256"):
            executor, runtime, _path, _binding, tmp, patches, factory = self._issue()
            runtime[field] = "0" * 64
            with self.assertRaises(Refusal): executor.run_case_a()
            self.assertEqual(executor.state, "ABORTED")
            self.assertEqual(factory.calls, 1)
            patches.close(); tmp.cleanup()

    def test_14_journal_failure_prevents_capture_and_invalidates_executor(self):
        executor, _runtime, path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        path.unlink()
        with self.assertRaises(Refusal): executor.run_case_a()
        self.assertEqual(executor.state, "ABORTED")
        self.assertEqual(factory.calls, 1)

    def test_15_case_order_state_close_abort_and_replay_are_fail_closed(self):
        executor, _runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        with self.assertRaises(Refusal): executor.run_case_b()
        with mock.patch.object(guard, "_execute_case_a_capture", return_value={"capture": b"wave"}), \
             mock.patch.object(guard, "validate_signed_capture", return_value=({"summary": {}}, b"wave")), \
             mock.patch.object(guard, "validate_case_a_instrument_evidence", return_value=b"native"), \
             mock.patch.object(guard, "parse_waveform_csv", return_value={
                 "MEASURED_TCK_HZ": 50_000_000, "MEASURED_HIGH_NS": 10.0,
                 "MEASURED_LOW_NS": 10.0, "MEASURED_DUTY_CYCLE": 50.0,
                 "JITTER_MIN_NS": 0.0, "JITTER_MAX_NS": 0.1,
                 "MEASURED_PERIOD_NS": 20.0, "SAMPLE_COUNT": 100,
                 "RISING_EDGE_COUNT": 87}):
            executor.run_case_a()
        self.assertEqual(executor.state, "CASE_A")
        with mock.patch.object(guard, "_execute_case_b_capture", return_value={"capture": b"tap"}), \
             mock.patch.object(guard, "validate_physical_capture_package", return_value={
                 "tap_capture_sha256": "a" * 64, "tap": {"final_state": "RUN_TEST_IDLE"}}):
            executor.run_case_b()
        self.assertEqual(executor.state, "CASE_B")
        executor.close()
        self.assertEqual(executor.state, "CLOSED")
        with self.assertRaises(Refusal): executor.run_case_a()
        with self.assertRaises(Refusal): executor.run_case_b()
        with self.assertRaises(Refusal): executor.close()
        self.assertEqual(factory.calls, 1)

        aborted, _runtime, _path, _binding, tmp2, patches2, _factory = self._issue()
        self.addCleanup(patches2.close); self.addCleanup(tmp2.cleanup)
        aborted.abort()
        self.assertEqual(aborted.state, "ABORTED")
        with self.assertRaises(Refusal): aborted.run_case_a()
        with self.assertRaises(Refusal): aborted.close()

    def test_16_direct_factory_and_legacy_session_bypass_refuse(self):
        with self.assertRaises(Refusal): guard._create_physical_transport("e" * 64, "f" * 64)
        endpoint = EndpointIdentity("e" * 64, "f" * 64, "selected")
        counter = {"transact": 0}
        with self.assertRaises(AdapterRefusal): GuardedPhysicalSession(FakeTransport(counter), endpoint)
        self.assertEqual(counter["transact"], 0)
        from first_silicon_cli import run_authorized_live, recover
        class Trap:
            def __getattr__(self, name): raise AssertionError(f"plugin method reached: {name}")
        for call in (lambda: run_authorized_live(Trap(), None, None, None, None, None, None, None, None),
                     lambda: recover(Trap(), None)):
            with self.assertRaises(RuntimeError): call()

    def test_17_mutated_live_state_cannot_reuse_executor_or_reconnect(self):
        executor, runtime, _path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        runtime["endpoint_target_identity_sha256"] = "0" * 64
        with self.assertRaises(Refusal): executor.run_case_a()
        with self.assertRaises(Refusal): executor.run_case_a()
        self.assertEqual(executor.state, "ABORTED")
        self.assertEqual(factory.calls, 1)

    def test_18_journal_was_fsynced_before_gate_returns_open_executor(self):
        executor, _runtime, path, _binding, tmp, patches, factory = self._issue()
        self.addCleanup(patches.close); self.addCleanup(tmp.cleanup)
        rows = [json.loads(row) for row in path.read_text().splitlines()]
        self.assertEqual(rows[0]["event"], "PRE_TRANSPORT")
        self.assertEqual(rows[1]["event"], "TRANSPORT_OPEN_REQUESTED")
        self.assertEqual(rows[2]["event"], "TRANSPORT_OPENED")
        self.assertEqual(executor.state, "OPEN")
        self.assertEqual(factory.calls, 1)

    def test_19_no_supported_transport_open_route_bypasses_master_gate(self):
        import inspect
        source = inspect.getsource(guard)
        self.assertNotIn("_CAPABILITY_REGISTRY", source)
        self.assertNotIn("open_transport_after_gate", source)
        self.assertEqual(source.count("_create_physical_transport("), 2)
        self.assertFalse(hasattr(guard, "transport_factory"))

    def test_20_physical_only_gates_remain_unqualified(self):
        binding = verify_immutable_v51(self.repo)
        self.assertFalse(binding.qualified_physical_envelope_available)
        self.assertFalse(binding.qualified_physical_envelope_available)
        self.assertEqual(binding.case_a["case_id"], CASE_A_ID)
        self.assertEqual(binding.case_b["case_id"], CASE_B_ID)


if __name__ == "__main__":
    unittest.main()
