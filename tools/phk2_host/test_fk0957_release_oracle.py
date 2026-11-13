"""Fresh-tree regression against the pinned independent FK0957 oracle.

Run from a clean checkout with:
    python3 -m unittest discover -s tools/phk2_host -p 'test_*fk0957*.py'

This test does not create a worktree, write a temporary file, or alter
PYTHONPATH. The reference source and audit harness are vendored byte-for-byte
from their identified commits under tests/reference/.
"""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import random
import unittest

import phk2_fk0957_topology_discovery as topology
import phk2_fk0957_topology_live_cli as cli
import phk2_fk0957_topology_transport as transport
import test_phk2_fk0957_topology_live_cli as live_cli_tests
import test_phk2_fk0957_topology_transport as transport_tests


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "tests/reference/fk0957_corrected_oracle_audit.py"
_SPEC = importlib.util.spec_from_file_location("fk0957_release_oracle_harness", HARNESS_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("pinned FK0957 oracle harness unavailable")
_HARNESS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_HARNESS)


def _production_envelope(snapshot, model):
    """Project reference stages to the production phase and granular state."""
    if snapshot.final_evidence_exists:
        return None
    stage = snapshot.stage
    stage_name = stage.name
    phase = _HARNESS.PHASE_BY_STAGE[stage_name]
    code = _HARNESS.PHASE_CODES[phase]
    if stage == model.Stage.SELECTION:
        code = ("NO_TARGET_CANDIDATE" if snapshot.target_candidates == 0 else
                "MULTIPLE_TARGET_CANDIDATES" if snapshot.target_candidates >= 2 else
                "CANDIDATE_IDENTITY_MISMATCH")
    if stage_name.startswith("SCAN_A_") or stage_name.startswith("SCAN_B_"):
        operation_state = stage_name
    else:
        operation_state = _HARNESS.STATE_BY_STAGE[stage_name]
    close_from = None
    transport_closed = int(snapshot.transport_closed)

    if stage == model.Stage.TRANSPORT_CLOSE:
        if snapshot.failure_origin is None:
            close_from = "SCAN_B_COMPLETE"
            if snapshot.transport_closed:
                phase = "LOCAL_VALIDATION"
                code = _HARNESS.PHASE_CODES[phase]
                operation_state = "TRANSPORT_CLOSED"
            else:
                operation_state = "TRANSPORT_CLOSING"
        else:
            origin = snapshot.failure_origin.name
            close_from = (origin if origin.startswith("SCAN_") else
                          _HARNESS.STATE_BY_STAGE[origin])
            operation_state = ("TRANSPORT_CLOSED" if snapshot.transport_closed
                               else "TRANSPORT_CLOSING")
    elif stage == model.Stage.LOCAL_VALIDATION:
        close_from = "SCAN_B_COMPLETE"
    elif stage == model.Stage.SIGNING_STAGING:
        # The corpus leaves local_validation_passed false, so this cannot be a
        # reachable LOCAL_VALIDATED signing state.
        operation_state = "TRANSPORT_CLOSED"
        close_from = "SCAN_B_COMPLETE"
    elif stage in (model.Stage.ATOMIC_PUBLISH, model.Stage.SUCCESS_REPORTING):
        # Preserve their asserted terminal progress. With boundary defaults
        # this is contradictory and must fail the validator's progress rules.
        phase = "LOCAL_SIGNING"
        code = _HARNESS.PHASE_CODES[phase]
        operation_state = "SIGNED_STAGED"
        close_from = "SCAN_B_COMPLETE"

    return {
        "status": "REFUSED", "phase": phase, "code": code,
        "evidence_path": "none", "signature_verified": False,
        "return_code": None, "target_candidates": snapshot.target_candidates,
        "device_opened": int(snapshot.device_opened),
        "scan_a_started": int(snapshot.scan_a_started),
        "scan_a_tck_emitted": snapshot.scan_a_tck_emitted,
        "scan_b_started": int(snapshot.scan_b_started),
        "scan_b_tck_emitted": snapshot.scan_b_tck_emitted,
        "transport_closed": transport_closed,
        "permit_consumed": int(snapshot.permit_consumed),
        "operation_state": operation_state, "close_from_state": close_from,
    }


class ReleaseOracleTests(unittest.TestCase):
    def test_complete_corrected_boundary_corpus(self):
        model = _HARNESS.load_reference(ROOT)
        valid = invalid = valid_rejected = invalid_accepted = 0
        mismatches = []
        for snapshot in model.boundary_combinations():
            expected = model.legal_snapshot(snapshot)
            valid += int(expected)
            invalid += int(not expected)
            envelope = _production_envelope(snapshot, model)
            actual = False if envelope is None else cli._bounded_envelope(envelope)
            valid_rejected += int(expected and not actual)
            invalid_accepted += int(not expected and actual)
            if expected != actual:
                mismatches.append({
                    "expected": "ACCEPT" if expected else "REJECT",
                    "actual": "ACCEPT" if actual else "REJECT",
                    "stage": snapshot.stage.name,
                    "phase": None if envelope is None else envelope["phase"],
                    "fields": {key: getattr(snapshot, key) for key in (
                        "permit_consumed", "target_candidates", "device_opened",
                        "scan_a_started", "scan_a_tck_emitted", "scan_b_started",
                        "scan_b_tck_emitted", "transport_closed")},
                    "failure_origin": (None if snapshot.failure_origin is None else
                                       snapshot.failure_origin.name),
                })
        counts = {
            "valid_states": valid,
            "invalid_states": invalid,
            "valid_state_rejected": valid_rejected,
            "invalid_state_accepted": invalid_accepted,
        }
        self.assertEqual(counts, {
            "valid_states": 28,
            "invalid_states": 249572,
            "valid_state_rejected": 0,
            "invalid_state_accepted": 0,
        }, msg=json.dumps(mismatches, sort_keys=True))

    def test_adversarial_boundaries_and_capability_surface(self):
        self.assertTrue(_HARNESS.targeted_checks(cli, transport)[
            "candidate_count_boundaries"])
        self.assertTrue(_HARNESS.targeted_checks(cli, transport)[
            "device_open_state"])
        self.assertTrue(_HARNESS.targeted_checks(cli, transport)[
            "no_generic_or_programming_surface"])

    def test_golden_transaction_hashes_and_counts(self):
        plan = topology.build_plan()
        self.assertEqual((plan.scan_a_tck_count, plan.scan_b_tck_count,
                          plan.tck_count), (591, 586, 1177))
        self.assertEqual(topology.scan_transaction_sha256(plan.scan_a_commands),
                         _HARNESS.EXPECTED_SCAN_A_SHA256)
        self.assertEqual(topology.scan_transaction_sha256(plan.scan_b_commands),
                         _HARNESS.EXPECTED_SCAN_B_SHA256)

    def test_twenty_seed_randomized_enumeration_and_fault_order(self):
        enum_trials = 0
        fault_tests = 0
        transport_names = (
            "test_short_reads_and_transport_failures_close_and_consume_permit",
            "test_close_failure_and_observation_tampering_refuse",
            "test_refusal_envelope_is_canonical_bounded_and_phase_specific",
            "test_operation_state_transitions_are_monotonic",
            "test_one_shot_workflow_orders_validate_before_local_sign_and_never_retries",
        )
        cli_names = (
            "test_atomic_publish_failure_removes_private_staging_artifacts",
            "test_failure_before_and_during_temp_write_leaves_no_staging_artifact",
            "test_ambiguous_post_link_error_is_resolved_as_published_success",
            "test_concurrent_output_creation_is_not_replaced_at_publish",
            "test_final_stdout_failure_after_publish_is_not_downgraded_to_refusal",
            "test_failure_immediately_after_publish_is_classified_post_success",
            "test_malformed_or_unbounded_refusal_becomes_internal_envelope",
            "test_contradictory_refusal_progress_is_discarded",
            "test_legitimate_partial_write_boundaries_and_large_candidate_count",
            "test_transport_close_preserves_each_legal_prior_state",
        )
        for index in range(20):
            seed = 0xF0957000 + index * 7919
            rng = random.Random(seed)
            fixture = transport_tests.TopologyTransportTests(
                "test_native_enumeration_filters_peer_serial_before_multiplicity")
            fixture.setUp()
            try:
                for _ in range(20):
                    peer_count = rng.randint(1, 8)
                    pairs = [((9, 3), "153300000957")]
                    pairs.extend(((9, port), f"153300000{rng.randint(958, 999):03d}")
                                 for port in range(4, 4 + peer_count))
                    rng.shuffle(pairs)
                    ports = [row[0] for row in pairs]
                    serials = [row[1] for row in pairs]
                    permit = fixture.permit()
                    _, native, rows = fixture.native_rows_for_serials(
                        serials, ports=ports, permit=permit)
                    chosen = topology.validate_candidates(permit, rows)
                    self.assertEqual(chosen.identity, permit.identity)
                    target_index = serials.index("153300000957")
                    native.open_exact(chosen)
                    native._ftdi.ftdi_usb_open_dev.assert_called_once_with(
                        native._ctx, 0x1234 + target_index)
                    self.assertEqual(len(rows), 1)
                    enum_trials += 1

                ordered = [(transport_tests.TopologyTransportTests, name)
                           for name in transport_names]
                ordered.extend((live_cli_tests.LiveCliTests, name) for name in cli_names)
                rng.shuffle(ordered)
                suite = unittest.TestSuite(
                    case_class(name) for case_class, name in ordered)
                result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
                self.assertTrue(result.wasSuccessful(), f"seed {seed:#x}")
                fault_tests += result.testsRun
            finally:
                fixture.doCleanups()
        self.assertEqual(enum_trials, 400)
        self.assertEqual(fault_tests, 300)


if __name__ == "__main__":
    unittest.main()
