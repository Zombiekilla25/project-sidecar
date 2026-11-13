from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fk0957_topology_state_model as model


def state(stage, **changes):
    return replace(model.Snapshot(stage), **changes)


def opened(**changes):
    values = dict(target_candidates=1, permit_consumed=True, device_opened=True)
    values.update(changes)
    return values


class IndependentTopologyStateModelTests(unittest.TestCase):
    def test_exhaustive_requested_boundary_and_boolean_space(self):
        valid, invalid = model.count_boundary_space()
        self.assertGreater(valid, 0)
        self.assertGreater(invalid, valid)
        self.assertEqual(valid + invalid, len(tuple(model.Stage)) * 6 * 5 * 5 * 32 * 2)
        self.assertEqual((model.SCAN_A_TCK_COUNT, model.SCAN_B_TCK_COUNT,
                          model.TOTAL_TCK_COUNT), (591, 586, 1177))
        self.boundary_valid = valid
        self.boundary_invalid = invalid

    def test_valid_partial_scan_a_and_complete_shift_before_read(self):
        partial = state(model.Stage.SCAN_A_EXIT_WRITE,
                        **opened(scan_a_started=True, scan_a_tck_emitted=590))
        nav_partial = state(model.Stage.SCAN_A_NAV_WRITE,
                            **opened(scan_a_started=True, scan_a_tck_emitted=1))
        bulk_ready_for_read = state(model.Stage.SCAN_A_BULK_READ,
                                    **opened(scan_a_started=True, scan_a_tck_emitted=585))
        read_before_final_bit = state(model.Stage.SCAN_A_FINAL_READ,
                                      **opened(scan_a_started=True, scan_a_tck_emitted=586))
        fully_written_exit = state(model.Stage.SCAN_A_EXIT_WRITE,
                                   **opened(scan_a_started=True, scan_a_tck_emitted=591))
        for item in (partial, nav_partial, bulk_ready_for_read,
                     read_before_final_bit, fully_written_exit):
            with self.subTest(stage=item.stage, tcks=item.scan_a_tck_emitted):
                self.assertTrue(model.legal_snapshot(item))

    def test_valid_partial_scan_b_requires_completed_scan_a(self):
        partial_nav = state(model.Stage.SCAN_B_NAV_WRITE,
                            **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                     scan_b_started=True, scan_b_tck_emitted=1))
        partial_bulk = state(model.Stage.SCAN_B_BULK_WRITE,
                             **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                      scan_b_started=True, scan_b_tck_emitted=579))
        bulk_ready_for_read = state(model.Stage.SCAN_B_BULK_READ,
                                    **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                             scan_b_started=True, scan_b_tck_emitted=580))
        read_before_final_bit = state(model.Stage.SCAN_B_FINAL_READ,
                                      **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                               scan_b_started=True, scan_b_tck_emitted=581))
        trailing_write = state(model.Stage.SCAN_B_EXIT_WRITE,
                               **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                        scan_b_started=True, scan_b_tck_emitted=586))
        for item in (partial_nav, partial_bulk, bulk_ready_for_read,
                     read_before_final_bit, trailing_write):
            with self.subTest(stage=item.stage, tcks=item.scan_b_tck_emitted):
                self.assertTrue(model.legal_snapshot(item))

    def test_close_failure_preserves_partial_history(self):
        partial = state(model.Stage.SCAN_A_BULK_WRITE,
                        **opened(scan_a_started=True, scan_a_tck_emitted=169))
        closed = model.close_after_failure(partial, closed=True)
        failed_close = model.close_after_failure(partial, closed=False)
        for item in (closed, failed_close):
            self.assertTrue(model.legal_snapshot(item))
            self.assertTrue(model.advance(partial, item))
            self.assertEqual(item.failure_origin, model.Stage.SCAN_A_BULK_WRITE)
            self.assertEqual(item.scan_a_tck_emitted, 169)
            self.assertFalse(item.final_evidence_exists)
            self.assertEqual(item.terminal_status, model.REFUSED)

    def test_open_failure_cleanup_preserves_unopened_handle_state(self):
        open_failure = state(model.Stage.OPEN, target_candidates=1,
                             permit_consumed=True, device_opened=False)
        closed = model.close_after_failure(open_failure, closed=True)
        failed_close = model.close_after_failure(open_failure, closed=False)
        for item in (closed, failed_close):
            self.assertTrue(model.legal_snapshot(item))
            self.assertTrue(model.advance(open_failure, item))
            self.assertEqual(item.failure_origin, model.Stage.OPEN)
            self.assertFalse(item.device_opened)
            self.assertFalse(item.final_evidence_exists)

    def test_close_after_complete_scan_is_valid_for_success_or_close_failure(self):
        common = opened(scan_a_started=True, scan_a_tck_emitted=591,
                        scan_b_started=True, scan_b_tck_emitted=586)
        closed = state(model.Stage.TRANSPORT_CLOSE, **common, transport_closed=True)
        close_failed = state(model.Stage.TRANSPORT_CLOSE, **common,
                             transport_closed=False, terminal_status=model.REFUSED)
        self.assertTrue(model.legal_snapshot(closed))
        self.assertTrue(model.legal_snapshot(close_failed))
        self.assertTrue(model.advance(
            state(model.Stage.SCAN_B_EXIT_WRITE, **common), close_failed))

    def test_rejects_scan_progress_before_open_or_mpsse(self):
        cases = (
            state(model.Stage.OPEN, target_candidates=1, permit_consumed=True,
                  scan_a_started=True, scan_a_tck_emitted=591),
            state(model.Stage.MPSSE_INIT, **opened(scan_a_started=True,
                                                   scan_a_tck_emitted=1)),
            state(model.Stage.SCAN_A_NAV_WRITE, target_candidates=1,
                  permit_consumed=True, scan_a_started=True, scan_a_tck_emitted=1),
        )
        for item in cases:
            with self.subTest(stage=item.stage):
                self.assertFalse(model.legal_snapshot(item))

    def test_open_stage_means_open_not_yet_completed_and_candidate_count_is_bounded(self):
        opened_in_open_stage = state(model.Stage.OPEN, target_candidates=1,
                                     permit_consumed=True, device_opened=True)
        self.assertFalse(model.legal_snapshot(opened_in_open_stage))
        for stage in (model.Stage.ENUMERATION, model.Stage.SELECTION):
            self.assertTrue(model.legal_snapshot(state(stage, target_candidates=256,
                                                        permit_consumed=True)))
            self.assertFalse(model.legal_snapshot(state(stage, target_candidates=300,
                                                         permit_consumed=True)))
        self.assertEqual(
            [model.bounded_candidate_count(value) for value in (0, 1, 2, 255, 256, 300)],
            [0, 1, 2, 255, 256, 256])
        with self.assertRaises(ValueError):
            model.bounded_candidate_count(-1)

    def test_rejects_scan_b_before_a_complete_and_all_overflow_counts(self):
        incomplete_a = state(model.Stage.SCAN_B_NAV_WRITE,
                             **opened(scan_a_started=True, scan_a_tck_emitted=590,
                                      scan_b_started=True, scan_b_tck_emitted=1))
        a_overflow = state(model.Stage.SCAN_A_EXIT_WRITE,
                           **opened(scan_a_started=True, scan_a_tck_emitted=592))
        b_overflow = state(model.Stage.SCAN_B_EXIT_WRITE,
                           **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                    scan_b_started=True, scan_b_tck_emitted=587))
        for item in (incomplete_a, a_overflow, b_overflow):
            with self.subTest(stage=item.stage):
                self.assertFalse(model.legal_snapshot(item))

    def test_rejects_completed_scan_without_started_prerequisite(self):
        a = state(model.Stage.SCAN_A_EXIT_WRITE, **opened(scan_a_tck_emitted=591))
        b = state(model.Stage.SCAN_B_EXIT_WRITE,
                  **opened(scan_a_started=True, scan_a_tck_emitted=591,
                           scan_b_tck_emitted=586))
        self.assertFalse(model.legal_snapshot(a))
        self.assertFalse(model.legal_snapshot(b))

    def test_local_validation_and_signing_require_complete_closed_scans(self):
        incomplete = opened(scan_a_started=True, scan_a_tck_emitted=591,
                            scan_b_started=True, scan_b_tck_emitted=585,
                            transport_closed=True)
        self.assertFalse(model.legal_snapshot(state(model.Stage.LOCAL_VALIDATION,
                                                    **incomplete)))
        incomplete_local = opened(scan_a_started=True, scan_a_tck_emitted=591,
                                  scan_b_started=True, scan_b_tck_emitted=586,
                                  transport_closed=True, local_validation_passed=False)
        self.assertFalse(model.legal_snapshot(state(model.Stage.SIGNING_STAGING,
                                                    **incomplete_local)))
        self.assertFalse(model.legal_snapshot(state(model.Stage.ATOMIC_PUBLISH,
                                                    **incomplete_local,
                                                    signing_staged=True)))

    def test_refusal_never_survives_atomic_publish(self):
        published = state(model.Stage.SUCCESS_REPORTING,
                          **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                   scan_b_started=True, scan_b_tck_emitted=586,
                                   transport_closed=True, local_validation_passed=True,
                                   signing_staged=True, final_evidence_exists=True))
        self.assertTrue(model.legal_snapshot(published))
        self.assertFalse(model.legal_snapshot(replace(published,
                                                      terminal_status=model.REFUSED)))
        self.assertTrue(model.legal_snapshot(replace(published,
                                                     terminal_status=model.REPORTING_FAILED)))

    def test_monotonic_transition_and_publish_point(self):
        prelive = state(model.Stage.PRELIVE_VALIDATION)
        permit_check = state(model.Stage.PERMIT_VALIDATION)
        permit_used = state(model.Stage.PERMIT_CONSUMPTION, permit_consumed=True)
        transaction_check = state(model.Stage.TRANSACTION_VALIDATION, permit_consumed=True)
        self.assertTrue(model.advance(prelive, permit_check))
        self.assertTrue(model.advance(permit_check, permit_used))
        self.assertTrue(model.advance(permit_used, transaction_check))
        self.assertFalse(model.advance(transaction_check, permit_check))

        signing = state(model.Stage.SIGNING_STAGING,
                        **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                 scan_b_started=True, scan_b_tck_emitted=586,
                                 transport_closed=True, local_validation_passed=True,
                                 signing_staged=True))
        publish = replace(signing, stage=model.Stage.ATOMIC_PUBLISH,
                          final_evidence_exists=True)
        success = replace(publish, stage=model.Stage.SUCCESS_REPORTING,
                          terminal_status=model.SUCCEEDED)
        report_failure = replace(publish, stage=model.Stage.SUCCESS_REPORTING,
                                 terminal_status=model.REPORTING_FAILED)
        self.assertTrue(model.advance(signing, publish))
        self.assertTrue(model.advance(publish, success))
        self.assertTrue(model.advance(publish, report_failure))
        self.assertFalse(model.advance(publish, replace(publish,
                                                        terminal_status=model.REFUSED)))

    def test_broken_stdout_is_reporting_failure_not_acquisition_refusal(self):
        complete = state(model.Stage.SUCCESS_REPORTING,
                         **opened(scan_a_started=True, scan_a_tck_emitted=591,
                                  scan_b_started=True, scan_b_tck_emitted=586,
                                  transport_closed=True, local_validation_passed=True,
                                  signing_staged=True, final_evidence_exists=True,
                                  terminal_status=model.REPORTING_FAILED))
        self.assertTrue(model.legal_snapshot(complete))
        self.assertNotEqual(complete.terminal_status, model.REFUSED)

    def test_grid_totals_are_reportable_and_model_has_no_production_import(self):
        valid, invalid = model.count_boundary_space()
        self.assertEqual(valid + invalid, len(tuple(model.Stage)) * 6 * 5 * 5 * 32 * 2)
        self.assertNotIn("phk2_fk0957_topology_live_cli", sys.modules)
        self.assertNotIn("phk2_fk0957_topology_transport", sys.modules)


if __name__ == "__main__":
    unittest.main()
