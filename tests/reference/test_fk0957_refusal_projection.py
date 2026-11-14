"""Regression tests for lossless oracle-to-refusal envelope projection.

The independent state classifier is pinned and unchanged. These tests cover
only the adapter that projects its classified snapshots into candidate schema.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
_audit_spec = importlib.util.spec_from_file_location(
    "fk0957_corrected_oracle_audit", HERE / "fk0957_corrected_oracle_audit.py")
audit = importlib.util.module_from_spec(_audit_spec)
assert _audit_spec and _audit_spec.loader
_audit_spec.loader.exec_module(audit)
model = audit.load_reference(HERE.parents[1])


def complete_state(stage, *, local_validation_passed=True, signing_staged=False):
    return model.Snapshot(
        stage=stage, target_candidates=1, permit_consumed=True,
        device_opened=True, scan_a_started=True, scan_a_tck_emitted=591,
        scan_b_started=True, scan_b_tck_emitted=586, transport_closed=True,
        final_evidence_exists=False,
        local_validation_passed=local_validation_passed,
        signing_staged=signing_staged,
    )


class RefusalProjectionTests(unittest.TestCase):
    def test_signing_staging_and_unstaged_atomic_publish_are_distinguishable(self):
        valid = complete_state(model.Stage.SIGNING_STAGING)
        invalid = complete_state(model.Stage.ATOMIC_PUBLISH)
        self.assertTrue(model.legal_snapshot(valid))
        self.assertFalse(model.legal_snapshot(invalid))
        valid_envelope = audit.refusal_envelope(valid, model)
        invalid_envelope = audit.refusal_envelope(invalid, model)
        self.assertNotEqual(valid_envelope, invalid_envelope)
        self.assertEqual(valid_envelope["operation_state"], "LOCAL_VALIDATED")
        self.assertEqual(invalid_envelope["operation_state"], "LOCAL_VALIDATED")
        self.assertEqual(valid_envelope["publication_state"], "NOT_STARTED")
        self.assertEqual(invalid_envelope["publication_state"], "PUBLISHING")

    def test_unvalidated_staging_cannot_project_as_a_valid_signed_stage(self):
        invalid = complete_state(model.Stage.ATOMIC_PUBLISH,
                                 local_validation_passed=False,
                                 signing_staged=True)
        self.assertFalse(model.legal_snapshot(invalid))
        envelope = audit.refusal_envelope(invalid, model)
        self.assertEqual(envelope["operation_state"], "TRANSPORT_CLOSED")
        self.assertEqual(envelope["publication_state"], "PUBLISHING")


if __name__ == "__main__":
    unittest.main()
