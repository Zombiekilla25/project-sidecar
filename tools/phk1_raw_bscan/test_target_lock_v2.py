#!/usr/bin/env python3
"""Offline tests for candidate/current/rollback lock roles; never opens devices."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import random
import unittest

from tools.phk1_raw_bscan.target_lock_v2 import (
    LockValidationError, build_lock, canonical_sha256, simulate_failure_restore,
    transition_image_state, validate_lock,
)

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
TARGET = dict(usb_path="usb-target", ftdi_serial="target-serial", vid="0403", pid="6010",
              interface="A", idcode="04b69093", dna="target-dna", bridge_lane="lane-0",
              workload_binding="workload-target")
PEER = dict(usb_path="usb-peer", ftdi_serial="peer-serial", vid="0403", pid="6010",
            interface="A", idcode="04b69093", dna="peer-dna", bridge_lane="lane-1",
            workload_binding="workload-peer")
XBT = dict(role="ROLLBACK_IMAGE", image_id="XBT_V4P1_KNOWN_GOOD",
           sha256="f9812864d13a6963700f60709507ff85ee660fb77e846e51be533b2d479502df",
           size=1000, target_part="xcvu33p-fsvh2104-2-e", path="/fixture/xbt.bit")
CANDIDATE = dict(role="CANDIDATE_IMAGE_TO_PROGRAM", image_id="PHK1_PATCHED_20261103",
                 sha256="47a392b76ebdfdd9edbfc5270f21b48fb6d1acb73e45a7425811865a196d76f8",
                 size=28329335, target_part="xcvu33p-fsvh2104-2-e", path="/fixture/phk1.bit")
CURRENT_XBT = dict(role="CURRENT_LOADED_IMAGE", image_id="XBT_V4P1_KNOWN_GOOD",
                   sha256=XBT["sha256"], size=XBT["size"], target_part=XBT["target_part"], path=XBT["path"])
CURRENT_PHK = dict(role="CURRENT_LOADED_IMAGE", image_id=CANDIDATE["image_id"],
                   sha256=CANDIDATE["sha256"], size=CANDIDATE["size"],
                   target_part=CANDIDATE["target_part"], path=CANDIDATE["path"])
MANIFEST = "a" * 64
QUALIFICATION = "b" * 64
GENERATION = "maintenance-generation-20261104-fixture"
NONCE = "nonce-for-lock-fixture-00000001"


def valid_lock(*, current=CURRENT_XBT, created=None, expires=None, nonce=NONCE,
               target=TARGET, peer=PEER, candidate=CANDIDATE, rollback=XBT,
               manifest=MANIFEST, qualification=QUALIFICATION, generation=GENERATION):
    created = created or NOW - timedelta(seconds=1)
    expires = expires or NOW + timedelta(seconds=599)
    return build_lock(target_identity=target, peer_identity=peer, current_image=current,
        candidate_image=candidate, rollback_image=rollback,
        created_utc=created.isoformat(), expires_utc=expires.isoformat(), authorization_nonce=nonce,
        maintenance_generation=generation, candidate_manifest_sha256=manifest,
        qualification_sha256=qualification, current_image_evidence="fixture:verified-XBT-load-record",
        rollback_authority="fixture:known-good-XBT-restore-authority")


def resign(lock):
    lock = deepcopy(lock)
    lock.pop("lock_sha256", None)
    lock["lock_sha256"] = canonical_sha256(lock)
    return lock


def validate(lock, *, used=None, target=TARGET, candidate=CANDIDATE, rollback=XBT,
             manifest=MANIFEST, qualification=QUALIFICATION, generation=GENERATION,
             current=CURRENT_XBT):
    return validate_lock(lock, now=NOW, expected_target=target, expected_peer=PEER,
        expected_candidate=candidate, expected_rollback=rollback,
        expected_manifest_sha256=manifest, expected_qualification_sha256=qualification,
        expected_maintenance_generation=generation, expected_current_image=current,
        expected_rollback_authority="fixture:known-good-XBT-restore-authority",
        used_nonces=used, intended_action="PROGRAM_CANDIDATE")


class TargetLockV2Tests(unittest.TestCase):
    def test_role_separation_and_canonical_transition(self):
        lock = valid_lock()
        self.assertEqual(lock["current_image"]["sha256"], XBT["sha256"])
        self.assertEqual(lock["candidate_image"]["sha256"], CANDIDATE["sha256"])
        self.assertEqual(lock["rollback_image"]["sha256"], XBT["sha256"])
        validate(lock)
        self.assertEqual(lock["intended_action"], "PROGRAM_CANDIDATE")
        state = {"current_image": CURRENT_XBT, "candidate_image": CANDIDATE,
                 "rollback_image": XBT, "production_restored": False}
        programmed = transition_image_state(state, "program_success")
        self.assertEqual(programmed["current_image"]["sha256"], CANDIDATE["sha256"])
        restored = transition_image_state(programmed, "rollback_success")
        self.assertEqual(restored["current_image"]["sha256"], XBT["sha256"])
        self.assertTrue(restored["production_restored"])

    def test_freshness_and_nonce(self):
        cases = [valid_lock(),
                 valid_lock(created=NOW-timedelta(seconds=601), expires=NOW-timedelta(seconds=1)),
                 valid_lock(created=NOW+timedelta(seconds=1), expires=NOW+timedelta(seconds=100))]
        validate(cases[0])
        for lock in cases[1:]:
            with self.assertRaises(LockValidationError): validate(lock)
        overlong = deepcopy(cases[0]); overlong["expires_utc"] = (NOW+timedelta(seconds=601)).isoformat(); overlong = resign(overlong)
        with self.assertRaises(LockValidationError): validate(overlong)
        missing = deepcopy(cases[0]); missing.pop("created_utc"); validate_should_reject(self, missing)
        self.assertCode(cases[0], used={NONCE}, code="NONCE_REPLAY")

    def assertCode(self, lock, *, code, **kwargs):
        with self.assertRaises(LockValidationError) as ctx: validate(lock, **kwargs)
        self.assertEqual(ctx.exception.code, code)

    def test_wrong_candidate_and_role_toctou(self):
        self.assertCode(valid_lock(), code="WRONG_CANDIDATE", candidate={**CANDIDATE,"sha256":"c"*64})
        self.assertCode(valid_lock(), code="WRONG_CANDIDATE", candidate={**CANDIDATE,"size":CANDIDATE["size"]+1})
        self.assertCode(valid_lock(), code="WRONG_CANDIDATE", candidate={**CANDIDATE,"target_part":"wrong-part"})
        self.assertCode(valid_lock(), code="WRONG_CANDIDATE", manifest="c"*64)
        self.assertCode(valid_lock(), code="WRONG_CANDIDATE", qualification="d"*64)
        self.assertCode(valid_lock(), code="WRONG_TARGET", target={**TARGET,"dna":"changed"})
        self.assertCode(valid_lock(), code="CURRENT_IMAGE_CHANGED", current={**CURRENT_XBT,"sha256":"c"*64})
        self.assertCode(valid_lock(), code="WRONG_ROLLBACK", rollback={**XBT,"sha256":"c"*64})
        self.assertCode(valid_lock(), code="MAINTENANCE_GENERATION", generation="new-generation")
        bad_peer = deepcopy(valid_lock()); bad_peer["peer_exclusion"]["peer_program_allowed"] = True
        self.assertCode(resign(bad_peer), code="PEER_AUTHORIZATION")

    def test_post_program_verification_action(self):
        lock = build_lock(target_identity=TARGET, peer_identity=PEER, current_image=CURRENT_PHK,
            candidate_image=CANDIDATE, rollback_image=XBT,
            created_utc=(NOW-timedelta(seconds=1)).isoformat(), expires_utc=(NOW+timedelta(seconds=599)).isoformat(),
            authorization_nonce="nonce-for-verify-fixture-000001", maintenance_generation=GENERATION,
            candidate_manifest_sha256=MANIFEST, qualification_sha256=QUALIFICATION,
            current_image_evidence="fixture:program-success", rollback_authority="fixture:known-good-XBT-restore-authority",
            intended_action="VERIFY_CANDIDATE")
        validate_lock(lock, now=NOW, expected_target=TARGET, expected_peer=PEER,
            expected_candidate=CANDIDATE, expected_rollback=XBT, expected_current_image=CURRENT_PHK,
            expected_manifest_sha256=MANIFEST, expected_qualification_sha256=QUALIFICATION,
            expected_maintenance_generation=GENERATION, intended_action="VERIFY_CANDIDATE")

    def test_failure_restore_matrix(self):
        initial = {"current_image": CURRENT_XBT, "candidate_image": CANDIDATE,
                   "rollback_image": XBT, "production_restored": False}
        phases = ("lock_generation", "maintenance_enter", "bridge_release", "jit_validation",
                  "program_start", "program_failure", "runner_start", "hello", "user3_poll",
                  "vector", "verification", "rollback")
        for phase in phases:
            state = simulate_failure_restore(phase, initial)
            self.assertEqual(state["current_image"]["sha256"], XBT["sha256"], phase)
            self.assertTrue(state["production_restored"], phase)
            self.assertEqual(state["miners_restored"], 8, phase)
            self.assertFalse(state["raw_runner_active"], phase)

    def test_complete_offline_canary_sequence(self):
        lock = valid_lock()
        validate(lock)
        state = {"current_image": CURRENT_XBT, "candidate_image": CANDIDATE,
                 "rollback_image": XBT, "production_restored": False,
                 "maintenance": False, "runner": False, "hello": 0, "user3_ready": False,
                 "vector": 0, "raw_exact": False, "canonical_exact": False, "cpu_exact": False}
        state["maintenance"] = True
        state = transition_image_state(state, "program_success")
        state["runner"] = True
        state["hello"] = 1
        state["user3_ready"] = True
        state["vector"] = 1
        state["raw_exact"] = state["canonical_exact"] = state["cpu_exact"] = True
        state = transition_image_state(state, "rollback_success")
        state.update(maintenance=False, runner=False, miners_restored=8,
                     bridge_restored=True, protected_workload_continuity=True)
        self.assertEqual(state["current_image"]["sha256"], XBT["sha256"])
        self.assertEqual((state["hello"], state["vector"]), (1, 1))
        self.assertTrue(all(state[k] for k in ("raw_exact", "canonical_exact", "cpu_exact",
                                                "production_restored", "bridge_restored",
                                                "protected_workload_continuity")))
        self.assertEqual(state["miners_restored"], 8)

    def test_10000_case_fuzz(self):
        rng = random.Random(0x51DEC4)
        valid_accept = invalid_accept = valid_reject = invalid_reject = 0
        for i in range(10_000):
            lock = valid_lock(nonce=f"fixture-nonce-{i:024d}")
            if i % 2 == 0:
                try:
                    validate(lock)
                    valid_accept += 1
                except LockValidationError:
                    valid_reject += 1
            else:
                mutation = rng.choice(("candidate_sha", "target", "peer", "nonce", "expiry", "maintenance", "rollback"))
                changed = deepcopy(lock)
                if mutation == "candidate_sha": changed["candidate_image"]["sha256"] = "c"*64
                elif mutation == "target": changed["target_identity"]["dna"] = "wrong-dna"
                elif mutation == "peer": changed["peer_identity"]["dna"] = "target-dna"
                elif mutation == "nonce": changed["authorization_nonce"] = ""
                elif mutation == "expiry": changed["expires_utc"] = (NOW-timedelta(seconds=1)).isoformat()
                elif mutation == "maintenance": changed["maintenance_generation"] = "stale-maintenance"
                else: changed["rollback_image"]["sha256"] = "d"*64
                changed = resign(changed)
                try:
                    validate(changed)
                    invalid_accept += 1
                except LockValidationError:
                    invalid_reject += 1
        self.assertEqual(valid_accept, 5000)
        self.assertEqual(valid_reject, 0)
        self.assertEqual(invalid_accept, 0)
        self.assertEqual(invalid_reject, 5000)


def validate_should_reject(test, lock):
    with test.assertRaises(LockValidationError): validate(lock)


if __name__ == "__main__": unittest.main(verbosity=2)
