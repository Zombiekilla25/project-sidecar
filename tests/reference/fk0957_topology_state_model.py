"""Independent executable reference model for the FK0957 topology operation.

This module intentionally does not import production code. The scan boundaries
below describe the reviewed fixed transaction at command/read boundaries so
that partial writes and cleanup history can be judged independently.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from itertools import product
from typing import Iterator


SCAN_A_TCK_COUNT = 591
SCAN_B_TCK_COUNT = 586
TOTAL_TCK_COUNT = 1177


class Stage(IntEnum):
    PRELIVE_VALIDATION = 0
    PERMIT_VALIDATION = 1
    PERMIT_CONSUMPTION = 2
    TRANSACTION_VALIDATION = 3
    REMOTE_BOOTSTRAP = 4
    ENUMERATION = 5
    SELECTION = 6
    OPEN = 7
    MPSSE_INIT = 8
    SCAN_A_NAV_WRITE = 9
    SCAN_A_BULK_WRITE = 10
    SCAN_A_BULK_READ = 11
    SCAN_A_FINAL_WRITE = 12
    SCAN_A_FINAL_READ = 13
    SCAN_A_EXIT_WRITE = 14
    SCAN_B_NAV_WRITE = 15
    SCAN_B_BULK_WRITE = 16
    SCAN_B_BULK_READ = 17
    SCAN_B_FINAL_WRITE = 18
    SCAN_B_FINAL_READ = 19
    SCAN_B_EXIT_WRITE = 20
    TRANSPORT_CLOSE = 21
    LOCAL_VALIDATION = 22
    SIGNING_STAGING = 23
    ATOMIC_PUBLISH = 24
    SUCCESS_REPORTING = 25


REFUSED = "REFUSED"
SUCCEEDED = "SUCCEEDED"
REPORTING_FAILED = "REPORTING_FAILED"
RUNNING = "RUNNING"


@dataclass(frozen=True)
class Snapshot:
    stage: Stage
    target_candidates: int = 0
    permit_consumed: bool = False
    device_opened: bool = False
    scan_a_started: bool = False
    scan_a_tck_emitted: int = 0
    scan_b_started: bool = False
    scan_b_tck_emitted: int = 0
    transport_closed: bool = False
    final_evidence_exists: bool = False
    local_validation_passed: bool = False
    signing_staged: bool = False
    failure_origin: Stage | None = None
    terminal_status: str = RUNNING


def _has_no_transport_progress(s: Snapshot) -> bool:
    return (not s.device_opened and not s.scan_a_started and
            s.scan_a_tck_emitted == 0 and not s.scan_b_started and
            s.scan_b_tck_emitted == 0 and not s.transport_closed)


def _valid_scan_progress(s: Snapshot, stage: Stage) -> bool:
    """Check a scan-state snapshot at its exact command/read boundary."""
    if s.target_candidates != 1 or not s.permit_consumed or not s.device_opened:
        return False
    if s.transport_closed or s.final_evidence_exists:
        return False
    if stage == Stage.SCAN_A_NAV_WRITE:
        return (s.scan_a_started and 0 <= s.scan_a_tck_emitted <= 9 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0)
    if stage == Stage.SCAN_A_BULK_WRITE:
        return (s.scan_a_started and 9 <= s.scan_a_tck_emitted <= 585 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0)
    if stage == Stage.SCAN_A_BULK_READ:
        return (s.scan_a_started and s.scan_a_tck_emitted == 585 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0)
    if stage == Stage.SCAN_A_FINAL_WRITE:
        return (s.scan_a_started and 585 <= s.scan_a_tck_emitted <= 586 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0)
    if stage == Stage.SCAN_A_FINAL_READ:
        return (s.scan_a_started and s.scan_a_tck_emitted == 586 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0)
    if stage == Stage.SCAN_A_EXIT_WRITE:
        return (s.scan_a_started and 586 <= s.scan_a_tck_emitted <= 591 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0)
    if stage == Stage.SCAN_B_NAV_WRITE:
        return (s.scan_a_started and s.scan_a_tck_emitted == 591 and
                s.scan_b_started and 0 <= s.scan_b_tck_emitted <= 4)
    if stage == Stage.SCAN_B_BULK_WRITE:
        return (s.scan_a_started and s.scan_a_tck_emitted == 591 and
                s.scan_b_started and 4 <= s.scan_b_tck_emitted <= 580)
    if stage == Stage.SCAN_B_BULK_READ:
        return (s.scan_a_started and s.scan_a_tck_emitted == 591 and
                s.scan_b_started and s.scan_b_tck_emitted == 580)
    if stage == Stage.SCAN_B_FINAL_WRITE:
        return (s.scan_a_started and s.scan_a_tck_emitted == 591 and
                s.scan_b_started and 580 <= s.scan_b_tck_emitted <= 581)
    if stage == Stage.SCAN_B_FINAL_READ:
        return (s.scan_a_started and s.scan_a_tck_emitted == 591 and
                s.scan_b_started and s.scan_b_tck_emitted == 581)
    if stage == Stage.SCAN_B_EXIT_WRITE:
        return (s.scan_a_started and s.scan_a_tck_emitted == 591 and
                s.scan_b_started and 581 <= s.scan_b_tck_emitted <= 586)
    return False


def legal_snapshot(s: Snapshot) -> bool:
    """Return whether a snapshot is reachable under the independent model."""
    if type(s.stage) is not Stage:
        return False
    if (type(s.target_candidates) is not int or not 0 <= s.target_candidates <= 300 or
            type(s.scan_a_tck_emitted) is not int or
            not 0 <= s.scan_a_tck_emitted <= SCAN_A_TCK_COUNT or
            type(s.scan_b_tck_emitted) is not int or
            not 0 <= s.scan_b_tck_emitted <= SCAN_B_TCK_COUNT):
        return False
    bool_fields = (s.permit_consumed, s.device_opened, s.scan_a_started,
                   s.scan_b_started, s.transport_closed, s.final_evidence_exists,
                   s.local_validation_passed, s.signing_staged)
    if any(type(value) is not bool for value in bool_fields):
        return False
    if (s.scan_a_tck_emitted and not s.scan_a_started or
            s.scan_b_tck_emitted and not s.scan_b_started or
            s.scan_b_started and (not s.scan_a_started or
                                  s.scan_a_tck_emitted != SCAN_A_TCK_COUNT)):
        return False
    if s.failure_origin is not None and s.stage != Stage.TRANSPORT_CLOSE:
        return False
    if s.device_opened and (not s.permit_consumed or s.target_candidates != 1):
        return False
    if s.scan_a_started and not s.device_opened:
        return False

    if s.final_evidence_exists:
        if (not s.permit_consumed or s.target_candidates != 1 or
                not s.device_opened or not s.scan_a_started or
                s.scan_a_tck_emitted != SCAN_A_TCK_COUNT or
                not s.scan_b_started or s.scan_b_tck_emitted != SCAN_B_TCK_COUNT or
                not s.transport_closed or not s.local_validation_passed or
                not s.signing_staged or s.stage < Stage.ATOMIC_PUBLISH):
            return False
    if s.signing_staged and not s.local_validation_passed:
        return False
    if s.local_validation_passed and (not s.transport_closed or
            s.scan_a_tck_emitted != SCAN_A_TCK_COUNT or
            s.scan_b_tck_emitted != SCAN_B_TCK_COUNT):
        return False

    if s.terminal_status == REFUSED and s.final_evidence_exists:
        return False
    if s.terminal_status == SUCCEEDED and not (
            s.stage == Stage.SUCCESS_REPORTING and s.final_evidence_exists):
        return False
    if s.terminal_status == REPORTING_FAILED and not (
            s.stage == Stage.SUCCESS_REPORTING and s.final_evidence_exists):
        return False
    if s.terminal_status not in (RUNNING, REFUSED, SUCCEEDED, REPORTING_FAILED):
        return False

    phase = s.stage
    if phase in (Stage.PRELIVE_VALIDATION, Stage.PERMIT_VALIDATION):
        return (s.target_candidates == 0 and not s.permit_consumed and
                _has_no_transport_progress(s) and not s.local_validation_passed and
                not s.signing_staged and not s.final_evidence_exists)
    if phase == Stage.PERMIT_CONSUMPTION:
        return (s.target_candidates == 0 and s.permit_consumed and
                _has_no_transport_progress(s) and not s.local_validation_passed and
                not s.signing_staged and not s.final_evidence_exists)
    if phase in (Stage.TRANSACTION_VALIDATION, Stage.REMOTE_BOOTSTRAP):
        return (s.target_candidates == 0 and s.permit_consumed and
                _has_no_transport_progress(s) and not s.local_validation_passed and
                not s.signing_staged and not s.final_evidence_exists)
    if phase in (Stage.ENUMERATION, Stage.SELECTION):
        return (s.permit_consumed and not s.device_opened and
                not s.scan_a_started and s.scan_a_tck_emitted == 0 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0 and
                not s.transport_closed and not s.local_validation_passed and
                not s.signing_staged and not s.final_evidence_exists)
    if phase == Stage.OPEN:
        return (s.permit_consumed and s.target_candidates == 1 and
                not s.scan_a_started and s.scan_a_tck_emitted == 0 and
                not s.scan_b_started and s.scan_b_tck_emitted == 0 and
                not s.transport_closed and not s.local_validation_passed and
                not s.signing_staged and not s.final_evidence_exists)
    if phase == Stage.MPSSE_INIT:
        return (s.permit_consumed and s.target_candidates == 1 and
                s.device_opened and not s.scan_a_started and
                s.scan_a_tck_emitted == 0 and not s.scan_b_started and
                s.scan_b_tck_emitted == 0 and not s.transport_closed and
                not s.local_validation_passed and not s.signing_staged and
                not s.final_evidence_exists)
    if phase in set(Stage) - {Stage.TRANSPORT_CLOSE, Stage.LOCAL_VALIDATION,
                              Stage.SIGNING_STAGING, Stage.ATOMIC_PUBLISH,
                              Stage.SUCCESS_REPORTING} and phase.value >= Stage.SCAN_A_NAV_WRITE:
        return _valid_scan_progress(s, phase)
    if phase == Stage.TRANSPORT_CLOSE:
        if s.local_validation_passed or s.signing_staged or s.final_evidence_exists:
            return False
        if s.failure_origin is None:
            return (s.target_candidates == 1 and s.permit_consumed and
                    s.device_opened and s.scan_a_started and
                    s.scan_a_tck_emitted == SCAN_A_TCK_COUNT and
                    s.scan_b_started and s.scan_b_tck_emitted == SCAN_B_TCK_COUNT)
        if type(s.failure_origin) is not Stage or s.failure_origin >= Stage.TRANSPORT_CLOSE:
            return False
        prior = replace(s, stage=s.failure_origin, transport_closed=False,
                        failure_origin=None, terminal_status=RUNNING)
        return legal_snapshot(prior)
    if phase == Stage.LOCAL_VALIDATION:
        return (s.target_candidates == 1 and s.permit_consumed and
                s.device_opened and s.scan_a_started and
                s.scan_a_tck_emitted == SCAN_A_TCK_COUNT and
                s.scan_b_started and s.scan_b_tck_emitted == SCAN_B_TCK_COUNT and
                s.transport_closed and not s.signing_staged and
                not s.final_evidence_exists)
    if phase == Stage.SIGNING_STAGING:
        return (s.target_candidates == 1 and s.permit_consumed and
                s.device_opened and s.scan_a_started and
                s.scan_a_tck_emitted == SCAN_A_TCK_COUNT and
                s.scan_b_started and s.scan_b_tck_emitted == SCAN_B_TCK_COUNT and
                s.transport_closed and s.local_validation_passed and
                not s.final_evidence_exists)
    if phase == Stage.ATOMIC_PUBLISH:
        return (s.target_candidates == 1 and s.permit_consumed and
                s.device_opened and s.scan_a_started and
                s.scan_a_tck_emitted == SCAN_A_TCK_COUNT and
                s.scan_b_started and s.scan_b_tck_emitted == SCAN_B_TCK_COUNT and
                s.transport_closed and s.local_validation_passed and
                s.signing_staged)
    if phase == Stage.SUCCESS_REPORTING:
        return s.final_evidence_exists and s.signing_staged and s.local_validation_passed
    return False


def advance(previous: Snapshot, following: Snapshot) -> bool:
    """Check a normal monotonic transition or cleanup transition to close."""
    if not legal_snapshot(previous) or not legal_snapshot(following):
        return False
    cleanup_transition = (
        following.stage == Stage.TRANSPORT_CLOSE and
        previous.stage >= Stage.MPSSE_INIT and
        previous.stage < Stage.TRANSPORT_CLOSE and
        previous.device_opened and
        following.failure_origin == previous.stage and
        following.terminal_status == REFUSED)
    normal_transition = (
        following.failure_origin is None and
        following.stage.value == previous.stage.value + 1)
    if not (cleanup_transition or normal_transition):
        return False
    monotone = (
        (previous.target_candidates == following.target_candidates or
         previous.stage < Stage.ENUMERATION <= following.stage),
        (not previous.permit_consumed or following.permit_consumed),
        (not previous.device_opened or following.device_opened),
        (not previous.scan_a_started or following.scan_a_started),
        previous.scan_a_tck_emitted <= following.scan_a_tck_emitted,
        (not previous.scan_b_started or following.scan_b_started),
        previous.scan_b_tck_emitted <= following.scan_b_tck_emitted,
        (not previous.transport_closed or following.transport_closed),
        (not previous.local_validation_passed or following.local_validation_passed),
        (not previous.signing_staged or following.signing_staged),
        (not previous.final_evidence_exists or following.final_evidence_exists),
    )
    if not all(monotone):
        return False
    if following.final_evidence_exists and not previous.final_evidence_exists:
        return following.stage == Stage.ATOMIC_PUBLISH
    return True


def close_after_failure(previous: Snapshot, *, closed: bool) -> Snapshot:
    """Model deterministic cleanup while retaining the original progress."""
    if (not legal_snapshot(previous) or previous.stage < Stage.MPSSE_INIT or
            previous.stage >= Stage.TRANSPORT_CLOSE or not previous.device_opened):
        raise ValueError("failure origin is not a closable operation stage")
    return replace(previous, stage=Stage.TRANSPORT_CLOSE, transport_closed=closed,
                   failure_origin=previous.stage, terminal_status=REFUSED)


def boundary_combinations() -> Iterator[Snapshot]:
    """Exhaust requested candidate/TCK boundaries and boolean permutations."""
    candidates = (0, 1, 2, 255, 256, 300)
    scan_a = (0, 1, 590, 591, 592)
    scan_b = (0, 1, 585, 586, 587)
    stages = tuple(Stage)
    flags = tuple(product((False, True), repeat=5))
    for stage, count, a_tck, b_tck, flagset, final_exists in product(
            stages, candidates, scan_a, scan_b, flags, (False, True)):
        opened, a_started, b_started, closed, consumed = flagset
        yield Snapshot(stage, count, consumed, opened, a_started, a_tck,
                       b_started, b_tck, closed, final_exists)


def count_boundary_space() -> tuple[int, int]:
    valid = invalid = 0
    for state in boundary_combinations():
        if legal_snapshot(state):
            valid += 1
        else:
            invalid += 1
    return valid, invalid
