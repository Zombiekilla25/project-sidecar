"""Offline audit harness for a candidate FK0957 topology state machine.

The oracle is the pinned, independent ``fk0957_topology_state_model`` module.
The candidate's canonical-envelope validator is the system under test, never
the source of expected state legality.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable


REFERENCE_MODEL_COMMIT = "ea2104c55a1d4dafe6da91c6d5ac28447ec336c1"
EXPECTED_SCAN_A_SHA256 = "81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2"
EXPECTED_SCAN_B_SHA256 = "08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a"

PHASE_BY_STAGE = {
    "PRELIVE_VALIDATION": "PRELIVE_VALIDATION",
    "PERMIT_VALIDATION": "PERMIT_VALIDATION",
    "PERMIT_CONSUMPTION": "LIBRARY_PROVENANCE",
    "TRANSACTION_VALIDATION": "PRELIVE_VALIDATION",
    "REMOTE_BOOTSTRAP": "REMOTE_BOOTSTRAP",
    "ENUMERATION": "DEVICE_ENUMERATION",
    "SELECTION": "DEVICE_SELECTION",
    "OPEN": "DEVICE_OPEN",
    "MPSSE_INIT": "MPSSE_INIT",
    "SCAN_A_NAV_WRITE": "SCAN_A_WRITE",
    "SCAN_A_BULK_WRITE": "SCAN_A_WRITE",
    "SCAN_A_BULK_READ": "SCAN_A_READ",
    "SCAN_A_FINAL_WRITE": "SCAN_A_WRITE",
    "SCAN_A_FINAL_READ": "SCAN_A_READ",
    "SCAN_A_EXIT_WRITE": "SCAN_A_WRITE",
    "SCAN_B_NAV_WRITE": "SCAN_B_WRITE",
    "SCAN_B_BULK_WRITE": "SCAN_B_WRITE",
    "SCAN_B_BULK_READ": "SCAN_B_READ",
    "SCAN_B_FINAL_WRITE": "SCAN_B_WRITE",
    "SCAN_B_FINAL_READ": "SCAN_B_READ",
    "SCAN_B_EXIT_WRITE": "SCAN_B_WRITE",
    "TRANSPORT_CLOSE": "TRANSPORT_CLOSE",
    "LOCAL_VALIDATION": "LOCAL_VALIDATION",
    "SIGNING_STAGING": "LOCAL_SIGNING",
    "ATOMIC_PUBLISH": "LOCAL_SIGNING",
    "SUCCESS_REPORTING": "LOCAL_SIGNING",
}

STATE_BY_STAGE = {
    "PRELIVE_VALIDATION": "PRELIVE",
    "PERMIT_VALIDATION": "PRELIVE",
    "PERMIT_CONSUMPTION": "PERMIT_VALIDATED",
    "TRANSACTION_VALIDATION": "PERMIT_VALIDATED",
    "REMOTE_BOOTSTRAP": "RUNTIME_READY",
    "ENUMERATION": "ENUMERATING",
    "SELECTION": "ENUMERATING",
    "OPEN": "DEVICE_SELECTED",
    "MPSSE_INIT": "DEVICE_OPENED",
    "TRANSPORT_CLOSE": "TRANSPORT_CLOSING",
    "LOCAL_VALIDATION": "TRANSPORT_CLOSED",
    "SIGNING_STAGING": "LOCAL_VALIDATED",
    "ATOMIC_PUBLISH": "SIGNED_STAGED",
    "SUCCESS_REPORTING": "SIGNED_STAGED",
}
for _stage in (
    "SCAN_A_NAV_WRITE", "SCAN_A_BULK_WRITE", "SCAN_A_BULK_READ",
    "SCAN_A_FINAL_WRITE", "SCAN_A_FINAL_READ", "SCAN_A_EXIT_WRITE",
):
    STATE_BY_STAGE[_stage] = "SCAN_A_ACTIVE"
for _stage in (
    "SCAN_B_NAV_WRITE", "SCAN_B_BULK_WRITE", "SCAN_B_BULK_READ",
    "SCAN_B_FINAL_WRITE", "SCAN_B_FINAL_READ", "SCAN_B_EXIT_WRITE",
):
    STATE_BY_STAGE[_stage] = "SCAN_B_ACTIVE"

PHASE_CODES = {
    "PRELIVE_VALIDATION": "TRANSACTION_PIN_MISMATCH",
    "PERMIT_VALIDATION": "PERMIT_INVALID",
    "LIBRARY_PROVENANCE": "LIBRARY_PIN_MISMATCH",
    "REMOTE_BOOTSTRAP": "REMOTE_BOOTSTRAP_FAILED",
    "DEVICE_ENUMERATION": "ENUMERATION_FAILED",
    "DEVICE_SELECTION": "CANDIDATE_IDENTITY_MISMATCH",
    "DEVICE_SELECTION": "CANDIDATE_IDENTITY_MISMATCH",
    "DEVICE_OPEN": "DEVICE_OPEN_FAILED",
    "MPSSE_INIT": "MPSSE_INIT_FAILED",
    "SCAN_A_WRITE": "SCAN_A_WRITE_FAILED",
    "SCAN_A_READ": "SCAN_A_READ_FAILED",
    "SCAN_B_WRITE": "SCAN_B_WRITE_FAILED",
    "SCAN_B_READ": "SCAN_B_READ_FAILED",
    "TRANSPORT_CLOSE": "TRANSPORT_CLOSE_FAILED",
    "LOCAL_VALIDATION": "LOCAL_VALIDATION_FAILED",
    "LOCAL_SIGNING": "LOCAL_SIGNING_FAILED",
}


def _run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], check=check,
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def load_reference(repo: Path):
    model_path = Path(__file__).with_name("fk0957_topology_state_model.py")
    pinned = _run_git(repo, "show", f"{REFERENCE_MODEL_COMMIT}:tests/reference/fk0957_topology_state_model.py").stdout.encode()
    if model_path.read_bytes() != pinned:
        raise RuntimeError("reference source differs from pinned commit")
    spec = importlib.util.spec_from_file_location("fk0957_independent_reference", model_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("reference model cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _candidate_close_from(snapshot, model) -> str:
    origin = snapshot.failure_origin
    if origin is None:
        return "SCAN_B_COMPLETE"
    if origin <= model.Stage.OPEN:
        return "DEVICE_SELECTED"
    if origin == model.Stage.MPSSE_INIT:
        return "DEVICE_OPENED"
    if origin.value <= model.Stage.SCAN_A_EXIT_WRITE:
        return "SCAN_A_ACTIVE"
    if origin.value <= model.Stage.SCAN_B_EXIT_WRITE:
        return "SCAN_B_ACTIVE"
    return "SCAN_B_COMPLETE"


def refusal_envelope(snapshot, model) -> dict[str, Any] | None:
    """Project only serialized candidate fields from an oracle snapshot.

    Published-evidence states are intentionally not coerced into refusals;
    their post-publish behavior is tested through the CLI failure-injection
    regressions instead.
    """
    stage = snapshot.stage
    if snapshot.final_evidence_exists:
        return None
    phase = PHASE_BY_STAGE[stage.name]
    code = PHASE_CODES[phase]
    if stage == model.Stage.SELECTION:
        code = ("NO_TARGET_CANDIDATE" if snapshot.target_candidates == 0 else
                "MULTIPLE_TARGET_CANDIDATES" if snapshot.target_candidates >= 2 else
                "CANDIDATE_IDENTITY_MISMATCH")
    op_state = STATE_BY_STAGE[stage.name]
    close_from = None
    transport_closed = int(snapshot.transport_closed)

    if stage == model.Stage.TRANSPORT_CLOSE:
        if snapshot.failure_origin is None:
            # A successfully closed transport has moved to local validation.
            phase = "LOCAL_VALIDATION"
            code = PHASE_CODES[phase]
            op_state = "TRANSPORT_CLOSED"
            close_from = "SCAN_B_COMPLETE"
        else:
            close_from = _candidate_close_from(snapshot, model)
            op_state = "TRANSPORT_CLOSED" if snapshot.transport_closed else "TRANSPORT_CLOSING"
    elif stage in (model.Stage.LOCAL_VALIDATION, model.Stage.SIGNING_STAGING,
                   model.Stage.ATOMIC_PUBLISH):
        close_from = "SCAN_B_COMPLETE"
        if stage == model.Stage.SIGNING_STAGING:
            if not snapshot.local_validation_passed:
                op_state = "TRANSPORT_CLOSED"
            elif snapshot.signing_staged:
                op_state = "SIGNED_STAGED"
        elif stage == model.Stage.ATOMIC_PUBLISH and not snapshot.signing_staged:
            op_state = "LOCAL_VALIDATED"

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
        "operation_state": op_state, "close_from_state": close_from,
    }


def compare_state_corpus(model, validator: Callable[[dict[str, Any]], bool]) -> dict[str, int]:
    valid = invalid = valid_rejected = invalid_accepted = 0
    for snapshot in model.boundary_combinations():
        expected = model.legal_snapshot(snapshot)
        valid += int(expected)
        invalid += int(not expected)
        envelope = refusal_envelope(snapshot, model)
        # The evidence-exists bit is not a refusal-envelope field. Those
        # snapshots cannot be accepted as REFUSED; post-publish reporting is
        # tested separately through the candidate CLI.
        accepted = False if envelope is None else bool(validator(envelope))
        if expected and not accepted:
            valid_rejected += 1
        elif not expected and accepted:
            invalid_accepted += 1
    return {
        "valid_states": valid,
        "invalid_states": invalid,
        "valid_state_rejected": valid_rejected,
        "invalid_state_accepted": invalid_accepted,
    }


def _manual_envelope(phase: str, operation_state: str, **changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "status": "REFUSED", "phase": phase,
        "code": PHASE_CODES[phase], "evidence_path": "none",
        "signature_verified": False, "return_code": None,
        "target_candidates": 1, "device_opened": 1,
        "scan_a_started": 0, "scan_a_tck_emitted": 0,
        "scan_b_started": 0, "scan_b_tck_emitted": 0,
        "transport_closed": 0, "permit_consumed": 1,
        "operation_state": operation_state, "close_from_state": None,
    }
    value.update(changes)
    return value


def targeted_checks(cli, transport) -> dict[str, bool]:
    validate = cli._bounded_envelope
    candidate_boundaries = True
    for count in (0, 1, 2, 255, 256):
        enum = _manual_envelope("DEVICE_ENUMERATION", "ENUMERATING",
                                target_candidates=count, device_opened=0)
        selection_code = ("NO_TARGET_CANDIDATE" if count == 0 else
                          "CANDIDATE_IDENTITY_MISMATCH" if count == 1 else
                          "MULTIPLE_TARGET_CANDIDATES")
        selected = _manual_envelope("DEVICE_SELECTION", "ENUMERATING",
                                    target_candidates=count, device_opened=0,
                                    code=selection_code)
        candidate_boundaries &= validate(enum) and validate(selected)
    too_many = _manual_envelope("DEVICE_SELECTION", "ENUMERATING",
                                target_candidates=300, device_opened=0,
                                code="MULTIPLE_TARGET_CANDIDATES")
    candidate_boundaries &= not validate(too_many)

    permit_relationships = (
        validate(_manual_envelope("PERMIT_VALIDATION", "PRELIVE",
                                  target_candidates="unknown", device_opened=0,
                                  permit_consumed=0)) and
        not validate(_manual_envelope("PERMIT_VALIDATION", "PRELIVE",
                                      target_candidates=0, device_opened=0,
                                      permit_consumed=1)) and
        validate(_manual_envelope("PRELIVE_VALIDATION", "PERMIT_VALIDATED",
                                  target_candidates=0, device_opened=0)) and
        not validate(_manual_envelope("PRELIVE_VALIDATION", "PRELIVE",
                                      target_candidates=1, device_opened=0,
                                      permit_consumed=0)) and
        not validate(_manual_envelope("REMOTE_BOOTSTRAP", "RUNTIME_READY",
                                      target_candidates=1, device_opened=0)))

    open_state = (
        validate(_manual_envelope("DEVICE_OPEN", "DEVICE_SELECTED",
                                  target_candidates=1, device_opened=0)) and
        not validate(_manual_envelope("DEVICE_OPEN", "DEVICE_SELECTED",
                                      target_candidates=1, device_opened=1)))

    scan_boundaries = True
    for ticks in (0, 1, 590, 591):
        scan_a_write = _manual_envelope("SCAN_A_WRITE", "SCAN_A_ACTIVE",
                                        scan_a_started=1, scan_a_tck_emitted=ticks)
        scan_a_read_expected = ticks in (585, 586)
        scan_a_read = _manual_envelope("SCAN_A_READ", "SCAN_A_ACTIVE",
                                       scan_a_started=1, scan_a_tck_emitted=ticks)
        scan_boundaries &= validate(scan_a_write)
        scan_boundaries &= (validate(scan_a_read) == scan_a_read_expected)
    for ticks in (0, 1, 585, 586):
        scan_b_write = _manual_envelope("SCAN_B_WRITE", "SCAN_B_ACTIVE",
                                        scan_a_started=1, scan_a_tck_emitted=591,
                                        scan_b_started=1, scan_b_tck_emitted=ticks)
        scan_b_read_expected = ticks in (580, 581)
        scan_b_read = _manual_envelope("SCAN_B_READ", "SCAN_B_ACTIVE",
                                       scan_a_started=1, scan_a_tck_emitted=591,
                                       scan_b_started=1, scan_b_tck_emitted=ticks)
        scan_boundaries &= validate(scan_b_write)
        scan_boundaries &= (validate(scan_b_read) == scan_b_read_expected)

    close_history = True
    close_rows = (
        ("DEVICE_SELECTED", 0, 0, 0, 0, 0),
        ("DEVICE_OPENED", 1, 0, 0, 0, 0),
        ("MPSSE_READY", 1, 0, 0, 0, 0),
        ("SCAN_A_ACTIVE", 1, 1, 169, 0, 0),
        ("SCAN_A_COMPLETE", 1, 1, 591, 0, 0),
        ("SCAN_B_ACTIVE", 1, 1, 591, 1, 17),
        ("SCAN_B_COMPLETE", 1, 1, 591, 1, 586),
    )
    for prior, opened, a_started, a_ticks, b_started, b_ticks in close_rows:
        close = _manual_envelope(
            "TRANSPORT_CLOSE", "TRANSPORT_CLOSING", target_candidates=1,
            device_opened=opened, scan_a_started=a_started,
            scan_a_tck_emitted=a_ticks, scan_b_started=b_started,
            scan_b_tck_emitted=b_ticks, transport_closed=0,
            close_from_state=prior)
        close_history &= validate(close)
    fabricated = _manual_envelope(
        "TRANSPORT_CLOSE", "TRANSPORT_CLOSING", target_candidates=1,
        device_opened=1, scan_a_started=1, scan_a_tck_emitted=591,
        scan_b_started=0, scan_b_tck_emitted=0, transport_closed=0,
        close_from_state="DEVICE_SELECTED")
    close_history &= not validate(fabricated)

    forbidden = ("shift_ir", "shift_dr", "generic_mpsse", "sign_remote",
                 "program_fpga", "jprogram", "jstart")
    no_generic_mutation_surface = not any(hasattr(transport, name) for name in forbidden)
    return {
        "candidate_count_boundaries": bool(candidate_boundaries),
        "permit_candidate_relationships": bool(permit_relationships),
        "device_open_state": bool(open_state),
        "partial_scan_boundaries": bool(scan_boundaries),
        "transport_close_history": bool(close_history),
        "no_generic_or_programming_surface": no_generic_mutation_surface,
    }


def _load_candidate_modules(candidate_host: Path):
    sys.path.insert(0, str(candidate_host))
    import phk2_fk0957_topology_live_cli as cli
    import phk2_fk0957_topology_transport as transport
    import phk2_fk0957_topology_discovery as topology
    if not callable(getattr(cli, "_bounded_envelope", None)):
        raise RuntimeError("candidate refusal validator is missing")
    return cli, transport, topology


def _run_focused_candidate_tests(candidate_host: Path) -> tuple[bool, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(candidate_host)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "-q",
         "test_phk2_fk0957_topology_live_cli",
         "test_phk2_fk0957_topology_transport"],
        cwd=candidate_host, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # Return bounded output only; exceptions are test data and stay local.
    return proc.returncode == 0, proc.stdout[-4000:]


def audit_candidate(repo: Path, candidate_sha: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-fA-F]{40}", candidate_sha):
        raise ValueError("candidate must be a full 40-character commit SHA")
    resolved = _run_git(repo, "rev-parse", "--verify", f"{candidate_sha}^{{commit}}").stdout.strip()
    if resolved.lower() != candidate_sha.lower():
        raise ValueError("candidate SHA did not resolve exactly")
    model = load_reference(repo)
    boundary_counts = model.count_boundary_space()
    if boundary_counts != (28, 249572):
        raise RuntimeError("pinned reference corpus has unexpected size")

    with tempfile.TemporaryDirectory(prefix="fk0957-audit-") as temp_dir:
        worktree = Path(temp_dir) / "candidate"
        _run_git(repo, "worktree", "add", "--detach", str(worktree), resolved)
        try:
            candidate_host = worktree / "tools" / "phk2_host"
            cli, transport, topology = _load_candidate_modules(candidate_host)
            corpus = compare_state_corpus(model, cli._bounded_envelope)
            targeted = targeted_checks(cli, transport)
            focused_pass, focused_output = _run_focused_candidate_tests(candidate_host)
            plan = topology.build_plan()
            transaction_ok = (
                (plan.scan_a_tck_count, plan.scan_b_tck_count, plan.tck_count) ==
                (591, 586, 1177) and
                topology.scan_transaction_sha256(plan.scan_a_commands) == EXPECTED_SCAN_A_SHA256 and
                topology.scan_transaction_sha256(plan.scan_b_commands) == EXPECTED_SCAN_B_SHA256)
            return {
                "candidate_commit": resolved,
                **corpus,
                "targeted_checks": targeted,
                "transaction_invariants": transaction_ok,
                "focused_tests_pass": focused_pass,
                "focused_test_output": focused_output,
            }
        finally:
            _run_git(repo, "worktree", "remove", "--force", str(worktree), check=False)


def self_test(repo: Path) -> dict[str, Any]:
    model_path = Path(__file__).with_name("fk0957_topology_state_model.py")
    tree = ast.parse(model_path.read_text())
    imports = {alias.name for node in ast.walk(tree)
               if isinstance(node, ast.Import) for alias in node.names}
    imports.update(node.module for node in ast.walk(tree)
                   if isinstance(node, ast.ImportFrom) and node.module)
    independent = not any(name.startswith(("phk2_fk0957_", "production."))
                          for name in imports)
    model = load_reference(repo)
    counts = model.count_boundary_space()
    return {
        "reference_model_commit": REFERENCE_MODEL_COMMIT,
        "reference_valid_states": counts[0],
        "reference_invalid_states": counts[1],
        "reference_model_independent": independent,
        "pass": counts == (28, 249572) and independent,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate_sha", nargs="?", help="full local candidate commit SHA")
    parser.add_argument("--self-test", action="store_true",
                        help="check the pinned oracle without loading a candidate")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[2]
    try:
        if args.self_test:
            result = self_test(repo)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["pass"] else 1
        if args.candidate_sha is None:
            parser.error("candidate_sha is required unless --self-test is used")
        result = audit_candidate(repo, args.candidate_sha)
    except Exception as exc:
        # Do not echo arbitrary exception text from candidate code.
        print(json.dumps({"audit_pass": False, "error_class": type(exc).__name__}, sort_keys=True))
        return 2
    result["audit_pass"] = (
        result["valid_state_rejected"] == 0 and
        result["invalid_state_accepted"] == 0 and
        all(result["targeted_checks"].values()) and
        result["transaction_invariants"] and result["focused_tests_pass"])
    print(json.dumps(result, sort_keys=True))
    return 0 if result["audit_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
