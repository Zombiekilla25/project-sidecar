#!/usr/bin/env python3
"""Offline verifier for the final two PHK2 TCK qualification cases.

This tool consumes evidence only. It has no transport or hardware operations.
Case IDs and their pass criteria must be supplied by the independently
qualified manifest, so the tool cannot make up or silently rename matrix rows.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import tempfile
from typing import Any

from physical_tck_preflight import PINNED_REVIEWED_BRIDGE_SHA256, PINNED_REVIEWED_BUILD_ID, Refusal

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: str | Path, label: str) -> tuple[Path, dict[str, Any]]:
    try:
        file = Path(path).resolve(strict=True)
    except OSError as exc:
        raise Refusal(f"{label} is unavailable: {exc}") from exc
    if not file.is_file():
        raise Refusal(f"{label} is not a file")
    try:
        value = json.loads(file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise Refusal(f"{label} is unreadable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise Refusal(f"{label} must be a JSON object")
    return file, value


def package_file(root: Path, ref: Any, label: str) -> tuple[Path, str]:
    if not isinstance(ref, dict):
        raise Refusal(f"{label} evidence reference missing")
    relative, expected = ref.get("path"), ref.get("sha256")
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise Refusal(f"{label} path must be relative to its evidence package")
    if not isinstance(expected, str) or not HEX64.fullmatch(expected):
        raise Refusal(f"{label} SHA256 invalid")
    path = root / relative
    cursor = root
    for part in Path(relative).parts:
        if part in ("", ".", ".."):
            raise Refusal(f"{label} path traversal refused")
        cursor /= part
        if cursor.is_symlink():
            raise Refusal(f"{label} symlink traversal refused")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise Refusal(f"{label} escapes evidence package") from exc
    if not resolved.is_file():
        raise Refusal(f"{label} is not a regular file")
    actual = sha256(resolved)
    if actual != expected:
        raise Refusal(f"{label} hash mismatch")
    return resolved, actual


def validate_manifest(path: str | Path) -> tuple[Path, dict[str, Any]]:
    manifest_path, manifest = read_json(path, "qualification manifest")
    if manifest.get("schema") != "PHK2-TCK-CLOSURE-MANIFEST-v1":
        raise Refusal("qualification manifest lacks PHK2-TCK-CLOSURE-MANIFEST-v1 closure attestation")
    if manifest.get("synthetic_fixture") is not False:
        raise Refusal("synthetic/mock manifest cannot qualify production")
    independent = manifest.get("independent_qualification")
    if not isinstance(independent, dict) or manifest.get("TCK_INDEPENDENT_PASS") != 38 or manifest.get("TCK_INDEPENDENT_FAIL") != 0:
        raise Refusal("independent qualification must report exactly 38 pass and 0 fail")
    if independent.get("result") != "PASS":
        raise Refusal("independent qualification status is not PASS")
    part = manifest.get("TARGET_PART")
    if not isinstance(part, str) or not part:
        raise Refusal("TARGET_PART missing")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise Refusal("routed/image artifact identity missing")
    root = manifest_path.parent
    for field in ("routed_dcp", "image"):
        _, actual = package_file(root, artifacts.get(field), field)
        declared = manifest.get("ROUTED_DCP_HASH" if field == "routed_dcp" else "IMAGE_HASH")
        if declared != actual:
            raise Refusal(f"{field} manifest identity/hash mismatch")
    route = manifest.get("route_qualification")
    if not isinstance(route, dict) or route.get("status") != "QUALIFIED":
        raise Refusal("routed artifact is not qualified")
    envelope = manifest.get("TCK_ANALYSIS_ENVELOPE")
    if not isinstance(envelope, dict) or envelope.get("qualified") is not True:
        raise Refusal("qualified routed TCK analysis envelope missing")
    for key in ("minimum_tck_hz", "maximum_tck_hz", "minimum_high_ns", "minimum_low_ns",
                "minimum_duty_cycle_percent", "maximum_duty_cycle_percent",
                "maximum_period_jitter_p2p_ns", "maximum_period_jitter_rms_ns"):
        value = envelope.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise Refusal(f"TCK envelope {key} missing or invalid")
    matrix = manifest.get("qualification_matrix")
    if not isinstance(matrix, dict) or matrix.get("status") != "AUTHENTICATED":
        raise Refusal("authenticated qualification matrix reference missing")
    package_file(root, matrix.get("source"), "qualification matrix source")
    cases = manifest.get("tck_dependent_cases")
    if not isinstance(cases, list) or len(cases) != 2:
        raise Refusal("manifest must identify exactly two remaining TCK-dependent cases")
    kinds = {c.get("kind") for c in cases if isinstance(c, dict)}
    if kinds != {"PHYSICAL_TCK_WAVEFORM", "BSCAN_CLOCK_INTERACTION"}:
        raise Refusal("matrix must identify one physical TCK case and one BSCAN clock-interaction case")
    ids = [c.get("case_id") for c in cases]
    if any(not isinstance(i, str) or not i.strip() for i in ids) or len(set(ids)) != 2:
        raise Refusal("two distinct source case IDs are required")
    for case in cases:
        for field in ("purpose", "required_inputs", "required_measurement", "pass_criteria", "fail_criteria", "evidence_output"):
            value = case.get(field)
            if isinstance(value, str):
                valid = bool(value.strip())
            else:
                valid = isinstance(value, list) and bool(value) and all(isinstance(item, str) and item.strip() for item in value)
            if not valid:
                raise Refusal(f"case {case.get('case_id')} lacks source-derived {field}")
    return manifest_path, manifest


def _fresh(value: Any, label: str) -> None:
    if not isinstance(value, str):
        raise Refusal(f"{label} timestamp missing")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Refusal(f"{label} timestamp invalid") from exc
    if stamp.tzinfo is None or (datetime.now(timezone.utc) - stamp).total_seconds() > 86400 or stamp > datetime.now(timezone.utc):
        raise Refusal(f"{label} is stale or future-dated")


def _hash_chain_entries(entries: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Hash-link ordered event payload digests for the append-only evidence journal."""
    journal: list[dict[str, Any]] = []
    previous = "0" * 64
    for sequence, (event, payload_hash) in enumerate(entries):
        if not isinstance(event, str) or not event or not HEX64.fullmatch(payload_hash):
            raise Refusal("evidence journal event/hash is malformed")
        entry = {"sequence": sequence, "event": event, "payload_sha256": payload_hash,
                 "previous_entry_sha256": previous}
        encoded = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        entry["entry_sha256"] = hashlib.sha256(encoded).hexdigest()
        previous = entry["entry_sha256"]
        journal.append(entry)
    return journal


def _verify_bridge(path: str | Path, part: str) -> dict[str, Any]:
    bp, bridge = read_json(path, "bridge attestation")
    if bridge.get("BRIDGE_SHA256") != PINNED_REVIEWED_BRIDGE_SHA256 or bridge.get("BUILD_ID") != PINNED_REVIEWED_BUILD_ID:
        raise Refusal("bridge ELF differs from statically reviewed SQRL/XVC binary")
    if bridge.get("TARGET_PART") != part:
        raise Refusal("bridge target part mismatch")
    if bridge.get("verified") is not True:
        raise Refusal("bridge identity is not verified")
    _fresh(bridge.get("verified_utc"), "bridge attestation")
    return {"path": str(bp), "sha256": sha256(bp), **bridge}


def _verify_authorization(path: str | Path, manifest: dict[str, Any]) -> dict[str, Any]:
    ap, auth = read_json(path, "authorization")
    if auth.get("status") != "AUTHORIZED" or auth.get("signature_verified") is not True:
        raise Refusal("explicit independently verified authorization missing")
    if auth.get("one_card_scope") is not True or auth.get("target_part") != manifest["TARGET_PART"]:
        raise Refusal("authorization is not bound to one card and exact target part")
    if auth.get("routed_dcp_hash") != manifest["ROUTED_DCP_HASH"] or auth.get("image_hash") != manifest["IMAGE_HASH"]:
        raise Refusal("authorization route/image identity mismatch")
    if auth.get("peer_exclusion") != "PASS" or auth.get("workload_preservation") != "PASS" or auth.get("rollback_readiness") != "PASS":
        raise Refusal("peer exclusion, workload preservation, and rollback readiness are mandatory")
    _fresh(auth.get("issued_utc"), "authorization")
    try:
        expiry = datetime.fromisoformat(auth["expires_utc"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError) as exc:
        raise Refusal("authorization expiry missing/invalid") from exc
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise Refusal("authorization expired")
    return {"path": str(ap), "sha256": sha256(ap), **auth}


def _measurement_in_envelope(measurement: dict[str, Any], envelope: dict[str, Any]) -> None:
    fields = ("MEASURED_TCK_HZ", "MEASURED_PERIOD_NS", "MEASURED_HIGH_NS", "MEASURED_LOW_NS",
              "MEASURED_DUTY_CYCLE", "JITTER_MIN_NS", "JITTER_MAX_NS",
              "MEASURED_JITTER_P2P_NS", "MEASURED_JITTER_RMS_NS")
    for key in fields:
        value = measurement.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise Refusal(f"waveform evidence missing {key}")
    expected_period = 1_000_000_000 / measurement["MEASURED_TCK_HZ"] if measurement["MEASURED_TCK_HZ"] > 0 else math.inf
    if not math.isclose(measurement["MEASURED_PERIOD_NS"], expected_period, rel_tol=0.02):
        raise Refusal("measured period does not correspond to measured TCK")
    if not math.isclose(measurement["MEASURED_HIGH_NS"] + measurement["MEASURED_LOW_NS"],
                        measurement["MEASURED_PERIOD_NS"], rel_tol=0.02):
        raise Refusal("measured high/low widths do not sum to the measured period")
    calculated_duty = 100 * measurement["MEASURED_HIGH_NS"] / measurement["MEASURED_PERIOD_NS"]
    if not math.isclose(measurement["MEASURED_DUTY_CYCLE"], calculated_duty, abs_tol=1.0):
        raise Refusal("measured duty cycle does not match measured pulse widths")
    if measurement["JITTER_MIN_NS"] > measurement["JITTER_MAX_NS"]:
        raise Refusal("measured jitter min/max are inverted")
    if not math.isclose(measurement["JITTER_MAX_NS"] - measurement["JITTER_MIN_NS"],
                        measurement["MEASURED_JITTER_P2P_NS"], rel_tol=0.05, abs_tol=0.01):
        raise Refusal("measured jitter min/max do not match peak-to-peak jitter")
    if not envelope["minimum_tck_hz"] <= measurement["MEASURED_TCK_HZ"] <= envelope["maximum_tck_hz"]:
        raise Refusal("measured TCK outside qualified envelope")
    if measurement["MEASURED_HIGH_NS"] < envelope["minimum_high_ns"] or measurement["MEASURED_LOW_NS"] < envelope["minimum_low_ns"]:
        raise Refusal("measured high/low pulse width outside qualified envelope")
    if not envelope["minimum_duty_cycle_percent"] <= measurement["MEASURED_DUTY_CYCLE"] <= envelope["maximum_duty_cycle_percent"]:
        raise Refusal("measured duty cycle outside qualified envelope")
    if measurement["MEASURED_JITTER_P2P_NS"] > envelope["maximum_period_jitter_p2p_ns"] or measurement["MEASURED_JITTER_RMS_NS"] > envelope["maximum_period_jitter_rms_ns"]:
        raise Refusal("measured jitter outside qualified envelope")


def validate_evidence(path: str | Path, manifest: dict[str, Any], bridge: dict[str, Any], auth: dict[str, Any]) -> dict[str, Any]:
    ep, evidence = read_json(path, "physical evidence")
    if evidence.get("schema") != "PHK2-TCK-CLOSURE-EVIDENCE-v1":
        raise Refusal("physical evidence schema missing")
    if evidence.get("evidence_class") != "PHYSICAL_REAL" or evidence.get("synthetic_fixture") is not False or evidence.get("production_evidence") is not True:
        raise Refusal("mock/synthetic evidence cannot promote production")
    _fresh(evidence.get("captured_utc"), "physical evidence")
    if evidence.get("manifest_sha256") != sha256(Path(manifest["_path"])):
        raise Refusal("evidence manifest binding mismatch")
    if evidence.get("routed_dcp_hash") != manifest["ROUTED_DCP_HASH"] or evidence.get("image_hash") != manifest["IMAGE_HASH"]:
        raise Refusal("physical evidence route/image identity mismatch")
    if evidence.get("bridge_sha256") != bridge["BRIDGE_SHA256"] or evidence.get("authorization_sha256") != auth["sha256"]:
        raise Refusal("physical evidence bridge/authorization identity mismatch")
    if evidence.get("peer_exclusion") != "PASS" or evidence.get("one_card_scope") is not True or evidence.get("workload_unchanged") is not True:
        raise Refusal("physical run lacks peer/one-card/workload preservation proof")
    env = manifest["TCK_ANALYSIS_ENVELOPE"]
    wave = evidence.get("case_a")
    if not isinstance(wave, dict) or wave.get("status") != "PASS":
        raise Refusal("physical TCK waveform case incomplete")
    waveform_case_id = next(c["case_id"] for c in manifest["tck_dependent_cases"] if c["kind"] == "PHYSICAL_TCK_WAVEFORM")
    if wave.get("case_id") != waveform_case_id:
        raise Refusal("waveform evidence case ID differs from authenticated matrix")
    _measurement_in_envelope(wave, env)
    package_root = ep.parent
    package_file(package_root, wave.get("raw_waveform"), "raw waveform")
    for key in ("preflight", "adapter_identity", "peer_exclusion_proof"):
        package_file(package_root, evidence.get(key), key)
    tap = evidence.get("case_b")
    if not isinstance(tap, dict) or tap.get("status") != "PASS":
        raise Refusal("BSCAN clock-interaction case incomplete")
    bscan_case_id = next(c["case_id"] for c in manifest["tck_dependent_cases"] if c["kind"] == "BSCAN_CLOCK_INTERACTION")
    if tap.get("case_id") != bscan_case_id:
        raise Refusal("BSCAN evidence case ID differs from authenticated matrix")
    for key in ("before_state", "after_state"):
        if tap.get(key) != "IDLE_CONFIRMED":
            raise Refusal("TAP before/after idle state evidence missing")
    if tap.get("fpga_programming") is not False or tap.get("workload_changed") is not False:
        raise Refusal("BSCAN evidence reports prohibited programming/workload change")
    if tap.get("unexpected_tap_response") is not False:
        raise Refusal("unexpected TAP response; physical evidence cannot pass")
    if tap.get("unexpected_user_instruction") is not False:
        raise Refusal("unexpected USER instruction; physical evidence cannot pass")
    if tap.get("contains_user_instruction") is True:
        user_case = next(c for c in manifest["tck_dependent_cases"] if c["kind"] == "BSCAN_CLOCK_INTERACTION")
        if (auth.get("user_instruction_authorized") is not True or
                user_case["case_id"] not in auth.get("authorized_user_instruction_case_ids", [])):
            raise Refusal("USER instruction requires separate case-bound authorization")
    elif tap.get("contains_user_instruction") is not False:
        raise Refusal("BSCAN evidence must state whether a USER instruction was used")
    if tap.get("tap_cycles", 0) <= 0 or tap.get("tap_cycles", 0) > 256:
        raise Refusal("BSCAN/TAP evidence is missing or exceeds bounded activity")
    if tap.get("settck_used_as_measurement") is not False:
        raise Refusal("XVC settck echo cannot serve as effective TCK proof")
    package_file(package_root, tap.get("transcript"), "TAP transcript")
    package_file(package_root, tap.get("physical_clock_correlation"), "BSCAN clock correlation")
    close = evidence.get("close")
    if not isinstance(close, dict) or close.get("transport_closed") is not True or close.get("tap_idle") is not True or close.get("peer_count_after") != 0:
        raise Refusal("post-test close/idle evidence incomplete")
    if evidence.get("final_case_statuses") != {c["case_id"]: "PASS" for c in manifest["tck_dependent_cases"]}:
        raise Refusal("both exact matrix cases must pass; partial completion refused")
    return {"path": str(ep), "sha256": sha256(ep), **evidence}


def promote(manifest_path: str | Path, bridge_path: str | Path, authorization_path: str | Path,
            evidence_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    mp, manifest = validate_manifest(manifest_path)
    manifest["_path"] = str(mp)
    bridge = _verify_bridge(bridge_path, manifest["TARGET_PART"])
    auth = _verify_authorization(authorization_path, manifest)
    evidence = validate_evidence(evidence_path, manifest, bridge, auth)
    out = Path(output_dir)
    if out.exists():
        raise Refusal("promotion output already exists; evidence output is append-only")
    out.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-", dir=out.parent))
    try:
        evidence_doc = json.loads(Path(evidence_path).read_text())
        ev_root = Path(evidence_path).resolve().parent
        references = [
            ("preflight", evidence_doc.get("preflight")),
            ("bridge_identity", {"path": str(Path(bridge_path).resolve()), "sha256": bridge["sha256"]}),
            ("card_identity", evidence_doc.get("adapter_identity")),
            ("qualification_manifest", {"path": str(mp), "sha256": sha256(mp)}),
            ("authorization_state", {"path": str(Path(authorization_path).resolve()), "sha256": auth["sha256"]}),
            ("peer_exclusion", evidence_doc.get("peer_exclusion_proof")),
            ("tck_waveform", evidence_doc["case_a"].get("raw_waveform")),
            ("tap_sequence", evidence_doc["case_b"].get("transcript")),
            ("case_a_result", {"case_id": evidence_doc["case_a"]["case_id"], "status": evidence_doc["case_a"]["status"]}),
            ("case_b_result", {"case_id": evidence_doc["case_b"]["case_id"], "status": evidence_doc["case_b"]["status"]}),
            ("final_idle_close", evidence_doc.get("close")),
        ]
        journal_events = []
        for event, payload in references:
            if isinstance(payload, dict) and "path" in payload and "sha256" in payload:
                if event in {"preflight", "card_identity", "peer_exclusion", "tck_waveform", "tap_sequence"}:
                    _, payload_hash = package_file(ev_root, payload, f"journal {event}")
                else:
                    file = Path(payload["path"]).resolve(strict=True)
                    payload_hash = sha256(file)
                    if payload_hash != payload["sha256"]:
                        raise Refusal(f"journal {event} hash mismatch")
            else:
                payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            journal_events.append((event, payload_hash))
        journal = _hash_chain_entries(journal_events)
        journal_path = staging / "evidence-journal.jsonl"
        with journal_path.open("x", encoding="utf-8") as stream:
            for entry in journal:
                stream.write(json.dumps(entry, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

        record = {
            "schema": "PHK2-TCK-PHYSICAL-PROMOTION-v1",
            "PHYSICAL_PROTOCOL_QUALIFIED": True,
            "TCK_CASE_A_PASS": True,
            "TCK_CASE_B_PASS": True,
            "QUALIFICATION_CASES": 40,
            "QUALIFICATION_CASES_PASS": 40,
            "QUALIFICATION_CASES_FAIL": 0,
            "PHYSICAL_HOST_TCK_CONTRACT_PROVEN": True,
            "TCK_INDEPENDENT_PASS": 40,
            "TCK_INDEPENDENT_FAIL": 0,
            "source_independent_pass": 38,
            "source_independent_fail": 0,
            "case_results": {c["case_id"]: "PASS" for c in manifest["tck_dependent_cases"]},
            "qualification_manifest_sha256": sha256(mp), "bridge_attestation_sha256": bridge["sha256"],
            "authorization_sha256": auth["sha256"], "physical_evidence_sha256": evidence["sha256"],
            "evidence_journal_sha256": sha256(journal_path),
            "created_utc": datetime.now(timezone.utc).isoformat(), "evidence_provenance": "PHYSICAL_REAL",
        }
        bundle = staging / "physical-evidence.tar"
        with tarfile.open(bundle, "w") as archive:
            archive.add(mp, arcname="qualification_package/qualification-manifest.json")
            for name in ("routed_dcp", "image"):
                artifact, _ = package_file(mp.parent, manifest["artifacts"][name], name)
                archive.add(artifact, arcname=f"qualification_package/{manifest['artifacts'][name]['path']}")
            matrix_file, _ = package_file(mp.parent, manifest["qualification_matrix"]["source"], "qualification matrix source")
            archive.add(matrix_file, arcname="qualification_package/qualification-matrix-source")
            archive.add(Path(bridge_path), arcname="bridge-attestation.json")
            archive.add(Path(authorization_path), arcname="authorization.json")
            archive.add(Path(evidence_path), arcname="physical_capture/physical-evidence.json")
            archive.add(journal_path, arcname="physical_capture/evidence-journal.jsonl")
            refs = [evidence_doc.get("preflight"), evidence_doc.get("adapter_identity"), evidence_doc.get("peer_exclusion_proof"),
                    evidence_doc["case_a"].get("raw_waveform"), evidence_doc["case_b"].get("transcript"),
                    evidence_doc["case_b"].get("physical_clock_correlation")]
            for ref in refs:
                file, _ = package_file(ev_root, ref, "bundled physical evidence")
                archive.add(file, arcname="physical_capture/" + file.relative_to(ev_root).as_posix())
        record["bundle_path"] = str(out / "physical-evidence.tar")
        record["bundle_sha256"] = sha256(bundle)
        (staging / "promotion.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
        with (staging / "promotion.json").open("rb") as stream:
            os.fsync(stream.fileno())
        staging_fd = os.open(staging, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)
        os.rename(staging, out)
        parent_fd = os.open(out.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return record
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification-manifest", required=True)
    parser.add_argument("--bridge-attestation", required=True)
    parser.add_argument("--authorization", required=True)
    parser.add_argument("--evidence", required=True, help="completed physical evidence JSON; this program does not capture it")
    parser.add_argument("--output-dir", required=True, help="new append-only promotion directory")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(promote(args.qualification_manifest, args.bridge_attestation, args.authorization,
                                 args.evidence, args.output_dir), indent=2))
    except (Refusal, OSError, ValueError, KeyError, tarfile.TarError) as exc:
        print(json.dumps({"PHYSICAL_PROTOCOL_QUALIFIED": False, "refusal": str(exc),
                          "LIVE_EXECUTION_AUTHORIZED": False}), file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
