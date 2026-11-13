"""Offline reproductions for FK0957 production startup/publish assumptions.

This script intentionally reports whether unsafe conditions can be reproduced;
it never enumerates devices, issues a permit, or invokes the acquisition path.
"""
from __future__ import annotations

import argparse
import itertools
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import inspect
import unittest
from unittest import mock
from typing import Any


def run_startup_probe(script: Path, env_updates: dict[str, str]) -> bool:
    with tempfile.TemporaryDirectory(prefix="fk0957-longrun-startup-") as temp:
        root = Path(temp)
        marker = root / "executed.marker"
        env = dict(os.environ)
        env.update(env_updates)
        env["FK0957_AUDIT_MARKER"] = str(marker)
        proc = subprocess.run(
            ["python3", str(script), "--help"], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        # Only the marker existence is returned; output and environment values
        # are deliberately not copied into the report.
        return marker.exists()


def pythonpath_ctypes_injection(script: Path) -> bool:
    with tempfile.TemporaryDirectory(prefix="fk0957-longrun-pythonpath-") as temp:
        root = Path(temp)
        (root / "ctypes.py").write_text(
            "import os\n"
            "from pathlib import Path\n"
            "Path(os.environ['FK0957_AUDIT_MARKER']).write_text('ran')\n",
            encoding="utf-8",
        )
        return run_startup_probe(script, {"PYTHONPATH": str(root)})


def sitecustomize_injection(script: Path) -> bool:
    with tempfile.TemporaryDirectory(prefix="fk0957-longrun-site-") as temp:
        root = Path(temp)
        (root / "sitecustomize.py").write_text(
            "import os\n"
            "from pathlib import Path\n"
            "Path(os.environ['FK0957_AUDIT_MARKER']).write_text('ran')\n",
            encoding="utf-8",
        )
        return run_startup_probe(script, {"PYTHONPATH": str(root)})


def ld_preload_injection(script: Path) -> bool | None:
    import shutil
    compiler = shutil.which("cc")
    if compiler is None:
        return None
    with tempfile.TemporaryDirectory(prefix="fk0957-longrun-ldpreload-") as temp:
        root = Path(temp)
        source = root / "audit.c"
        library = root / "audit.so"
        source.write_text(
            "#include <stdio.h>\n#include <stdlib.h>\n"
            "__attribute__((constructor)) static void audit_ctor(void) {\n"
            " const char *p = getenv(\"FK0957_AUDIT_MARKER\");\n"
            " if (p) { FILE *f = fopen(p, \"w\"); if (f) {"
            " fputs(\"ran\", f); fclose(f); } }\n}\n",
            encoding="ascii",
        )
        subprocess.run([compiler, "-shared", "-fPIC", "-o", str(library),
                        str(source)], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        return run_startup_probe(script, {"LD_PRELOAD": str(library)})


def publish_race(cli: Any) -> dict[str, bool]:
    original_replace = os.replace
    original_link = os.link
    publisher_source = inspect.getsource(cli._publish_evidence_atomic)
    uses_noreplace_link = "os.link(" in publisher_source
    with tempfile.TemporaryDirectory(prefix="fk0957-longrun-publish-") as temp:
        destination = Path(temp) / "evidence.json"
        injected = False

        def create_competing_destination(src, dst, *, src_dir_fd=None, dst_dir_fd=None,
                                         follow_symlinks=True):
            nonlocal injected
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                         dir_fd=dst_dir_fd)
            os.write(fd, b"COMPETING_WRITER")
            os.close(fd)
            injected = True
            if uses_noreplace_link:
                return original_link(src, dst, src_dir_fd=src_dir_fd,
                                     dst_dir_fd=dst_dir_fd,
                                     follow_symlinks=follow_symlinks)
            return original_replace(src, dst, src_dir_fd=src_dir_fd,
                                    dst_dir_fd=dst_dir_fd)

        if uses_noreplace_link:
            os.link = create_competing_destination
        else:
            os.replace = create_competing_destination
        refused = False
        try:
            cli._publish_evidence_atomic(destination, b"SIGNED_AUDIT_FIXTURE")
        except Exception:
            refused = True
        finally:
            os.replace = original_replace
            os.link = original_link
        final_bytes = destination.read_bytes()
        return {
            "race_injected": injected,
            "destination_exists": destination.exists(),
            "publish_refused": refused,
            "competing_file_preserved": final_bytes == b"COMPETING_WRITER",
            "competing_file_overwritten": final_bytes == b"SIGNED_AUDIT_FIXTURE",
        }


def parent_move_race(cli: Any, orchestrator: Any) -> dict[str, bool]:
    with tempfile.TemporaryDirectory(prefix="fk0957-longrun-parent-move-") as temp:
        root = Path(temp)
        parent = root / "requested-parent"
        moved = root / "moved-parent"
        replacement = root / "replacement-parent"
        parent.mkdir()
        replacement.mkdir()
        destination = parent / "record.json"
        original_open_parent = orchestrator._open_path_parent
        moved_once = False

        def move_after_open(path):
            nonlocal moved_once
            fd, name = original_open_parent(path)
            if not moved_once:
                os.rename(parent, moved)
                os.symlink(replacement, parent, target_is_directory=True)
                moved_once = True
            return fd, name

        orchestrator._open_path_parent = move_after_open
        refused = False
        try:
            try:
                cli._publish_evidence_atomic(destination, b"SIGNED_AUDIT_FIXTURE")
            except (OSError, ValueError):
                refused = True
        finally:
            orchestrator._open_path_parent = original_open_parent
        return {
            "race_injected": moved_once,
            "publish_refused": refused,
            "publish_reported_success": (moved / "record.json").exists() or
                                        (replacement / "record.json").exists(),
            "requested_path_resolves_to_evidence": destination.exists(),
            "replacement_path_written": (replacement / "record.json").exists(),
        }


def filesystem_path_attack_matrix(cli: Any, transport: Any) -> dict[str, bool]:
    outcomes: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="fk0957-path-matrix-") as temp:
        root = Path(temp)
        target = root / "sentinel"
        target.write_bytes(b"preserve")
        symlink = root / "output-symlink"
        symlink.symlink_to(target)
        try:
            cli._publish_evidence_atomic(symlink, b"new")
        except Exception:
            outcomes["output_symlink_refused"] = symlink.is_symlink() and target.read_bytes() == b"preserve"
        hardlink = root / "output-hardlink"
        os.link(target, hardlink)
        try:
            cli._publish_evidence_atomic(hardlink, b"new")
        except Exception:
            outcomes["output_hardlink_refused"] = hardlink.stat().st_ino == target.stat().st_ino
        real_parent = root / "real-parent"
        real_parent.mkdir()
        alias = root / "parent-alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        try:
            cli._publish_evidence_atomic(alias / "record.json", b"new")
        except OSError:
            outcomes["parent_symlink_refused"] = not (real_parent / "record.json").exists()

        collision = root / ".fk0957-evidence-fixed"
        collision.mkdir(mode=0o700)
        marker = collision / "marker"
        marker.write_bytes(b"preserve")
        with mock.patch.object(cli.secrets, "token_hex", return_value="fixed"):
            try:
                cli._publish_evidence_atomic(root / "collision.json", b"new")
            except FileExistsError:
                outcomes["temp_directory_collision_refused"] = marker.read_bytes() == b"preserve"

        key = root / "key.pem"
        key.write_bytes(b"not a real private key")
        key.chmod(0o600)
        key_link = root / "key-symlink"
        key_link.symlink_to(key)
        try:
            transport._read_local_private_key(key_link)
        except OSError:
            outcomes["signing_key_symlink_refused"] = True
        key_hardlink = root / "key-hardlink"
        os.link(key, key_hardlink)
        try:
            transport._read_local_private_key(key_hardlink)
        except Exception:
            outcomes["signing_key_hardlink_refused"] = True
        key_parent = root / "key-parent"
        key_parent.mkdir()
        nested_key = key_parent / "key.pem"
        nested_key.write_bytes(b"fake")
        nested_key.chmod(0o600)
        key_parent_alias = root / "key-parent-alias"
        key_parent_alias.symlink_to(key_parent, target_is_directory=True)
        try:
            transport._read_local_private_key(key_parent_alias / "key.pem")
        except OSError:
            outcomes["signing_key_parent_symlink_refused"] = True
    return outcomes


def fake_backend_signing_test(host: Path) -> dict[str, int]:
    import sys
    sys.path.insert(0, str(host))
    import test_phk2_fk0957_topology_transport as fixtures
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "TopologyTransportTests.test_local_record_builder_signs_only_after_valid_transport",
        fixtures)
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=0).run(suite)
    if not result.wasSuccessful():
        raise AssertionError("fake backend signing test did not complete cleanly")
    return {"tests_run": result.testsRun, "successes": result.testsRun}


def independent_transaction_audit(plan: Any) -> dict[str, Any]:
    """Re-decode MPSSE framing and manifest bytes without production helpers."""
    import hashlib

    def decode(commands):
        clocks = 0
        read_bytes = 0
        manifest = bytearray(b"FK0957-MPSSE-SCAN-MANIFEST-v1\0")
        for command in commands:
            raw = bytes(command.write)
            if not raw:
                raise AssertionError("empty MPSSE command")
            opcode = raw[0]
            if opcode in (0x4B, 0x6B):
                # MPSSE TMS commands encode TMS in bits 0..6 and the
                # simultaneous TDI value in bit 7. Validate only the
                # declared TMS clocks; bit 7 is a separate data signal.
                tms_clocks = raw[1] + 1 if len(raw) >= 2 else 0
                tms_mask = (1 << tms_clocks) - 1 if tms_clocks else 0
                if (len(raw) != 3 or raw[1] > 6 or
                        raw[2] & ~(tms_mask | 0x80)):
                    raise AssertionError("malformed TMS command")
                clocks += tms_clocks
            elif opcode == 0x39:
                if len(raw) < 4:
                    raise AssertionError("truncated byte-shift command")
                byte_count = int.from_bytes(raw[1:3], "little") + 1
                if len(raw) != 3 + byte_count:
                    raise AssertionError("byte-shift payload length mismatch")
                clocks += byte_count * 8
            else:
                raise AssertionError(f"unexpected scan opcode {opcode:02x}")
            read_bytes += command.read_bytes
            label = command.label.encode("ascii")
            scan = (command.scan or "").encode("ascii")
            manifest.extend(len(raw).to_bytes(4, "big"))
            manifest.extend(raw)
            manifest.extend(command.read_bytes.to_bytes(4, "big"))
            manifest.extend(command.tck_count.to_bytes(4, "big"))
            manifest.extend(len(label).to_bytes(2, "big"))
            manifest.extend(label)
            manifest.extend(len(scan).to_bytes(2, "big"))
            manifest.extend(scan)
        return clocks, read_bytes, hashlib.sha256(manifest).hexdigest()

    a_clocks, a_reads, a_hash = decode(plan.scan_a_commands)
    b_clocks, b_reads, b_hash = decode(plan.scan_b_commands)
    return {
        "scan_a_tck_count": a_clocks, "scan_b_tck_count": b_clocks,
        "total_tck_count": a_clocks + b_clocks,
        "scan_a_read_bytes": a_reads, "scan_b_read_bytes": b_reads,
        "scan_a_sha256": a_hash, "scan_b_sha256": b_hash,
        "matches_reviewed_golden": (
            a_clocks == 591 and b_clocks == 586 and a_clocks + b_clocks == 1177 and
            a_reads == 73 and b_reads == 73 and
            a_hash == "81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2" and
            b_hash == "08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a"),
    }


def malformed_type_campaign(validator: Any, safe_refusal: Any,
                           refusal_type: Any, seed: int = 0xF0957) -> dict[str, int]:
    import random
    rng = random.Random(seed)
    atoms = [None, True, False, -1, 0, 1, 591, 592, 586, 587, 10**100,
             "", "REFUSED", "UNKNOWN", [], {}, [1], {"x": 1}]
    fields = ["status", "phase", "code", "return_code", "target_candidates",
              "device_opened", "permit_consumed", "scan_a_started",
              "scan_a_tck_emitted", "scan_b_started", "scan_b_tck_emitted",
              "transport_closed", "operation_state", "close_from_state",
              "evidence_path", "signature_verified"]
    base = {
        "status": "REFUSED", "phase": "SCAN_A_WRITE", "code": "SCAN_A_WRITE_FAILED",
        "evidence_path": "none", "signature_verified": False, "return_code": None,
        "target_candidates": 1, "device_opened": 1, "scan_a_started": 1,
        "scan_a_tck_emitted": 169, "scan_b_started": 0, "scan_b_tck_emitted": 0,
        "transport_closed": 0, "permit_consumed": 1,
        "operation_state": "SCAN_A_BULK_WRITE", "close_from_state": None,
    }
    invalid_or_noncanonical = 0
    exceptions = 0
    safe_fallbacks = 0
    unsafe_fallbacks = 0
    for _ in range(10000):
        candidate = dict(base)
        key = rng.choice(fields)
        candidate[key] = rng.choice(atoms)
        raw = json.dumps(candidate).encode("utf-8")
        try:
            accepted = validator(candidate)
        except Exception:
            exceptions += 1
            accepted = False
        invalid_or_noncanonical += int(not accepted)
        if not accepted:
            refusal = refusal_type("untrusted exception text must not escape")
            refusal.canonical_envelope = lambda raw=raw: raw
            output = safe_refusal(refusal)
            try:
                safe = json.loads(output)
            except Exception:
                unsafe_fallbacks += 1
                continue
            if (safe.get("phase") == "INTERNAL_REFUSAL" and
                    safe.get("code") == "INTERNAL_REFUSAL" and
                    b"untrusted exception text" not in output and
                    b"UNKNOWN" not in output):
                safe_fallbacks += 1
            else:
                unsafe_fallbacks += 1
    return {"generated": 10000, "rejected_or_noncanonical": invalid_or_noncanonical,
            "validator_exceptions": exceptions, "safe_fallbacks": safe_fallbacks,
            "unsafe_fallbacks": unsafe_fallbacks}


def enumeration_permutation_campaign(host: Path) -> dict[str, int]:
    """Exercise the real sysfs/libusb selection logic through its fake backend."""
    import sys
    sys.path.insert(0, str(host))
    import test_phk2_fk0957_topology_transport as fixtures
    from phk2_fk0957_topology_discovery import Refusal, validate_candidates

    target = "153300000957"
    peers = ("153300000958", "153300000959", "153300000960", "153300000961")
    case = fixtures.TopologyTransportTests(
        "test_native_enumeration_filters_peer_serial_before_multiplicity")
    case.setUp()
    unique_selected = 0
    duplicates_refused = 0
    fake_open_calls = 0
    try:
        for serials in itertools.permutations((target,) + peers):
            peer_ports = {serial: 4 + index for index, serial in enumerate(peers)}
            ports = tuple((9, 3) if serial == target else (9, peer_ports[serial])
                          for serial in serials)
            permit = case.permit()
            _, native, rows = case.native_rows_for_serials(
                serials, ports=ports, permit=permit)
            selected = validate_candidates(permit, rows)
            expected_index = serials.index(target)
            if int(selected.handle_token) != 0x1234 + expected_index:
                raise AssertionError("enumeration order changed exact target selection")
            native.open_exact(selected)
            if native._ftdi.ftdi_usb_open_dev.call_count != 1:
                raise AssertionError("selected target was not the sole fake open")
            unique_selected += 1
            fake_open_calls += 1
        duplicate_values = (target, target, peers[0], peers[1], peers[2])
        for serials in itertools.permutations(duplicate_values):
            ports = tuple((9, 3 + index) for index in range(len(serials)))
            permit = case.permit()
            _, native, rows = case.native_rows_for_serials(
                serials, ports=ports, permit=permit)
            try:
                validate_candidates(permit, rows)
            except Refusal:
                duplicates_refused += 1
            else:
                raise AssertionError("duplicate exact target was selected")
            if native._ftdi.ftdi_usb_open_dev.call_count:
                raise AssertionError("duplicate exact target reached fake open")
    finally:
        case.doCleanups()
    return {"unique_target_permutations_selected": unique_selected,
            "duplicate_target_permutations_refused": duplicates_refused,
            "fake_open_calls": fake_open_calls}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.production_root.resolve()
    host = root / "tools" / "phk2_host"
    import sys
    sys.path.insert(0, str(host))
    import phk2_fk0957_topology_live_cli as cli
    import phk2_fk0957_topology_discovery as topology
    import phk2_fk0957_topology_transport as transport
    import phk2_fk0957_remote_orchestrator as orchestrator
    transport_source = (host / "phk2_fk0957_topology_transport.py").read_text(encoding="utf-8")
    cli_source = (host / "phk2_fk0957_topology_live_cli.py").read_text(encoding="utf-8")

    plan = topology.build_plan()
    malformed = transport.Refusal("must not leak")
    malformed.canonical_envelope = lambda: json.dumps({
        "status": "REFUSED", "phase": [], "code": "INTERNAL_REFUSAL",
        "evidence_path": "none", "signature_verified": False,
        "return_code": None, "target_candidates": 0, "device_opened": 0,
        "scan_a_started": 0, "scan_a_tck_emitted": 0, "scan_b_started": 0,
        "scan_b_tck_emitted": 0, "transport_closed": 0, "permit_consumed": 0,
        "operation_state": "PRELIVE", "close_from_state": None,
    }).encode()
    safe_fallback = json.loads(cli._safe_refusal(malformed))
    reports = {
        "pythonpath_ctypes_injection_reproduced": pythonpath_ctypes_injection(
            host / "phk2_fk0957_topology_live_cli.py"),
        "sitecustomize_injection_reproduced": sitecustomize_injection(
            host / "phk2_fk0957_topology_live_cli.py"),
        "ld_preload_constructor_reproduced": ld_preload_injection(
            host / "phk2_fk0957_topology_live_cli.py"),
        "publish_race": publish_race(cli),
        "parent_move_race": parent_move_race(cli, orchestrator),
        "filesystem_path_attacks": filesystem_path_attack_matrix(cli, transport),
        "fake_backend_signing_test": fake_backend_signing_test(host),
        "malformed_type_campaign": malformed_type_campaign(
            cli._bounded_envelope, cli._safe_refusal, transport.Refusal),
        "malformed_internal_refusal_falls_back_safely": (
            safe_fallback.get("phase") == "INTERNAL_REFUSAL" and
            safe_fallback.get("code") == "INTERNAL_REFUSAL"),
        "enumeration_permutations": enumeration_permutation_campaign(host),
        "caller_supplied_backend_seam_present": (
            callable(getattr(transport, "_run_with_backend", None)) and
            tuple(inspect.signature(transport._run_with_backend).parameters) ==
            ("permit", "backend")),
        "cli_calls_only_reviewed_transport_entry": (
            "perform_fk0957_topology_discovery_once" in cli_source and
            "_run_with_backend" not in cli_source),
        "transport_hash_omits_cli_source": (
            "phk2_fk0957_topology_live_cli.py" not in transport_source and
            "Path(__file__).resolve()" in transport_source),
        "transactions": independent_transaction_audit(plan),
    }
    print(json.dumps(reports, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
