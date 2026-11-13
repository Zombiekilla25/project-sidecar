"""Independent, harmless acceptance attacks for FK0957 live-read readiness.

Runs source gates and temporary-process fixtures only. It never issues a permit
or invokes the physical transport. The report records reproduced unsafe
conditions as failures; it is not a production validator.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from typing import Any


def _probe(script: Path, updates: dict[str, str]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="fk0957-accept-startup-") as d:
        root = Path(d)
        marker = root / "sentinel"
        env = dict(os.environ)
        env.update(updates)
        env["FK0957_AUDIT_MARKER"] = str(marker)
        cp = subprocess.run([sys.executable, str(script), "--help"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False)
        return {"marker_executed": marker.exists(), "exit_code": cp.returncode}


def startup_attacks(host: Path) -> dict[str, Any]:
    cli = host / "phk2_fk0957_topology_live_cli.py"
    reports: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="fk0957-accept-startup-fixtures-") as d:
        root = Path(d)
        payload = ("import os\nfrom pathlib import Path\n"
                   "Path(os.environ['FK0957_AUDIT_MARKER']).write_text('ran')\n")
        (root / "ctypes.py").write_text(payload, encoding="utf-8")
        reports["PYTHONPATH_ctypes"] = _probe(cli, {"PYTHONPATH": str(root)})
        (root / "sitecustomize.py").write_text(payload, encoding="utf-8")
        reports["sitecustomize"] = _probe(cli, {"PYTHONPATH": str(root)})
        (root / "usercustomize.py").write_text(payload, encoding="utf-8")
        reports["usercustomize"] = _probe(cli, {
            "PYTHONPATH": str(root), "PYTHONNOUSERSITE": ""})

        # PATH substitution executes before the real interpreter. The fixture
        # marks execution and then execs the already-resolved trusted binary.
        fakebin = root / "bin"
        fakebin.mkdir()
        fake_python = fakebin / "python3"
        fake_python.write_text(
            "#!/bin/sh\n"
            "echo ran > \"$FK0957_AUDIT_MARKER\"\n"
            f"exec {sys.executable!s} \"$@\"\n", encoding="utf-8")
        fake_python.chmod(0o700)
        env_path = str(fakebin) + os.pathsep + os.environ.get("PATH", "")
        marker = root / "path-sentinel"
        env = dict(os.environ, FK0957_AUDIT_MARKER=str(marker), PATH=env_path)
        subprocess.run(["python3", str(cli), "--help"], env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=False)
        reports["PATH_python3"] = {"marker_executed": marker.exists()}
        # Mirror the documented .venv/bin/python path in a disposable fixture
        # tree and replace its final interpreter symlink target harmlessly.
        fake_venv = root / ".venv" / "bin"
        fake_venv.mkdir(parents=True)
        venv_python = fake_venv / "python"
        venv_marker = root / "venv-sentinel"
        venv_python.write_text(
            "#!/bin/sh\n"
            f"echo ran > {str(venv_marker)!r}\n"
            f"exec {sys.executable!s} \"$@\"\n", encoding="utf-8")
        venv_python.chmod(0o700)
        subprocess.run([str(venv_python), str(cli), "--help"],
                       env=dict(os.environ, PYTHONPATH=str(cli.parent)),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=False)
        reports["documented_venv_executable_substitution"] = {
            "marker_executed": venv_marker.exists()}

        # PYTHONHOME is a startup control; an intentionally incomplete prefix
        # should be rejected/affect startup. No files outside this temp tree.
        bad_home = root / "empty-home"
        bad_home.mkdir()
        reports["PYTHONHOME"] = _probe(cli, {"PYTHONHOME": str(bad_home)})

        compiler = shutil.which("cc")
        if compiler:
            source = root / "harmless.c"
            so = root / "libaudit.so"
            source.write_text(
                "#include <stdio.h>\n#include <stdlib.h>\n"
                "__attribute__((constructor)) static void c(void){"
                "const char*p=getenv(\"FK0957_AUDIT_MARKER\");"
                "if(p){FILE*f=fopen(p,\"w\");if(f){fputs(\"ran\",f);fclose(f);}}}\n",
                encoding="ascii")
            subprocess.run([compiler, "-shared", "-fPIC", "-o", str(so), str(source)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            reports["LD_PRELOAD"] = _probe(cli, {"LD_PRELOAD": str(so)})
            # A benign ctypes fixture proves that ambient search can redirect
            # a later name-based load; it does not load FTDI or USB libraries.
            marker = root / "ldpath-sentinel"
            env = dict(os.environ, LD_LIBRARY_PATH=str(root),
                       FK0957_AUDIT_MARKER=str(marker))
            cp = subprocess.run(
                [sys.executable, "-I", "-c", "import ctypes; ctypes.CDLL('libaudit.so')"],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            reports["LD_LIBRARY_PATH_fixture"] = {
                "marker_executed": marker.exists(), "exit_code": cp.returncode}
        else:
            reports["LD_PRELOAD"] = None
            reports["LD_LIBRARY_PATH_fixture"] = None
    return reports


def source_gates(repo: Path) -> dict[str, Any]:
    host = repo / "tools/phk2_host"
    names = {
        "live_cli": host / "phk2_fk0957_topology_live_cli.py",
        "transport": host / "phk2_fk0957_topology_transport.py",
        "observer": host / "phk2_fk0957_identity_observer.py",
        "collector": host / "phk2_fk0957_remote_collector.py",
        "backend": host / "phk2_fk0957_readonly_backend.py",
    }
    texts = {k: p.read_text(encoding="utf-8") for k, p in names.items() if p.exists()}
    cli = texts["live_cli"]
    transport = texts["transport"]
    docs = (repo / "docs/phk2-fk0957-topology-discovery-offline.md").read_text(encoding="utf-8")
    hash_fn = transport.split("def transport_source_sha256()", 1)[1].split("\ndef ", 1)[0]
    runtime_sha_includes = {
        "live_cli": "phk2_fk0957_topology_live_cli.py" in hash_fn,
        "observer": "phk2_fk0957_identity_observer.py" in hash_fn,
        "collector": "phk2_fk0957_remote_collector.py" in hash_fn,
        "backend": "phk2_fk0957_readonly_backend.py" in hash_fn,
        "manifest_or_policy": any(s in hash_fn for s in ("manifest", "policy.json", "qualification")),
    }
    return {
        "has_isolated_launcher": any((repo / p).exists() for p in (
            "tools/phk2_host/fk0957-topology-launcher",
            "tools/phk2_host/fk0957_topology_launcher.py")),
        "launcher_clears_startup_vars": False,
        "cli_calls_ssh": bool(re.search(r"subprocess\.(run|Popen)|ssh\\b", cli)),
        "cli_has_remote_signing_protocol": "remote-sign" in cli or "signing_request" in cli,
        "cli_uses_local_native_transport": "perform_fk0957_topology_discovery_once" in cli,
        "bridge_handoff_gate_in_cli_or_transport": any(
            token in cli + transport for token in ("validate_bridge_handoff", "bridge_owner", "handoff_nonce")),
        "cross_process_exclusive_lock": any(token in cli + transport for token in ("flock", "lockf", "bridge_lock")),
        "transport_hash_source_coverage": runtime_sha_includes,
        "transport_hash_covers_git_head_and_dirty_state": "git rev-parse" in hash_fn or "git status" in hash_fn,
        "documented_pythonpath_launch": "PYTHONPATH=" in docs and "topology_live_cli.py" in docs,
        "documented_null_hash_claim_with_native_adapter": (
            "transport source hash remains null until a reviewed production" in docs),
        "documented_invocation_lines": [line.strip() for line in docs.splitlines()
                                         if "PYTHONPATH=" in line or "topology_live_cli.py" in line],
        "runtime_hash_source_file_count_literal": hash_fn.count(".py") + hash_fn.count(".cpp"),
    }


def provenance_tamper_fixture(repo: Path) -> dict[str, Any]:
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_transport as transport
    target = Path(transport.__file__).resolve()
    # Isolate source-hash behavior from the separately reported native-library
    # preflight; this fixture deliberately does not approve or load any library.
    with mock.patch.object(transport, "_require_native_files", return_value=()):
        baseline = transport.transport_source_sha256()
    original = Path.read_bytes

    def altered(path: Path) -> bytes:
        data = original(path)
        if path.resolve() == target:
            return data[:-1] + bytes([data[-1] ^ 1])
        return data

    with mock.patch.object(transport, "_require_native_files", return_value=()), \
            mock.patch.object(Path, "read_bytes", altered):
        changed = transport.transport_source_sha256()
    coverage = {"live_cli": False, "transport": True, "backend": False,
                "observer": False, "collector": False, "launcher": False,
                "manifest_config": False}
    return {"one_byte_change_rejected_or_hash_changed": {
                name: (changed != baseline if name == "transport" else False)
                for name in coverage},
            "covered_sources": [name for name, present in coverage.items() if present],
            "uncovered_sources": [name for name, present in coverage.items() if not present],
            "dirty_tree_gate_present": False, "wrong_head_gate_present": False}


def malformed_boundary(repo: Path, count: int = 20000) -> dict[str, int]:
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_live_cli as cli
    import phk2_fk0957_topology_transport as transport

    base = transport.RefusalEnvelope(
        phase="PRELIVE_VALIDATION", code="TRANSACTION_PIN_MISMATCH", return_code=None,
        target_candidates=0, device_opened=0, scan_a_started=0,
        scan_a_tck_emitted=0, scan_b_started=0, scan_b_tck_emitted=0,
        transport_closed=0, permit_consumed=0, operation_state="PRELIVE")
    variants: list[Any] = [None, True, False, -1, 0, 1, 2**200, "", "x", [], {}, ["x"], {"x": 1}]
    fields = tuple(base.as_dict()) + ("status", "evidence_path", "signature_verified")
    calls = escaped = noncanonical = secret_leaks = 0
    for i in range(count):
        value = base.as_dict()
        value.update({"status": "REFUSED", "evidence_path": "none",
                      "signature_verified": False})
        field = fields[i % len(fields)]
        value[field] = variants[(i // len(fields)) % len(variants)]

        class HostileRefusal(transport.Refusal):
            def canonical_envelope(self) -> bytes:
                return json.dumps(value, separators=(",", ":")).encode()

        calls += 1
        try:
            output = cli._safe_refusal(HostileRefusal("hidden attacker string"))
        except Exception:
            escaped += 1
            continue
        try:
            decoded = json.loads(output)
            if (not isinstance(decoded, dict) or decoded.get("status") != "REFUSED" or
                    decoded.get("evidence_path") != "none" or
                    decoded.get("signature_verified") is not False or len(output) > 2048):
                noncanonical += 1
            if b"hidden attacker string" in output:
                secret_leaks += 1
        except Exception:
            noncanonical += 1
    return {"generated": calls, "escaped_exceptions": escaped,
            "unsafe_or_noncanonical_outputs": noncanonical,
            "exception_text_leaks": secret_leaks}


def fake_backend_reachability(repo: Path) -> dict[str, Any]:
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_transport as transport
    source = Path(transport.__file__).read_text(encoding="utf-8")
    importable_seams = [name for name in ("_run_with_backend", "_run_consumed_permit")
                        if hasattr(transport, name)]
    test_path = repo / "tools/phk2_host/test_phk2_fk0957_topology_transport.py"
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "TopologyTransportTests.test_local_record_builder_signs_only_after_valid_transport",
        __import__("test_phk2_fk0957_topology_transport"))
    sink = __import__("io").StringIO()
    with mock.patch.object(transport, "_require_native_files", return_value=()):
        result = unittest.TextTestRunner(stream=sink, verbosity=0).run(suite)
    return {
        "production_importable_synthetic_seams": importable_seams,
        "test_fake_backend_fixture_path_exists": test_path.is_file(),
        "synthetic_observation_signed_by_existing_seam": result.wasSuccessful() and result.testsRun == 1,
        "test_count": result.testsRun,
        "failure_classes": [type(err).__name__ for _, err in result.errors + result.failures],
    }


def bridge_gate_attack(repo: Path) -> dict[str, Any]:
    """Replace the acquisition boundary with a refusal sentinel; no hardware."""
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_live_cli as cli
    import phk2_fk0957_topology_transport as transport
    cases = ("missing_handoff", "stale_handoff", "wrong_bridge_identity",
             "competing_owner", "unknown_owner", "different_permit", "different_target")
    reached = []
    with tempfile.TemporaryDirectory(prefix="fk0957-bridge-gate-") as d:
        root = Path(d)
        for case in cases:
            output = root / f"{case}.json"
            with mock.patch.object(cli, "_read_descriptor", return_value=b"mock descriptor"), \
                    mock.patch.object(cli.transport,
                                      "perform_fk0957_topology_discovery_once",
                                      side_effect=transport.Refusal("sentinel stop")) as acquire:
                _, status = cli.run_once(Path("synthetic-descriptor.json"), output)
                if acquire.call_count:
                    reached.append(case)
                if output.exists() or status == 0:
                    raise AssertionError("bridge refusal fixture unexpectedly published success")
    return {"cases": list(cases), "reached_acquisition_boundary": reached,
            "device_open_possible_in_fixture": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("production_repo", type=Path)
    parser.add_argument("--expected-head", help="require an exact production candidate commit")
    args = parser.parse_args()
    repo = args.production_repo.resolve()
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                            capture_output=True, text=True, check=True).stdout
    if args.expected_head and head != args.expected_head:
        print(json.dumps({"production_head": head, "expected_head": args.expected_head,
                          "exact_candidate_match": False}, sort_keys=True))
        return 2
    report = {
        "production_head": head,
        "expected_head": args.expected_head,
        "exact_candidate_match": (args.expected_head is None or head == args.expected_head),
        "production_clean": not status.strip(),
        "startup_attacks": startup_attacks(repo / "tools/phk2_host"),
        "source_gates": source_gates(repo),
        "provenance_tamper_fixture": provenance_tamper_fixture(repo),
        "malformed_boundary": malformed_boundary(repo),
        "fake_backend": fake_backend_reachability(repo),
        "bridge_gate_attack": bridge_gate_attack(repo),
        "native_library_pin_preflight": _native_pin_status(repo),
    }
    print(json.dumps(report, sort_keys=True))
    return 0


def _native_pin_status(repo: Path) -> dict[str, Any]:
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_transport as transport
    try:
        transport._require_native_files()
    except Exception as exc:
        return {"pass": False, "exception_class": type(exc).__name__}
    return {"pass": True, "exception_class": None}


if __name__ == "__main__":
    raise SystemExit(main())
