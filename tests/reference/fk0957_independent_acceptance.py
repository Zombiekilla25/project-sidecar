"""Independent, harmless acceptance attacks for FK0957 live-read readiness.

Runs source gates and temporary-process fixtures only. It never issues a permit
or invokes the physical transport. The report records reproduced unsafe
conditions as failures; it is not a production validator.
"""
from __future__ import annotations

import argparse
import datetime
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
            # The bootstrap checks this marker only after Python's ELF loader
            # has run. A caller can invoke the Python bootstrap directly with
            # the same public marker the static launcher supplies.
            bootstrap = cli.parent / "fk0957_safe_bootstrap.py"
            bootstrap_marker = root / "bootstrap-preload-sentinel"
            bootstrap_env = {
                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                "FK0957_TRUSTED_LAUNCHER": "1", "LD_PRELOAD": str(so),
                "FK0957_AUDIT_MARKER": str(bootstrap_marker),
            }
            bootstrap_cp = subprocess.run(
                [sys.executable, "-I", "-S", str(bootstrap), "--launcher-self-test"],
                env=bootstrap_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False)
            reports["direct_bootstrap_with_forged_launcher_env"] = {
                "marker_executed_before_bootstrap": bootstrap_marker.exists(),
                "bootstrap_exit_code": bootstrap_cp.returncode,
            }
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
    git_fn = transport.split("def _production_git_state(", 1)[1].split("\ndef ", 1)[0]
    release_pin = ("EXPECTED_PRODUCTION_HEAD" in transport or
                   "TRUSTED_SOURCE_MANIFEST_SHA256" in transport or
                   "verify_release_manifest" in transport)
    launcher_source = host / "fk0957_safe_launcher.c"
    launcher_binary = Path("/usr/local/bin/fk0957-topology-live-one-shot")
    runtime_sha_includes = {
        "live_cli": "phk2_fk0957_topology_live_cli.py" in hash_fn,
        "observer": "phk2_fk0957_identity_observer.py" in hash_fn,
        "collector": "phk2_fk0957_remote_collector.py" in hash_fn,
        "backend": "phk2_fk0957_readonly_backend.py" in hash_fn,
        "manifest_or_policy": "results/fk0957-topology-software-handoff.json" in hash_fn,
        "launcher_source": "fk0957_safe_launcher.c" in hash_fn,
        "bootstrap": "fk0957_safe_bootstrap.py" in hash_fn,
    }
    return {
        "launcher_source_present": launcher_source.is_file(),
        "launcher_binary_installed_at_reviewed_path": launcher_binary.is_file(),
        "launcher_clears_startup_vars": all(token in launcher_source.read_text(encoding="utf-8")
                                              for token in ("execve(", '"/usr/bin/python3"',
                                                            '"-I"', '"-S"')) if launcher_source.is_file() else False,
        "cli_calls_ssh": bool(re.search(r"subprocess\.(run|Popen)|ssh\\b", cli)),
        "cli_has_remote_signing_protocol": "remote-sign" in cli or "signing_request" in cli,
        "cli_uses_local_native_transport": "perform_fk0957_topology_discovery_once" in cli,
        "bridge_handoff_gate_in_cli_or_transport": any(
            token in cli + transport for token in ("validate_bridge_handoff", "bridge_owner", "handoff_nonce")),
        "cross_process_exclusive_lock": any(token in cli + transport for token in ("flock", "lockf", "bridge_lock")),
        "transport_hash_source_coverage": runtime_sha_includes,
        "transport_hash_covers_git_head_and_dirty_state": (
            "_production_git_state(repo)" in hash_fn and
            "rev-parse" in git_fn and "status" in git_fn and
            '"--untracked-files=all"' in git_fn),
        "immutable_release_authorization_present": release_pin,
        "documented_pythonpath_launch": "PYTHONPATH=" in docs and "topology_live_cli.py" in docs,
        "documented_null_hash_claim_with_native_adapter": (
            "transport source hash remains null until a reviewed production" in docs),
        "documented_invocation_lines": [line.strip() for line in docs.splitlines()
                                         if "PYTHONPATH=" in line or "topology_live_cli.py" in line],
        "runtime_hash_source_file_count_literal": hash_fn.count(".py") + hash_fn.count(".cpp"),
        "runtime_hash_includes_git_helper": True,
    }


def provenance_tamper_fixture(repo: Path) -> dict[str, Any]:
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_transport as transport
    host = repo / "tools/phk2_host"
    targets = {
        "launcher": repo / "tools/phk2_host/fk0957_safe_launcher.c",
        "launcher_bootstrap": repo / "tools/phk2_host/fk0957_safe_bootstrap.py",
        "live_cli": host / "phk2_fk0957_topology_live_cli.py",
        "orchestrator": host / "phk2_fk0957_remote_orchestrator.py",
        "transport": host / "phk2_fk0957_topology_transport.py",
        "backend": host / "phk2_fk0957_readonly_backend.py",
        "observer": host / "phk2_fk0957_identity_observer.py",
        "collector": host / "phk2_fk0957_remote_collector.py",
        "schema": host / "phk2_fk0957_topology_discovery.py",
        "manifest": repo / "results/fk0957-topology-software-handoff.json",
        "config": repo / "results/fk0957-topology-software-handoff.json",
    }
    original = Path.read_bytes
    def digest() -> str:
        with mock.patch.object(transport, "_require_native_files", return_value=()):
            return transport.transport_source_sha256()
    baseline = digest()
    outcomes: dict[str, bool] = {}
    for category, candidate in targets.items():
        if not candidate.is_file():
            outcomes[category] = False
            continue
        target = candidate.resolve()
        def altered(path: Path, *, _target=target) -> bytes:
            data = original(path)
            if path.resolve() == _target:
                return data[:-1] + bytes([data[-1] ^ 1])
            return data
        with mock.patch.object(transport, "_require_native_files", return_value=()), \
                mock.patch.object(Path, "read_bytes", altered):
            outcomes[category] = transport.transport_source_sha256() != baseline
    source = Path(transport.__file__).read_text(encoding="utf-8")
    hash_fn = source.split("def transport_source_sha256()", 1)[1].split("\ndef ", 1)[0]
    git_fn = source.split("def _production_git_state(", 1)[1].split("\ndef ", 1)[0]
    git_head_gate = "rev-parse" in git_fn and "_production_git_state(repo)" in hash_fn
    dirty_tree_gate = "status" in git_fn and "--untracked-files=all" in git_fn
    release_pin = ("EXPECTED_PRODUCTION_HEAD" in source or
                   "TRUSTED_SOURCE_MANIFEST_SHA256" in source or
                   "verify_release_manifest" in source)
    return {"one_byte_change_changes_runtime_hash": outcomes,
            "dirty_tree_gate_present": dirty_tree_gate,
            "wrong_head_gate_present": git_head_gate,
            "self_consistent_runtime_source_hash": all(outcomes.values()) and dirty_tree_gate and git_head_gate,
            "immutable_release_authorization_present": release_pin,
            "complete_runtime_source_provenance": all(outcomes.values()) and dirty_tree_gate and git_head_gate and release_pin}


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
    import inspect
    public_signature = tuple(inspect.signature(
        transport.run_fk0957_topology_discovery).parameters)
    internal_signature = tuple(inspect.signature(
        transport._run_consumed_permit).parameters) if hasattr(
            transport, "_run_consumed_permit") else ()
    importable_seams = [name for name in ("_run_with_backend",)
                        if hasattr(transport, name)]
    backend_parameter_injection = (
        "backend" in public_signature or "backend" in internal_signature or
        bool(importable_seams))
    internal_native_factory = (
        "backend = _NativeLibFtdi(trace)" in source or
        "backend = _NativeLibFtdi()" in source)
    test_path = repo / "tools/phk2_host/test_phk2_fk0957_topology_transport.py"
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "TopologyTransportTests.test_local_record_builder_signs_only_after_valid_transport",
        __import__("test_phk2_fk0957_topology_transport"))
    sink = __import__("io").StringIO()
    with mock.patch.object(transport, "_require_native_files", return_value=()):
        result = unittest.TextTestRunner(stream=sink, verbosity=0).run(suite)
    return {
        "production_importable_backend_injection_seams": importable_seams,
        "public_entry_parameters": list(public_signature),
        "internal_transport_parameters": list(internal_signature),
        "internal_native_factory_is_hardcoded": internal_native_factory,
        "production_synthetic_observation_path": backend_parameter_injection,
        "test_fake_backend_fixture_path_exists": test_path.is_file(),
        "test_only_fake_transport_flow_passes": result.wasSuccessful() and result.testsRun == 1,
        "test_count": result.testsRun,
        "failure_classes": [type(err).__name__ for _, err in result.errors + result.failures],
    }


def unconsumed_permit_internal_entry_attack(repo: Path) -> dict[str, Any]:
    """Use a local fake FTDI backend to probe the private transport entrypoint."""
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_discovery as topology
    import phk2_fk0957_topology_transport as transport

    class FakeBackend:
        def __init__(self):
            self.candidate = topology.Candidate(
                topology.DescriptorIdentity(
                    "FK0957", "153300000957A", "153300000957", "1-9.3",
                    "0403", "6010", "Xilinx", "SQRL FK", "A"), object())
            self.open_count = 0
            self.close_count = 0
            self.read_sizes: list[int] = []
            self._runtime = {}
            for pin in transport.LIBRARY_PINS:
                stamp = transport._stat_fingerprint(pin.path.stat())
                self._runtime[pin.name] = transport._LoadedLibrary(
                    pin, None, -1, stamp, stamp, str(pin.path))

        def enumerate_candidates(self):
            return (self.candidate,)

        def open_exact(self, candidate):
            if candidate is not self.candidate:
                raise AssertionError("candidate substitution")
            self.open_count += 1

        def initialize_mpsse(self):
            self.write_exact(topology.MPSSE_SYNC)
            if self.read_exact(2) != topology.MPSSE_SYNC_REPLY:
                raise AssertionError("synthetic sync mismatch")
            self.write_exact(topology.MPSSE_SETUP)

        def write_exact(self, _data):
            return None

        def read_exact(self, size):
            self.read_sizes.append(size)
            if size == 2 and len(self.read_sizes) == 1:
                return topology.MPSSE_SYNC_REPLY
            return bytes(size)

        def close_checked(self):
            self.close_count += 1

    now = datetime.datetime.now(datetime.timezone.utc)
    identity = topology.DescriptorIdentity(
        "FK0957", "153300000957A", "153300000957", "1-9.3",
        "0403", "6010", "Xilinx", "SQRL FK", "A")
    fabricated = topology.DiscoveryPermit(
        "f" * 64, identity, "fabricated-unconsumed-nonce", now.isoformat(),
        (now + datetime.timedelta(seconds=120)).isoformat(), "0" * 64, object())
    backends: list[FakeBackend] = []

    def factory(_trace=None):
        backend = FakeBackend()
        backends.append(backend)
        return backend

    with mock.patch.object(transport, "transport_source_sha256", return_value="a" * 64), \
            mock.patch.object(transport, "_production_git_state", return_value=("a" * 40, True)), \
            mock.patch.object(transport, "_NativeLibFtdi", side_effect=factory):
        results = [transport._run_consumed_permit(fabricated),
                   transport._run_consumed_permit(fabricated)]
    with topology._PERMIT_LOCK:
        registered = fabricated._token in topology._ACTIVE
        consumed = fabricated._token in topology._CONSUMED
    return {
        "same_fabricated_permit_calls": len(results),
        "permit_registered": registered,
        "permit_consumed": consumed,
        "simulated_device_opens": sum(item.open_count for item in backends),
        "simulated_transport_closes": sum(item.close_count for item in backends),
        "sealed_observations_returned": all(
            item._proof in transport._SEALED_RESULTS for item in results),
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


def remote_signing_and_handoff_gates(repo: Path) -> dict[str, Any]:
    host = repo / "tools/phk2_host"
    cli = (host / "phk2_fk0957_topology_live_cli.py").read_text(encoding="utf-8")
    transport = (host / "phk2_fk0957_topology_transport.py").read_text(encoding="utf-8")
    discovery = (host / "phk2_fk0957_topology_discovery.py").read_text(encoding="utf-8")
    code = cli + transport + discovery
    key_path = "/home/rmann/.local/share/sidecar/operator-keys/"
    ssh_present = bool(re.search(r"\bssh\b|SSH_AUTH_SOCK", code))
    handoff_present = any(word in code for word in (
        "validate_bridge_handoff", "handoff_issuer", "handoff_signature",
        "bridge_owner", "operation_id"))
    return {
        "ssh_auth_sock_consumed": "SSH_AUTH_SOCK" in code,
        "ssh_agent_forwarding_path": ssh_present,
        "remote_acquisition_path": ssh_present,
        "local_key_path_is_hardcoded": key_path in transport,
        "private_key_transmission_code_present": bool(re.search(
            r"(ssh|stdin|bundle|remote).{0,100}(private.key|LOCAL_SIGNING_KEY_PATH)|"
            r"(private.key|LOCAL_SIGNING_KEY_PATH).{0,100}(ssh|stdin|bundle|remote)",
            code, re.I | re.S)),
        "remote_signing_protocol_present": bool(re.search(r"remote.{0,40}sign|sign.{0,40}remote", code, re.I)),
        "fixed_local_signing_flow_present": "perform_fk0957_topology_discovery_once" in transport and
                                             "sign_local_discovery_record" in transport,
        "handoff_issuer_or_authentication_present": handoff_present,
        "operation_id_binding_present": "operation_id" in code,
        "permit_nonce_binding_present": "permit_nonce" in transport and "nonce" in discovery,
        "unsigned_record_remote_boundary_present": "canonical unsigned" in code.lower(),
        "result_integrity_seal_present": "_SEALED_RESULTS" in transport and
                                          "_validate_transport_observation" in transport,
        "replay_guard_present": "_SIGNED_PERMITS" in transport and "_RESULTS" in discovery,
        "source_hash_present": "transport_source_sha256" in transport,
        "wrong_production_head_gate_present": "git rev-parse" in code or "EXPECTED_PRODUCTION_HEAD" in code,
    }


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
        "remote_signing_and_handoff_gates": remote_signing_and_handoff_gates(repo),
        "malformed_boundary": malformed_boundary(repo),
        "fake_backend": fake_backend_reachability(repo),
        "unconsumed_permit_internal_entry_attack": unconsumed_permit_internal_entry_attack(repo),
        "bridge_gate_attack": bridge_gate_attack(repo),
        "native_library_pin_preflight": _native_pin_status(repo),
    }
    print(json.dumps(report, sort_keys=True))
    return 0


def _native_pin_status(repo: Path) -> dict[str, Any]:
    sys.path.insert(0, str(repo / "tools/phk2_host"))
    import phk2_fk0957_topology_transport as transport
    details = {}
    for name in ("libc", "libftdi", "libusb"):
        pin = next(row for row in transport.LIBRARY_PINS if row.name == name)
        path = pin.path
        actual: dict[str, Any] = {"pinned_path": str(path), "expected_sha256": pin.sha256,
                                  "expected_build_id": pin.build_id,
                                  "expected_size": pin.size}
        try:
            stat = path.stat()
            raw = path.read_bytes()
            actual.update({"exists": True, "realpath": str(path.resolve(strict=True)),
                           "sha256": hashlib.sha256(raw).hexdigest(), "size": stat.st_size,
                           "mode": oct(stat.st_mode & 0o777), "uid": stat.st_uid,
                           "gid": stat.st_gid, "inode": stat.st_ino, "links": stat.st_nlink})
            notes = subprocess.run(["readelf", "-n", str(path)], capture_output=True,
                                   text=True, check=False).stdout
            match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes)
            actual["build_id"] = match.group(1).lower() if match else None
            dynamic = subprocess.run(["readelf", "-d", str(path)], capture_output=True,
                                     text=True, check=False).stdout
            soname = re.search(r"Library soname: \[([^]]+)\]", dynamic)
            actual["soname"] = soname.group(1) if soname else None
            owner = subprocess.run(["dpkg-query", "-S", str(path)], capture_output=True,
                                   text=True, check=False).stdout.strip()
            actual["package_owner"] = owner
            if owner and ": " in owner:
                package = owner.split(": ", 1)[0]
                version = subprocess.run(["dpkg-query", "-W", "-f=${Version}", package],
                                         capture_output=True, text=True, check=False).stdout.strip()
                actual["package_version"] = version or None
            actual["pin_matches_bytes_build_size"] = (
                actual["sha256"] == pin.sha256 and actual["build_id"] == pin.build_id and
                stat.st_size == pin.size)
        except OSError as exc:
            actual.update({"exists": False, "read_error_class": type(exc).__name__})
        details[name] = actual
    try:
        transport._require_native_files()
    except Exception as exc:
        return {"pass": False, "exception_class": type(exc).__name__, "libraries": details}
    return {"pass": True, "exception_class": None, "libraries": details}


if __name__ == "__main__":
    raise SystemExit(main())
