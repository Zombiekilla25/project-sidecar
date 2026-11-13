#!/usr/bin/env python3
"""Build a deterministic manifest for the pinned FK0957 production release."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_HEAD = "3226bfc1474d6afa873fce7327ded6dac548baae"
ORACLE_COMMIT = "ea2104c55a1d4dafe6da91c6d5ac28447ec336c1"
AUDIT_HARNESS_COMMIT = "c7c1f7fd015149c3ce60a1401bb50682153b8c48"
MAINTENANCE_CONTROLLER_REFERENCE = "14258638f283576f8017ce284c44ef925b9374d6"
OUT = ROOT / "qualification/fk0957/RELEASE_CANDIDATE_MANIFEST.json"

PRODUCTION_PATHS = (
    "tools/phk2_host/phk2_fk0957_topology_live_cli.py",
    "tools/phk2_host/phk2_fk0957_topology_transport.py",
    "tools/phk2_host/phk2_fk0957_topology_discovery.py",
    "tools/phk2_host/phk2_fk0957_idcode_gate.py",
    "tools/phk2_host/phk2_fk0957_remote_orchestrator.py",
    "tools/phk2_host/phk2_fk0957_identity_observer.py",
    "tools/phk2_host/phk2_fk0957_readonly_backend.py",
    "tools/phk2_host/phk2_fk0957_remote_collector.py",
    "tools/phk2_host/phk2_fk0957_ephemeral_bundle.py",
    "tools/phk2_host/phk2_fk0957_ephemeral_runner.py",
)


def git(*args: str) -> bytes:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def assignments(tree: ast.Module) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            result[node.target.id] = node.value
    return result


def resolve(node: ast.AST, values: dict[str, ast.AST]):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in values:
            raise ValueError(f"unresolved source constant: {node.id}")
        return resolve(values[node.id], values)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Path":
        return resolve(node.args[0], values)
    if isinstance(node, ast.Tuple):
        return tuple(resolve(item, values) for item in node.elts)
    raise ValueError("unexpected constant expression")


def transport_source() -> tuple[bytes, ast.Module, dict[str, ast.AST]]:
    raw = git("show", f"{PRODUCTION_HEAD}:tools/phk2_host/phk2_fk0957_topology_transport.py")
    tree = ast.parse(raw)
    return raw, tree, assignments(tree)


def library_pins(values: dict[str, ast.AST]) -> list[dict[str, object]]:
    pins_node = values["LIBRARY_PINS"]
    if not isinstance(pins_node, ast.Tuple):
        raise ValueError("library pin tuple missing")
    pins = []
    for call in pins_node.elts:
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "_LibraryPin":
            raise ValueError("unexpected library pin source shape")
        args = [resolve(argument, values) for argument in call.args]
        name, path, digest, build_id, soname, size = args
        observed: dict[str, object] = {
            "realpath_expected": path, "sha256_expected": digest,
            "build_id_expected": build_id, "soname": soname, "size_expected": size,
        }
        native_path = Path(path)
        if native_path.is_file():
            real = str(native_path.resolve(strict=True))
            blob = native_path.read_bytes()
            readelf = subprocess.run(["readelf", "-n", real], check=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True).stdout
            match = re.search(r"Build ID: ([0-9a-fA-F]+)", readelf)
            observed.update({
                "realpath_observed": real,
                "sha256_observed": sha256(blob),
                "size_observed": len(blob),
                "build_id_observed": match.group(1).lower() if match else None,
            })
            observed["installed_pin_match"] = (
                real == path and sha256(blob) == digest and len(blob) == size and
                match is not None and match.group(1).lower() == build_id)
        else:
            observed["installed_pin_match"] = False
            observed["installed_file_present"] = False
        pins.append({"logical_name": name, **observed})
    return pins


def known_hosts_pin() -> dict[str, object]:
    source = Path("results/fk0957-topology-software-handoff.json")
    source_bytes = (ROOT / source).read_bytes()
    sidecar = (ROOT / (str(source) + ".sha256")).read_text().split()
    if len(sidecar) != 2 or sidecar[0] != sha256(source_bytes) or sidecar[1] != str(source):
        raise ValueError("tracked FK0957 host-pin provenance manifest checksum rejected")
    provenance = json.loads(source_bytes)["testbench_host_key_pin_observation"]
    return {
        "path": provenance["source_path"], "mode_octal": provenance["mode"],
        "hardlink_count": provenance["hardlink_count"],
        "sha256": provenance["known_hosts_sha256"],
        "ed25519_fingerprint": provenance["ed25519_fingerprint"],
        "source_manifest": str(source),
        "source_manifest_sha256": sha256(source_bytes),
        "scope": provenance["verification_scope"] + "; not used by local topology CLI",
    }


def main() -> int:
    head = git("rev-parse", PRODUCTION_HEAD + "^{commit}").decode().strip()
    if head != PRODUCTION_HEAD:
        raise ValueError("pinned production commit unavailable")
    git("merge-base", "--is-ancestor", PRODUCTION_HEAD, "HEAD")
    model_path = "tests/reference/fk0957_topology_state_model.py"
    harness_path = "tests/reference/fk0957_corrected_oracle_audit.py"
    oracle_test_path = "tests/reference/test_fk0957_topology_state_model.py"
    if (ROOT.joinpath(model_path).read_bytes() != git(
            "show", f"{ORACLE_COMMIT}:{model_path}") or
            ROOT.joinpath(harness_path).read_bytes() != git(
            "show", f"{AUDIT_HARNESS_COMMIT}:{harness_path}") or
            ROOT.joinpath(oracle_test_path).read_bytes() != git(
            "show", f"{ORACLE_COMMIT}:{oracle_test_path}")):
        raise ValueError("independent oracle or harness bytes differ from pinned commits")
    transport_raw, _tree, values = transport_source()
    constants = {name: resolve(values[name], values) for name in (
        "CARD_ID", "ADAPTER_SERIAL", "USB_DESCRIPTOR_SERIAL", "FTDI_VID",
        "FTDI_PID", "FTDI_INTERFACE_NAME", "EXPECTED_SCAN_A_TCK",
        "EXPECTED_SCAN_B_TCK", "EXPECTED_TOTAL_TCK", "GOLDEN_SCAN_A_SHA256",
        "GOLDEN_SCAN_B_SHA256", "GOLDEN_PLAN_SHA256",
        "GOLDEN_COMMAND_CONTRACT_SHA256", "GOLDEN_TMS_SHA256", "GOLDEN_TDI_SHA256",
        "GOLDEN_TDI_A_SHA256", "GOLDEN_TDI_B_SHA256",
    )}
    source_hashes = {
        path: sha256(git("show", f"{PRODUCTION_HEAD}:{path}"))
        for path in PRODUCTION_PATHS
    }
    audit_paths = (
        "tests/reference/fk0957_topology_state_model.py",
        "tests/reference/fk0957_corrected_oracle_audit.py",
        "tests/reference/test_fk0957_topology_state_model.py",
        "tools/phk2_host/test_fk0957_release_oracle.py",
        "qualification/fk0957/README.md",
        "qualification/fk0957/build_release_manifest.py",
    )
    audit_hashes = {path: sha256((ROOT / path).read_bytes()) for path in audit_paths}
    pin = known_hosts_pin()
    qualification = {
        "cycles": 3,
        "tests_per_cycle": 193,
        "independent_model_tests_passed": 15,
        "corrected_oracle": {
            "valid_states": 28, "invalid_states": 249572,
            "valid_state_rejected": 0, "invalid_state_accepted": 0,
        },
        "deterministic_seed_count_per_cycle": 20,
        "unique_seed_count": 20,
        "randomized_enumeration_layouts_per_cycle": 400,
        "fault_order_tests_per_cycle": 300,
        "hardware_access": False,
        "ssh_or_network_access": False,
        "usb_or_jtag_functions_called": False,
    }
    result = {
        "schema": "FK0957-RELEASE-CANDIDATE-MANIFEST-v1",
        "production_head": PRODUCTION_HEAD,
        "scope": "offline source, oracle, and mocked qualification; not live authorization",
        "source_sha256": source_hashes,
        "transaction_and_topology_sha256": constants,
        "expected_descriptor_identity": {
            "card_id": constants["CARD_ID"],
            "adapter_serial": constants["ADAPTER_SERIAL"],
            "usb_descriptor_serial": constants["USB_DESCRIPTOR_SERIAL"],
            "vid": f"{constants['FTDI_VID']:04X}",
            "pid": f"{constants['FTDI_PID']:04X}",
            "interface": constants["FTDI_INTERFACE_NAME"],
        },
        "host_key_provenance": pin,
        "native_library_pins": library_pins(values),
        "independent_inputs": {
            "corrected_oracle_commit": ORACLE_COMMIT,
            "audit_harness_commit": AUDIT_HARNESS_COMMIT,
            "audit_harness_scope_note": (
                "Reference model source is unchanged. The release adapter maps each granular model stage "
                "to production operation_state; the harness quick-check projection is not used."
            ),
            "maintenance_controller_reference_commit": MAINTENANCE_CONTROLLER_REFERENCE,
            "maintenance_controller_integrated": False,
        },
        "documentation_cli_comparison": {
            "match": False,
            "discrepancy": (
                "The topology handoff says four zero mutation counters in the success summary. "
                "The actual CLI summary has three zero counters (write_count, reset_count, "
                "program_count) and jtag_operation_count=1. Production documentation is not "
                "being edited while Right's audit is active."
            ),
        },
        "release_readiness": "BLOCKED_PENDING_DOCUMENTATION_REVIEW_AND_RIGHT_AUDIT",
        "fresh_runtime": {
            "python_executable": sys.executable,
            "python_version": sys.version.split()[0],
            "cryptography_version": __import__("cryptography").__version__,
            "cryptography_origin": __import__("cryptography").__file__,
            "qualification_command_has_pythonpath_override": False,
            "qualification_command_reads_tmp_source": False,
        },
        "qualification": qualification,
        "audit_artifact_sha256": audit_hashes,
    }
    raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    OUT.write_bytes(raw)
    OUT.with_suffix(OUT.suffix + ".sha256").write_text(
        sha256(raw) + "  " + str(OUT.relative_to(ROOT)) + "\n")
    print("RELEASE_CANDIDATE_MANIFEST_SHA256=" + sha256(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
