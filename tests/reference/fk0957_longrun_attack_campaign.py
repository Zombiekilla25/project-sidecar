"""Offline reproductions for FK0957 production startup/publish assumptions.

This script intentionally reports whether unsafe conditions can be reproduced;
it never enumerates devices, issues a permit, or invokes the acquisition path.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import tempfile
import inspect
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
        except OSError:
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


def malformed_type_campaign(validator: Any, seed: int = 0xF0957) -> dict[str, int]:
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
    for _ in range(10000):
        candidate = dict(base)
        key = rng.choice(fields)
        candidate[key] = rng.choice(atoms)
        try:
            accepted = validator(candidate)
        except Exception:
            exceptions += 1
            continue
        invalid_or_noncanonical += int(not accepted)
    return {"generated": 10000, "rejected_or_noncanonical": invalid_or_noncanonical,
            "validator_exceptions": exceptions}


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
        "malformed_type_campaign": malformed_type_campaign(cli._bounded_envelope),
        "malformed_internal_refusal_falls_back_safely": (
            safe_fallback.get("phase") == "INTERNAL_REFUSAL" and
            safe_fallback.get("code") == "INTERNAL_REFUSAL"),
        "transactions": {
            "scan_a_tck_count": plan.scan_a_tck_count,
            "scan_b_tck_count": plan.scan_b_tck_count,
            "total_tck_count": plan.tck_count,
            "scan_a_sha256": topology.scan_transaction_sha256(plan.scan_a_commands),
            "scan_b_sha256": topology.scan_transaction_sha256(plan.scan_b_commands),
        },
    }
    print(json.dumps(reports, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
