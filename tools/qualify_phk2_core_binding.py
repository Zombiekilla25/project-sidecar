#!/usr/bin/env python3
"""Offline qualification entrypoint for a future committed PHK2 core bundle.

No hardware, Vivado, bitstream, SSH, or package access is performed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from verify_phk2_core_contract import EXPECTED as CONTRACT_PORTS
ADAPTER_TB = ROOT / "tests/phk2_board/tb_core_contract_adapter.sv"
ADAPTER = ROOT / "rtl/phk2_board/phk2_core_contract_adapter.sv"
REQUIRED_MODULE = "phk2_core_contract_adapter"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fail(msg: str) -> None:
    raise ValueError(msg)


def qualify(core_dir: Path, expected_commit: str, manifest_path: Path | None = None) -> dict:
    core_dir = core_dir.resolve()
    manifest_path = (manifest_path or core_dir / "source_manifest.json").resolve()
    if not manifest_path.is_file():
        fail(f"missing source manifest: {manifest_path}")
    manifest = json.loads(manifest_path.read_text())
    commit = manifest.get("commit")
    if commit != expected_commit or not re.fullmatch(r"[0-9a-f]{40,64}", str(commit)):
        fail(f"commit mismatch: manifest={commit!r} expected={expected_commit!r}")
    if manifest.get("contract") != "PHK2-BOARD-CORE-CONTRACT-v1":
        fail("candidate manifest contract version mismatch")
    qualification = manifest.get("timing_qualification", {})
    if qualification.get("status") != "PASS" or qualification.get("commit") != expected_commit:
        fail("candidate does not provide timing qualification bound to the expected commit")
    try:
        timing_wns = float(qualification.get("wns_ns"))
    except (TypeError, ValueError):
        timing_wns = -1.0
    if qualification.get("target_part") != "xcvu33p-fsvh2104-2-e" or timing_wns < 0:
        fail("timing qualification must name xcvu33p-fsvh2104-2-e and nonnegative WNS")
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        fail("manifest has no source list")
    paths: list[Path] = []
    for item in sources:
        rel = Path(item["path"])
        if rel.is_absolute() or ".." in rel.parts:
            fail(f"unsafe source path: {rel}")
        path = (core_dir / rel).resolve()
        if core_dir not in path.parents or not path.is_file():
            fail(f"missing/escaping source: {rel}")
        if sha(path) != item.get("sha256"):
            fail(f"source SHA mismatch: {rel}")
        text = path.read_text(errors="replace")
        if re.search(r"\bmodule\s+phk2_core_stub\b", text):
            fail(f"test-only stub is forbidden in candidate sources: {rel}")
        paths.append(path)
    adapter_sources = [p for p in paths if re.search(
        rf"\bmodule\s+{REQUIRED_MODULE}\b", p.read_text(errors="replace"))]
    if len(adapter_sources) != 1:
        fail(f"expected exactly one {REQUIRED_MODULE} module; found {len(adapter_sources)}")
    if not any(p.name == "phk2_core_contract_adapter.sv" for p in paths):
        fail("required adapter module file is missing from manifest")
    adapter_text = adapter_sources[0].read_text(errors="replace")
    ports = {}
    for direction, hi, lo, name in re.findall(
        r"\b(input|output)\s+wire\s+(?:\[(\d+):(\d+)\]\s+)?(\w+)", adapter_text):
        ports[name] = (direction, int(hi) - int(lo) + 1 if hi else 1)
    if ports != CONTRACT_PORTS:
        fail("candidate adapter ports/widths do not match frozen v1 interface")
    core_module = manifest.get("core_module")
    if not isinstance(core_module, str) or not core_module or core_module == REQUIRED_MODULE:
        fail("manifest must name the timing core module separately from the boundary adapter")
    if not any(re.search(rf"\bmodule\s+{re.escape(core_module)}\b", p.read_text(errors="replace")) for p in paths):
        fail(f"required timing core module not found in hashed sources: {core_module}")
    binding_tb = manifest.get("binding_testbench")
    if not binding_tb:
        fail("candidate must include a timing-core binding testbench")
    tb_path = (core_dir / binding_tb).resolve()
    if core_dir not in tb_path.parents or not tb_path.is_file():
        fail("candidate binding testbench is missing or escapes candidate directory")
    # Compile the complete candidate source set with the canonical behavioral
    # testbench. This also catches missing transitive RTL modules.
    with tempfile.TemporaryDirectory(prefix="phk2-core-qualify-") as td:
        out = Path(td) / "adapter.vvp"
        cp = subprocess.run(["iverilog", "-g2012", "-s", "tb_core_contract_adapter",
                             "-o", str(out), str(ADAPTER_TB), *map(str, paths)],
                            text=True, capture_output=True)
        if cp.returncode:
            fail(f"candidate compile failed: {cp.stderr.strip()}")
        sim = subprocess.run(["vvp", str(out)], text=True, capture_output=True)
        if sim.returncode or "CORE_ADAPTER_RTL_TESTS=9/9" not in sim.stdout:
            fail(f"candidate adapter simulation failed: {sim.stdout} {sim.stderr}")
        bind_out = Path(td) / "binding.vvp"
        cp = subprocess.run(["iverilog", "-g2012", "-s", "tb_timing_core_binding",
                             "-o", str(bind_out), str(tb_path), *map(str, paths)],
                            text=True, capture_output=True)
        if cp.returncode:
            fail(f"timing-core binding compile failed: {cp.stderr.strip()}")
        bind_sim = subprocess.run(["vvp", str(bind_out)], text=True, capture_output=True)
        if bind_sim.returncode or "TIMING_CORE_BINDING_TESTS=PASS" not in bind_sim.stdout:
            fail(f"timing-core binding simulation failed: {bind_sim.stdout} {bind_sim.stderr}")
    return {"status": "PASS", "commit": commit,
            "source_count": len(paths), "adapter_module": REQUIRED_MODULE,
            "compile": "PASS", "simulation": "PASS_9/9_PLUS_CORE_BINDING",
            "core_module": core_module,
            "hardware_access": 0, "vivado": "NOT_RUN"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate_core_dir", type=Path)
    ap.add_argument("--expected-commit", required=True)
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    try:
        result = qualify(args.candidate_core_dir, args.expected_commit, args.manifest)
        payload = json.dumps(result, sort_keys=True, indent=2) + "\n"
        if args.output:
            args.output.write_text(payload)
        print(payload, end="")
        return 0
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
