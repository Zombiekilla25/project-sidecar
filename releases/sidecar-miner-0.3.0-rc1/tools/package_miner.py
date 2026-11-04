#!/usr/bin/env python3
"""Assemble a public-safe, data-only Sidecar miner release candidate."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from sidecar_miner import __version__
from sidecar_miner.release_info import release_manifest

DOCS=("architecture.md","backend-qualification.md","benchmarks.md","cuda-backend.md",
      "first-silicon-benchmark.md","fleet-orchestration-test-report.md","fleet-orchestration.md",
      "live-miner-roadmap.md","logging.md","miner-supervisor.md","one-share-live-canary.md",
      "safety-model.md","sidecar-miner-integrated-architecture.md","sidecar-scheduler-architecture.md")
FIXTURES=("benchmark","cuda","fleet","qualification","synthetic")


def _hash_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""):h.update(block)
    return h.hexdigest()

def _tree_hash(root:Path,*,exclude_manifest=False):
    rows=[]
    for path in sorted(x for x in root.rglob("*") if x.is_file() and not (exclude_manifest and x.relative_to(root).as_posix()=="release-manifest.json")):
        rows.append(f"{path.relative_to(root).as_posix()}  {_hash_file(path)}\n")
    return hashlib.sha256("".join(rows).encode()).hexdigest(),{row.split("  ",1)[0]:row.strip().split("  ",1)[1] for row in rows}

def package(output: str|Path) -> Path:
    target=Path(output).expanduser().resolve()
    if target.exists():shutil.rmtree(target)
    target.mkdir(parents=True)
    for name in ("sidecar_miner","sidecar_scheduler","bin"):
        shutil.copytree(ROOT/name,target/name,ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
    (target/"schemas").mkdir();
    for path in sorted((ROOT/"schemas").glob("*.json")):
        shutil.copy2(path,target/"schemas"/path.name)
    (target/"docs").mkdir()
    for name in DOCS:
        src=ROOT/"docs"/name
        if src.exists():shutil.copy2(src,target/"docs"/name)
    milestone=ROOT/"docs/run-logs/2026-11-03-sidecar-miner-0.3.0-rc1.md"
    if milestone.exists():
        (target/"docs/run-logs").mkdir(parents=True,exist_ok=True)
        shutil.copy2(milestone,target/"docs/run-logs"/milestone.name)
    (target/"fixtures").mkdir()
    for name in FIXTURES:
        src=ROOT/"fixtures"/name
        if src.exists():shutil.copytree(src,target/"fixtures"/name,ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
    for name in ("requirements.txt","sidecar-miner.kryptex.example.json","README-sidecar-miner.md","README.md","CHANGELOG.md","sidecar-miner"):
        shutil.copy2(ROOT/name,target/name)
    (target/"assets").mkdir()
    shutil.copy2(ROOT/"assets/project-sidecar-logo.png",target/"assets/project-sidecar-logo.png")
    (target/"tools").mkdir()
    native_dir=target/"tools/phk1_raw_bscan";native_dir.mkdir()
    native_sources=("build-dependencies.txt","build_sidecar_native.sh","sidecar_transport_abi.cpp",
        "sidecar_transport_abi.h","mpsse_backend.cpp","mpsse_backend.hpp","libftdi_io.cpp",
        "libftdi_io.hpp","usb_selection.cpp","usb_selection.hpp","usb_identity.hpp")
    for name in native_sources:shutil.copy2(ROOT/"tools/phk1_raw_bscan"/name,native_dir/name)
    for name in ("package_miner.py","sidecar_release_selftest.py","sidecar_release_soak.py"):
        src=ROOT/"tools"/name
        if src.exists():shutil.copy2(src,target/"tools"/name)
    manifest=release_manifest()
    manifest.update({"release_channel":"release-candidate","build_timestamp_utc":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
        "package_content_sha256":None,"package_file_sha256":None,
        "source_tree_sha256":None})
    manifest["qualification_schemas"]={"phk1":"schemas/phk1-physical-qualification-v1.schema.json","cuda":"schemas/cuda-qualification-v1.schema.json"}
    manifest["benchmark_schemas"]={"first_silicon":"schemas/first-silicon-benchmark-v1.schema.json","gpu_fk_comparison":"schemas/gpu-fk-comparison-v1.schema.json"}
    manifest["fleet_schemas"]={"config":"schemas/fk33-fleet-config-v1.schema.json","status":"schemas/fk33-fleet-status-v1.schema.json","timing":"schemas/fk33-timing-v1.schema.json"}
    manifest["fixture_directories"]=list(FIXTURES)
    # Hash the staged source trees and all package payload files before the manifest.
    manifest["source_tree_sha256"]={name:_tree_hash(target/name)[0] for name in ("sidecar_miner","sidecar_scheduler","bin","schemas","tools/phk1_raw_bscan")}
    content_hash,file_hashes=_tree_hash(target)
    manifest["package_content_sha256"]=content_hash
    manifest["package_file_sha256"]=file_hashes
    (target/"release-manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    return target

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument("--output",default=str(ROOT/"dist"/f"sidecar-miner-{__version__}"))
    a=p.parse_args(argv);result=package(a.output)
    print(json.dumps({"status":"PASS","package":str(result),"manifest":str(result/"release-manifest.json"),
        "git_commit":release_manifest()["git_commit"]},sort_keys=True));return 0
if __name__=="__main__":raise SystemExit(main())
