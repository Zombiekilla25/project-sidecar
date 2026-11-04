"""Offline operator commands for explicit qualification artifact management."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any

from .qualification import CUDA_BACKEND,PHK1_BACKEND
from .qualification_store import QualificationStore

def _public(row: dict[str,Any]) -> dict[str,Any]:
    return {k:v for k,v in row.items() if k not in ("path",)}

def _short(value):return value[:12] if isinstance(value,str) else "unknown"

def qualification_main(argv=None) -> int:
    p=argparse.ArgumentParser(prog="sidecar-miner qualification")
    p.add_argument("--store",help="qualification store directory")
    sub=p.add_subparsers(dest="action",required=True)
    def scoped_options(cmd):
        cmd.add_argument("--store",dest="store",default=argparse.SUPPRESS)
        cmd.add_argument("--json",dest="json",action="store_true",default=argparse.SUPPRESS)
    imp=sub.add_parser("import",help="validate and copy one explicit artifact into the local store")
    scoped_options(imp)
    imp.add_argument("file");imp.add_argument("--expected-bitstream-sha256")
    imp.add_argument("--expected-library-sha256");imp.add_argument("--expected-source-sha256")
    imp.add_argument("--expected-fixture-sha256")
    listing=sub.add_parser("list",help="list public-safe stored qualification summaries");scoped_options(listing)
    show=sub.add_parser("show",help="show one public-safe stored qualification")
    scoped_options(show)
    show.add_argument("backend",choices=("phk1","cuda"))
    a=p.parse_args(argv);store=QualificationStore(a.store)
    if not hasattr(a,"json"):a.json=False
    try:
        if a.action=="import":
            target,record=store.import_file(a.file,expected_bitstream_sha256=a.expected_bitstream_sha256,
                expected_library_sha256=a.expected_library_sha256,expected_source_sha256=a.expected_source_sha256,
                expected_fixture_sha256=a.expected_fixture_sha256)
            out={"status":"IMPORTED","backend_type":record.backend_type,"qualified":record.qualified,
                "qualification_timestamp":record.qualification_timestamp,"stored_name":target.name,
                "identity":({"bitstream_sha256":record.bitstream_sha256,"runner_sha256":record.runner_sha256,
                    "backend_sha256":record.backend_sha256} if record.backend_type==PHK1_BACKEND else
                    {"library_sha256":record.library_sha256,"source_sha256":record.source_sha256,
                     "fixture_sha256":record.fixture_sha256}),
                "checks":({"transport_version":record.transport_version,"protocol_version":record.protocol_version,
                    "vector_id":record.vector_id,"raw_result_exact":record.raw_result_exact,
                    "canonical_result_exact":record.canonical_result_exact,"cpu_crosscheck":record.cpu_crosscheck,
                    "rollback_verified":record.rollback_pass} if record.backend_type==PHK1_BACKEND else
                    {"device_name":record.device_name,"explicit_device_selection":record.explicit_device_selection})}
        elif a.action=="list":
            rows=[_public(row) for row in store.records()]
            if a.json:print(json.dumps(rows,sort_keys=True));return 0
            if not rows:print("No qualification artifacts imported.");return 0
            for row in rows:
                identity=row["identity"]
                if row["backend_type"]==PHK1_BACKEND:
                    suffix=f"bitstream={_short(identity.get('bitstream_sha256'))} runner={_short(identity.get('runner_sha256'))}"
                elif row["backend_type"]==CUDA_BACKEND:
                    suffix=f"library={_short(identity.get('library_sha256'))}"
                else:suffix="identity=invalid"
                print(f"{row['backend_type']} qualified={str(row['qualified']).lower()} "
                    f"timestamp={row.get('qualification_timestamp') or 'unknown'} schema={row.get('schema_version')} {suffix}")
            return 0
        else:
            backend=PHK1_BACKEND if a.backend=="phk1" else CUDA_BACKEND
            rows=[r for r in store.records() if r["backend_type"]==backend]
            if not rows:
                print(json.dumps({"status":"NOT_FOUND","backend_type":backend},sort_keys=True));return 1
            row=rows[-1];out={"status":"FOUND","backend_type":backend,**_public(row)}
        print(json.dumps(out,sort_keys=True) if a.json or a.action!="list" else out)
        return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({"status":"REJECTED","reason":str(exc),"network_activity":"not attempted"},sort_keys=True))
        return 3

def status_main(argv=None) -> int:
    p=argparse.ArgumentParser(prog="sidecar-miner status")
    p.add_argument("--config");p.add_argument("--store");p.add_argument("--json",action="store_true")
    a=p.parse_args(argv)
    from .config import Config
    from .qualification import load_qualification_artifact,pinned_source_hashes
    from .supervisor import BackendQualificationState,qualified_backends_for_mode
    c=Config.load(a.config);store=QualificationStore(a.store or c.qualification_store or None)
    gpu_record=fk_record=None;gpu_ok=fk_ok=False
    try:
        gp=c.cuda_qualification or store.find(CUDA_BACKEND,expected_library_sha256=c.cuda_library_sha256 or None,
            expected_source_sha256=c.cuda_source_sha256 or None,expected_fixture_sha256=c.cuda_fixture_sha256 or None)
        if gp and c.cuda_library_sha256 and c.cuda_source_sha256 and c.cuda_fixture_sha256:
            gpu_record=load_qualification_artifact(gp,expected_backend_type=CUDA_BACKEND,
                expected_library_sha256=c.cuda_library_sha256,expected_source_sha256=c.cuda_source_sha256,
                expected_fixture_sha256=c.cuda_fixture_sha256);gpu_ok=gpu_record.qualified
    except (OSError,ValueError,TypeError):gpu_record=None
    try:
        fp=c.fk_qualification or (store.find(PHK1_BACKEND,expected_bitstream_sha256=c.fk_bitstream_sha256 or None))
        if fp and c.fk_bitstream_sha256:
            runner,backend=pinned_source_hashes()
            fk_record=load_qualification_artifact(fp,expected_backend_type=PHK1_BACKEND,
                expected_runner_sha256=runner,expected_backend_sha256=backend,
                expected_bitstream_sha256=c.fk_bitstream_sha256);fk_ok=fk_record.qualified
    except (OSError,ValueError,TypeError):fk_record=None
    q=BackendQualificationState(gpu_ok,fk_ok)
    available=list(qualified_backends_for_mode(c.mode,q))
    obj={"mode":c.mode,"pool_configured":bool(c.pool),"live_enabled":bool(c.live_enabled),
        "live_transport_enabled":False,"canary_share_limit":1,
        "gpu":{"configured":c.gpu_id is not None or bool(c.gpu),"qualified":gpu_ok,
            "availability":"unavailable" if not gpu_ok else "qualified; runtime device check deferred",
            "qualification_identity":None if not gpu_record else {"library_sha256":gpu_record.library_sha256,
                "source_sha256":gpu_record.source_sha256,"fixture_sha256":gpu_record.fixture_sha256}},
        "fk":{"configured":bool(c.fk_target or c.fk_devices),"qualified":fk_ok,
            "availability":"unavailable" if not fk_ok else "qualified; physical open remains separately gated",
            "qualification_identity":None if not fk_record else {"bitstream_sha256":fk_record.bitstream_sha256,
                "runner_sha256":fk_record.runner_sha256,"backend_sha256":fk_record.backend_sha256}},
        "schedulable_backends":available,"qualification_store_configured":bool(a.store or c.qualification_store),
        "hardware_access":"none"}
    if a.json:print(json.dumps(obj,sort_keys=True));return 0
    print(f"mode={c.mode} pool_configured={'yes' if obj['pool_configured'] else 'no'} "
        f"live_enabled={'yes' if c.live_enabled else 'no'} live_transport_enabled=no canary_shares=1")
    gpu_identity=obj["gpu"]["qualification_identity"] or {}
    fk_identity=obj["fk"]["qualification_identity"] or {}
    print(f"GPU configured={'yes' if obj['gpu']['configured'] else 'no'} qualified={'yes' if gpu_ok else 'no'} "
        f"schedulable={'yes' if 'gpu' in available else 'no'} library={str(gpu_identity.get('library_sha256','none'))[:12]}")
    print(f"FK configured={'yes' if obj['fk']['configured'] else 'no'} qualified={'yes' if fk_ok else 'no'} "
        f"schedulable={'yes' if 'gpu+fk' in available else 'no'} bitstream={str(fk_identity.get('bitstream_sha256','none'))[:12]} "
        f"runner={str(fk_identity.get('runner_sha256','none'))[:12]}")
    return 0
