"""Guarded operator interface for the first one-share Sidecar canary.

The command is preview-only by default. This build intentionally has no live
transport launcher; a validated live request still stops before DNS/socket
activity until that separately reviewed runtime is integrated.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Any

from .config import Config
from .qualification import (CUDA_BACKEND,PHK1_BACKEND,load_qualification_artifact,
    pinned_source_hashes)
from .supervisor import parse_pool_endpoint, qualified_backends_for_mode, BackendQualificationState

EXIT_OK=0
EXIT_CONFIG=2
EXIT_QUALIFICATION=3
EXIT_NETWORK=4
EXIT_BACKEND=5
EXIT_REJECTED=6
EXIT_VERIFY=7
EXIT_INTERRUPTED=130
EXIT_LIVE_UNAVAILABLE=78

def validate_pool_host(host: str) -> str:
    if not isinstance(host,str) or not host or host!=host.strip() or any(ch.isspace() for ch in host):
        raise ValueError("pool hostname is malformed")
    if ":" in host:
        try:ipaddress.IPv6Address(host)
        except ValueError as exc:raise ValueError("pool IPv6 host is malformed") from exc
        return host
    try:ipaddress.IPv4Address(host);return host
    except ValueError:pass
    pattern=r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?"
    if not re.fullmatch(pattern,host):raise ValueError("pool hostname is malformed")
    return host.lower()

def validate_runtime_config(config: Config) -> tuple[str,int]:
    host,port=parse_pool_endpoint(config.pool)
    if config.pool.strip().startswith("[") and ":" not in host:
        raise ValueError("pool IPv6 host is malformed")
    validate_pool_host(host)
    for label,value in (("wallet/user",config.wallet),("worker",config.worker),("password",config.pool_password)):
        if not isinstance(value,str) or "\n" in value or "\r" in value or "\0" in value:
            raise ValueError(f"{label} contains invalid control characters")
    if not config.wallet.strip():raise ValueError("wallet/user is required")
    if not config.worker.strip() or len(config.worker)>128:raise ValueError("worker alias is invalid")
    if len(config.wallet)>512 or len(config.pool_password)>512:raise ValueError("pool credential length is invalid")
    return host,port

def _sha(value: str, label: str) -> str:
    if not isinstance(value,str) or not re.fullmatch(r"[0-9a-f]{64}",value):
        raise ValueError(f"{label} must be a lowercase SHA256")
    return value

def resolve_qualifications(mode: str, *, cuda_artifact: str|None,
        cuda_library_sha256: str|None=None, cuda_source_sha256: str|None=None,
        cuda_fixture_sha256: str|None=None, fk_artifact: str|None=None,
        fk_bitstream_sha256: str|None=None) -> tuple[BackendQualificationState,dict[str,Any]]:
    gpu=fk=False
    identities={"gpu":None,"fk":None}
    if mode in ("gpu-only","sidecar","auto") and cuda_artifact:
        expected={"expected_library_sha256":_sha(cuda_library_sha256,"CUDA library SHA256"),
            "expected_source_sha256":_sha(cuda_source_sha256,"CUDA source SHA256"),
            "expected_fixture_sha256":_sha(cuda_fixture_sha256,"CUDA fixture SHA256")}
        q=load_qualification_artifact(cuda_artifact,expected_backend_type=CUDA_BACKEND,**expected)
        gpu=True
        identities["gpu"]={"library_sha256":q.library_sha256,"source_sha256":q.source_sha256,
            "fixture_sha256":q.fixture_sha256,"qualification_timestamp":q.qualified_at_utc,
            "artifact_sha256":q.qualification_sha256}
    if mode in ("sidecar","auto") and fk_artifact:
        bitstream=_sha(fk_bitstream_sha256,"PHK1 bitstream SHA256")
        runner,backend=pinned_source_hashes()
        q=load_qualification_artifact(fk_artifact,expected_backend_type=PHK1_BACKEND,
            expected_runner_sha256=runner,expected_backend_sha256=backend,expected_bitstream_sha256=bitstream)
        fk=True
        identities["fk"]={"bitstream_sha256":q.bitstream_sha256,
            "runner_sha256":q.runner_sha256,"backend_sha256":q.backend_sha256,
            "qualification_timestamp":q.qualified_at_utc,"artifact_sha256":q.qualification_sha256}
    if mode in ("gpu-only","sidecar") and not gpu:
        raise ValueError("CUDA GPU qualification artifact is required and must match current library/fixture identities")
    if mode=="sidecar" and not fk:
        raise ValueError("PHK1 qualification artifact is required and must match current runner/bitstream identities")
    if mode=="auto" and not gpu:
        raise ValueError("auto mode requires a valid CUDA qualification for its GPU producer/fallback")
    state=BackendQualificationState(gpu,fk,
        identities["gpu"]["library_sha256"] if gpu else None,
        identities["fk"]["backend_sha256"] if fk else None,
        identities["gpu"]["artifact_sha256"] if gpu else None,
        identities["fk"]["artifact_sha256"] if fk else None)
    return state,identities

def build_execution_plan(config: Config, *, live: bool, qualifications: BackendQualificationState|None=None,
                         qualification_ids: dict|None=None, fk_target: str|None=None) -> dict[str,Any]:
    host,port=validate_runtime_config(config)
    if config.mode not in ("gpu-only","sidecar","auto"):raise ValueError("invalid mode")
    if live and config.gpu_id is None:
        raise ValueError("live GPU use requires explicit --gpu-id")
    if live and config.gpu_id is not None and config.gpu_id<0:
        raise ValueError("GPU ID must be non-negative")
    qualification=qualifications or BackendQualificationState(False,False)
    selectable=qualified_backends_for_mode(config.mode,qualification)
    selected=("gpu" if selectable else "unqualified") if config.mode=="auto" else (selectable[0] if selectable else "unqualified")
    if config.mode=="auto" and qualification.fk_qualified and config.gpu_timing and config.fk_timing:
        from .integrated_scheduler import IntegratedScheduler,load_timing_inputs
        gpu_timing,fk_timing=load_timing_inputs(config.gpu_timing,config.fk_timing)
        class QualifiedFk: healthy=True
        choice=IntegratedScheduler("auto",gpu_timing,fk_timing,[QualifiedFk()]).choose()
        selected="gpu+fk" if choice.mode=="sidecar" else "gpu"
        decision=choice.decision.value
    else:decision="INSUFFICIENT_DATA" if config.mode=="auto" else "OPERATOR_SELECTED"
    if live and selected=="gpu+fk" and not fk_target:
        raise ValueError("live FK selection requires a logical --fk-target")
    return {"schema":"sidecar-canary-execution-plan-v1","mode":config.mode,
        "selected_backend":selected,"qualified_backends":list(selectable),
        "qualification":qualification_ids or {"gpu":None,"fk":None},
        "pool":{"host":host,"port":port},"worker":config.worker,
        "wallet_configured":bool(config.wallet),"password_configured":bool(config.pool_password),
        "gpu_id":config.gpu_id,"fk_target":fk_target if selected=="gpu+fk" or config.mode=="sidecar" else None,
        "gpu_runtime_check":"deferred until qualified runtime preflight",
        "share_limit":1,"live_requested":bool(live),"live_enabled":False,"scheduler_decision":decision,
        "expected_behavior":"stop after first submitted share response",
        "network_activity":"not attempted"}

def _parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="sidecar-canary",description="Guarded one-share Project Sidecar canary launcher")
    p.add_argument("--config",help="operator JSON config; default ~/.config/project-sidecar/canary.json when present")
    p.add_argument("--pool");p.add_argument("--wallet");p.add_argument("--worker");p.add_argument("--password")
    p.add_argument("--mode",choices=("gpu-only","sidecar","auto"));p.add_argument("--gpu-id",type=int);p.add_argument("--fk-target")
    p.add_argument("--gpu-timing");p.add_argument("--fk-timing")
    p.add_argument("--cuda-qualification");p.add_argument("--cuda-library-sha256");p.add_argument("--cuda-source-sha256");p.add_argument("--cuda-fixture-sha256")
    p.add_argument("--fk-qualification");p.add_argument("--fk-bitstream-sha256")
    p.add_argument("--store",help="local public-safe qualification store directory")
    p.add_argument("--plan",default="CANARY_EXECUTION_PLAN.json")
    p.add_argument("--check",action="store_true",help="validate configuration and qualification artifacts without connecting")
    p.add_argument("--live",action="store_true",help="explicit live intent; current build still refuses live transport")
    p.add_argument("--dry-run",action="store_true",help="run local loopback mock pool and mock backends")
    p.add_argument("--mock-response",choices=("accept","reject"),default="accept",help=argparse.SUPPRESS)
    p.add_argument("--mock-fault",choices=("none","stale-job","backend"),default="none",help=argparse.SUPPRESS)
    return p

def main(argv=None) -> int:
    args=_parser().parse_args(argv)
    config_path=args.config
    if config_path is None:
        default=Path.home()/".config/project-sidecar/canary.json"
        config_path=str(default) if default.exists() else None
    try:
        operator_data={}
        if config_path:
            operator_data=json.loads(Path(config_path).read_text(encoding="utf-8"))
            if not isinstance(operator_data,dict):raise ValueError("operator config must be a JSON object")
        def setting(cli_value,key,default=None):
            if cli_value is not None:return cli_value
            env_value=os.environ.get("SIDECAR_"+key.upper())
            if env_value is not None:return env_value
            return operator_data.get(key,default)
        c=Config.load(config_path)
        if c.canary_shares>1:raise ValueError("first-live canary config cannot set canary_shares above 1")
        updates={"pool":args.pool,"wallet":args.wallet,"worker":args.worker,
            "pool_password":args.password,"mode":args.mode,"gpu_id":args.gpu_id,
            "gpu_timing":args.gpu_timing,"fk_timing":args.fk_timing,
            "canary_shares":1,"live_enabled":args.live}
        c=replace(c,**{k:v for k,v in updates.items() if v is not None})
        fk_target=setting(args.fk_target,"fk_target",c.fk_target)
        cuda_artifact=setting(args.cuda_qualification,"cuda_qualification",c.cuda_qualification)
        cuda_library=setting(args.cuda_library_sha256,"cuda_library_sha256",c.cuda_library_sha256)
        cuda_source=setting(args.cuda_source_sha256,"cuda_source_sha256",c.cuda_source_sha256)
        cuda_fixture=setting(args.cuda_fixture_sha256,"cuda_fixture_sha256",c.cuda_fixture_sha256)
        fk_artifact=setting(args.fk_qualification,"fk_qualification",c.fk_qualification)
        fk_bitstream=setting(args.fk_bitstream_sha256,"fk_bitstream_sha256",c.fk_bitstream_sha256)
        store_root=args.store or setting(None,"qualification_store",c.qualification_store) or None
        plan_path=setting(args.plan,"canary_plan_path","CANARY_EXECUTION_PLAN.json")
        quals=None
        ids={"gpu":None,"fk":None}
        if args.check or args.live:
            from .qualification_store import QualificationStore
            store=QualificationStore(store_root)
            if not cuda_artifact:
                found=store.find(CUDA_BACKEND,expected_library_sha256=cuda_library or None,
                    expected_source_sha256=cuda_source or None,expected_fixture_sha256=cuda_fixture or None)
                cuda_artifact=str(found) if found else None
            if not fk_artifact and fk_bitstream:
                found=store.find(PHK1_BACKEND,expected_bitstream_sha256=fk_bitstream)
                fk_artifact=str(found) if found else None
            quals,ids=resolve_qualifications(c.mode,cuda_artifact=cuda_artifact,
                cuda_library_sha256=cuda_library,cuda_source_sha256=cuda_source,
                cuda_fixture_sha256=cuda_fixture,fk_artifact=fk_artifact,
                fk_bitstream_sha256=fk_bitstream)
        plan=build_execution_plan(c,live=args.live,qualifications=quals,qualification_ids=ids,fk_target=fk_target)
        Path(plan_path).write_text(json.dumps(plan,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    except (OSError,ValueError,TypeError,KeyError) as exc:
        reason=str(exc)
        print(json.dumps({"status":"QUALIFICATION_FAILED" if "qualification" in reason.lower() or "artifact" in reason.lower() else "CONFIG_FAILED",
            "reason":reason,"network_activity":"not attempted","share_limit":1},sort_keys=True))
        return EXIT_QUALIFICATION if "qualification" in reason.lower() or "artifact" in reason.lower() else EXIT_CONFIG
    print("PROJECT SIDECAR CANARY")
    print(f"Mode: {plan['mode']}\nBackend: {plan['selected_backend']}\nQualification: {', '.join(plan['qualified_backends']) or 'none'}")
    print(f"Pool: {plan['pool']['host']}:{plan['pool']['port']}\nWorker: {plan['worker']}\nShare limit: 1")
    live_summary="REQUESTED; blocked before network by this build" if args.live else "DISABLED"
    print(f"Live network: {live_summary}\nExpected behavior: stop after first submitted share response")
    print(f"Execution plan: {plan_path}")
    if args.live:
        if not plan["qualified_backends"]:
            print(json.dumps({"status":"QUALIFICATION_FAILED","network_activity":"not attempted"},sort_keys=True))
            return EXIT_QUALIFICATION
        print(json.dumps({"status":"BLOCKED","reason":"live transport is not enabled in this build; no DNS/socket connection attempted",
            "network_activity":"not attempted","result_path":"LIVE_MINER_CANARY_RESULT.json"},sort_keys=True))
        return EXIT_LIVE_UNAVAILABLE
    if args.dry_run:
        try:
            from .offline import run_supervised_offline_canary
            r=run_supervised_offline_canary(c.mode,1,c.gpu_timing or None,c.fk_timing or None,
                reject_shares=args.mock_response=="reject",
                stale_before_submit=args.mock_fault=="stale-job",
                backend_failure=args.mock_fault=="backend")
            print(json.dumps(r,sort_keys=True))
            if r["success"]:return EXIT_OK
            if r.get("pool_response")=="rejected":return EXIT_REJECTED
            if r.get("share_attempts",0)==0 and args.mock_fault=="stale-job":return EXIT_VERIFY
            return EXIT_BACKEND
        except KeyboardInterrupt:return EXIT_INTERRUPTED
        except Exception as exc:
            print(json.dumps({"status":"BACKEND_FAILED","reason":str(exc),"network_activity":"loopback mock only"},sort_keys=True))
            return EXIT_BACKEND
    if not plan["qualified_backends"] and args.check:
        print(json.dumps({"status":"QUALIFICATION_FAILED","network_activity":"not attempted"},sort_keys=True))
        return EXIT_QUALIFICATION
    print(json.dumps({"status":"PREVIEW","network_activity":"not attempted","share_limit":1},sort_keys=True))
    return EXIT_OK

if __name__=="__main__":raise SystemExit(main())
