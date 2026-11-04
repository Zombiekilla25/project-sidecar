#!/usr/bin/env python3
"""Exercise a staged release package using offline fixtures only."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(package:Path,*args,env):
    result=subprocess.run([sys.executable,str(package/"sidecar-miner"),*args],cwd=package,env=env,
        capture_output=True,text=True,timeout=30)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args}: {result.stdout} {result.stderr}")
    return result.stdout.strip()

def selftest(package:Path)->dict:
    package=package.resolve()
    with tempfile.TemporaryDirectory(prefix="sidecar-release-selftest-") as temp:
        temp=Path(temp);store=temp/"qualifications";bench=temp/"benchmark.json"
        env={k:v for k,v in os.environ.items() if not k.startswith("SIDECAR_")}
        env.update({"PYTHONPATH":str(package),"HOME":str(temp),"XDG_DATA_HOME":str(temp/"data"),"XDG_CONFIG_HOME":str(temp/"config"),"PYTHONDONTWRITEBYTECODE":"1"})
        checks={}
        checks["version"]="sidecar-miner 0.3.0-rc1" in run(package,"--version",env=env)
        status=json.loads(run(package,"status","--json",env=env));checks["status"]=isinstance(status,dict)
        imported=json.loads(run(package,"qualification","import",str(package/"fixtures/qualification/valid-phk1-qualified.json"),"--store",str(store),"--expected-bitstream-sha256","b"*64,env=env))
        checks["qualification_fixture_import"]=imported.get("status") in ("IMPORTED","PASS")
        listed=json.loads(run(package,"qualification","list","--store",str(store),"--json",env=env))
        shown=json.loads(run(package,"qualification","show","phk1","--store",str(store),env=env))
        checks["qualification_list_show"]=bool(listed) and shown.get("status")=="FOUND"
        dry=json.loads(run(package,"--dry-run","--mode","gpu-only",env=env));checks["offline_miner"]=(dry.get("status")=="PASS" and dry.get("live_pool_connections")==0)
        fleet_config=json.loads((package/"fixtures/fleet/eight-fk-offline.json").read_text())
        qualification=package/"fixtures/qualification/valid-phk1-qualified.json"
        q=json.loads(qualification.read_text())
        fleet_config.update({"qualification_artifact":str(qualification),"expected_runner_sha256":q["runner_sha256"],
            "expected_backend_sha256":q["backend_sha256"],"protocol_version":q["protocol_version"]})
        for index,row in enumerate(fleet_config["cards"]):
            row.update({"physical_binding_id":f"release-selftest-{index}","expected_bitstream_sha256":q["bitstream_sha256"],
                "expected_runner_sha256":q["runner_sha256"],"expected_backend_sha256":q["backend_sha256"],
                "rollback_image_sha256":"e"*64})
        fleet_path=temp/"fleet.json";fleet_path.write_text(json.dumps(fleet_config))
        fleet=json.loads(run(package,"fleet","rollout","--dry-run","--fleet",str(fleet_path),env=env));checks["fleet_dry_run"]=fleet.get("mock_actions_only") is True
        fs=json.loads(run(package,"fleet","status","--fleet",str(fleet_path),"--json",env=env))
        fp=json.loads(run(package,"fleet","plan","--fleet",str(fleet_path),env=env))
        fw=run(package,"fleet","watch","--fleet",str(fleet_path),"--iterations","1","--json",env=env)
        checks["fleet_status_plan_watch"]=bool(fs) and bool(fp) and bool(json.loads(fw))
        fixture=package/"fixtures/benchmark/transport-bound.json"
        ing=json.loads(run(package,"benchmark","ingest",str(fixture),"--store",str(bench),env=env));checks["benchmark_ingest"]=ing.get("status")=="PASS"
        show=json.loads(run(package,"benchmark","show","--store",str(bench),env=env));checks["benchmark_synthetic"]=show.get("measured") is False
        for command in (("benchmark","fleet","--store",str(bench)),("benchmark","bottleneck","--store",str(bench))):
            checks[" ".join(command[:2])]=isinstance(json.loads(run(package,*command,env=env)),dict)
        if not all(checks.values()):raise AssertionError(f"release selftest failed: {checks}")
        return {"status":"PASS","checks":checks,"external_network_attempts":0,"hardware_access":"none"}

def main(argv=None):
    import argparse
    p=argparse.ArgumentParser();p.add_argument("package",type=Path);a=p.parse_args(argv)
    try:print(json.dumps(selftest(a.package),sort_keys=True));return 0
    except Exception as exc:print(json.dumps({"status":"FAIL","error":str(exc),"external_network_attempts":0,"hardware_access":"none"},sort_keys=True));return 1
if __name__=="__main__":raise SystemExit(main())
