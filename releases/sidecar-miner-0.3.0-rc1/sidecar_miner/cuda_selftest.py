"""One-tile, one-launch CUDA vector harness. `--plan-only` is default-safe."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from .cuda_fixture import load_fixture, compare_digests


def load_vector(path):
    fixture=load_fixture(path,replay=True)
    return {"A":fixture.A_noised.tobytes(),"Bt":fixture.Bt_noised.tobytes(),
            "key":fixture.key,"target":fixture.target,"expected":fixture.expected_bytes,
            "m":fixture.m,"n":fixture.n,"k":fixture.k,"rank":fixture.reduction,
            "digest_count":fixture.digest_count,"oracle_source":fixture.manifest["cpu_oracle"]["identity"]}


def _worker(gpu_id, vector_path, library):
    from .cuda_backend import CudaPearlHashBackend, CudaPowBatch
    from sidecar_scheduler.contracts import WorkBatch
    vector=load_vector(vector_path); backend=CudaPearlHashBackend(gpu_id,library,allow_unqualified=True)
    allocated=[]
    try:
        backend.initialize()
        for data in (vector["A"],vector["Bt"],vector["key"],vector["target"],bytes(vector["digest_count"]*64),
                     bytes(vector["digest_count"]*32),bytes(4),bytes(8)):
            ptr=backend.allocate(len(data));allocated.append(ptr);backend.upload(ptr,data)
        batch_id="cuda-selftest-0";fingerprint=hashlib.sha256(Path(vector_path).read_bytes()).hexdigest()
        job=type("VectorJob",(),{"fingerprint":fingerprint,"generation":0})()
        backend.prepare_job(job)
        work=CudaPowBatch(*(int(p.value) for p in allocated),vector["m"],vector["n"],vector["k"],vector["rank"],0)
        batch=WorkBatch.create(fingerprint,0,batch_id,b"single-vector",1,context=work)
        result=backend.compute_batch(batch)
        output=result.payload
        if output.digest_count!=vector["digest_count"] or not compare_digests(load_fixture(vector_path),output.digests):
            raise RuntimeError("CUDA digest differs from CPU/reference fixture")
        return {"status":"PASS","gpu_id":gpu_id,"digest":output.digests.hex(),"oracle_source":vector["oracle_source"]}
    finally:
        for ptr in reversed(allocated):
            try: backend.free(ptr)
            except Exception: pass
        backend.close()


def main(argv=None):
    p=argparse.ArgumentParser(prog="sidecar-cuda-selftest")
    p.add_argument("--gpu-id",type=int,required=True);p.add_argument("--fixture","--vector",dest="fixture",required=True)
    p.add_argument("--library",default=os.environ.get("SIDECAR_CUDA_LIBRARY"))
    p.add_argument("--timeout-seconds",type=int,default=20,choices=range(1,31))
    p.add_argument("--execute",action="store_true",help="run exactly one vector on the selected GPU")
    p.add_argument("--_worker",action="store_true",help=argparse.SUPPRESS)
    a=p.parse_args(argv)
    try: vector=load_vector(a.fixture)
    except Exception as e: p.error(str(e))
    if a.gpu_id<0: p.error("gpu-id must be non-negative")
    if not a.execute:
        print(json.dumps({"status":"PLAN_ONLY","gpu_id":a.gpu_id,"batch_size":1,"launches":1,"retries":0,
                          "timeout_seconds":a.timeout_seconds,"fixture_sha256":hashlib.sha256(Path(a.fixture).read_bytes()).hexdigest(),
                          "digest_count":vector["digest_count"],"oracle_source":vector["oracle_source"],"cuda_library_loaded":False},sort_keys=True));return 0
    if not a._worker:
        if os.environ.get("SIDECAR_CUDA_SELFTEST_CONFIRM")!="1":
            p.error("execution requires SIDECAR_CUDA_SELFTEST_CONFIRM=1 after an idle GPU is confirmed")
        command=[sys.executable,"-m","sidecar_miner.cuda_selftest","--_worker","--execute","--gpu-id",str(a.gpu_id),"--fixture",a.fixture,"--timeout-seconds",str(a.timeout_seconds)]
        if a.library: command.extend(["--library",a.library])
        try:
            out=subprocess.run(command,capture_output=True,text=True,timeout=a.timeout_seconds,check=False)
            sys.stdout.write(out.stdout);sys.stderr.write(out.stderr);return out.returncode
        except subprocess.TimeoutExpired: print(json.dumps({"status":"TIMEOUT","gpu_id":a.gpu_id,"retries":0}));return 124
    try: print(json.dumps(_worker(a.gpu_id,a.fixture,a.library),sort_keys=True));return 0
    except Exception as e: print(json.dumps({"status":"FAIL","gpu_id":a.gpu_id,"error":str(e)},sort_keys=True));return 1


if __name__=="__main__": raise SystemExit(main())
