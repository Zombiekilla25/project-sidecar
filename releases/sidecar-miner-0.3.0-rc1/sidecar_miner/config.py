from __future__ import annotations
from dataclasses import dataclass
import json, os
from pathlib import Path
import re

@dataclass(frozen=True)
class Config:
    pool: str = ""
    wallet: str = ""
    worker: str = "sidecar"
    mode: str = "gpu-only"
    gpu: str = ""
    gpu_id: int | None = None
    reconnect_min: float = 1.0
    reconnect_max: float = 30.0
    fk_count: int = 1
    fk_devices: tuple[str, ...] = ()
    gpu_timing: str = ""
    fk_timing: str = ""
    pool_password: str = "x"
    live_enabled: bool = False
    canary_shares: int = 0
    qualification_store: str = ""
    cuda_qualification: str = ""
    cuda_library_sha256: str = ""
    cuda_source_sha256: str = ""
    cuda_fixture_sha256: str = ""
    fk_qualification: str = ""
    fk_bitstream_sha256: str = ""
    fk_target: str = ""
    @classmethod
    def load(cls, path: str | None = None, environ=None):
        env = os.environ if environ is None else environ
        data = {}
        if path:
            data = json.loads(Path(path).read_text())
            if not isinstance(data, dict): raise ValueError("config must be a JSON object")
            allowed={"pool","pool_host","pool_port","wallet","worker","mode","gpu","gpu_id",
                "reconnect_min","reconnect_max","fk_count","fk_devices","gpu_timing","fk_timing",
                "pool_password","password","live_enabled","canary_shares","qualification_store",
                "cuda_qualification","cuda_library_sha256","cuda_source_sha256","cuda_fixture_sha256",
                "fk_qualification","fk_bitstream_sha256","fk_target"}
            if "backend" in data:raise ValueError("unknown backend selection; use mode gpu-only, sidecar, or auto")
            unknown=set(data)-allowed
            if unknown:raise ValueError(f"unknown config field(s): {', '.join(sorted(unknown))}")
        def val(key, default): return env.get("SIDECAR_" + key.upper(), env.get(key.upper(), data.get(key, default)))
        mode = val("mode", "gpu-only")
        if mode not in ("gpu-only", "gpu_only", "sidecar", "auto"): raise ValueError("MODE must be auto, gpu-only, or sidecar")
        mode = "gpu-only" if mode == "gpu_only" else mode
        fk_count=int(val("fk_count",1))
        if fk_count not in (1,2,4,8): raise ValueError("FK_COUNT must be 1, 2, 4, or 8")
        raw_devices=val("fk_devices", [])
        if isinstance(raw_devices,str): raw_devices=[x for x in raw_devices.split(",") if x]
        if not isinstance(raw_devices,(list,tuple)) or any(not isinstance(x,str) or not re.fullmatch(r"fk[0-7]",x) for x in raw_devices):
            raise ValueError("FK_DEVICES must contain logical names fk0 through fk7")
        fk_devices=tuple(raw_devices)
        if len(set(fk_devices))!=len(fk_devices) or len(fk_devices)>fk_count:
            raise ValueError("FK_DEVICES must be unique and no more than FK_COUNT")
        raw_gpu_id=val("gpu_id", None)
        gpu_id=None if raw_gpu_id in (None, "") else int(raw_gpu_id)
        if gpu_id is not None and gpu_id < 0: raise ValueError("GPU_ID must be non-negative")
        live_raw=val("live_enabled", False)
        if isinstance(live_raw,str):
            if live_raw.lower() not in ("0","1","false","true","no","yes","off","on"):
                raise ValueError("LIVE_ENABLED must be a boolean")
            live_enabled=live_raw.lower() in ("1","true","yes","on")
        elif isinstance(live_raw,bool):live_enabled=live_raw
        else:raise ValueError("LIVE_ENABLED must be a boolean")
        canary_shares=int(val("canary_shares",0))
        if canary_shares<0 or canary_shares>1000:raise ValueError("CANARY_SHARES must be between 0 and 1000")
        pool_value=val("pool","")
        if not pool_value and val("pool_host","") and val("pool_port",""):
            host_value=str(val("pool_host",""))
            if ":" in host_value and not host_value.startswith("["):host_value=f"[{host_value}]"
            pool_value=f"{host_value}:{val('pool_port','')}"
        return cls(pool=str(pool_value), wallet=str(val("wallet", "")), worker=str(val("worker", "sidecar")), mode=mode,
                   gpu=str(val("gpu", "")), gpu_id=gpu_id, reconnect_min=float(val("reconnect_min", 1)), reconnect_max=float(val("reconnect_max", 30)),
                   fk_count=fk_count, fk_devices=fk_devices,
                   gpu_timing=str(val("gpu_timing", "")), fk_timing=str(val("fk_timing", "")),
                   pool_password=str(val("pool_password",val("password","x"))),live_enabled=live_enabled,canary_shares=canary_shares,
                   qualification_store=str(val("qualification_store","")),
                   cuda_qualification=str(val("cuda_qualification","")),
                   cuda_library_sha256=str(val("cuda_library_sha256","")),
                   cuda_source_sha256=str(val("cuda_source_sha256","")),
                   cuda_fixture_sha256=str(val("cuda_fixture_sha256","")),
                   fk_qualification=str(val("fk_qualification","")),
                   fk_bitstream_sha256=str(val("fk_bitstream_sha256","")),
                   fk_target=str(val("fk_target","")))
