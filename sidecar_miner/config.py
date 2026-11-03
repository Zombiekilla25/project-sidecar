from __future__ import annotations
from dataclasses import dataclass
import json, os
from pathlib import Path

@dataclass(frozen=True)
class Config:
    pool: str = ""
    wallet: str = ""
    worker: str = "sidecar"
    mode: str = "gpu-only"
    reconnect_min: float = 1.0
    reconnect_max: float = 30.0
    @classmethod
    def load(cls, path: str | None = None, environ=None):
        env = os.environ if environ is None else environ
        data = {}
        if path:
            data = json.loads(Path(path).read_text())
            if not isinstance(data, dict): raise ValueError("config must be a JSON object")
        def val(key, default): return env.get("SIDECAR_" + key.upper(), data.get(key, default))
        mode = val("mode", "gpu-only")
        if mode not in ("gpu-only", "sidecar"): raise ValueError("MODE must be gpu-only or sidecar")
        return cls(str(val("pool", "")), str(val("wallet", "")), str(val("worker", "sidecar")), mode,
                   float(val("reconnect_min", 1)), float(val("reconnect_max", 30)))
