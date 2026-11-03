from __future__ import annotations
import time
from .models import MiningJob

def decode_prl_notify(message: object, sequence: int, difficulty=None, telemetry=None) -> MiningJob:
    started=time.perf_counter()
    try:
        if not isinstance(message,dict) or message.get("method")!="mining.notify" or message.get("id") is not None: raise ValueError("expected PRL mining.notify notification")
        return MiningJob.from_notify(message.get("params"),sequence,difficulty)
    finally:
        if telemetry is not None: telemetry.record_stage("job_parse",time.perf_counter()-started)
