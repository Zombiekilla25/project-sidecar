from __future__ import annotations
from typing import Protocol
from .models import MiningJob, Candidate

class GpuBackend(Protocol):
    def prepare_job(self, job: MiningJob) -> None: ...
    def compute_batch(self, job: MiningJob, batch_size: int) -> list[Candidate]: ...

class Fk33Backend(Protocol):
    def prepare(self, job: MiningJob) -> None: ...
    def execute(self, job: MiningJob, candidates: list[Candidate]) -> list[Candidate]: ...

class MockGpuBackend:
    """Deterministic contract mock; produces candidates only, never PearlHash proofs."""
    def __init__(self): self.prepared = None; self.batches = 0
    def prepare_job(self, job): self.prepared = job.fingerprint
    def compute_batch(self, job, batch_size):
        if self.prepared != job.fingerprint: raise RuntimeError("GPU job was not prepared")
        if batch_size < 1: raise ValueError("batch_size must be positive")
        self.batches += 1
        return []

class UnavailableFk33Backend:
    def prepare(self, job): raise RuntimeError("FK33 backend unavailable")
    def execute(self, job, candidates): raise RuntimeError("FK33 backend unavailable")


def timed_gpu_batch(backend,job,batch_size,telemetry):
    """Time a high-level GPU backend call; time is measured, never estimated."""
    import time
    start=time.perf_counter()
    try: return backend.compute_batch(job,batch_size)
    finally: telemetry.record_stage("gpu_backend",time.perf_counter()-start)

def timed_fk_execute(backend,job,candidates,telemetry):
    """Time one high-level FK backend call without exposing transport details."""
    import time
    start=time.perf_counter()
    try: return backend.execute(job,candidates)
    finally: telemetry.record_stage("fk_backend",time.perf_counter()-start)
