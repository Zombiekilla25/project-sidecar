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
