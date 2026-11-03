from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Scheduler:
    mode: str = "gpu-only"
    fallback_count: int = 0
    def __post_init__(self):
        if self.mode not in ("gpu-only", "sidecar"): raise ValueError("invalid mode")
    def run_fk_or_fallback(self, backend, job, candidates):
        if self.mode == "gpu-only": return candidates
        try:
            backend.prepare(job)
            return backend.execute(job, candidates)
        except Exception:
            self.fallback_count += 1
            self.mode = "gpu-only"
            return candidates
