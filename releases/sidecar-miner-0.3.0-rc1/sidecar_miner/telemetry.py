from dataclasses import dataclass, asdict, field
import time
@dataclass
class Telemetry:
    pool_state: str = "disconnected"
    mode: str = "gpu-only"
    scheduler_decision: str = "INSUFFICIENT_DATA"
    job_generation: int | None = None
    current_job_id: str | None = None
    job_received_at: float | None = None
    accepted_shares: int = 0
    rejected_shares: int = 0
    stale_shares: int = 0
    stale_results: int = 0
    gpu_jobs: int = 0
    gpu_batches: int = 0
    fk_jobs: int = 0
    fk_batches: int = 0
    gpu_seconds: float = 0.0
    fk_seconds: float = 0.0
    transfer_seconds: float = 0.0
    fk_transfer_seconds: float | None = None
    fk_compute_seconds: float | None = None
    verification_seconds: float = 0.0
    end_to_end_seconds: float = 0.0
    fallback_count: int = 0
    backend_health: dict | None = None
    stage_seconds: dict = field(default_factory=dict)
    @property
    def job_age_seconds(self): return None if self.job_received_at is None else max(0.0,time.time()-self.job_received_at)
    def record_stage(self,name,seconds): self.stage_seconds[name]=self.stage_seconds.get(name,0.0)+max(0.0,float(seconds))
    def as_dict(self):
        d=asdict(self); d["job_age_seconds"]=self.job_age_seconds; return d
