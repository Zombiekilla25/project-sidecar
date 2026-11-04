"""Application mode selection over measured Sidecar and GPU end-to-end timings."""
from __future__ import annotations
from dataclasses import dataclass
import json
from pathlib import Path
from sidecar_scheduler.ingest import load_phk1_canary
from sidecar_scheduler.model import Decision,decide
from sidecar_scheduler.timing import TimingRecord

@dataclass(frozen=True)
class ScheduleChoice:
    mode:str
    decision:Decision
    reason:str
    forced:bool=False

def load_timing_inputs(gpu_path:str|None,fk_path:str|None):
    gpu=TimingRecord.load(gpu_path,'gpu') if gpu_path else None
    fk=None
    if fk_path:
        raw=json.loads(Path(fk_path).read_text())
        if isinstance(raw,dict) and raw.get('schema')=='sidecar-phk1-canary-result-v1':
            parsed=load_phk1_canary(fk_path)
            fk=TimingRecord.from_dict({'schema':'sidecar-fk-timing-v1','source':'PHK1 canary result','measured':True,'identity':parsed['identity'],'timings_us':parsed['timings_us']},'fk')
        else: fk=TimingRecord.from_dict(raw,'fk')
    return gpu,fk

class IntegratedScheduler:
    def __init__(self,mode='auto',gpu_timing=None,fk_timing=None,fk_backends=()):
        if mode not in ('auto','gpu-only','sidecar'):raise ValueError('mode must be auto, gpu-only, or sidecar')
        self.mode=mode;self.gpu_timing=gpu_timing;self.fk_timing=fk_timing;self.fk_backends=list(fk_backends)
    def healthy_fks(self):return [b for b in self.fk_backends if getattr(b,'healthy',True)]
    def choose(self,job=None):
        if self.mode=='gpu-only':return ScheduleChoice('gpu-only',Decision.INSUFFICIENT_DATA,'operator selected GPU-only; FK is disabled',True)
        healthy=self.healthy_fks()
        if self.mode=='sidecar':
            if not healthy:raise RuntimeError('sidecar mode requires a healthy FK backend')
            return ScheduleChoice('sidecar',Decision.INSUFFICIENT_DATA,'operator selected sidecar mode; no performance claim is implied',True)
        decision=decide(self.gpu_timing,self.fk_timing,fk_available=bool(healthy),fk_healthy=bool(healthy))
        if decision is Decision.SIDECAR_WINS:return ScheduleChoice('sidecar',decision,'matched measured end-to-end timing favors Sidecar')
        return ScheduleChoice('gpu-only',decision,'auto mode defaults to GPU-only without measured Sidecar win')
