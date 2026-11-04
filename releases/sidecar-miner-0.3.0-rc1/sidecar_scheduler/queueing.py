from __future__ import annotations
from collections import deque
from dataclasses import dataclass

@dataclass
class Backpressure:
    max_gpu_to_fk:int=8
    max_fk_to_verify:int=8
    gpu_to_fk:deque=None
    fk_to_verify:deque=None
    active:dict=None
    generation:int=0
    def __post_init__(self):
        if self.max_gpu_to_fk<1 or self.max_fk_to_verify<1:raise ValueError('queue capacity must be positive')
        self.gpu_to_fk=self.gpu_to_fk or deque(); self.fk_to_verify=self.fk_to_verify or deque(); self.active=self.active or {}
    def enqueue_gpu(self,batch):
        if batch.generation!=self.generation:return False
        if len(self.gpu_to_fk)>=self.max_gpu_to_fk:return False
        self.gpu_to_fk.append(batch);return True
    def enqueue_verify(self,result):
        if result.generation!=self.generation:return False
        if len(self.fk_to_verify)>=self.max_fk_to_verify:return False
        self.fk_to_verify.append(result);return True
    def start_active(self,batch):
        if batch.generation!=self.generation:return False
        self.active[batch.batch_id]=batch;return True
    def accepts_active(self,batch_id,generation):
        batch=self.active.get(batch_id)
        return bool(batch and generation==self.generation==batch.generation)
    def finish_active(self,batch_id):return self.active.pop(batch_id,None)
    def new_generation(self,generation):
        if generation<=self.generation:raise ValueError('generation must increase')
        self.generation=generation
        self.gpu_to_fk.clear(); self.fk_to_verify.clear(); self.active.clear()
    def take_fk(self):return self.gpu_to_fk.popleft() if self.gpu_to_fk else None
    def take_verify(self):return self.fk_to_verify.popleft() if self.fk_to_verify else None
