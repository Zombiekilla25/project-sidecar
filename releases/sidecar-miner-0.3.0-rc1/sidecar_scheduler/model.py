from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import math
from .timing import TimingRecord, fk_total_us, gpu_total_us

class Decision(str,Enum):
    GPU_ONLY_WINS='GPU_ONLY_WINS'
    SIDECAR_WINS='SIDECAR_WINS'
    INSUFFICIENT_DATA='INSUFFICIENT_DATA'
    FK_UNAVAILABLE='FK_UNAVAILABLE'
    FK_UNHEALTHY='FK_UNHEALTHY'

@dataclass(frozen=True)
class Accounting:
    gpu_only_total_us: float|None
    sidecar_total_us: float|None
    sidecar_speedup: float|None
    transfer_percent: float|None
    fpga_compute_percent: float|None
    host_overhead_percent: float|None
    break_even_transfer_time_us: float|None
    end_to_end_throughput_items_s: float|None

def _percent(v,total): return 100*v/total if v is not None and total and total>0 else None

def account(gpu:TimingRecord|None,fk:TimingRecord|None,item_count:int|None=None)->Accounting:
    gt=gpu_total_us(gpu) if gpu else None; st=fk_total_us(fk) if fk else None
    count=item_count or (fk.values.get('batch_size') if fk else None) or (gpu.values.get('batch_size') if gpu else None)
    speed=gt/st if gt is not None and st and st>0 else None
    v=fk.values if fk else {}
    transfer=None
    if st:
        nums=[v.get('input_stream_us'),v.get('output_stream_us')]
        if all(x is not None for x in nums): transfer=sum(nums)
    compute=v.get('fpga_compute_us')
    host=None
    if st and transfer is not None and compute is not None: host=max(0.0,st-transfer-compute)
    throughput=count*1e6/st if count and st and st>0 else None
    return Accounting(gt,st,speed,_percent(transfer,st),_percent(compute,st),_percent(host,st),max(0.0,gt-(st-transfer)) if gt is not None and st is not None and transfer is not None else None,throughput)

def decide(gpu:TimingRecord|None,fk:TimingRecord|None,fk_available=True,fk_healthy=True)->Decision:
    if not fk_available:return Decision.FK_UNAVAILABLE
    if not fk_healthy:return Decision.FK_UNHEALTHY
    a=account(gpu,fk)
    if a.gpu_only_total_us is None or a.sidecar_total_us is None:return Decision.INSUFFICIENT_DATA
    if not gpu.measured or not fk.measured:return Decision.INSUFFICIENT_DATA
    if gpu.identity.get('job_fingerprint')!=fk.identity.get('job_fingerprint'):return Decision.INSUFFICIENT_DATA
    if gpu.values.get('batch_size') is None or gpu.values.get('batch_size')!=fk.values.get('batch_size'):return Decision.INSUFFICIENT_DATA
    return Decision.SIDECAR_WINS if a.sidecar_total_us<a.gpu_only_total_us else Decision.GPU_ONLY_WINS

@dataclass(frozen=True)
class BatchPrediction:
    batch_size:int
    predicted_total_us:float
    throughput_items_s:float
    speedup_vs_gpu_only:float|None

def simulate_batch_sizes(gpu_total_us:float,gpu_batch:int,fk_fixed_us:float,fk_transport_per_item_us:float,fk_compute_per_item_us:float,verify_per_item_us:float=0.0,batches=(1,2,4,8,16,32,64),host_per_item_us:float=0.0):
    nums=(gpu_total_us,fk_fixed_us,fk_transport_per_item_us,fk_compute_per_item_us,verify_per_item_us,host_per_item_us)
    if any(not math.isfinite(x) or x<0 for x in nums) or gpu_batch<1: raise ValueError('invalid simulator timing')
    out=[]
    for n in batches:
        if n<1:continue
        gpu=n*gpu_total_us/gpu_batch
        # Sidecar component timings describe the replaced stage plus its end-to-end overhead.
        # Do not add the full GPU-only kernel time again to the accelerated path.
        total=fk_fixed_us+n*(fk_transport_per_item_us+fk_compute_per_item_us+verify_per_item_us+host_per_item_us)
        out.append(BatchPrediction(n,total,n*1e6/total if total else 0,gpu/total if total else None))
    return out

def recommended_batch(predictions):
    return max(predictions,key=lambda p:p.throughput_items_s).batch_size if predictions else None

def break_even_batch(gpu_total_us_per_item,fk_fixed_us,fk_per_item_us):
    if gpu_total_us_per_item<=fk_per_item_us:return None
    return max(1,math.ceil(fk_fixed_us/(gpu_total_us_per_item-fk_per_item_us)))

@dataclass(frozen=True)
class PipelinePrediction:
    mode:str
    batch_time_us:float
    steady_state_throughput_items_s:float
    simulated:bool=True

def pipeline_prediction(gpu_us:float,fk_us:float,verify_us:float,item_count:int,mode:str):
    if min(gpu_us,fk_us,verify_us)<0 or item_count<=0:raise ValueError('invalid pipeline inputs')
    if mode=='SERIAL': cycle=gpu_us+fk_us+verify_us
    elif mode=='DOUBLE_BUFFERED': cycle=max(gpu_us,fk_us)+verify_us
    elif mode=='PIPELINED': cycle=max(gpu_us,fk_us,verify_us)
    else:raise ValueError('mode must be SERIAL, DOUBLE_BUFFERED, or PIPELINED')
    return PipelinePrediction(mode,cycle,item_count*1e6/cycle if cycle else 0)
