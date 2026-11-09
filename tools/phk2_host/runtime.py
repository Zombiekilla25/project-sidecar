"""PHK2 frozen host contract and offline semantic mock; no hardware transport."""
from __future__ import annotations
import hashlib, struct
from dataclasses import dataclass
from pathlib import Path
SIZE=112
@dataclass(frozen=True)
class Descriptor:
    job_key:bytes; generation:int; setup_seed64:int; noise_seed_A:bytes; noise_seed_B:bytes
    def __post_init__(self):
        if len(self.job_key)!=32 or len(self.noise_seed_A)!=32 or len(self.noise_seed_B)!=32: raise ValueError('three byte strings must be 32 bytes')
        if not 0<=self.generation<2**64 or not 0<=self.setup_seed64<2**64: raise ValueError('u64 field out of range')
    def encode(self): return self.job_key+struct.pack('<QQ',self.generation,self.setup_seed64)+self.noise_seed_A+self.noise_seed_B
    @classmethod
    def decode(cls,b):
        if len(b)!=SIZE: raise ValueError('descriptor length must equal 112')
        return cls(b[:32],*struct.unpack_from('<QQ',b,32),b[48:80],b[80:112])
def sha(b): return hashlib.sha256(b).hexdigest()
def fixture_path(): return Path(__file__).resolve().parents[2]/'fixtures/phk2-host-runtime/authoritative-vector-001'
def fixture_descriptor(): return Descriptor.decode((fixture_path()/'descriptor.bin').read_bytes())
def mock_cpu_oracle(desc:Descriptor,generation:int,start:int=0,count:int=64,range_id:int=1):
    """Independent host expected values for explicitly mock-only work items."""
    values=[]
    for slot in range(count):
        row,col=divmod(start+slot,8)
        raw=hashlib.sha256(desc.encode()+struct.pack('<QHHI',generation,range_id,slot,start)).digest()
        canonical=hashlib.sha256(b'PHK2-CANONICAL-MOCK-v1'+raw).digest()
        values.append(Result(generation,range_id,slot,row,col,raw,canonical))
    return values
@dataclass(frozen=True)
class Result:
    generation:int; range_id:int; slot:int; row_tile:int; col_tile:int; raw_result:bytes; canonical_result:bytes
    def encode(self):
        if len(self.raw_result)!=32 or len(self.canonical_result)!=32: raise ValueError('results must be 32 bytes')
        return struct.pack('<QHHHH',self.generation,self.range_id,self.slot,self.row_tile,self.col_tile)+self.raw_result+self.canonical_result
class MockDevice:
    """Deterministic LOAD_JOB/START_RANGE/STATUS/READ_RESULT/ABORT mock."""
    def __init__(self): self.generation=None; self.job=None; self.range_id=None; self.results=[]; self.state='IDLE'; self.trace=[]; self.device_error=False
    def ev(self,op,**x): self.trace.append({'op':op,'state':self.state,**x})
    def load_job(self,raw):
        d=Descriptor.decode(raw)
        if self.generation is not None and d.generation<=self.generation: self.ev('LOAD_JOB_REJECT',generation=d.generation); raise ValueError('generation must increase')
        self.job=d; self.generation=d.generation; self.results=[]; self.range_id=None; self.state='READY'; self.ev('LOAD_JOB',generation=d.generation); return d.generation
    def start_range(self,generation,start=0,count=64,range_id=1):
        if generation!=self.generation or self.job is None: self.ev('START_RANGE_REJECT',generation=generation); raise ValueError('stale generation')
        if count!=64 or start<0 or start+count>65536: raise ValueError('range must contain 64 valid tile indices')
        if self.device_error: self.state='DEVICE_ERROR'; self.ev('DEVICE_ERROR',generation=generation); raise RuntimeError('mock device error')
        self.range_id=range_id; self.state='RUNNING'; self.results=[]; self.ev('START_RANGE',generation=generation,start=start,count=count,range_id=range_id)
        for slot in range(count):
            row,col=divmod(start+slot,8)
            raw=hashlib.sha256(self.job.encode()+struct.pack('<QHHI',generation,range_id,slot,start)).digest()
            canonical=hashlib.sha256(b'PHK2-CANONICAL-MOCK-v1'+raw).digest()
            self.results.append(Result(generation,range_id,slot,row,col,raw,canonical))
        self.state='DONE'; return list(self.results)
    def status(self): self.ev('STATUS',generation=self.generation); return self.state
    def read_result(self,generation,range_id):
        if (generation,range_id)!=(self.generation,self.range_id): self.ev('READ_RESULT_REJECT',generation=generation); raise ValueError('stale result identity')
        self.ev('READ_RESULT',generation=generation,range_id=range_id,count=len(self.results)); return list(self.results)
    def abort(self,generation,range_id):
        if (generation,range_id)!=(self.generation,self.range_id): raise ValueError('abort identity mismatch')
        self.results=[]; self.state='ABORTED'; self.ev('ABORT',generation=generation,range_id=range_id)
def evidence(d,rid,results,timing,oracle,trace):
    return {'schema':'PHK2-Evidence-v1','manifest':{'mode':'mock','descriptor_sha256':sha(d.encode()),'target_image_identity':None},'descriptor':{'length':112,'sha256':sha(d.encode()),'generation':d.generation},'job_range':{'range_id':rid,'result_count':len(results)},'status_trace':trace,'result_trace':[{'slot':r.slot,'generation':r.generation,'row_tile':r.row_tile,'col_tile':r.col_tile,'raw_result_hex':r.raw_result.hex(),'canonical_result_hex':r.canonical_result.hex()} for r in results],'timing':timing,'cpu_oracle_comparison':oracle}

class TimeoutOnce:
    """Fault transport used to assert ambiguous commands are never retried."""
    def __init__(self): self.calls=0
    def start_range(self,*args):
        self.calls+=1
        raise TimeoutError('mock ambiguous transport timeout')
def verify_result_set(results,count=64):
    slots=[r.slot for r in results]
    if len(results)!=count or len(set(slots))!=count or set(slots)!=set(range(count)):
        raise ValueError('missing or duplicate result')
    return True
def verify_exact(expected:bytes,actual:bytes):
    if expected!=actual: raise ValueError('CPU result mismatch')
    return True
