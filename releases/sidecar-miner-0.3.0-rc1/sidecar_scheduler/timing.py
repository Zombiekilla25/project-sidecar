from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json, math

FK_FIELDS=('program_time_us','backend_open_us','target_revalidation_us','hello_us','host_pack_us','input_stream_us','fpga_compute_us','output_stream_us','host_compose_us','verify_us','vector_total_us','logical_input_bits','logical_output_bits','physical_scan_clocks','jtag_clock_hz','batch_size')
GPU_FIELDS=('job_setup_us','host_to_gpu_us','kernel_us','gpu_to_host_us','verification_us','total_us','batch_size','throughput')

@dataclass(frozen=True)
class TimingRecord:
    schema: str
    source: str
    measured: bool
    values: dict
    identity: dict
    @classmethod
    def load(cls,path,kind):
        obj=json.loads(Path(path).read_text())
        return cls.from_dict(obj,kind)
    @classmethod
    def from_dict(cls,obj,kind):
        if not isinstance(obj,dict): raise ValueError('timing input must be an object')
        schema='sidecar-fk-timing-v1' if kind=='fk' else 'sidecar-gpu-timing-v1'
        if obj.get('schema')!=schema: raise ValueError(f'expected schema {schema}')
        if not isinstance(obj.get('source'),str) or not obj['source']: raise ValueError('source identity required')
        measured=obj.get('measured')
        if not isinstance(measured,bool): raise ValueError('measured boolean required')
        values=obj.get('timings_us')
        if not isinstance(values,dict): raise ValueError('timings_us object required')
        values=dict(values)
        for key,value in tuple(values.items()):
            if isinstance(value,str) and value.upper()=='UNKNOWN': values[key]=None
        fields=FK_FIELDS if kind=='fk' else GPU_FIELDS
        for key,value in values.items():
            if key not in fields: raise ValueError(f'unknown timing field: {key}')
            if value is not None and (isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<0): raise ValueError(f'invalid timing value: {key}')
        required=('vector_total_us',) if kind=='fk' else ('total_us','batch_size')
        for key in required:
            if key not in values: raise ValueError(f'missing required timing field: {key}')
        if kind=='gpu' and values['batch_size'] is not None and (not isinstance(values['batch_size'],int) or isinstance(values['batch_size'],bool) or values['batch_size']<=0): raise ValueError('batch_size must be positive integer or null')
        if kind=='fk' and values.get('batch_size') is not None and (not isinstance(values['batch_size'],int) or isinstance(values['batch_size'],bool) or values['batch_size']<=0): raise ValueError('batch_size must be positive integer or null')
        for key in ('logical_input_bits','logical_output_bits','physical_scan_clocks','jtag_clock_hz','batch_size') if kind=='fk' else ():
            if values.get(key) is not None and (not isinstance(values[key],int) or isinstance(values[key],bool) or values[key]<0): raise ValueError(f'{key} must be nonnegative integer or null')
        ident=obj.get('identity',{})
        if not isinstance(ident,dict): raise ValueError('identity must be an object')
        if kind=='fk':
            for key in ('job_fingerprint','result_identity'):
                if not isinstance(ident.get(key),str) or not ident[key]: raise ValueError(f'missing result identity {key}')
        elif not isinstance(ident.get('job_fingerprint'),str) or not ident['job_fingerprint']:
            raise ValueError('missing GPU job_fingerprint identity')
        return cls(schema,obj['source'],measured,values,ident)

def fk_total_us(record:TimingRecord):
    direct=record.values.get('vector_total_us')
    if direct is not None:return float(direct)
    keys=('program_time_us','backend_open_us','target_revalidation_us','hello_us','host_pack_us','input_stream_us','fpga_compute_us','output_stream_us','host_compose_us','verify_us')
    vals=[record.values.get(k) for k in keys]
    return sum(vals) if all(v is not None for v in vals) else None

def gpu_total_us(record:TimingRecord):
    value=record.values.get('total_us')
    return float(value) if value is not None else None
