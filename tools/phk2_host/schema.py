"""Dependency-free checks mirroring the checked-in JSON schemas."""
def validate_evidence(d):
 required={'schema','manifest','descriptor','job_range','status_trace','result_trace','timing','cpu_oracle_comparison'}
 if not required<=d.keys() or d['schema']!='PHK2-Evidence-v1': raise ValueError('not PHK2 Evidence-v1')
 if d['descriptor'].get('length')!=112 or len(d['descriptor'].get('sha256',''))!=64: raise ValueError('invalid descriptor identity')
 if not isinstance(d['status_trace'],list) or not isinstance(d['result_trace'],list): raise ValueError('traces must be arrays')
 timing=d['timing']; fields={'HOST_PACK_US','DESCRIPTOR_TX_US','FPGA_WORK_US','RESULT_RX_US','HOST_VERIFY_US','TOTAL_US'}
 if timing.get('measurement_class') not in ('MOCK','SILICON') or not fields<=timing.keys(): raise ValueError('invalid timing record')
 for name in fields:
  value=timing[name]
  if value is not None and (not isinstance(value,(float,int)) or value<0): raise ValueError(f'invalid timing {name}')
 return True
def validate_benchmark(d):
 fields={'schema_version','measurement_class','clock_mhz','tile_count','batch','work_items_per_sec','transport_fraction','fpga_fraction','power_w','performance_per_w'}
 if not fields<=d.keys() or d['schema_version']!='PHK2-Benchmark-v1' or d['measurement_class'] not in ('MOCK','SILICON'): raise ValueError('invalid benchmark v1 header')
 if d['batch']<1: raise ValueError('batch must be positive')
 for k in ('clock_mhz','work_items_per_sec','power_w','performance_per_w'):
  if d[k] is not None and d[k]<0: raise ValueError(f'{k} cannot be negative')
 for k in ('transport_fraction','fpga_fraction'):
  if d[k] is not None and not 0<=d[k]<=1: raise ValueError(f'{k} must be in [0,1]')
 return True
