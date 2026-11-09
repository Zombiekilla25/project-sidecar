#!/usr/bin/env python3
import argparse,gzip,json,time
from pathlib import Path
from runtime import MockDevice,evidence,fixture_descriptor,fixture_path,mock_cpu_oracle,verify_result_set,sha
from oracle import fixture_oracle
from schema import validate_evidence,validate_benchmark

def run_batch(out=None):
 total0=time.perf_counter_ns(); d=fixture_descriptor()
 t=time.perf_counter_ns(); packed=d.encode(); pack_us=(time.perf_counter_ns()-t)/1000
 dev=MockDevice(); t=time.perf_counter_ns(); dev.load_job(packed); tx_us=(time.perf_counter_ns()-t)/1000
 t=time.perf_counter_ns(); generated=dev.start_range(d.generation); dev.status(); work_us=(time.perf_counter_ns()-t)/1000
 t=time.perf_counter_ns(); results=dev.read_result(d.generation,1); rx_us=(time.perf_counter_ns()-t)/1000
 t=time.perf_counter_ns(); oracle=fixture_oracle()
 fixture=json.loads(gzip.open(fixture_path()/'cpu_workgen_trace.json.gz','rt').read()); captured=(fixture_path()/'operand_tile.bin').read_bytes()
 expected=mock_cpu_oracle(d,d.generation,0,64,1)
 mock_exact=verify_result_set(results) and all(a.raw_result==b.raw_result and a.canonical_result==b.canonical_result for a,b in zip(results,expected))
 match=mock_exact and sha(captured)==fixture['tile_sha256'] and len(fixture['records'])==4096 and oracle['checks']['exact']
 verify_us=(time.perf_counter_ns()-t)/1000; total_us=(time.perf_counter_ns()-total0)/1000
 timing={'measurement_class':'MOCK','HOST_PACK_US':pack_us,'DESCRIPTOR_TX_US':tx_us,'FPGA_WORK_US':work_us,'RESULT_RX_US':rx_us,'HOST_VERIFY_US':verify_us,'TOTAL_US':total_us}
 ev=evidence(d,1,results,timing,{'classification':'QUALIFIED_CPU_GOLDEN_CAPTURE_REPLAY','fixture_operand_sha256':sha(captured),'trace_operand_sha256':fixture['tile_sha256'],'records':len(fixture['records']),'oracle_checks':oracle['checks'],'mock_batch_cpu_exact':mock_exact,'exact':match},dev.trace)
 ev['manifest']['target_image_status']='NOT_PHYSICALLY_QUALIFIED'
 validate_evidence(ev)
 if out: Path(out).write_text(json.dumps(ev,indent=2)+'\n')
 return ev,match

def main():
 p=argparse.ArgumentParser(prog='phk2-host'); p.add_argument('command',choices=['check','descriptor','oracle','dry-run','replay','benchmark-ingest','benchmark-compare']); p.add_argument('--input'); p.add_argument('--output'); p.add_argument('--phk1'); p.add_argument('--phk2'); p.add_argument('--start',type=int,default=0); p.add_argument('--count',type=int,default=1); a=p.parse_args(); d=fixture_descriptor()
 if a.command=='descriptor':
  if a.input: d=__import__('runtime').Descriptor.decode(Path(a.input).read_bytes())
  print(json.dumps({'length':112,'sha256':sha(d.encode()),'decoded':{'job_key':d.job_key.hex(),'generation_fence':d.generation,'setup_seed64':d.setup_seed64,'noise_seed_A':d.noise_seed_A.hex(),'noise_seed_B':d.noise_seed_B.hex()}},indent=2)); return 0
 if a.command=='oracle':
  if not a.input: raise SystemExit('oracle requires --input with exactly 112 descriptor bytes')
  from oracle import predict
  d=__import__('runtime').Descriptor.decode(Path(a.input).read_bytes()); answer=predict(d,a.start,a.count)
  obj={'schema':'PHK2-CPU-Oracle-Result-v1','capture':answer['capture'],'descriptor_sha256':sha(d.encode()),'range':{'start':a.start,'count':a.count},'expected_operands_sha256':[sha(x) for x in answer['expected_operands']],'expected_compact_result_hex':[x.hex() for x in answer['expected_compact_result']],'canonical_result_hex':[x.hex() for x in answer['canonical_result']],'checks':answer['checks']}
  target=Path(a.output) if a.output else None
  if target: target.write_text(json.dumps(obj,indent=2)+'\n')
  else: print(json.dumps(obj,indent=2))
  return 0 if answer['checks']['exact'] else 1
 if a.command=='check':
  from qualify import qualify
  print(json.dumps(qualify(),indent=2)); return 0
 if a.command in ('dry-run','replay'):
  if a.command=='replay' and a.input:
   ev=json.loads(Path(a.input).read_text()); validate_evidence(ev); ok=ev.get('cpu_oracle_comparison',{}).get('exact') is True
   print('PHK2_EVIDENCE_REPLAY='+('PASS' if ok else 'FAIL')); return 0 if ok else 1
  ev,ok=run_batch(a.output); print('PHK2_HOST_BATCH64_MOCK='+('PASS' if ok else 'FAIL')); return 0 if ok else 1
 if a.command=='benchmark-compare':
  from benchmark import compare
  print(json.dumps(compare(json.loads(Path(a.phk1).read_text()),json.loads(Path(a.phk2).read_text())),indent=2)); return 0
 if a.command=='benchmark-ingest':
  q=json.loads(Path(a.input).read_text()); required={'schema_version','clock_mhz','tile_count','batch','work_items_per_sec','transport_fraction','fpga_fraction','power_w','performance_per_w'}
  if not required<=q.keys(): raise SystemExit('benchmark schema fields missing')
  validate_benchmark(q)
  print(json.dumps({'valid':True,'record':q},indent=2)); return 0
if __name__=='__main__': main()
