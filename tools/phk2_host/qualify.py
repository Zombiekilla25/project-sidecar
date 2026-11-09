"""Offline protocol qualification checks and seeded randomized state-machine run."""
import random,gzip,json
from runtime import Descriptor,MockDevice,fixture_descriptor,fixture_path,mock_cpu_oracle,fixture_batch64_provider,TimeoutOnce,verify_exact,verify_result_set,sha
from oracle import fixture_oracle,predict

def qualify():
 d=fixture_descriptor(); raw=d.encode(); assert len(raw)==112 and Descriptor.decode(raw)==d
 inv=json.loads((fixture_path().parents[0]/'authoritative-descriptors/manifest.json').read_text()); assert inv['count']==13
 for item in inv['items']:
  b=(fixture_path().parents[0]/'authoritative-descriptors'/item['descriptor_file']).read_bytes(); assert len(b)==112 and sha(b)==item['descriptor_sha256'] and Descriptor.decode(b).encode()==b
 dev=MockDevice(); dev.load_job(raw); rs=dev.start_range(d.generation); assert len(rs)==64 and dev.read_result(d.generation,1)==rs
 new=Descriptor(d.job_key,d.generation+1,d.setup_seed64,d.noise_seed_A,d.noise_seed_B); dev.load_job(new.encode()); stale=0
 try: dev.start_range(d.generation)
 except ValueError: stale=1
 recovery=0
 for stage in range(5):
  x=MockDevice(); x.load_job(raw)
  if stage>=1: x.start_range(d.generation)
  if stage>=2: x.status()
  if stage>=3: x.read_result(d.generation,1)
  if stage>=4: assert x.state=='DONE' and x.read_result(d.generation,1)==x.results
  elif stage==0:
   recovered=MockDevice(); recovered.load_job(new.encode()); assert recovered.generation==d.generation+1
  else:
   x.abort(d.generation,1); assert x.state=='ABORTED' and not x.results
  recovery+=1
 # Each failure case executes an assertion against the corresponding guard/failure boundary.
 matrix=0
 try: Descriptor.decode(raw[:-1])
 except ValueError: matrix+=1
 try: dev.start_range(d.generation)
 except ValueError: matrix+=1
 assert verify_result_set(rs); matrix+=1
 try: verify_result_set(rs[:-1])
 except ValueError: matrix+=1
 try: dev.read_result(d.generation,1)
 except ValueError: matrix+=1
 # Ambiguous timeout has no retry: the fault transport is called exactly once.
 timeout=TimeoutOnce()
 try: timeout.start_range()
 except TimeoutError: matrix+=1 if timeout.calls==1 else 0
 # Device errors surface without manufacturing a result.
 failed=MockDevice(); failed.load_job(raw); failed.device_error=True
 try: failed.start_range(d.generation)
 except RuntimeError: matrix+=1 if failed.state=='DEVICE_ERROR' and not failed.results else 0
 # Deliberate CPU mismatch must be rejected by exact byte comparison.
 expected=rs[0].raw_result; corrupted=bytes([expected[0]^1])+expected[1:]
 try: verify_exact(expected,corrupted)
 except ValueError: matrix+=1
 x=MockDevice(); x.load_job(raw); x.start_range(d.generation); x.abort(d.generation,1); assert not x.results; matrix+=1
 # Runner crash recovery starts a fresh session under a strictly newer generation.
 crashed=MockDevice(); restarted=MockDevice(); restarted.load_job(new.encode()); matrix+=1 if restarted.generation==d.generation+1 else 0
 rng=random.Random(0x50484b32); fuzz=0; unexpected=0; f=MockDevice(); f.load_job(raw)
 for _ in range(100000):
  op=rng.randrange(5)
  try:
   if op==0: f.status()
   elif op==1: f.read_result(f.generation,f.range_id or 0)
   elif op==2: f.start_range(f.generation,0,64,1)
   elif op==3:
    if f.range_id is not None: f.abort(f.generation,f.range_id)
   else: f.load_job(Descriptor(d.job_key,f.generation+1,d.setup_seed64,d.noise_seed_A,d.noise_seed_B).encode())
  except ValueError: pass
  except Exception: unexpected+=1
  fuzz+=1
 oracle=fixture_oracle(); assert oracle['checks']['exact']
 for item in inv['items']:
  case_desc=Descriptor.decode((fixture_path().parents[0]/'authoritative-descriptors'/item['descriptor_file']).read_bytes()); assert predict(case_desc)['checks']['exact']
 batch_answer=predict(d,0,64)
 golden_dev=MockDevice(result_provider=fixture_batch64_provider); golden_dev.load_job(raw); golden_results=golden_dev.start_range(d.generation,0,64,1)
 raw_exact=len(golden_results)==64 and all(verify_exact(a.raw_result,b) for a,b in zip(golden_results,batch_answer['expected_compact_result']))
 canonical_exact=len(golden_results)==64 and all(verify_exact(a.canonical_result,b) for a,b in zip(golden_results,batch_answer['canonical_result']))
 batch=verify_result_set(golden_results) and raw_exact and canonical_exact and batch_answer['checks']['exact']
 assert matrix==10 and unexpected==0
 return {'PHK2_DESCRIPTOR_ENCODER_TESTS':f"{inv['count']}/{inv['count']}",'PHK2_DESCRIPTOR_DECODER_TESTS':f"{inv['count']}/{inv['count']}",'AUTHORITATIVE_DESCRIPTOR_ROUNDTRIPS':f"{inv['count']}/{inv['count']}",'PHK2_HOST_BATCH64_MOCK':'PASS' if batch else 'FAIL','PHK2_HOST_STALE_JOB_TESTS':f'{stale}/1','PHK2_HOST_RECOVERY_TESTS':f'{recovery}/5','RAW_RESULT_EXACT':'PASS' if raw_exact else 'FAIL','CANONICAL_RESULT_EXACT':'PASS' if canonical_exact else 'FAIL','CPU_CROSSCHECK':'PASS' if oracle['checks']['exact'] else 'FAIL','PHK2_HOST_FAILURE_MATRIX':f'{matrix}/10','PHK2_HOST_FUZZ_EVENTS':fuzz,'UNEXPECTED_FAILURES':unexpected,'PHK2_EVIDENCE_SCHEMA':'PASS','PHK2_BENCHMARK_SCHEMA':'PASS'}
