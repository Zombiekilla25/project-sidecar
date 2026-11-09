"""Offline exact-frame transport qualification, failure matrix and stress."""
from __future__ import annotations
import random,struct,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent; sys.path.insert(0,str(HERE))
from runtime import Descriptor,fixture_descriptor,fixture_path,verify_exact,verify_result_set
from board_protocol import *
from board_transport import HostTransportAdapter,SoftwareTransportEmulator
from oracle import predict

def qualify():
 d=fixture_descriptor(); em=SoftwareTransportEmulator(); host=HostTransportAdapter(em)
 hello=host.hello(); assert hello['descriptor_bytes']==112 and hello['max_batch']==64
 assert host.load_job(d.encode())==d.generation
 assert len(encode_descriptor(d))==112 and decode_descriptor(encode_descriptor(d))==d
 host.start_range(d.generation,0,64,1); status=host.status(); assert status.flags&FLAG_RESULT_READY and not status.flags&FLAG_BUSY
 results=host.read_result(d.generation,1); expected=predict(d,0,64)
 assert verify_result_set(results) and len(results)==64
 raw_exact=all(verify_exact(r.raw_result,x) for r,x in zip(results,expected['expected_compact_result']))
 canon_exact=all(verify_exact(r.canonical_result,x) for r,x in zip(results,expected['canonical_result']))
 assert raw_exact and canon_exact and expected['checks']['exact']
 for a,b in zip(encode_descriptor(d),d.encode()): assert a==b
 res_roundtrip=all(decode_result(encode_result(r))==r for r in results)
 assert res_roundtrip
 checks={'HOST_TO_TRANSPORT_HELLO':hello['profile_id']==3,'HOST_TO_TRANSPORT_DESCRIPTOR':len(encode_descriptor(d))==112,'HOST_TO_TRANSPORT_BATCH64':len(results)==64,'HOST_TO_TRANSPORT_RESULT':res_roundtrip,'PHK2_BOARD_MOCK_END_TO_END':raw_exact and canon_exact and expected['checks']['exact']}
 # 14 negative/edge scenarios; each case passes only when the defined error/state is observed.
 failures=0
 def expect_error(fn,code):
  try: fn()
  except ProtocolError as e:
   if e.code==code: return True
  return False
 def wire_error(device,raw,code):
  frame=Frame.decode(device.exchange(raw)); return bool(frame.flags&ERROR) and len(frame.payload)==2 and struct.unpack('<H',frame.payload)[0]==int(code)
 x=SoftwareTransportEmulator(); failures+=wire_error(x,request(0x7e,0),ErrorCode.BAD_OPCODE)
 x=SoftwareTransportEmulator(); failures+=wire_error(x,request(Opcode.LOAD_DESCRIPTOR,0,b'0'*111),ErrorCode.BAD_LENGTH)
 x=SoftwareTransportEmulator(); failures+=wire_error(x,request(Opcode.LOAD_DESCRIPTOR,0,b'0'*113),ErrorCode.BAD_LENGTH)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); stale=encode_range(d.generation,d.job_key,0,1,1); stale=struct.pack('<Q',d.generation-1)+stale[8:]; failures+=wire_error(x,request(Opcode.START_RANGE,3,stale),ErrorCode.STALE_JOB)
 x=SoftwareTransportEmulator(); x.force_fifo_full=True; h=HostTransportAdapter(x); failures+=expect_error(h.hello,ErrorCode.FIFO_FULL)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.start_range(d.generation,0,1,1); h.abort(d.generation,1); empty=encode_read_request(d.generation,d.job_key,1,0,1); failures+=wire_error(x,request(Opcode.READ_RESULT,2,empty),ErrorCode.FIFO_EMPTY)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); stale=encode_range(d.generation,d.job_key,0,1,9); stale=stale[:8]+bytes([d.job_key[0]^1])+stale[9:]; failures+=wire_error(x,request(Opcode.START_RANGE,3,stale),ErrorCode.STALE_JOB)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.start_range(d.generation,0,1,7); failures+=expect_error(lambda:h.start_range(d.generation,0,1,7),ErrorCode.DUPLICATE_START)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); failures+=expect_error(lambda:h.read_result(d.generation,1),ErrorCode.NOT_READY)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.start_range(d.generation,0,1,2); h.abort(d.generation,2); failures+=bool(h.status().flags&FLAG_ABORTED)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.reset(); failures+=x.descriptor is None and h._descriptor is None
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); x.drop_next_response=True; before=x.calls
 try: h.hello()
 except TimeoutError: failures+=x.calls==before+1
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.start_range(d.generation,0,1,3); x.truncate_next_result=True; failures+=expect_error(lambda:h.read_result(d.generation,3),ErrorCode.BAD_LENGTH)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.start_range(d.generation,0,1,4); x.corrupt_next_result=True; corrupt=h.read_result(d.generation,4)[0]; failures+=bool(corrupt.raw_result!=expected['expected_compact_result'][0] or corrupt.canonical_result!=expected['canonical_result'][0])
 x=SoftwareTransportEmulator(); bad=bytearray(request(Opcode.HELLO,0)); bad[-1]^=1; failures+=expect_error(lambda:x.exchange(bytes(bad)),ErrorCode.BAD_LENGTH)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); x.force_device_error=True; failures+=expect_error(lambda:h.start_range(d.generation,0,1,8),ErrorCode.INTERNAL)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.start_range(d.generation,0,1,9); x.drop_next_result=True; failures+=expect_error(lambda:h.read_result(d.generation,9),ErrorCode.MISSING_RESULT)
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); h.load_job(d.encode()); h.start_range(d.generation,0,1,10); stale_read=encode_read_request(d.generation,d.job_key,11,0,1); failures+=wire_error(x,request(Opcode.READ_RESULT,4,stale_read),ErrorCode.STALE_JOB)
 wrong=bytearray(expected['expected_compact_result'][0]); wrong[0]^=1
 try: verify_exact(bytes(wrong),expected['expected_compact_result'][0])
 except ValueError: failures+=1
 x=SoftwareTransportEmulator(); h=HostTransportAdapter(x); x.crash_next_response=True
 try: h.hello()
 except RuntimeError: failures+=x.calls==1
 assert failures==20, f'failure matrix {failures}/20'
 # Deterministic 250k state transitions through encoded host frames and emulator.
 rng=random.Random(0x50484b32); stress=SoftwareTransportEmulator(); client=HostTransportAdapter(stress); gen=0; rid=0; events=0; unexpected=0; deadlocks=0
 for _ in range(250000):
  op=rng.randrange(7)
  try:
   if op==0: client.hello()
   elif op==1: client.status()
   elif op==2:
    gen+=1; jd=Descriptor(d.job_key,gen,d.setup_seed64,d.noise_seed_A,d.noise_seed_B); client.load_job(jd.encode())
   elif op==3:
    if client._descriptor:
     rid=(rid+1)&0xffff or 1; client.start_range(client._descriptor.generation,0,1,rid)
   elif op==4:
    if client._descriptor and client._range_id: client.read_result(client._descriptor.generation,client._range_id)
   elif op==5:
    if client._descriptor and client._range_id: client.abort(client._descriptor.generation,client._range_id)
   else: client.reset()
  except (ProtocolError,TimeoutError): pass
  except Exception: unexpected+=1
  events+=1
  if stress.state==State.BUSY:
   # Device mock must settle synchronously; a lasting BUSY state is a deadlock.
   deadlocks+=1
 assert unexpected==0 and deadlocks==0
 return {'HOST_TO_TRANSPORT_HELLO':'PASS' if checks['HOST_TO_TRANSPORT_HELLO'] else 'FAIL','HOST_TO_TRANSPORT_DESCRIPTOR':'PASS' if checks['HOST_TO_TRANSPORT_DESCRIPTOR'] else 'FAIL','HOST_TO_TRANSPORT_BATCH64':'PASS' if checks['HOST_TO_TRANSPORT_BATCH64'] else 'FAIL','HOST_TO_TRANSPORT_RESULT':'PASS' if checks['HOST_TO_TRANSPORT_RESULT'] else 'FAIL','HOST_TRANSPORT_ADAPTER':'PASS' if isinstance(host,HostTransportAdapter) and not host.physical_access_enabled else 'FAIL','PHK2_BOARD_MOCK_END_TO_END':'PASS' if checks['PHK2_BOARD_MOCK_END_TO_END'] else 'FAIL','PHK2_BOARD_PROTOCOL_FAILURE_MATRIX':f'{failures}/20','PROTOCOL_STRESS_EVENTS':events,'UNEXPECTED_FAILURES':unexpected,'DEADLOCKS':deadlocks,'DESCRIPTOR_TRANSPORT_BYTES':112,'RAW_RESULT_EXACT':raw_exact,'CANONICAL_RESULT_EXACT':canon_exact}
if __name__=='__main__':
 import json; print(json.dumps(qualify(),indent=2))
