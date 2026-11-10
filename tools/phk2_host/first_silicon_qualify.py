"""Offline first-silicon host harness qualification and 100k mock stress."""
from __future__ import annotations
import contextlib,hashlib,io,json,random,struct,tempfile,time
from pathlib import Path
from board_protocol import *
from board_transport import HostTransportAdapter,SoftwareTransportEmulator
from first_silicon_harness import *
from first_silicon_cli import main as cli_main
from oracle import predict
from runtime import Descriptor,fixture_descriptor,fixture_path,sha

ROOT=Path(__file__).resolve().parents[2]
WIRE=json.loads((ROOT/'fixtures/phk2-host-runtime/wire-golden-v1.json').read_text())

class FaultDevice(EvidenceEmulator):
    def __init__(self,evidence,mode='none',delay=0,**kw):super().__init__(evidence,**kw);self.mode=mode;self.delay=delay;self.busy_left=0
    def transact(self,raw):
        req=Frame.decode(raw)
        if self.mode=='hello_timeout' and req.opcode==Opcode.HELLO:raise TimeoutError('injected HELLO timeout')
        if self.mode in ('result_timeout','disconnect') and req.opcode==Opcode.READ_RESULT:
            if self.mode=='result_timeout':raise TimeoutError('injected result timeout')
            raise ConnectionError('injected transport disconnect')
        if self.mode=='fifo':self.force_fifo_full=True
        return super().transact(raw)
    def exchange(self,raw):
        req=Frame.decode(raw)
        out=super().exchange(raw)
        if self.mode=='bad_hello' and req.opcode==Opcode.HELLO:
            f=Frame.decode(out);p=bytearray(f.payload);p[2]=9;return response(req,bytes(p))
        if req.opcode==Opcode.START_RANGE and self.mode=='status_error':self.state=State.ERROR;self.error_code=int(ErrorCode.INTERNAL)
        if req.opcode==Opcode.START_RANGE and self.mode=='short_result':self.truncate_next_result=True
        if req.opcode==Opcode.START_RANGE and self.mode in ('wrong_result_count','extra_result'):
            self.status_count_delta=-1 if self.mode=='wrong_result_count' else 0
        if req.opcode==Opcode.STATUS and self.mode in ('wrong_result_count','extra_result'):
            f=Frame.decode(out);s=Status.decode(f.payload);count=s.result_count+(getattr(self,'status_count_delta',0) or 0)
            if self.mode=='extra_result':count=s.result_count
            return response(req,Status(s.generation,s.range_id,s.state,s.flags,s.input_occupancy,s.result_occupancy,s.next_slot,s.error_code,count,s.input_free).encode())
        if req.opcode==Opcode.READ_RESULT and self.mode in ('duplicate_result','extra_result','raw_mismatch','canonical_mismatch'):
            f=Frame.decode(out);payload=f.payload
            if self.mode=='duplicate_result':payload=payload+payload
            elif self.mode=='extra_result':
                r=Result(self.descriptor.generation,self.range_id,1,0,1,b'X'*32,b'Y'*64);payload=payload+r.encode()
            elif self.mode=='raw_mismatch':
                q=bytearray(payload);q[16]^=1;payload=bytes(q)
            else:
                q=bytearray(payload);q[48]^=1;payload=bytes(q)
            return response(req,payload)
        return out

class StressDevice(SoftwareTransportEmulator):
    def __init__(self,rng,**kwargs):super().__init__(**kwargs);self.rng=rng;self.busy_left=0
    def exchange(self,raw):
        req=Frame.decode(raw)
        if req.opcode==Opcode.START_RANGE:
            out=super().exchange(raw);self.busy_left=self.rng.randrange(4);return out
        if req.opcode==Opcode.STATUS and self.busy_left:
            saved=self.state;self.state=State.BUSY
            try:return super().exchange(raw)
            finally:self.state=saved;self.busy_left-=1
        return super().exchange(raw)

def must(cond,msg):
    if not cond:raise AssertionError(msg)

def fixture_setup():
    d=fixture_descriptor();single=predict(d,0,1);batch=predict(d,0,64)
    must(single['checks']['exact'] and batch['checks']['exact'],'authoritative CPU oracle fixture mismatch')
    return d,single,batch

def session_case(root,d,answer,count,device_cls=DelayedReadyEmulator,mode='none',delay=0):
    bundle=EvidenceBundle(root,{"candidate_bitstream_sha256":None,"descriptor_sha256":sha(d.encode()),"measurement_class":"MOCK"})
    dev=device_cls(bundle,mode=mode,delay=delay) if device_cls is FaultDevice else device_cls(bundle,ready_delay=delay)
    return FirstSiliconSession(dev,bundle),dev,bundle

def run_fault_matrix(tmp,d,answer):
    cases=[]
    # 1 bad HELLO response, 2 HELLO timeout
    for mode,expect in [('bad_hello','HELLO_FAILURE'),('hello_timeout','HELLO_FAILURE')]:
        s,dev,b=session_case(tmp/f'{mode}',d,answer,1,FaultDevice,mode);r=s.run(d,answer,0,1,1);must(r['classification']==expect and r['counters']['load_descriptor_count']==0,'HELLO failure did not stop before descriptor');must(r['counters']['retries']==0,'HELLO retry');cases.append(mode)
    # 3 truncated descriptor is rejected before any transport command.
    e=EvidenceBundle(tmp/'truncated_descriptor',{});dev=FaultDevice(e);host=HostTransportAdapter(dev);host.hello();calls=dev.calls
    try:host.load_job(d.encode()[:-1]);raise AssertionError('truncated descriptor accepted')
    except ProtocolError:pass
    must(dev.calls==calls,'truncated descriptor reached transport');cases.append('truncated_descriptor')
    # 4 a bad frame CRC is rejected by the existing frozen frame decoder.
    e=EvidenceBundle(tmp/'bad_frame_crc',{});dev=FaultDevice(e);bad=bytes.fromhex(WIRE['vectors']['BAD_CRC']['corrupt_request_hex'])
    try:dev.transact(bad);raise AssertionError('bad CRC accepted')
    except ValueError:pass
    must(dev.descriptor is None and dev.state==State.IDLE,'bad CRC mutated device state');cases.append('bad_frame_crc')
    # 5 duplicate generation/descriptor rejection.
    e=EvidenceBundle(tmp/'rejected_descriptor',{});dev=FaultDevice(e);host=HostTransportAdapter(dev);host.hello();host.load_job(d.encode())
    try:host.load_job(d.encode());raise AssertionError('same generation accepted')
    except ProtocolError as ex:must(ex.code==ErrorCode.BAD_GENERATION,'wrong descriptor rejection code')
    must(dev.range_id==0,'rejected descriptor started work');cases.append('rejected_descriptor')
    # 6 STATUS error, 7 FIFO/backpressure.
    s,dev,b=session_case(tmp/'status_error',d,answer,1,FaultDevice,'status_error');r=s.run(d,answer,0,1,1);must(r['classification']=='FPGA_STATUS_ERROR','STATUS error not surfaced');cases.append('status_error')
    s,dev,b=session_case(tmp/'fifo_full',d,answer,1,FaultDevice,'fifo');r=s.run(d,answer,0,1,1);must(r['classification']=='HELLO_FAILURE' and r['counters']['load_descriptor_count']==0,'FIFO refusal not fail closed');cases.append('fifo_backpressure')
    # 8 short result, 9 extra record, 10 duplicate result.
    for mode in ('short_result','extra_result','duplicate_result'):
        s,dev,b=session_case(tmp/mode,d,answer,1,FaultDevice,mode);r=s.run(d,answer,0,1,1);must(r['classification']=='TRANSPORT_FAILURE' and r['canonical_result_exact']=='NOT_RUN','malformed result was accepted/canonicalized');cases.append(mode)
    # 11 result timeout, 12 wrong count, 13 raw mismatch, 14 canonical mismatch, 15 disconnect.
    for mode,expected in [('result_timeout','TRANSPORT_FAILURE'),('wrong_result_count','TRANSPORT_FAILURE'),('raw_mismatch','RAW_RESULT_MISMATCH'),('canonical_mismatch','CANONICAL_RESULT_MISMATCH'),('disconnect','TRANSPORT_FAILURE')]:
        s,dev,b=session_case(tmp/mode,d,answer,1,FaultDevice,mode);r=s.run(d,answer,0,1,1);must(r['classification']==expected,f'{mode}: {r["classification"]}');must(r['counters']['retries']==0,'transport retry');cases.append(mode)
    return cases

def run_stress(d,answer,n=100000):
    rng=random.Random(0x50484B3246534853);unexpected=dups=dropped=stale=0;events=0;reads=0
    for i in range(n):
        em=StressDevice(rng,input_capacity=512 if i&1 else 1024,result_capacity=1);host=HostTransportAdapter(em);rid=(rng.randrange(65535)+1)
        try:
            hello=host.hello();must(hello['profile_id']==3,'hello profile')
            host.load_job(d.encode());host.start_range(d.generation,0,1,rid)
            for _ in range(8):
                status=host.status()
                if status.state==State.DONE and status.flags&FLAG_RESULT_READY:break
            else:raise AssertionError('ready timeout')
            got=host.read_result(d.generation,rid);reads+=len(got)
            verify_result_set(got,d,1,0,rid)
            if len(got)!=1:dropped+=1
            if got[0].raw_result!=answer['expected_compact_result'][0] or got[0].canonical_result!=answer['canonical_result'][0]:unexpected+=1
            if any((x.generation,x.range_id)!=(d.generation,rid) for x in got):stale+=1
            if len({x.slot for x in got})!=len(got):dups+=1
        except Exception:unexpected+=1
        events+=1
        # Virtual delivery delay/backpressure is randomized through 0..3 BUSY polls.
    return {"events":events,"unexpected_failures":unexpected,"duplicate_results":dups,"dropped_results":dropped,"stale_result_accepts":stale,"result_records":reads}

def qualify():
    d,single,batch=fixture_setup();checks={}
    # Descriptor encoder fixture equality, all 13 plus one Batch64 fixture.
    inv=json.loads((ROOT/'fixtures/phk2-host-runtime/authoritative-descriptors/manifest.json').read_text());encoder=0
    frozen=json.loads((ROOT/'fixtures/phk2-first-silicon/descriptor-oracle-manifest-v1.json').read_text())
    must(frozen['count']==13 and len(frozen['retained_production_descriptors'])==13,'frozen fixture index must contain all 13 production descriptors')
    indexed_fields=('descriptor_sha256','job_identity_hex','seed_identity_sha256','expected_result_count','expected_raw_result_sha256','expected_canonical_result_sha256','cpu_oracle_sha256')
    fixture_index_tests=int(all(all(item.get(k) for k in indexed_fields) for item in frozen['retained_production_descriptors']))
    for item in inv['items']:
        raw=(ROOT/'fixtures/phk2-host-runtime/authoritative-descriptors'/item['descriptor_file']).read_bytes();decoded=Descriptor.decode(raw)
        indexed=next(x for x in frozen['retained_production_descriptors'] if x['capture']==item['capture'])
        must(indexed['descriptor_sha256']==item['descriptor_sha256'],'frozen fixture descriptor identity drift')
        encoder+=int(encode_descriptor(decoded)==raw and sha(encode_descriptor(decoded))==item['descriptor_sha256'])
    encoder+=int(encode_descriptor(d)==(fixture_path()/'descriptor.bin').read_bytes());checks['DESCRIPTOR_ENCODER_TESTS']=f'{encoder}/14'
    one=frozen['fixtures']['single_work'];many=frozen['fixtures']['batch64']
    fixture_index_tests+=int(one['descriptor_sha256']==sha(d.encode()) and one['expected_result_count']==1 and one['expected_raw_result_sha256']==sha(single['expected_compact_result'][0]) and one['expected_canonical_result_sha256']==sha(single['canonical_result'][0]) and one['cpu_oracle_sha256']==oracle_record_sha(d,single))
    fixture_index_tests+=int(many['descriptor_sha256']==sha(d.encode()) and many['expected_result_count']==64 and many['expected_raw_result_sha256']==sha(b''.join(batch['expected_compact_result'])) and many['expected_canonical_result_sha256']==sha(b''.join(batch['canonical_result'])) and many['cpu_oracle_sha256']==oracle_record_sha(d,batch))
    checks['FROZEN_FIXTURE_INDEX_TESTS']=f'{fixture_index_tests}/3'
    # HELLO decoder: exact golden response, length, and capability rejection.
    hello=Frame.decode(bytes.fromhex(WIRE['vectors']['HELLO']['response_hex'])).payload;h=decode_hello_payload(hello);hello_tests=1
    try:decode_hello_payload(hello[:-1])
    except ProtocolError:hello_tests+=1
    try:decode_hello_payload(bytes([0,hello[1]])+hello[2:])
    except ProtocolError:hello_tests+=1
    try:decode_hello_payload(hello[:2]+bytes([9])+hello[3:])
    except ProtocolError:hello_tests+=1
    checks['HELLO_DECODER_TESTS']=f'{hello_tests}/4'
    # Error response decoder exact golden payload plus malformed/identity cases.
    error_raw=Frame(Opcode.HELLO|0x80,RESPONSE|ERROR,7,struct.pack('<H',int(ErrorCode.BAD_LENGTH))).encode();error_tests=int(decode_error_frame(error_raw,7)==ErrorCode.BAD_LENGTH)
    for raw,seq in ((Frame(Opcode.HELLO|0x80,RESPONSE,7,b'').encode(),7),(error_raw,8),(Frame(Opcode.HELLO|0x80,RESPONSE|ERROR,7,struct.pack('<H',0xffff)).encode(),7)):
        try:decode_error_frame(raw,seq)
        except ProtocolError:error_tests+=1
    checks['ERROR_DECODER_TESTS']=f'{error_tests}/4'
    # STATUS and RESULT exact golden response fixtures.
    stat_payload=Frame.decode(bytes.fromhex(WIRE['vectors']['STATUS']['response_hex'])).payload;st=decode_status_payload(stat_payload,0x0102030405060708,2);status_tests=1
    for raw,g,r in ((stat_payload[:-1],st.generation,st.range_id),(stat_payload,st.generation+1,st.range_id)):
        try:decode_status_payload(raw,g,r)
        except ProtocolError:status_tests+=1
    checks['STATUS_DECODER_TESTS']=f'{status_tests}/3'
    result_payload=Frame.decode(bytes.fromhex(WIRE['vectors']['READ_RESULT']['response_hex'])).payload;record=decode_result_payload(result_payload,0x0102030405060708,2);result_tests=1
    result_tests+=int(encode_result(record)==result_payload)
    for raw,g in ((result_payload[:-1],record.generation),(result_payload,record.generation+1)):
        try:decode_result_payload(raw,g,record.range_id)
        except ProtocolError:result_tests+=1
    checks['RESULT_DECODER_TESTS']=f'{result_tests}/4'
    # Single-work fixture with exact order and one no-retry failure case.
    with tempfile.TemporaryDirectory(prefix='phk2-host-qual-') as td:
        tmp=Path(td);s,dev,bun=session_case(tmp/'single',d,single,1,delay=2);r=s.run(d,single,0,1,1)
        reqs=[json.loads(x) for x in (bun.root/'protocol_transcript.jsonl').read_text().splitlines() if json.loads(x).get('event')=='request'];ops=[x['opcode'] for x in reqs]
        single_ok=(ops[0]==Opcode.HELLO and ops[1]==Opcode.LOAD_DESCRIPTOR and ops[2]==Opcode.START_RANGE and ops[-1]==Opcode.STATUS and ops.count(Opcode.HELLO)==1 and ops.count(Opcode.LOAD_DESCRIPTOR)==1 and ops.count(Opcode.START_RANGE)==1)
        single_tests=int(r['classification']=='PASS')+int(r['raw_result_exact']=='PASS' and r['canonical_result_exact']=='PASS' and r['cpu_crosscheck']=='PASS')+int(single_ok)
        bads,_,_=session_case(tmp/'badhello',d,single,1,FaultDevice,'hello_timeout');badres=bads.run(d,single,0,1,1);single_tests+=int(badres['classification']=='HELLO_FAILURE' and badres['counters']['load_descriptor_count']==0)
        checks['SINGLE_WORK_SESSION_TESTS']=f'{single_tests}/4'
        # Batch64 full transaction, all 64 exact raw/canonical outputs and CPU oracle.
        bs,bd,bb=session_case(tmp/'batch64',d,batch,64,delay=1);br=bs.run(d,batch,0,64,3)
        batch_tests=int(br['result_count']==64)+int(br['raw_result_exact']=='PASS')+int(br['canonical_result_exact']=='PASS')+int(br['cpu_crosscheck']=='PASS')
        checks['BATCH64_SESSION_TESTS']=f"{batch_tests}/4"
        checks['BATCH64_RAW_RESULT_EXACT']=br['raw_result_exact'];checks['BATCH64_CANONICAL_RESULT_EXACT']=br['canonical_result_exact'];checks['BATCH64_CPU_CROSSCHECK']=br['cpu_crosscheck']
        # Evidence files are unique, complete, and synced before recovery marker.
        evidence_tests=0
        evidence_tests+=int(all((bb.root/name).is_file() for name in EvidenceBundle.REQUIRED))
        evidence_tests+=int((bb.root/'raw_input.bin').read_bytes()==d.encode())
        evidence_tests+=int((bb.root/'raw_output.bin').stat().st_size==64*112)
        evidence_tests+=int((bb.root/'raw_result_bytes.bin').stat().st_size==64*32 and (bb.root/'canonical_result_bytes.bin').stat().st_size==64*64)
        evidence_tests+=int((bb.root/'PRE_RECOVERY_EVIDENCE_SYNC.json').exists())
        checks['EVIDENCE_BUNDLE_TESTS']=f'{evidence_tests}/5'
        fault=run_fault_matrix(tmp/'faults',d,single);checks['FAULT_MATRIX_TESTS']=f'{len(fault)}/15';checks['FAULT_CASES']=fault
        # Mock recovery interface only; not called by result validation or CLI.
        hooks=MockRecoveryHooks();hooks.restore_xbt();hooks.restore_shared_bridge();hooks.restore_miner_workloads();hooks.check_semantic_workload_continuity()
        checks['RECOVERY_INTERFACE_TESTS']=f'{int(hooks.calls==["restore_xbt","restore_shared_bridge","restore_miner_workloads","check_semantic_workload_continuity"])}/1'
        budget=ProgramBudget();called=[];budget.program_target_once(lambda:called.append('target') or 'MOCK_OK')
        target_ok=(budget.target_program_count==1 and called==['target'])
        try:budget.program_target_once(lambda:called.append('retry'))
        except RuntimeError:target_ok=target_ok and called==['target']
        try:budget.program_peer(lambda:called.append('peer'))
        except RuntimeError:pass
        peer_ok=budget.peer_program_count==0 and not any(x=='peer' for x in called) and AttemptCounters().peer_bytes_sent==0
        checks['PEER_SAFETY_TESTS']=f'{int(peer_ok)}/1';checks['TARGET_PROGRAM_BUDGET_TESTS']=f'{int(target_ok)}/1'
        # Generated command accepts all future arguments but defaults offline;
        # the live switch without its explicit authorization refuses.
        fake_bit=tmp/'candidate.fake';fake_bit.write_bytes(b'not a bitstream; offline argument fixture only')
        fake_lock=tmp/'lock.json';fake_lock.write_text('{"offline_fixture":true}')
        dry_evidence=tmp/'cli-dry-run';capture=io.StringIO()
        with contextlib.redirect_stdout(capture):code=cli_main(['--bitstream',str(fake_bit),'--bitstream-sha',hashlib.sha256(fake_bit.read_bytes()).hexdigest(),'--target-lock',str(fake_lock),'--descriptor',str(fixture_path()/'descriptor.bin'),'--evidence-dir',str(dry_evidence)])
        dry=json.loads(capture.getvalue());cli_tests=int(code==0 and dry['mode']=='OFFLINE_DRY_RUN' and dry['hardware_access']==0 and dry['program_attempts']==0 and dry['classification']=='PASS')
        cli_manifest=json.loads((dry_evidence/'ATTEMPT_MANIFEST.json').read_text())
        cli_tests+=int(cli_manifest['candidate_bitstream_sha256']==hashlib.sha256(fake_bit.read_bytes()).hexdigest() and cli_manifest['target_lock_sha256']==sha(fake_lock.read_bytes()) and cli_manifest['descriptor_sha256']==sha((fixture_path()/'descriptor.bin').read_bytes()) and cli_manifest['host_executable_sha256'] is None and all(cli_manifest.get(k) for k in ('host_cli_source_sha256','host_harness_source_sha256','protocol_source_sha256','transport_reference_source_sha256')))
        auth=tmp/'authorization.json'; auth.write_text(json.dumps({"schema":"PHK2-FIRST-SILICON-AUTH-v1","single_use":True,"one_card_authorized":True,"candidate_image_qualified":True,"wire_contract_qualified":True,"bitstream_sha256":hashlib.sha256(fake_bit.read_bytes()).hexdigest(),"target_lock_sha256":sha(fake_lock.read_bytes()),"descriptor_sha256":sha((fixture_path()/'descriptor.bin').read_bytes()),"max_program_attempts":1,"max_hello_attempts":1,"max_transactions":1,"peer_program_allowed":False,"expires_utc":"2099-01-01T00:00:00Z"}))
        capture=io.StringIO()
        with contextlib.redirect_stdout(capture):refusal=cli_main(['--live','--authorization',str(auth),'--bitstream',str(fake_bit),'--bitstream-sha',hashlib.sha256(fake_bit.read_bytes()).hexdigest(),'--target-lock',str(fake_lock),'--descriptor',str(fixture_path()/'descriptor.bin'),'--evidence-dir',str(tmp/'live-evidence')])
        refused=json.loads(capture.getvalue());cli_tests+=int(refusal==3 and refused['classification']=='PRECHECK_REFUSAL' and not refused['live_action_performed'] and auth.exists() and not (tmp/'live-evidence').exists())
        checks['COMMAND_GENERATOR_TESTS']=f'{cli_tests}/3'
    stress=run_stress(d,single);checks['HOST_STRESS_EVENTS']=stress['events'];checks['UNEXPECTED_FAILURES']=stress['unexpected_failures'];checks['DUPLICATE_RESULTS']=stress['duplicate_results'];checks['DROPPED_RESULTS']=stress['dropped_results'];checks['STALE_RESULT_ACCEPTS']=stress['stale_result_accepts']
    checks['DESCRIPTOR_ENCODER_EXACT']='PASS' if encoder==14 else 'FAIL'
    checks['SINGLE_RAW_RESULT_EXACT']='PASS' if r['raw_result_exact']=='PASS' else 'FAIL'
    checks['RESULTS_RAW_CANONICAL_CPU']='PASS' if all(checks[k]=='PASS' for k in ('BATCH64_RAW_RESULT_EXACT','BATCH64_CANONICAL_RESULT_EXACT','BATCH64_CPU_CROSSCHECK')) else 'FAIL'
    checks['HARDWARE_ACCESS']=0;checks['FPGA_PROGRAM_ATTEMPTS']=0;checks['HELLO_ATTEMPTS']=0;checks['LIVE_TRANSACTION_COUNT']=0
    checks['SINGLE_RAW_RESULT_EXACT']=r['raw_result_exact'];checks['SINGLE_CANONICAL_RESULT_EXACT']=r['canonical_result_exact'];checks['SINGLE_CPU_CROSSCHECK']=r['cpu_crosscheck']
    checks['FIRST_SILICON_HOST_READY']=bool(encoder==14 and fixture_index_tests==3 and hello_tests==4 and error_tests==4 and status_tests==3 and result_tests==4 and single_tests==4 and br['classification']=='PASS' and br['result_count']==64 and checks['RESULTS_RAW_CANONICAL_CPU']=='PASS' and len(fault)==15 and stress['events']>=100000 and not any(stress[k] for k in ('unexpected_failures','duplicate_results','dropped_results','stale_result_accepts')) and evidence_tests==5 and peer_ok and cli_tests==3 and hooks.calls==['restore_xbt','restore_shared_bridge','restore_miner_workloads','check_semantic_workload_continuity'])
    checks['BASE_COMMIT']='1978750ef21471076d463d99166f3ab011269d14';checks['HOST_RUNTIME_REFERENCE_COMMIT']='6ec5e5ac959c169df3e706377e7287f9c55b3392';checks['PHYSICAL_PROTOCOL_QUALIFIED']=False
    checks['scope_note']='Host/mock readiness only. Current project records still mark the physical board response endpoint/protocol unqualified; this result authorizes no hardware action.'
    return checks

if __name__=='__main__':print(json.dumps(qualify(),indent=2))
