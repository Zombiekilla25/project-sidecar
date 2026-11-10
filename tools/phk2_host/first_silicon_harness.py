"""Fail-closed PHK2 first-silicon session logic with offline mock support only.

Wire encoding/decoding is delegated to the committed board_protocol module.
This module has no USB/JTAG/FTDI or FPGA programmer dependency.
"""
from __future__ import annotations
import hashlib, json, os, struct, time, uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol
from board_protocol import (
    ERROR, RESPONSE, ErrorCode, Frame, HELLO_RESPONSE, Opcode, ProtocolError,
    State, Status, decode_result, encode_descriptor,
)
from board_transport import HostTransportAdapter, SoftwareTransportEmulator
from runtime import Descriptor, Result, sha

RESULT_CLASSES={"PASS","HELLO_FAILURE","TRANSPORT_FAILURE","FPGA_STATUS_ERROR","RAW_RESULT_MISMATCH","CANONICAL_RESULT_MISMATCH","CPU_CROSSCHECK_FAILURE","RECOVERY_FAILURE","PRECHECK_REFUSAL"}

def decode_hello_payload(raw: bytes) -> dict:
    if len(raw)!=HELLO_RESPONSE.size: raise ProtocolError(ErrorCode.BAD_LENGTH,"HELLO response must be 14 bytes")
    major,minor,profile,descriptor_bytes,max_batch,result_bytes,features=HELLO_RESPONSE.unpack(raw)
    if (major,profile,descriptor_bytes,max_batch,result_bytes)!=(1,3,112,64,112): raise ProtocolError(ErrorCode.BAD_LENGTH,"HELLO capability mismatch")
    return {"major":major,"minor":minor,"profile_id":profile,"descriptor_bytes":descriptor_bytes,"max_batch":max_batch,"result_bytes":result_bytes,"features":features}

def decode_error_frame(raw: bytes, expected_sequence: int|None=None) -> ErrorCode:
    frame=Frame.decode(raw)
    if not frame.flags&RESPONSE or not frame.flags&ERROR or len(frame.payload)!=2: raise ProtocolError(ErrorCode.BAD_LENGTH,"malformed PHK2 error response")
    if expected_sequence is not None and frame.sequence!=expected_sequence: raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,"error response sequence mismatch")
    try: return ErrorCode(struct.unpack("<H",frame.payload)[0])
    except ValueError as e: raise ProtocolError(ErrorCode.INTERNAL,"unknown device error code") from e

def decode_status_payload(raw: bytes, generation: int, range_id: int) -> Status:
    status=Status.decode(raw)
    if (status.generation,status.range_id)!=(generation,range_id): raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,"STATUS identity mismatch")
    return status

def decode_result_payload(raw: bytes, generation: int, range_id: int) -> Result:
    item=decode_result(raw)
    if (item.generation,item.range_id)!=(generation,range_id): raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,"result identity mismatch")
    return item

def canonical_json_sha(value) -> str:
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    return hashlib.sha256(raw).hexdigest()

def oracle_record_sha(descriptor: Descriptor, answer: dict) -> str:
    return canonical_json_sha({
        "descriptor_sha256":sha(descriptor.encode()),
        "range":{"start":0,"count":len(answer["expected_compact_result"])},
        "operand_sha256":[sha(x) for x in answer["expected_operands"]],
        "raw_result_sha256":sha(b"".join(answer["expected_compact_result"])),
        "canonical_result_sha256":sha(b"".join(answer["canonical_result"])),
    })

def verify_result_set(results: list[Result], descriptor: Descriptor, count: int, start: int, range_id: int) -> None:
    if len(results)!=count: raise ProtocolError(ErrorCode.MISSING_RESULT,f"expected {count} records, got {len(results)}")
    slots=[r.slot for r in results]
    if slots!=list(range(count)): raise ProtocolError(ErrorCode.MISSING_RESULT,"duplicate, missing, or reordered result slot")
    for slot,r in enumerate(results):
        row,col=divmod(start+slot,8)
        if (r.generation,r.range_id,r.row_tile,r.col_tile)!=(descriptor.generation,range_id,row,col):
            raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,"result generation/range/coordinate mismatch")
        if len(r.raw_result)!=32 or len(r.canonical_result)!=64:
            raise ProtocolError(ErrorCode.BAD_LENGTH,"raw/canonical result lengths differ from frozen contract")

class EvidenceBundle:
    """Unique append-only attempt directory; syncs command evidence before I/O."""
    REQUIRED=("ATTEMPT_MANIFEST.json","ATTEMPT_SUMMARY.md","raw_input.bin","raw_output.bin","protocol_transcript.jsonl","status_transcript.jsonl","error_transcript.jsonl","timing.json","recovery_result.json")
    def __init__(self,root:Path,metadata:dict):
        self.root=root; root.mkdir(parents=True,exist_ok=False); self.metadata=metadata.copy(); self.metadata.setdefault("attempt_id",str(uuid.uuid4())); self.metadata.setdefault("measurement_class","MOCK");self.metadata.setdefault("host_executable_sha256",None);self.metadata.setdefault("host_harness_source_sha256",sha(Path(__file__).read_bytes()))
        (root/"raw_output.bin").write_bytes(b"")
        for name in ("protocol_transcript.jsonl","status_transcript.jsonl","error_transcript.jsonl"):(root/name).write_bytes(b"")
        self.write_json("ATTEMPT_MANIFEST.json",self.metadata)
    def _sync_dir(self):
        try:
            fd=os.open(self.root,os.O_RDONLY); os.fsync(fd); os.close(fd)
        except OSError: pass
    def write_json(self,name,obj):
        data=(json.dumps(obj,indent=2,sort_keys=True)+"\n").encode(); p=self.root/name
        with p.open("wb") as f:f.write(data);f.flush();os.fsync(f.fileno())
        self._sync_dir()
    def append(self,name,obj):
        with (self.root/name).open("ab") as f:f.write((json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode());f.flush();os.fsync(f.fileno())
        self._sync_dir()
    def write_bytes(self,name,data):
        with (self.root/name).open("wb") as f:f.write(data);f.flush();os.fsync(f.fileno())
        self._sync_dir()
    def append_output(self,data):
        with (self.root/"raw_output.bin").open("ab") as f:f.write(data);f.flush();os.fsync(f.fileno())
        self._sync_dir()
    def before_recovery(self,classification,details):
        self.write_json("PRE_RECOVERY_EVIDENCE_SYNC.json",{"classification":classification,"details":details,"utc_ns":time.time_ns(),"all_open_evidence_fsynced":True})
    def finalize(self,summary,timing,recovery=None):
        self.write_json("timing.json",timing)
        self.write_json("recovery_result.json",recovery or {"state":"NOT_RUN","reason":"offline result verification is isolated from recovery hooks"})
        p=self.root/"ATTEMPT_SUMMARY.md"
        with p.open("w") as f:f.write("# PHK2 first-silicon attempt evidence\n\n"+"\n".join(f"- **{k}:** {v}" for k,v in summary.items())+"\n");f.flush();os.fsync(f.fileno())
        self._sync_dir()

class EvidenceEmulator(SoftwareTransportEmulator):
    def __init__(self,evidence:EvidenceBundle,**kwargs): super().__init__(**kwargs); self.evidence=evidence; self.command_id=0;self.last_response_raw=None
    def transact(self,raw):
        self.command_id+=1
        req=Frame.decode(raw)
        self.evidence.append("protocol_transcript.jsonl",{"event":"request","monotonic_ns":time.monotonic_ns(),"command_id":self.command_id,"opcode":req.opcode,"sequence":req.sequence,"payload_bytes":len(req.payload),"frame_hex":raw.hex()})
        try: response=super().transact(raw)
        except Exception as exc:
            self.evidence.append("error_transcript.jsonl",{"event":"transport_exception","command_id":self.command_id,"type":type(exc).__name__,"message":str(exc)})
            raise
        self.last_response_raw=response
        rsp=Frame.decode(response)
        self.evidence.append("protocol_transcript.jsonl",{"event":"response","monotonic_ns":time.monotonic_ns(),"command_id":self.command_id,"opcode":rsp.opcode,"sequence":rsp.sequence,"flags":rsp.flags,"payload_bytes":len(rsp.payload),"frame_hex":response.hex()})
        if req.opcode==Opcode.READ_RESULT and not rsp.flags&ERROR:self.evidence.append_output(rsp.payload)
        return response

class EvidenceTransportProxy:
    """Recorder wrapper for a future explicitly authorized transactor plugin."""
    def __init__(self,inner,evidence):self.inner=inner;self.evidence=evidence;self.command_id=0;self.last_response_raw=None
    def transact(self,raw):
        self.command_id+=1;req=Frame.decode(raw)
        self.evidence.append("protocol_transcript.jsonl",{"event":"request","monotonic_ns":time.monotonic_ns(),"command_id":self.command_id,"opcode":req.opcode,"sequence":req.sequence,"payload_bytes":len(req.payload),"frame_hex":raw.hex()})
        try:response=self.inner.transact(raw)
        except Exception as exc:
            self.evidence.append("error_transcript.jsonl",{"event":"transport_exception","command_id":self.command_id,"type":type(exc).__name__,"message":str(exc)});raise
        self.last_response_raw=response;rsp=Frame.decode(response)
        self.evidence.append("protocol_transcript.jsonl",{"event":"response","monotonic_ns":time.monotonic_ns(),"command_id":self.command_id,"opcode":rsp.opcode,"sequence":rsp.sequence,"flags":rsp.flags,"payload_bytes":len(rsp.payload),"frame_hex":response.hex()})
        if req.opcode==Opcode.READ_RESULT and not rsp.flags&ERROR:self.evidence.append_output(rsp.payload)
        return response

class DelayedReadyEmulator(EvidenceEmulator):
    """Mock-only virtual latency/backpressure: READY follows N BUSY polls."""
    def __init__(self,evidence,ready_delay=0,**kwargs): super().__init__(evidence,**kwargs);self.ready_delay=ready_delay
    def exchange(self,raw):
        req=Frame.decode(raw)
        if req.opcode==Opcode.START_RANGE:
            response=super().exchange(raw)
            self._busy_polls_left=self.ready_delay
            return response
        if req.opcode==Opcode.STATUS and getattr(self,"_busy_polls_left",0)>0:
            saved=self.state;self.state=State.BUSY
            try: response=super().exchange(raw)
            finally:self.state=saved;self._busy_polls_left-=1
            return response
        return super().exchange(raw)

@dataclass
class AttemptCounters:
    program_attempts:int=0; hello_attempts:int=0; transaction_count:int=0
    target_program_count:int=0; peer_program_count:int=0; target_bytes_sent:int=0; peer_bytes_sent:int=0
    load_descriptor_count:int=0; start_count:int=0; result_read_commands:int=0; retries:int=0

class FirstSiliconSession:
    """One logical transaction, no retries; transport is always injected."""
    def __init__(self,device:SoftwareTransportEmulator,evidence:EvidenceBundle,poll_limit=32):
        self.device=device;self.evidence=evidence;self.host=HostTransportAdapter(device);self.poll_limit=poll_limit;self.counters=AttemptCounters()
    def run(self,descriptor:Descriptor,answer:dict,start:int,count:int,range_id:int=1)->dict:
        if count not in (1,64): raise ValueError("only the qualified count=1 or count=64 windows are accepted")
        c=self.counters; t0=time.monotonic_ns(); marks={}; status_records=[]; errors=[]
        pack_start=time.monotonic_ns();encoded=encode_descriptor(descriptor);marks["host_pack_us"]=(time.monotonic_ns()-pack_start)/1000; self.evidence.write_bytes("raw_input.bin",encoded)
        self.evidence.metadata.update({"descriptor_sha256":sha(encoded),"descriptor_bytes":len(encoded),"range":{"start":start,"count":count,"range_id":range_id},"oracle_sha256":oracle_record_sha(descriptor,answer)})
        self.evidence.write_json("ATTEMPT_MANIFEST.json",self.evidence.metadata)
        result={"classification":"PASS","result_count":0,"result_set_valid":False,"raw_result_exact":"NOT_RUN","canonical_result_exact":"NOT_RUN","cpu_crosscheck":"NOT_RUN"}
        # HELLO is the first and only entry to the command session.
        t=time.monotonic_ns();c.hello_attempts+=1
        try:
            hello=self.host.hello()
            marks["hello_us"]=(time.monotonic_ns()-t)/1000
            if hello["profile_id"]!=3: raise ProtocolError(ErrorCode.BAD_LENGTH,"profile mismatch")
            raw_hello=Frame.decode(self.device.last_response_raw).payload
            decoded_hello=decode_hello_payload(raw_hello)
            self.evidence.append("status_transcript.jsonl",{"phase":"HELLO","raw_response_payload_hex":raw_hello.hex(),"decoded":decoded_hello})
        except Exception as exc:
            result.update(classification="HELLO_FAILURE",error=f"{type(exc).__name__}: {exc}")
            self.evidence.append("error_transcript.jsonl",{"phase":"HELLO","type":type(exc).__name__,"message":str(exc)})
            return self._finish(result,marks,t0,encoded,b"",[],answer,status_records,errors)
        # Only after successful HELLO may descriptor submission begin.
        t=time.monotonic_ns();c.load_descriptor_count+=1
        try: accepted=self.host.load_job(encoded)
        except TimeoutError as exc:
            return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":str(exc)},marks,t0,encoded,b"",[],answer,status_records,errors)
        marks["descriptor_transmit_us"]=(time.monotonic_ns()-t)/1000
        if accepted!=descriptor.generation: return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":"descriptor ack mismatch"},marks,t0,encoded,b"",[],answer,status_records,errors)
        self.evidence.append("status_transcript.jsonl",{"phase":"LOAD_DESCRIPTOR_ACCEPTED","generation":accepted,"job_key_sha256":sha(descriptor.job_key)})
        c.transaction_count+=1;t=time.monotonic_ns();c.start_count+=1
        try:self.host.start_range(descriptor.generation,start,count,range_id)
        except Exception as exc:return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":f"{type(exc).__name__}: {exc}"},marks,t0,encoded,b"",[],answer,status_records,errors)
        marks["start_transmit_us"]=(time.monotonic_ns()-t)/1000;wait_start=time.monotonic_ns();ready=None
        marks["transport_in_us"]=marks["descriptor_transmit_us"]+marks["start_transmit_us"]
        for poll in range(1,self.poll_limit+1):
            try: st=self.host.status()
            except Exception as exc:return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":f"STATUS {type(exc).__name__}: {exc}"},marks,t0,encoded,b"",[],answer,status_records,errors)
            raw_status=Frame.decode(self.device.last_response_raw).payload
            rec={"phase":"WORK_STATUS","poll":poll,"generation":st.generation,"range_id":st.range_id,"raw_status_hex":raw_status.hex(),"state":st.state.name,"flags":st.flags,"result_count":st.result_count,"error_code":st.error_code,"input_occupancy":st.input_occupancy,"result_occupancy":st.result_occupancy}
            status_records.append(rec);self.evidence.append("status_transcript.jsonl",rec)
            if st.flags & (1<<2) or st.state==State.ERROR:
                return self._finish(result|{"classification":"FPGA_STATUS_ERROR","error_code":st.error_code},marks,t0,encoded,b"",[],answer,status_records,errors)
            if st.generation!=descriptor.generation or st.range_id!=range_id:
                return self._finish(result|{"classification":"FPGA_STATUS_ERROR","error":"stale status identity"},marks,t0,encoded,b"",[],answer,status_records,errors)
            if st.state==State.DONE and st.flags&(1<<1):
                if st.result_count!=count:return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":f"wrong result count in STATUS: {st.result_count}, expected {count}"},marks,t0,encoded,b"",[],answer,status_records,errors)
                ready=poll;break
        marks["fpga_wait_us"]=(time.monotonic_ns()-wait_start)/1000
        if ready is None:return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":"bounded STATUS poll deadline expired"},marks,t0,encoded,b"",[],answer,status_records,errors)
        t=time.monotonic_ns()
        try: records=self.host.read_result(descriptor.generation,range_id)
        except TimeoutError as exc:return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":str(exc)},marks,t0,encoded,b"",[],answer,status_records,errors)
        except Exception as exc:return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":f"{type(exc).__name__}: {exc}"},marks,t0,encoded,b"",[],answer,status_records,errors)
        marks["transport_out_us"]=(time.monotonic_ns()-t)/1000
        c.result_read_commands=sum(1 for x in self.device.trace if x.get("op")=="READ_RESULT") if hasattr(self.device,"trace") else sum(1 for x in self.evidence.root.joinpath("protocol_transcript.jsonl").read_text().splitlines() if json.loads(x).get("opcode")==Opcode.READ_RESULT)
        try:verify_result_set(records,descriptor,count,start,range_id)
        except Exception as exc:return self._finish(result|{"classification":"TRANSPORT_FAILURE","error":f"invalid result set: {exc}"},marks,t0,encoded,b"".join(r.encode() for r in records),records,answer,status_records,errors)
        result["result_set_valid"]=True
        raw=b"".join(r.raw_result for r in records);canonical=b"".join(r.canonical_result for r in records)
        # Single-item production capture stores a 4x5 CPU comparison; count 1
        # on the board maps to its first origin result. Batch64 maps all 64.
        exp_raw=answer["expected_compact_result"][:count];exp_can=answer["canonical_result"][:count]
        t=time.monotonic_ns(); composed=b"".join(r.canonical_result for r in records);marks["compose_us"]=(time.monotonic_ns()-t)/1000
        t=time.monotonic_ns();raw_ok=raw==b"".join(exp_raw);can_ok=canonical==b"".join(exp_can);cpu_ok=bool(answer.get("checks",{}).get("exact",False));marks["verify_us"]=(time.monotonic_ns()-t)/1000
        result.update(result_count=len(records),raw_result_sha256=sha(raw),canonical_result_sha256=sha(composed),raw_result_exact="PASS" if raw_ok else "FAIL",canonical_result_exact="PASS" if can_ok else "FAIL",cpu_crosscheck="PASS" if cpu_ok else "FAIL",raw_result_bytes=len(raw),canonical_result_bytes=len(canonical),result_wire_records_sha256=sha(b"".join(r.encode() for r in records)))
        if not raw_ok:result["classification"]="RAW_RESULT_MISMATCH"
        elif not can_ok:result["classification"]="CANONICAL_RESULT_MISMATCH"
        elif not cpu_ok:result["classification"]="CPU_CROSSCHECK_FAILURE"
        try:
            t=time.monotonic_ns();final_status=self.host.status();marks["final_status_us"]=(time.monotonic_ns()-t)/1000
            final_raw=Frame.decode(self.device.last_response_raw).payload
            if (final_status.generation,final_status.range_id)!=(descriptor.generation,range_id) or final_status.state not in (State.DONE,State.ABORTED,State.ERROR):
                raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,"final STATUS identity/state mismatch")
            final_rec={"phase":"FINAL_STATUS","raw_status_hex":final_raw.hex(),"state":final_status.state.name,"flags":final_status.flags,"result_count":final_status.result_count}
            self.evidence.append("status_transcript.jsonl",final_rec)
        except Exception as exc:
            result.update(classification="FPGA_STATUS_ERROR",error=f"final STATUS: {exc}")
        return self._finish(result,marks,t0,encoded,b"".join(r.encode() for r in records),records,answer,status_records,errors)
    def _finish(self,result,marks,t0,encoded,wire_results,records,answer,status_records,errors):
        if result.get("classification")!="PASS":
            self.evidence.append("error_transcript.jsonl",{"phase":"SESSION_TERMINAL","classification":result.get("classification"),"detail":result.get("error",result.get("error_code")),"monotonic_ns":time.monotonic_ns()})
        marks["vector_total_us"]=(time.monotonic_ns()-t0)/1000
        protocol=[json.loads(x) for x in (self.evidence.root/"protocol_transcript.jsonl").read_text().splitlines() if x]
        acceptance=[x["monotonic_ns"] for x in protocol if x.get("event")=="response" and x.get("opcode")==int(Opcode.LOAD_DESCRIPTOR|0x80)]
        reads=[x["monotonic_ns"] for x in protocol if x.get("event")=="response" and x.get("opcode")==int(Opcode.READ_RESULT|0x80)]
        marks["fpga_acceptance_monotonic_ns"]=acceptance[-1] if acceptance else None
        marks["first_result_monotonic_ns"]=reads[0] if reads else None
        marks["last_result_monotonic_ns"]=reads[-1] if reads else None
        marks.setdefault("measurement_class","MOCK")
        total=marks["vector_total_us"];tin=marks.get("descriptor_transmit_us",0)+marks.get("start_transmit_us",0);tout=marks.get("transport_out_us",0);wait=marks.get("fpga_wait_us",0)
        timing={k.upper():round(v,3) if isinstance(v,(int,float)) else v for k,v in marks.items() if k!="measurement_class"};timing["measurement_class"]="MOCK";timing["transport_fraction"]=round((tin+tout)/total,6) if total else None;timing["fpga_fraction"]=(round(wait/total,6) if total else None)
        if result.get("result_set_valid"):
            self.evidence.write_bytes("raw_result_bytes.bin",b"".join(r.raw_result for r in records));self.evidence.write_bytes("canonical_result_bytes.bin",b"".join(r.canonical_result for r in records))
        else:
            self.evidence.write_bytes("unverified_result_records.bin",wire_results)
        self.evidence.write_bytes("result_records.bin",wire_results)
        self.evidence.before_recovery(result["classification"],{"counters":asdict(self.counters),"raw_result_bytes":len(b"".join(r.raw_result for r in records))})
        summary={**result,"counters":asdict(self.counters),"raw_result_sha256":result.get("raw_result_sha256"),"canonical_result_sha256":result.get("canonical_result_sha256"),"oracle_sha256":oracle_record_sha(Descriptor.decode(encoded),answer),"status_polls":len(status_records)}
        self.evidence.finalize(summary,timing,{"state":"MOCK_ONLY","restore_xbt":"NOT_RUN","restore_shared_bridge":"NOT_RUN","restore_workloads":"NOT_RUN","semantic_continuity":"NOT_RUN","separate_from_result_verification":True})
        return {**summary,"timing":timing,"result_classes_valid":result.get("classification") in RESULT_CLASSES}

class RecoveryHooks(Protocol):
    def restore_xbt(self)->dict: ...
    def restore_shared_bridge(self)->dict: ...
    def restore_miner_workloads(self)->dict: ...
    def check_semantic_workload_continuity(self)->dict: ...

class MockRecoveryHooks:
    """Test double only; no production/hardware side effect."""
    def __init__(self):self.calls=[]
    def restore_xbt(self):self.calls.append("restore_xbt");return {"state":"MOCK"}
    def restore_shared_bridge(self):self.calls.append("restore_shared_bridge");return {"state":"MOCK"}
    def restore_miner_workloads(self):self.calls.append("restore_miner_workloads");return {"state":"MOCK"}
    def check_semantic_workload_continuity(self):self.calls.append("check_semantic_workload_continuity");return {"state":"MOCK"}

class ProgramBudget:
    """Future one-card budget; peer programming is unconditionally refused."""
    def __init__(self):self.target_program_count=0;self.peer_program_count=0
    def program_target_once(self,program_callback,*args,**kwargs):
        if self.target_program_count>=1:raise RuntimeError("candidate programming budget exhausted; no retry")
        self.target_program_count+=1
        return program_callback(*args,**kwargs)
    def program_peer(self,*_args,**_kwargs):
        raise RuntimeError("peer programming is forbidden")
