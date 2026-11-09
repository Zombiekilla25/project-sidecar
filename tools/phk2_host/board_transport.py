"""Software-only framed transport adapter and PHK2 device emulator.

Physical BSCAN/XVC/USB access is deliberately unavailable in this module.
"""
from __future__ import annotations
import hashlib,struct,sys
from pathlib import Path
from board_protocol import *
from runtime import Descriptor,Result,fixture_descriptor,fixture_path

class SoftwareTransportEmulator:
    def __init__(self,input_capacity=512,result_capacity=64):
        self.input_capacity=input_capacity; self.result_capacity=result_capacity
        self.input_occupancy=0; self.force_fifo_full=False; self.drop_next_response=False; self.crash_next_response=False; self.force_device_error=False; self.drop_next_result=False; self.truncate_next_result=False; self.corrupt_next_result=False
        self.descriptor=None; self.range_id=0; self.start=0; self.count=0; self.results=[]; self.state=State.IDLE
        self.error_code=0; self.stale_job=False; self.overflow=False; self.aborted=False; self.calls=0; self.deadlocked=False
    def _fail(self,code,msg):
        self.error_code=int(code)
        if code==ErrorCode.STALE_JOB: self.stale_job=True
        if code==ErrorCode.FIFO_FULL: self.overflow=True
        self.state=State.ERROR
        raise ProtocolError(code,msg)
    def _status(self,gen,rid):
        flags=(FLAG_BUSY if self.state==State.BUSY else 0)|(FLAG_RESULT_READY if self.results and not self.aborted else 0)|(FLAG_ERROR if self.error_code else 0)|(FLAG_STALE_JOB if self.stale_job else 0)|(FLAG_OVERFLOW if self.overflow else 0)|(FLAG_ABORTED if self.aborted else 0)
        return Status(gen,rid,self.state,flags,self.input_occupancy,len(self.results),len(self.results),self.error_code,len(self.results),max(0,self.input_capacity-self.input_occupancy))
    def _make_results(self,gen,key,start,count,rid):
        if self.descriptor is None or key!=self.descriptor.job_key: self._fail(ErrorCode.STALE_JOB,'range job key is stale')
        rows=[]; provider=None
        if self.descriptor==fixture_descriptor() and start+count<=64:
            root=fixture_path()/'batch64'; raw=(root/'expected_digests.bin').read_bytes(); can=(root/'expected_transcripts.bin').read_bytes()
            provider=([raw[i*32:(i+1)*32] for i in range(64)],[can[i*64:(i+1)*64] for i in range(64)])
        for local in range(count):
            absolute=start+local; row,col=divmod(absolute,8)
            if provider:
                digest,canonical=provider[0][absolute],provider[1][absolute]
            else:
                digest=hashlib.sha256(self.descriptor.encode()+struct.pack('<IHH',absolute,rid,local)).digest()
                one=hashlib.sha256(b'PHK2-BOARD-MOCK-CANONICAL'+digest).digest(); canonical=one+one
            rows.append(Result(gen,rid,local,row,col,digest,canonical))
        if len(rows)>self.result_capacity: self.overflow=True; self._fail(ErrorCode.FIFO_FULL,'result FIFO capacity exceeded')
        self.results=rows
    def exchange(self,raw:bytes)->bytes:
        self.calls+=1
        req=Frame.decode(raw)
        if req.flags or req.opcode&0x80: self._fail(ErrorCode.BAD_OPCODE,'requests must be unflagged request opcodes')
        if self.force_fifo_full or len(raw)>self.input_capacity:
            self.overflow=True
            return response(req,struct.pack('<H',int(ErrorCode.FIFO_FULL)),error=True)
        self.input_occupancy=len(raw)
        try:
            try: op=Opcode(req.opcode)
            except ValueError: return response(req,struct.pack('<H',int(ErrorCode.BAD_OPCODE)),error=True)
            p=req.payload
            if op==Opcode.HELLO:
                if p: raise ProtocolError(ErrorCode.BAD_LENGTH,'HELLO request payload must be empty')
                return response(req,hello_payload())
            if op==Opcode.LOAD_DESCRIPTOR:
                if len(p)!=112: raise ProtocolError(ErrorCode.BAD_LENGTH,'LOAD_DESCRIPTOR requires 112 bytes')
                d=decode_descriptor(p)
                if self.descriptor is not None and d.generation<=self.descriptor.generation: raise ProtocolError(ErrorCode.BAD_GENERATION,'generation must strictly increase')
                self.descriptor=d; self.range_id=0; self.results=[]; self.state=State.READY; self.error_code=0; self.stale_job=False; self.overflow=False; self.aborted=False
                return response(req,LOAD_ACK.pack(d.generation,d.job_key))
            if op==Opcode.START_RANGE:
                gen,key,start,count,rid=decode_range(p)
                if self.descriptor is None: raise ProtocolError(ErrorCode.NOT_READY,'descriptor not loaded')
                if gen!=self.descriptor.generation: raise ProtocolError(ErrorCode.STALE_JOB,'generation mismatch')
                if key!=self.descriptor.job_key: raise ProtocolError(ErrorCode.STALE_JOB,'job key mismatch')
                if self.range_id==rid and self.range_id!=0: raise ProtocolError(ErrorCode.DUPLICATE_START,'duplicate range ID')
                if self.force_fifo_full: raise ProtocolError(ErrorCode.FIFO_FULL,'input FIFO full')
                if self.force_device_error: raise ProtocolError(ErrorCode.INTERNAL,'mock device error')
                self.range_id=rid; self.start=start; self.count=count; self.state=State.BUSY; self.aborted=False; self.error_code=0
                self._make_results(gen,key,start,count,rid); self.state=State.DONE
                return response(req,START_ACK.pack(gen,rid,count))
            if op==Opcode.STATUS:
                if len(p)!=STATUS_REQ.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'STATUS request must be 10 bytes')
                gen,rid=STATUS_REQ.unpack(p)
                if self.descriptor and gen!=self.descriptor.generation: self.stale_job=True; self.error_code=int(ErrorCode.STALE_JOB)
                return response(req,self._status(gen,rid).encode())
            if op==Opcode.READ_RESULT:
                gen,key,rid,cursor,limit=decode_read_request(p)
                if not self.results or self.aborted:
                    code=ErrorCode.FIFO_EMPTY if self.range_id==0 or self.aborted else ErrorCode.NOT_READY
                    raise ProtocolError(code,'result FIFO empty or result not ready')
                if gen!=self.descriptor.generation or key!=self.descriptor.job_key or rid!=self.range_id: raise ProtocolError(ErrorCode.STALE_JOB,'stale result identity')
                if limit==0: return response(req,b'')
                if self.drop_next_result: self.drop_next_result=False; return response(req,b'')
                chunk=b''.join(encode_result(r) for r in self.results[cursor:cursor+limit])
                if self.truncate_next_result and chunk: self.truncate_next_result=False; chunk=chunk[:-1]
                if self.corrupt_next_result and chunk: self.corrupt_next_result=False; chunk=chunk[:-1]+bytes([chunk[-1]^1])
                return response(req,chunk)
            if op==Opcode.ABORT:
                gen,key,rid,_reason=decode_abort(p)
                if self.descriptor is None or (gen,key,rid)!=(self.descriptor.generation,self.descriptor.job_key,self.range_id): raise ProtocolError(ErrorCode.STALE_JOB,'abort identity mismatch')
                self.results=[]; self.state=State.ABORTED; self.aborted=True
                return response(req,struct.pack('<QH',gen,rid))
            if op==Opcode.RESET:
                if p: raise ProtocolError(ErrorCode.BAD_LENGTH,'RESET request must be empty')
                self.__init__(self.input_capacity,self.result_capacity)
                return response(req,b'')
        except ProtocolError as e:
            self.error_code=int(e.code)
            if e.code==ErrorCode.STALE_JOB: self.stale_job=True
            if e.code==ErrorCode.FIFO_FULL: self.overflow=True
            return response(req,struct.pack('<H',int(e.code)),error=True)
        finally: self.input_occupancy=0
    def transact(self,raw):
        if self.crash_next_response:
            self.crash_next_response=False; self.calls+=1
            raise RuntimeError('mock runner crash')
        if self.drop_next_response:
            self.drop_next_response=False; self.calls+=1
            raise TimeoutError('mock response timeout; request is not retried')
        return self.exchange(raw)

class HostTransportAdapter:
    """Implements the PHK2 host runtime Transport seam over encoded frames."""
    physical_access_enabled=False
    def __init__(self,emulator:SoftwareTransportEmulator):
        self._device=emulator; self._sequence=0; self._descriptor=None; self._range_id=0; self._range_count=0; self._start=0; self._hello=False
    def _exchange(self,op,payload=b''):
        seq=self._sequence; self._sequence=(seq+1)&0xffff
        raw=request(op,seq,payload); response_raw=self._device.transact(raw); got=Frame.decode(response_raw)
        if got.opcode!=(int(op)|0x80) or got.sequence!=seq or not got.flags&RESPONSE: raise ProtocolError(ErrorCode.BAD_LENGTH,'response identity mismatch')
        if got.flags&ERROR:
            code=ErrorCode(struct.unpack('<H',got.payload)[0]) if len(got.payload)==2 else ErrorCode.INTERNAL
            raise ProtocolError(code,f'{op.name} rejected: {code.name}')
        return got.payload
    def hello(self):
        payload=self._exchange(Opcode.HELLO)
        if len(payload)!=HELLO_RESPONSE.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'HELLO response size mismatch')
        major,minor,profile,desc_bytes,batch,result_bytes,features=HELLO_RESPONSE.unpack(payload)
        if (major,desc_bytes,batch,result_bytes)!=(1,112,64,112): raise ProtocolError(ErrorCode.BAD_LENGTH,'unsupported HELLO capabilities')
        self._hello=True; return {'major':major,'minor':minor,'profile_id':profile,'descriptor_bytes':desc_bytes,'max_batch':batch,'result_bytes':result_bytes,'features':features}
    def load_job(self,descriptor:bytes)->int:
        d=decode_descriptor(descriptor); ack=self._exchange(Opcode.LOAD_DESCRIPTOR,encode_descriptor(d))
        if len(ack)!=LOAD_ACK.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'LOAD_DESCRIPTOR ack size mismatch')
        gen,key=LOAD_ACK.unpack(ack)
        if (gen,key)!=(d.generation,d.job_key): raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,'descriptor acknowledgement mismatch')
        self._descriptor=d; return gen
    def start_range(self,generation:int,start:int,count:int,range_id:int):
        if self._descriptor is None: raise ProtocolError(ErrorCode.NOT_READY,'descriptor not loaded')
        payload=encode_range(generation,self._descriptor.job_key,start,count,range_id); ack=self._exchange(Opcode.START_RANGE,payload)
        if len(ack)!=START_ACK.size or START_ACK.unpack(ack)!=(generation,range_id,count): raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,'START_RANGE ack mismatch')
        self._range_id=range_id; self._range_count=count; self._start=start; return []
    def status(self):
        if self._descriptor is None: gen=0; rid=0
        else: gen=self._descriptor.generation; rid=self._range_id
        return Status.decode(self._exchange(Opcode.STATUS,STATUS_REQ.pack(gen,rid)))
    def read_result(self,generation:int,range_id:int):
        if self._descriptor is None or self._range_count==0: raise ProtocolError(ErrorCode.NOT_READY,'range not started')
        if not self.status().flags&FLAG_RESULT_READY: raise ProtocolError(ErrorCode.NOT_READY,'result_ready is not asserted')
        out=[]; cursor=0
        while cursor<self._range_count:
            max_records=min(MAX_RESULT_RECORDS_PER_READ,self._range_count-cursor)
            payload=self._exchange(Opcode.READ_RESULT,encode_read_request(generation,self._descriptor.job_key,range_id,cursor,max_records))
            if len(payload)%RESULT_SIZE: raise ProtocolError(ErrorCode.BAD_LENGTH,'partial result record')
            if len(payload)>MAX_DRAIN-HEADER.size-CRC.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'result drain exceeds 512-byte bound')
            records=[decode_result(payload[i:i+RESULT_SIZE]) for i in range(0,len(payload),RESULT_SIZE)]
            if not records: raise ProtocolError(ErrorCode.MISSING_RESULT,'result read returned no records before range completion')
            out.extend(records); cursor+=len(records)
        return out
    def abort(self,generation:int,range_id:int):
        if self._descriptor is None: raise ProtocolError(ErrorCode.NOT_READY,'descriptor not loaded')
        p=self._exchange(Opcode.ABORT,encode_abort(generation,self._descriptor.job_key,range_id))
        if len(p)!=10 or struct.unpack('<QH',p)!=(generation,range_id): raise ProtocolError(ErrorCode.IDENTITY_MISMATCH,'ABORT ack mismatch')
    def reset(self): self._exchange(Opcode.RESET); self._descriptor=None; self._range_id=0; self._range_count=0
    def set_physical(self,*_args,**_kwargs): raise RuntimeError('physical PHK2 transport is disabled in this worktree')
class PhysicalBscanTransport:
    def __init__(self,*_args,**_kwargs): raise RuntimeError('physical BSCAN/XVC transport is disabled; use SoftwareTransportEmulator')
