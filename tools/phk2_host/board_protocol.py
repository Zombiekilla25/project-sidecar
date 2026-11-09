"""PHK2 board protocol v1: exact bounded frames and fixed payload codecs."""
from __future__ import annotations
import binascii, struct
from dataclasses import dataclass
from enum import IntEnum
from runtime import Descriptor, Result
MAGIC=b'\xc2\x5a'; VERSION=1; HEADER=struct.Struct('<2sBBBBHH'); CRC=struct.Struct('<I')
MAX_PAYLOAD=112; MAX_DRAIN=512; MAX_RESULT_RECORDS_PER_READ=4
RESPONSE=1; ERROR=2
class Opcode(IntEnum):
    HELLO=0x01; LOAD_DESCRIPTOR=0x10; START_RANGE=0x11; STATUS=0x12
    READ_RESULT=0x13; ABORT=0x14; RESET=0x1f
class ErrorCode(IntEnum):
    BAD_OPCODE=1; BAD_LENGTH=2; BAD_GENERATION=3; STALE_JOB=4; BUSY=5
    FIFO_FULL=6; FIFO_EMPTY=7; DUPLICATE_START=8; NOT_READY=9
    RANGE_INVALID=10; IDENTITY_MISMATCH=11; INTERNAL=12; MISSING_RESULT=13
class ProtocolError(ValueError):
    def __init__(self,code:ErrorCode,message:str): self.code=code; super().__init__(message)
def crc32(data:bytes)->int: return binascii.crc32(data)&0xffffffff
@dataclass(frozen=True)
class Frame:
    opcode:int; flags:int; sequence:int; payload:bytes
    def encode(self)->bytes:
        if not 0<=self.sequence<=0xffff: raise ProtocolError(ErrorCode.BAD_LENGTH,'sequence outside u16')
        if len(self.payload)>0xffff: raise ProtocolError(ErrorCode.BAD_LENGTH,'payload too large')
        head=HEADER.pack(MAGIC,VERSION,int(self.opcode),self.flags,0,self.sequence,len(self.payload))
        body=head+self.payload
        return body+CRC.pack(crc32(body))
    @classmethod
    def decode(cls,raw:bytes)->'Frame':
        if len(raw)<HEADER.size+CRC.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'short frame')
        magic,version,opcode,flags,reserved,seq,n=HEADER.unpack_from(raw)
        if magic!=MAGIC or version!=VERSION or reserved or flags&~(RESPONSE|ERROR): raise ProtocolError(ErrorCode.BAD_LENGTH,'invalid frame header')
        if len(raw)!=HEADER.size+n+CRC.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'frame length mismatch')
        if CRC.unpack_from(raw,len(raw)-4)[0]!=crc32(raw[:-4]): raise ProtocolError(ErrorCode.BAD_LENGTH,'frame CRC mismatch')
        return cls(opcode,flags,seq,raw[HEADER.size:-4])
def response(req:Frame,payload:bytes=b'',error:bool=False)->bytes:
    return Frame(req.opcode|0x80,RESPONSE|(ERROR if error else 0),req.sequence,payload).encode()
def request(op:Opcode,seq:int,payload:bytes=b'')->bytes: return Frame(op,0,seq,payload).encode()
def encode_descriptor(desc:Descriptor)->bytes:
    raw=desc.encode()
    if len(raw)!=112: raise ProtocolError(ErrorCode.BAD_LENGTH,'descriptor payload must be 112 bytes')
    return raw
def decode_descriptor(raw:bytes)->Descriptor:
    if len(raw)!=112: raise ProtocolError(ErrorCode.BAD_LENGTH,'descriptor payload must be 112 bytes')
    return Descriptor.decode(raw)
RANGE=struct.Struct('<Q32sIHH') # generation, full job key, start index, count, range ID
def encode_range(generation:int,job_key:bytes,start_index:int,count:int,range_id:int)->bytes:
    if len(job_key)!=32 or not 0<=start_index<2**32 or not 1<=count<=64 or not 0<=range_id<=0xffff: raise ProtocolError(ErrorCode.RANGE_INVALID,'invalid range fields')
    return RANGE.pack(generation,job_key,start_index,count,range_id)
def decode_range(raw:bytes):
    if len(raw)!=RANGE.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'START_RANGE payload must be 48 bytes')
    generation,key,start,count,rid=RANGE.unpack(raw)
    if not 1<=count<=64: raise ProtocolError(ErrorCode.RANGE_INVALID,'range count must be 1..64')
    return generation,key,start,count,rid
STATUS_REQ=struct.Struct('<QH')
STATUS_WIRE=struct.Struct('<QHBBHHHHHH') # 24-byte, six independent flag bits
HELLO_RESPONSE=struct.Struct('<BBHHHHI') # 14 bytes
LOAD_ACK=struct.Struct('<Q32s')
START_ACK=struct.Struct('<QHH')
ABORT_WIRE=struct.Struct('<Q32sHH')
def encode_abort(generation,job_key,range_id,reason=0):
    if len(job_key)!=32: raise ProtocolError(ErrorCode.BAD_LENGTH,'ABORT job key must be 32 bytes')
    return ABORT_WIRE.pack(generation,job_key,range_id,reason)
def decode_abort(raw):
    if len(raw)!=ABORT_WIRE.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'ABORT payload must be 44 bytes')
    return ABORT_WIRE.unpack(raw)
def hello_payload(): return HELLO_RESPONSE.pack(1,0,3,112,64,112,0x0000003f)
class State(IntEnum): IDLE=0; READY=1; BUSY=2; DONE=3; ABORTED=4; ERROR=5
FLAG_BUSY=1<<0; FLAG_RESULT_READY=1<<1; FLAG_ERROR=1<<2; FLAG_STALE_JOB=1<<3; FLAG_OVERFLOW=1<<4; FLAG_ABORTED=1<<5
@dataclass(frozen=True)
class Status:
    generation:int; range_id:int; state:State; flags:int; input_occupancy:int; result_occupancy:int; next_slot:int; error_code:int; result_count:int; input_free:int
    def encode(self): return STATUS_WIRE.pack(self.generation,self.range_id,int(self.state),self.flags,self.input_occupancy,self.result_occupancy,self.next_slot,self.error_code,self.result_count,self.input_free)
    @classmethod
    def decode(cls,raw):
        if len(raw)!=STATUS_WIRE.size: raise ProtocolError(ErrorCode.BAD_LENGTH,'STATUS response must be 24 bytes')
        gen,rid,state,flags,*rest=STATUS_WIRE.unpack(raw)
        if flags&~0x3f: raise ProtocolError(ErrorCode.BAD_LENGTH,'undefined status bits set')
        try: state=State(state)
        except ValueError as e: raise ProtocolError(ErrorCode.BAD_LENGTH,'unknown status state') from e
        return cls(gen,rid,state,flags,*rest)
RESULT_PREFIX=struct.Struct('<QHHHH'); RESULT_SIZE=112
def encode_result(r:Result)->bytes:
    raw=r.encode()
    if len(raw)!=RESULT_SIZE: raise ProtocolError(ErrorCode.BAD_LENGTH,'wire result requires 32-byte raw digest and 64-byte canonical transcript')
    return raw
def decode_result(raw:bytes)->Result:
    if len(raw)!=RESULT_SIZE: raise ProtocolError(ErrorCode.BAD_LENGTH,'result record must be exactly 112 bytes')
    gen,rid,slot,row,col=RESULT_PREFIX.unpack_from(raw)
    return Result(gen,rid,slot,row,col,raw[16:48],raw[48:112])
def encode_read_request(generation:int,job_key:bytes,range_id:int,cursor:int,max_records:int)->bytes:
    if len(job_key)!=32 or not 0<=max_records<=4: raise ProtocolError(ErrorCode.RANGE_INVALID,'READ_RESULT limit must be 0..4 records')
    return struct.pack('<Q32sHHH',generation,job_key,range_id,cursor,max_records)
def decode_read_request(raw):
    if len(raw)!=46: raise ProtocolError(ErrorCode.BAD_LENGTH,'READ_RESULT payload must be 46 bytes')
    gen,key,rid,cursor,limit=struct.unpack('<Q32sHHH',raw)
    if limit>4: raise ProtocolError(ErrorCode.RANGE_INVALID,'READ_RESULT limit exceeds 4')
    return gen,key,rid,cursor,limit
