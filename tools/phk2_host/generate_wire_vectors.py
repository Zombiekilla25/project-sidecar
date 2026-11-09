#!/usr/bin/env python3
"""Generate public synthetic PHK2 wire golden frames from frozen codecs."""
from __future__ import annotations
import json, struct
from pathlib import Path
from board_protocol import (
    Opcode, Frame, RESPONSE, ERROR, ErrorCode, State, Status, Result,
    request, response, encode_range, encode_read_request, encode_abort,
    hello_payload, LOAD_ACK, START_ACK, STATUS_REQ, STATUS_WIRE,
    RESULT_SIZE, encode_result,
)


def generate() -> dict:
    key=bytes(range(32))
    descriptor=key+struct.pack('<QQ',0x0102030405060708,0x1112131415161718)+bytes(range(32,96))
    assert len(descriptor)==112
    gen=0x0102030405060708
    cmds={
        'HELLO': (Opcode.HELLO,b'',hello_payload()),
        'LOAD_DESCRIPTOR': (Opcode.LOAD_DESCRIPTOR,descriptor,LOAD_ACK.pack(gen,key)),
        'START_RANGE_COUNT_1': (Opcode.START_RANGE,encode_range(gen,key,0,1,1),START_ACK.pack(gen,1,1)),
        'START_RANGE_COUNT_64': (Opcode.START_RANGE,encode_range(gen,key,0,64,2),START_ACK.pack(gen,2,64)),
        'STATUS': (Opcode.STATUS,STATUS_REQ.pack(gen,2),Status(gen,2,State.DONE,2,0,64,64,0,64,512).encode()),
        'READ_RESULT': (Opcode.READ_RESULT,encode_read_request(gen,key,2,0,1),encode_result(Result(gen,2,0,0,0,bytes(range(32)),bytes(range(64))))),
        'ABORT': (Opcode.ABORT,encode_abort(gen,key,2,7),struct.pack('<QH',gen,2)),
        'RESET': (Opcode.RESET,b'',b''),
    }
    vectors={}
    for i,(name,(op,payload,reply)) in enumerate(cmds.items()):
        req=request(op,i,payload)
        rsp=response(Frame(int(op),0,i,payload),reply)
        vectors[name]={'request_hex':req.hex(),'response_hex':rsp.hex(),
                       'request_payload_bytes':len(payload),'response_payload_bytes':len(reply)}
    # A CRC failure is rejected locally. The RTL parser raises sticky error and
    # does not accept/execute the command, so there is intentionally no reply.
    bad=bytearray(request(Opcode.HELLO,0)); bad[-1]^=1
    vectors['BAD_CRC']={'corrupt_request_hex':bytes(bad).hex(),'expected':'REJECT_NO_COMMAND_NO_AUTOMATIC_RETRY'}
    return {'schema':'PHK2-WIRE-GOLDEN-VECTORS-v1','fixture_class':'SYNTHETIC_PROTOCOL_ONLY',
            'descriptor_data_bytes':112,'frame_header_bytes':10,'frame_crc_bytes':4,
            'frame_overhead_bytes':14,'frame_crc_known_answer':{'input_hex':b'123456789'.hex(),'crc32_iso_hdlc':f'{0xcbf43926:08x}'},
            'vectors':vectors}

if __name__=='__main__':
    out=Path(__file__).resolve().parents[2]/'fixtures/phk2-host-runtime/wire-golden-v1.json'
    out.write_text(json.dumps(generate(),indent=2,sort_keys=True)+'\n')
    print(out)
