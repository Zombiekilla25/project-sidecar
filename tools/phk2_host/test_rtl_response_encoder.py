#!/usr/bin/env python3
"""Compare the synthesizable RTL response encoder with frozen host frames."""
from __future__ import annotations
import json, struct, subprocess, tempfile
from pathlib import Path
from board_protocol import Frame, ErrorCode, response
from runtime import Result

ROOT=Path(__file__).resolve().parents[2]
MAX_PAYLOAD=448

def main():
    vectors=json.loads((ROOT/'fixtures/phk2-host-runtime/wire-golden-v1.json').read_text())['vectors']
    cases=[]
    for name,item in vectors.items():
        if name=='BAD_CRC': continue
        request=Frame.decode(bytes.fromhex(item['request_hex']))
        reply=Frame.decode(bytes.fromhex(item['response_hex']))
        cases.append((request.opcode,request.sequence,reply.payload,False,bytes.fromhex(item['response_hex'])))
    req4=Frame(0x13,0,0x789a,b'')
    payload4=b''.join(Result(0x0102030405060708,0x0203,i,i//8,i%8,
      bytes((i+j)&255 for j in range(32)),bytes((i+j+32)&255 for j in range(64))).encode() for i in range(4))
    resp4=response(req4,payload4)
    decoded4=Frame.decode(resp4)
    cases.append((req4.opcode,req4.sequence,decoded4.payload,False,resp4))
    req=Frame(0x7e,0,0x3456,b'')
    err=response(req,struct.pack('<H',int(ErrorCode.BAD_OPCODE)),error=True)
    er=Frame.decode(err)
    cases.append((req.opcode,req.sequence,er.payload,True,err))
    if len(cases)!=10 or len(cases[-2][2])!=448: raise AssertionError('expected nine success frames including four-record read and one error response')
    with tempfile.TemporaryDirectory(prefix='phk2-wire-encoder-') as td:
        td=Path(td)
        inputs=[]; expected=[]; lengths=[]
        for opcode,seq,payload,is_error,frame in cases:
            fields=bytes((opcode,))+struct.pack('<HH',seq,len(payload))+payload+bytes(MAX_PAYLOAD-len(payload))
            inputs.append(f'{int.from_bytes(fields,"little"):0{len(fields)*2}x}')
            expected.append(f'{int.from_bytes(frame+bytes(462-len(frame)),"little"):0924x}')
            lengths.append(len(frame))
        (td/'encoder-input.mem').write_text('\n'.join(inputs)+'\n')
        (td/'encoder-expected.mem').write_text('\n'.join(expected)+'\n')
        (td/'encoder-length.mem').write_text('\n'.join(f'{n:04x}' for n in lengths)+'\n')
        out=td/'sim.vvp'
        subprocess.run(['iverilog','-g2012','-s','tb_phk2_protocol_response_encoder','-o',str(out),
          str(ROOT/'rtl/phk2_board/phk2_protocol_response_encoder.sv'),
          str(ROOT/'tests/phk2_board/tb_phk2_protocol_response_encoder.sv')],check=True,cwd=ROOT)
        run=subprocess.run(['vvp',str(out)],text=True,capture_output=True,cwd=td)
        if run.returncode: raise SystemExit(run.stdout+run.stderr)
        print(run.stdout.strip())

if __name__=='__main__': main()
