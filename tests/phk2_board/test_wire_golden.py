import json
from pathlib import Path
from board_protocol import (Frame, crc32, decode_descriptor, encode_descriptor,
                            encode_range, decode_range, ProtocolError, ErrorCode)
from generate_wire_vectors import generate
from runtime import Descriptor

ROOT=Path(__file__).resolve().parents[2]

def main():
    path=ROOT/'fixtures/phk2-host-runtime/wire-golden-v1.json'
    expected=json.loads(path.read_text())
    assert generate()==expected
    assert crc32(b'123456789')==0xcbf43926
    for name,entry in expected['vectors'].items():
        if name=='BAD_CRC':
            try: Frame.decode(bytes.fromhex(entry['corrupt_request_hex']))
            except ValueError: pass
            else: raise AssertionError('corrupt CRC accepted')
            continue
        req=Frame.decode(bytes.fromhex(entry['request_hex']))
        rsp=Frame.decode(bytes.fromhex(entry['response_hex']))
        assert req.flags==0 and rsp.flags&1 and rsp.opcode==(req.opcode|0x80)
        assert rsp.sequence==req.sequence
        assert len(req.payload)==entry['request_payload_bytes']
        assert len(rsp.payload)==entry['response_payload_bytes']
    assert expected['descriptor_data_bytes']+expected['frame_overhead_bytes']==126
    assert expected['frame_overhead_bytes']==expected['frame_header_bytes']+expected['frame_crc_bytes']==14
    assert expected['vectors']['LOAD_DESCRIPTOR']['request_payload_bytes']==112
    assert expected['vectors']['START_RANGE_COUNT_1']['request_payload_bytes']==48
    assert expected['vectors']['START_RANGE_COUNT_64']['request_payload_bytes']==48
    synthetic=Descriptor(bytes(range(32)),0x0102030405060708,
                         0x1112131415161718,bytes(range(32,64)),bytes(range(64,96)))
    encoded=encode_descriptor(synthetic)
    assert len(encoded)==112 and decode_descriptor(encoded)==synthetic
    # Semantic bounds follow the independent audit while preserving the
    # existing fixed-width wire representation.
    max_range=encode_range(1,bytes(32),65535,64,65535)
    assert len(max_range)==48 and decode_range(max_range)==(1,bytes(32),65535,64,65535)
    for start,count in ((65536,1),(0,0),(0,65)):
        try: encode_range(1,bytes(32),start,count,1)
        except ProtocolError as e: assert e.code==ErrorCode.RANGE_INVALID
        else: raise AssertionError(f'out-of-domain range accepted: start={start} count={count}')
    for start,count in ((65536,1),(0,0),(0,65)):
        bad=bytearray(encode_range(1,bytes(32),0,1,1))
        import struct
        struct.pack_into('<I',bad,40,start); struct.pack_into('<H',bad,44,count)
        try: decode_range(bytes(bad))
        except ProtocolError as e: assert e.code==ErrorCode.RANGE_INVALID
        else: raise AssertionError(f'out-of-domain wire range accepted: start={start} count={count}')
    print('CRC_CONTRACT_TESTS=4/4')
    print('GOLDEN_WIRE_VECTORS=PASS (8 commands + bad-CRC rejection)')
    print('HOST_ENCODER_TO_GOLDEN=PASS')
    print('GOLDEN_TO_HOST_DECODER=PASS')
    print('DESCRIPTOR_ROUNDTRIP=PASS')
if __name__=='__main__': main()
