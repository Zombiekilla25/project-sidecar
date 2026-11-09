import json
from pathlib import Path
from board_protocol import Frame, crc32, decode_descriptor, encode_descriptor
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
    print('CRC_CONTRACT_TESTS=4/4')
    print('GOLDEN_WIRE_VECTORS=PASS (8 commands + bad-CRC rejection)')
    print('HOST_ENCODER_TO_GOLDEN=PASS')
    print('GOLDEN_TO_HOST_DECODER=PASS')
    print('DESCRIPTOR_ROUNDTRIP=PASS')
if __name__=='__main__': main()
