"""PHK1 host request/response framing used by offline raw-BSCAN fixtures."""
from __future__ import annotations
import binascii
import hashlib
import struct

MAGIC=b'PHK1'; RESPONSE_MAGIC=b'PHKR'; VERSION=1
STATUS_READY_MASK=1<<4
RECORD_COUNT=2048; RECORD_BITS=96; PAYLOAD_BYTES=24576
REQUEST_HEADER=struct.Struct('<4sHHIB3xHHI')
RESPONSE_HEADER=struct.Struct('<4sBBHIBBHHHI')

def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xffffffff

def build_request(transaction_id: int, tile_index: int, payload: bytes) -> bytes:
    if not 0 <= transaction_id <= 0xffffffff or not 0 <= tile_index < 8:
        raise ValueError('request identity outside PHK1 canary bounds')
    if len(payload) != PAYLOAD_BYTES:
        raise ValueError('request tile must contain exactly 24576 bytes')
    header=REQUEST_HEADER.pack(MAGIC,VERSION,1,transaction_id,tile_index,
                               RECORD_COUNT,RECORD_BITS,PAYLOAD_BYTES)
    return header+struct.pack('<I',crc32(header))+payload+struct.pack('<I',crc32(payload))

def parse_response(frame: bytes, transaction_id: int, tile_index: int) -> list[int]:
    if len(frame)!=96: raise ValueError('response length mismatch')
    fields=RESPONSE_HEADER.unpack(frame[:24])
    magic,version,status,opcode,txid,tile,reserved,count,width,reserved2,size=fields
    if (magic!=RESPONSE_MAGIC or version!=VERSION or status!=0 or opcode!=0x8001 or
        txid!=transaction_id or tile!=tile_index or reserved or reserved2 or
        count!=16 or width!=32 or size!=64):
        raise ValueError('response identity/status/dimensions mismatch')
    if struct.unpack('<I',frame[24:28])[0]!=crc32(frame[:24]):
        raise ValueError('response header CRC mismatch')
    payload=frame[28:92]
    if struct.unpack('<I',frame[92:96])[0]!=crc32(payload):
        raise ValueError('response payload CRC mismatch')
    return [int.from_bytes(payload[i:i+4],'little') for i in range(0,64,4)]

def vector_transaction_id(vector_id: str, payload_sha256: str) -> int:
    digest=hashlib.sha256((vector_id+'|'+payload_sha256).encode()).digest()
    return int.from_bytes(digest[:4],'little')

def parse_status(word: int) -> dict:
    if not 0 <= int(word) <= 0xffffffff:
        raise ValueError('status word out of range')
    word=int(word)
    if not word & STATUS_READY_MASK:
        raise ValueError('PHK1_READY is not asserted')
    return {'phk1_ready':True,'rx_space':bool(word&1),'error':bool(word&2),
            'tx_available':bool(word&4),'tx_flush':bool(word&8)}
