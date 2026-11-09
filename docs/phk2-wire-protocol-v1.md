# PHK2 FK33 wire protocol v1

**State: host codec frozen; physical device endpoint not yet qualified.**

This document resolves the earlier 114-byte proposal in favor of the
production-backed host runtime's 112-byte descriptor. Exact executable source
identities are listed in [the wire-source audit](phk2-wire-source-audit.md).
Golden synthetic frames are in
[`wire-golden-v1.json`](../fixtures/phk2-host-runtime/wire-golden-v1.json).

## Framing

All integers are unsigned little-endian unless stated otherwise.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 2 | Magic: `C2 5A` |
| 2 | 1 | Version: 1 |
| 3 | 1 | Opcode; response opcode is request opcode OR `0x80` |
| 4 | 1 | Flags: bit 0 response, bit 1 error, all others zero |
| 5 | 1 | Reserved, zero |
| 6 | 2 | Sequence ID |
| 8 | 2 | Payload length in bytes |
| 10 | N | Opcode payload |
| 10+N | 4 | CRC-32/ISO-HDLC, little-endian |

The CRC covers bytes 0 through the last payload byte. Parameters are reflected
polynomial `0xedb88320`, init `0xffffffff`, refin/refout true, xorout
`0xffffffff`; the check value for ASCII `123456789` is `0xcbf43926`.
Frame overhead is 14 bytes. A LOAD_DESCRIPTOR request is 126 framed bytes:
112 payload + 14 overhead.

Malformed headers, unsupported versions/opcodes, invalid lengths, and bad CRCs
must not execute a command. The current RTL parser suppresses command
acceptance and raises sticky parser error on CRC failure; it does not emit a
framed error response. The software codec rejects the frame. Recovery uses
STATUS or explicit RESET; the host must never blindly resend an ambiguously
clocked request. This parser/response recovery behavior still needs end-to-end
RTL qualification.

## Commands and responses

| Command | Op | Request payload | Successful response payload |
|---|---:|---|---|
| HELLO | `01` | empty | 14 bytes: major u8, minor u8, profile u16, descriptor bytes u16, max batch u16, result bytes u16, feature bits u32 |
| LOAD_DESCRIPTOR | `10` | exactly 112 descriptor bytes | 40 bytes: accepted generation u64, accepted job key[32] |
| START_RANGE | `11` | 48 bytes below | 12 bytes: generation u64, range ID u16, accepted count u16 |
| STATUS | `12` | generation u64, range ID u16 (10 bytes) | 24 bytes below |
| READ_RESULT | `13` | generation u64, job key[32], range ID u16, first slot u16, max records u16 (46 bytes) | zero to four complete 112-byte records |
| ABORT | `14` | generation u64, job key[32], range ID u16, reason u16 (44 bytes) | generation u64, range ID u16 (10 bytes) |
| RESET | `1f` | empty | empty |

A successful response uses flags bit 0 and echoes the request sequence. An error
response uses flags bits 0 and 1, opcode OR `0x80`, echoes the sequence, and
contains exactly one u16 error code.

### Descriptor

The 112-byte payload is:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 32 | job key |
| 32 | 8 | generation fence, u64 LE |
| 40 | 8 | setup seed, u64 LE |
| 48 | 32 | noise seed A |
| 80 | 32 | noise seed B |

The board profile is fixed as version 1/profile 3 in HELLO. The descriptor
carries no operand bytes. Generations must increase strictly on descriptor
replacement.

### START_RANGE

| Offset | Width | Field |
|---:|---:|---|
| 0 | 8 | generation, u64 LE |
| 8 | 32 | full job key |
| 40 | 4 | start index, u32 LE |
| 44 | 2 | count, u16 LE, range 1–64 |
| 46 | 2 | range ID, u16 LE |

A range is accepted only if generation and all job-key bytes match the loaded
descriptor. Duplicate active/completed range IDs are rejected.

### STATUS

| Offset | Width | Field |
|---:|---:|---|
| 0 | 8 | generation |
| 8 | 2 | range ID |
| 10 | 1 | state |
| 11 | 1 | independent status flags |
| 12 | 2 | input occupancy |
| 14 | 2 | result occupancy |
| 16 | 2 | next result slot |
| 18 | 2 | error code |
| 20 | 2 | result count |
| 22 | 2 | input free capacity |

Status flag bits are busy=0, result_ready=1, error=2, stale_job=3, overflow=4,
aborted=5. Higher bits are zero. State values are IDLE=0, READY=1, BUSY=2,
DONE=3, ABORTED=4, ERROR=5.

### READ_RESULT record

Each 112-byte record is generation u64, range ID u16, slot u16, row tile
u16, column tile u16, raw result[32], canonical transcript[64]. Fields are
serialized in that order. The host must check the identity and CPU-verify all
returned candidate/result data. A response is bounded to four records so the
framed read fits under 512 bytes.

### Errors

| Code | Name |
|---:|---|
| 1 | BAD_OPCODE |
| 2 | BAD_LENGTH |
| 3 | BAD_GENERATION |
| 4 | STALE_JOB |
| 5 | BUSY |
| 6 | FIFO_FULL |
| 7 | FIFO_EMPTY |
| 8 | DUPLICATE_START |
| 9 | NOT_READY |
| 10 | RANGE_INVALID |
| 11 | IDENTITY_MISMATCH |
| 12 | INTERNAL |
| 13 | MISSING_RESULT |

## 112 versus 114

The old 114-byte LOAD_JOB payload was generation[4] + profile[2] +
incomplete_header[76] + target[32]. It is a superseded, distinct proposal,
not a 112-byte descriptor plus two bytes of framing. That draft also assumed
12-byte common-frame overhead and a 14-byte START_RANGE payload; the selected
contract instead uses 14-byte frame overhead and a 48-byte START_RANGE
payload. Current LOAD_DESCRIPTOR payload is 112 bytes and the complete frame
is 126 bytes.

## Qualification boundary

The host codec, emulator, CPU oracle flow and synthetic golden frame set agree
on the host-side formats above. The RTL request parser checks inbound frames,
but the board top still uses a test-only core stub and emits raw result bytes
rather than framed responses. The current timing-qualified PHK2 measurement
top does not implement the descriptor/range/result transaction interface.

An offline wrapper experiment was driven with the current descriptor and the
timing-qualified analysis datapath. It reproduced all 4,096 records of the
retained 4x8 operand fixture, but its result transcript differed from the
production CPU oracle (`5ef101...` RTL versus `b16ffe...` oracle); the digest
also differed and was internally consistent with the RTL transcript. This is
a compute/result-shape mismatch, not a framing or endian issue. The experiment
is isolated under `experiments/phk2-core-contract-diagnostic/` and excluded
from the physical source manifest. The count-1 mismatch blocks Batch64
integration. Therefore `PHK2_WIRE_PROTOCOL_FROZEN=false` for physical use
until the device response encoder, full core binding, and result semantics
agree with the host/oracle contract.

The initial PHK2 175 MHz board clock proposal is 200 MHz differential input ->
IBUFDS -> PLLE4_ADV with DIVCLK divide 2, feedback multiply 14, CLKOUT divide
8 -> 175 MHz BUFGCE core clock. This yields a 1.4 GHz PLL VCO mathematically;
it is a new PHK2 design choice, not a historical qualified clock. Vivado
clocking legality has not yet been checked, so this proposal is not qualified.
