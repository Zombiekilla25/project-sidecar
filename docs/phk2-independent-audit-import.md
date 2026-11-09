# Independent PHK2 semantic audit import

The auditor worktree was read only. Source identities:

| Artifact | SHA-256 |
|---|---|
| `results/phk2-independent-oracle-audit.json` | `30204f917df2c084ea31e04fa958064a8ce5f92d5731a1848f0abaa44e4101a3` |
| `docs/phk2-independent-oracle-audit.md` | `6694965a0ebd6c2add6abd97f8b9a334b4f0b9e1a7b75e7d60526534aeac2017` |
| `tools/validate_phk2_wire_contract.py` | `06ea271098bcc73a5f17cc3c4884cb797fe4399fdd15a0398fb8e88ae01ff4cb` |
| `fixtures/phk2-independent/batch64-golden-v1.jsonl.gz` | `c6c7a9405b52a4a746f74921b5c781cdba1dadab2e80387dcca99663edd7804d` |

The auditor uses production host runtime commit
`6ec5e5ac959c169df3e706377e7287f9c55b3392`, replays 13 retained capture
descriptors, validates 100,000 descriptor/job/result identity cases, and
generates 1,000 Batch64 rows. Those Batch64 rows have distinct job keys and
generation values but intentionally reuse one authoritative arithmetic seed
tuple; they are identity/result-binding vectors, not 1,000 seed ensembles.

## 125 versus 126 bytes

The numbers describe different objects:

| Offset | Bytes | Semantic field | Middle model | Independent model | Authority |
|---:|---:|---|---|---|---|
| 0 | 2 | frame magic | `C2 5A` | excluded | host frame codec |
| 2 | 1 | version | `01` | excluded | host frame codec |
| 3 | 1 | opcode | `LOAD_DESCRIPTOR=10` | excluded | host frame codec |
| 4 | 1 | flags | `00` request | excluded | host frame codec |
| 5 | 1 | reserved | `00` | excluded | host frame codec |
| 6 | 2 | sequence | u16 LE | excluded | host frame codec |
| 8 | 2 | payload length | `112` u16 LE | excluded | host frame codec |
| 10 | 112 | descriptor fields | full 112-byte production descriptor | same 112-byte descriptor | committed runtime and retained descriptors |
| 122 | 4 | CRC trailer | CRC-32/ISO-HDLC, LE | excluded | selected host codec only |
| — | 8 | range generation identity | separate START_RANGE field | counted in semantic minimum | independent semantic audit |
| — | 2 | bounded range start | START_RANGE wire storage is u32; accepted domain 0..65535 | 2 semantic bytes | independent semantic audit / bounded host domain |
| — | 1 | qualified count | START_RANGE wire storage is u16; accepted domain 1..64 | 1 semantic byte | independent semantic audit / qualified count |
| — | 2 | range ID | u16 | 2 semantic bytes | both models |

Thus 125 is a semantic byte lower bound: 112 descriptor bytes plus 13
explicit range-identity bytes. It excludes frame headers, CRC, duplicate job
key echoes, and the actual separate command frames. 126 is the complete
framed LOAD_DESCRIPTOR command: 10-byte header + 112-byte payload + 4-byte
CRC. There is no byte arithmetic error and no terminator byte. The current
START_RANGE frame adds 62 bytes (10 + 48 + 4), making the actual two-command
load/start exchange 188 bytes, before status or results. These totals are not
interchangeable.

The separate `114` value remains a superseded payload draft. It is not part of
either 125-byte semantic accounting or 126-byte framed LOAD_DESCRIPTOR.

The machine-readable semantic projection is
[`results/phk2-independent-semantic-contract.json`](../results/phk2-independent-semantic-contract.json).
It passes the auditor's validator. That validator checks semantic fields; it
does not validate opcodes, CRC, or exact frame bytes.

## Core result mismatch

For the retained Vector001 descriptor (generation 8, setup seed
`0957000000000004`, K=4096, R=256), the previous wrapper produced one
4×8 subtile. The retained trace and generated RTL records agreed for all
4,096 K records at 12 bytes/record. The production Batch64 CPU oracle defines
one full work item as 16 A bytes + 16 B bytes per K record, 32 bytes/record.
At record 0 the shared first-subtile inputs are exact:

```text
full CPU record (32 bytes): 25c608d9 eff33fe212e713bb f0e21739 c92fe025e204c242 edece8f4e54dfae4
current RTL 4×8 record:      25c608d9 c92fe025e204c242
```

The first missing data is operand-shape offset 12: the current single subtile
does not include A rows 4..15 and B columns 8..15. This is a partial-tile
mapping issue, not seed, Philox, BLAKE3, endian, signed conversion, or host
serialization. The class is `OTHER: INCOMPLETE_4X8_SUBTILE_COVERAGE_OF_16X16_WORK_ITEM`.

CPU-only algebraic composition verified that four 4-row groups × two 8-column
groups, with the eight 16-word tile transcripts XOR-composed, reproduces the
production CPU transcript exactly. The diagnostic wrapper is being extended
to run those eight subtiles serially through the existing arithmetic tile.
This CPU identity does not itself qualify the RTL wrapper; the RTL differential
must still pass before claiming a production record or Batch64 pass.
