# PHK2 wire-source audit

Review branch: `host/phk2-fk33-board-integration-20261108`, commit
`8f8e07fa7d6c2637c58fd1713afed8d928becaf3`.

## Authority table

| Definition | Source / commit | SHA-256 | Authority and finding |
|---|---|---|---|
| Current board wire profile | `protocol/phk2-board-v1.json`, `fbf97f297c1fa4ea770e1ffa7fa64bec4e264a3a` | `9d25dc6697d63d49d59315e9ac42d1dded888de0dd2d30b6ad05e6d4627a5cff` | Newer command set and 112-byte descriptor; matches the host codecs. |
| Host frame and payload encoder/decoder | `tools/phk2_host/board_protocol.py`, `fbf97f297c1fa4ea770e1ffa7fa64bec4e264a3a` | `f9e7bbd5f956ed04a7a247f40b35961ce731d50f99ac7c05e8f3365482b14a9f` | Executable encoding authority for frames, CRC, payload layouts and error codes. |
| Host transport/device emulator | `tools/phk2_host/board_transport.py`, `fbf97f297c1fa4ea770e1ffa7fa64bec4e264a3a` | `ee2bbd4bebabfc9be49c51d38bc8239c41ad1adbcad1e52fcbc967050cc8f7ba` | Encodes requests, validates response identity and models command lifecycle. Physical access is disabled. |
| Descriptor semantics and CPU runtime | `tools/phk2_host/runtime.py`, `6ec5e5ac959c169df3e706377e7287f9c55b3392` | `8e4597ae14cf531615c7e206327630b3858468a66741f5480115e8bec715ba62` | Defines exact 112-byte descriptor field order and the host-side model. |
| Production CPU oracle adapter | `tools/phk2_host/oracle.py`, `6ec5e5ac959c169df3e706377e7287f9c55b3392` | `d7dc0d8468d72725b3eee99b989f08572c7d5ec251b4c84433164eb62f562c4b` | Computes expected production-backed operands/results; it is the correctness authority, not a wire-format source. |
| Host protocol qualification | `tools/phk2_host/board_qualify.py`, `fbf97f297c1fa4ea770e1ffa7fa64bec4e264a3a` | `740940d22a0bb5a0249682e99a6010bba904e9a9177242349fae0ccb398b5b56` | Exercises the host emulator and CPU oracle; it is not a physical BSCAN qualification. |
| RTL request-frame decoder | `rtl/phk2_board/phk2_protocol_decoder.sv`, `fbf97f297c1fa4ea770e1ffa7fa64bec4e264a3a` | `79edc740e073499e3d894b214dfe8882bacabbf4315591504efda532235f41cf` | Implements inbound framing/CRC and emits decoded commands. It does not encode framed responses. |
| RTL response-frame encoder | `rtl/phk2_board/phk2_protocol_response_encoder.sv`, local diagnostic change | `f5ba28ffa241d2a41dc9b306f7a2bd23443066200895f709b05645c4bc1e2a6f` | Standalone ready/valid framed response encoder; nine host golden responses, a maximum four-record READ_RESULT response, and an error response pass with backpressure. Not yet instantiated in the board top. |
| RTL board top | `rtl/phk2_board/phk2_fk33_board_top.sv`, `fbf97f297c1fa4ea770e1ffa7fa64bec4e264a3a` | `1e52c41c74c64c2ea785b754e07564d0bffc79655d3be00ca33c9aea15804633` | Uses a test stub and raw byte result FIFO; not a complete protocol endpoint or production top. |
| Frozen descriptor statement | `docs/phk2-v1-descriptor.md`, `b9970deba3e75dae81a88b42149f632429b4bbe9` | `81c8d8cf3fd206178bcf9189a71bffa6e4663848253a3052058ff9160d9421e2` | Core descriptor contract: 112 bytes; explicitly does not define physical framing. |
| Superseded compact protocol draft | `docs/phk2-compact-protocol.md`, `8bee18faf40889d2010c11f8c5236e1c8062fff3` | `9374419fecb2b5c33e8b8d80fedd5d855aab270f8f63ee5b5e61f525c408ec9d` | Earlier, incomplete 114-byte `LOAD_JOB` proposal; CRC details and command set were unfinished. |
| Superseded transport model | `tools/phk2_seed_work_golden.py`, `8bee18faf40889d2010c11f8c5236e1c8062fff3` in `project-sidecar-phk2-throughput-study` | `41bc42f3400d7a1bd18809d1882f1fa3f008eda1c06d3ab42c460e64e0a84553` | Carries modeled 114-byte payload/12-byte common-frame assumptions from the same draft; not an independent normative source. |
| Latest routed analysis top | `rtl/phk2_v1_analysis_top.sv`, `84ef0eb998077270c4eef6b95f107c18cac70438` | `6eebc0c22346e33d9d521fb4a924468122056f2f999256339316976a8c7fc02d` | This is the 175 MHz routed wrapper and sequential datapath. The top uses synthetic internal work state and is not a production board transaction core. |
| Measurement wrapper | `rtl/phk2_core_synth_top.sv`, `84ef0eb998077270c4eef6b95f107c18cac70438` | `c99d7f7dc34c0278cca36bb4862e42f5c4fe456d52752f8ddefc2cf85cf2dcf0` | Single-item datapath interface; it does not implement descriptor/range commands or the board result contract. |

## Resolution of 112 versus 114 bytes

`DESCRIPTOR_DATA_BYTES=112`. The selected command is `LOAD_DESCRIPTOR`, whose
payload is those 112 bytes exactly. The board frame adds a 10-byte header and
4-byte CRC trailer, so `WIRE_FRAME_OVERHEAD_BYTES=14` and the complete framed
request is 126 bytes.

The old 114-byte `LOAD_JOB` payload is not the 112-byte descriptor plus two
framing bytes. It is a different draft layout: generation (4), profile (2),
incomplete header (76), and target (32), totaling 114. The associated model
also assumed 12-byte frame overhead and a 14-byte START_RANGE payload; both
differ from the selected frame and range definitions. That proposal predates
the production-backed descriptor contract and is superseded. Its fields are
not mapped onto the production descriptor by assumption.

The selected descriptor is `job_key[32]`, `generation_fence[u64 LE]`,
`setup_seed64[u64 LE]`, `noise_seed_A[32]`, and `noise_seed_B[32]`. Its identity
and production semantics are bound to the host runtime and CPU oracle fixtures.

## CRC and command-source reconciliation

The current host codec and RTL request parser both use reflected CRC-32/ISO-HDLC
with polynomial `0xedb88320`, initial state `0xffffffff`, final XOR
`0xffffffff`, and little-endian trailer over the 10-byte header plus payload.
The standard `123456789` check value is `0xcbf43926`.

The old draft's phrase “to be frozen” is stale. The later executable host codec
and board protocol JSON define the convention above. However, the RTL parser
currently only parses requests and sets a sticky parser error; it does not
produce a framed error response. The board top's test stub returns raw result
bytes, not complete response frames. Thus host request encoding and inbound RTL
framing agree, but a full host/device protocol endpoint has not yet been proven.

## Real-core binding result

The timing-qualified core at `84ef0eb...` is a measurement wrapper with
`item_start`, operand stream, tile, digest-filter, and candidate ports. It does
not implement 112-byte descriptor acceptance, range scheduling, transaction
reset, full generation/job-key stale checks, or the board contract's 112-byte
raw/canonical result stream. The committed board top still instantiates
`phk2_core_stub`. The stub is test-only and cannot enter a physical source set.

Therefore this audit resolves the old wire draft in favor of the production
host runtime, but it does not mark `PHK2_WIRE_PROTOCOL_FROZEN=true`: response
encoding exists as a standalone module but is not connected to the BSCAN
response path, and the real timing-core binding fails CPU-oracle result
comparison. The source-bound results are in
[`phk2-wire-protocol-v1.json`](../results/phk2-wire-protocol-v1.json).
