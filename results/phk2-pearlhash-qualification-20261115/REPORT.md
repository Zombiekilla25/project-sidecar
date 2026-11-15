# Independent PHK2 PearlHash Qualification — 2026-11-15

## Verdict

**Overall: BLOCKED for production workload / acceleration qualification.** The exact candidate passes substantial offline arithmetic and production-capture comparisons for its declared work-generation and single 4×8 tile scope. It does not yet establish full 16×16 production-tile behavior, board integration, cancellation in the routed top, or measured end-to-end acceleration. A directed controller test also exposes simultaneous abort/start behavior that should be specified and tested before relying on the batch controller.

No hardware, SSH, network, CUDA, pool, USB/JTAG, controller, signer, guardian, or FPGA programming path was used.

## Immutable identities

- PHK2 RTL candidate: `96f719903646977020570e5d7674bbbd60b39dde` (`feat/phk2-v1-core-rtl`), clean before/after verification; only ignored build products were generated.
- Production source capture identity: `open-pearl-miner` commit `41ef42158b110a088662f3aac1f7fd9c064bbe1b`. Its checkout contains an unrelated pre-existing modification to `csrc/gemm/pearl_ampere_tc.cu`; no changes were made there. Replay independently checked the pinned files it consumes.
- Capture replay document: `docs/phk2-production-capture-replay.json`, SHA256 `0d9bcb344e40ff6952fc9145280db5095531a591c9e646d6b030cd074ad24717`.
- Independent replay output: `/tmp/phk2-independent-production-replay-20261115.json`, same SHA256 as the deterministic replay document.
- RTL route-report checksum manifest: `results/phk2-v1-route-reports/SHA256SUMS`, SHA256 `b4a1e3431d2e1797a94a5170d3983ea046f9c8ab651931337b6f94ce26c62e7b`; report hashes checked against that manifest.
- Production files whose SHA256 matched capture pins included RNG CUDA `945ce7d5603f9d0ba422706c0882208aff361295aa6070e8224728a5cdf01a0e`, config serialization `26d9c5df58e4043ba502b7e4f7769537cdbc63eb469564a94da35faee34f9dac`, pool config `f73ac2faeda1490c381b3e46cbb5eac5ff0f95205d29fb7238298796ca4f324a` (see capture document for the complete source identity set).

## Production arithmetic and evidence scope

The reviewed production profile is V3, M=N=131072, K=4096, R=256. The miner uses a 16×16 hash tile, builds a per-tile transcript and compares keyed BLAKE3 output to the little-endian U256 target (`<=`). Matrix/setup commitment produces two 32-byte noise seeds; the independently replayed compact hardware descriptor carries setup seed plus both noise seeds and job/generation binding. The job key alone is **not** proven sufficient to regenerate the base-matrix commitment or noise seeds.

The 13 retained source-bound captures each reproduced exact CPU transcripts and keyed digests for the 20 captured GPU operand lanes; all 130 capture-manifest file records checked for size/hash, and all 13 records say share submission was false. The independent replay then checked 100,000 Philox references (seed 1346915122) and 100,000 randomized production work-generation points (seed 4126011031): zero mismatches. These are offline artifact comparisons, not evidence that a pool accepted or rejected a share.

The RTL implements exact Philox lane selection, rank-indexed sparse perturbation and keyed BLAKE3 uniform noise. Noise values are `(digest_byte & 0x3f) - 32`; noised signed int8 overflow is reported rather than clamped. B indexing is transposed (`k*131072 + col`), and its seed is setup seed + 1 modulo 2^64. The 4×8 record has 4 A bytes and 8 B bytes. The tile adapter uses K=4096 and R=256, accumulates signed products in signed 32-bit lanes, folds 32 accumulator words to 16 jackpot words, and the result filter hashes the 512-bit transcript before little-endian target comparison. In addition, an independent exhaustive check covered all 16,777,216 signed `(a0,a1,b)` triples for `packed_mul2`; every decoded product matched signed 8×8 multiplication.

## RTL regression results

The full local runner completed successfully in 102 seconds on the repeated run; the completed run output is preserved at `/tmp/phk2-independent-rtl-96f7199.log`.

- Philox combinational and sequential: 10,000 each, zero mismatch; sequential block latency 10 rounds.
- Keyed BLAKE3 combinational/sequential: 1,000 each, zero mismatch; sequential 14 rounds/hash.
- Descriptor/control checks and stale-job batch64 cases: pass (5/5 stale cases).
- Tile adapter: pass; production tile records: 4,096, 49,152 bytes, zero mismatch.
- Result pipeline: 9/9; result-path stress: 250,000 events, zero unexpected failures, duplicates, drops, stale accepts, or deadlocks.
- Full work generation: random 10,000 and sequential 10,000, zero mismatch. Sequential producer measured 418 cycles per 96-bit 4×8 operand record in all sampled cases.
- Authoritative captures in RTL: 53,248 records in combinational and sequential fixtures, zero mismatch; all 13 sequential capture tiles passed.
- One-tile end-to-end simulation: 49,152 operand bytes, 16 result words, 4,147 cycles. Batch64 combinational and sequential simulations: 262,144 records each; sequential path reported 109,840,833 total simulation cycles, of which 109,576,192 were work generation.
- Independent production replay: 13/13 captures exact; 100,000+100,000 seeded randomized checks, zero mismatches.

## Control-state discrepancy

A new disposable Icarus test asserted `abort=1` and `start=1` together while `request_generation == loaded_generation` on an active `phk2_batch64_controller`. Observed after the edge: `active=1, stale=0, work_index=0`. The `start` assignments later in the same sequential block override the earlier abort assignments. Thus abort does not dominate simultaneous start. The module is used by control/stale tests but is not instantiated in `phk2_v1_analysis_top`; this is a batch-controller contract discrepancy, not a mismatch in the tested tile arithmetic. Resolve intended priority and add a directed regression before relying on cancellation semantics.

The routed analysis top ties abort low, so route reports do not qualify abort handling. Its result output is consumed with `candidate_ready=1`, so the routed implementation does not measure external result backpressure. Separate simulation tests do cover held result and backpressure behavior.

## Scope gap: 4×8 versus production 16×16

The retained physical capture is a 4×5 region of operand lanes; the design’s generated record and arithmetic adapter cover a 4×8 block (32 outputs). Production consumes 16×16 output tiles (256 outputs). That is eight 4×8 output regions by raw element count, but the current work does not prove the required full-tile operand reuse, transcript ordering/fold equivalence, eight-region scheduler, or aggregate result protocol. Batch64 is 64 tile coordinates in one grid context, not 64 independent seeds. Therefore no full-production-tile throughput should be inferred by multiplying the 4×8 number by eight.

## Routed timing and resource audit

Reports are from Vivado 2026.1, part `xcvu33p-fsvh2104-2-e`, design `phk2_v1_analysis_top`, state `Routed`. The Tcl selects that analysis wrapper, makes a clock only, and assigns a generic clock plus five GPIO pins; it is not the FK33 board shell. At 175/200/225 MHz the reported WNS is +0.366/+0.022/+0.024 ns, respectively, with zero internally failing setup endpoints. The 175 MHz routed utilization is 8,204 LUTs, 7,231 FFs, 28 DSPs, zero BRAM and zero URAM. These numbers belong only to the routed analysis wrapper and cannot be projected to a complete board implementation. Timing summaries warn that two input ports have no input delay and three output ports have no output delay; the internal path result is not a complete interface timing signoff. 200/225 MHz have only ~22/24 ps setup margin in these constraints.

At 175 MHz, a 418-cycle serialized work-generation record implies about 418,660 records/s and 1,712,128 cycles (about 9.78 ms) for 4,096 records per 4×8 tile, before host setup, result protocol, or board transport. The tile-only one-item simulation’s 4,147 cycles is much smaller; work generation dominates. This is a simulation/clock projection, not measured silicon throughput. The 64-item sequential batch simulation is about 0.628 s if naively mapped to 175 MHz and likewise is not a performance result.

## Break-even assessment and next work

Input-byte reduction ratios in the capture model are conditional on preserved output sizes. They do not demonstrate speedup. A break-even result needs matched GPU and FPGA measurements over the same complete production job, including matrix commitment/setup, seed production, transfer, scheduling, FPGA work, transcript/hash and proof reconstruction, and returned result. No defensible end-to-end break-even value exists yet.

Shortest credible path: (1) fix/specify abort/start priority and prove held-result/backpressure plus generation rollover in the controller contract; (2) implement and CPU-oracle-test the complete production 16×16 tile/transcript path; (3) integrate the real FK33 clock/reset/CDC/transport shell and complete IO timing constraints; (4) route that exact board top and measure sustained end-to-end throughput against the same GPU job, excluding no setup or return work.

## Safety and limits

HARDWARE_ACCESS=NO. CUDA/FPGA/USB/JTAG/SSH/network/pool activity=NO. This report makes no production readiness, silicon identity, pool acceptance, or acceleration claim.

Reproducer: `abort-start-repro.sv` (run with `iverilog -g2012 -s abort_start_repro -o /tmp/repro rtl/phk2_batch64_controller.sv abort-start-repro.sv && vvp /tmp/repro`); observed output is `active=1 stale=0` after simultaneous abort/start.

Measured duration record: the full RTL runner's repeated invocation took 102 seconds. The capture-replay process completed successfully, but its wall-clock duration was not retained by the wrapper; no duration is claimed for that run.
