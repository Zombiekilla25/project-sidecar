# Project Sidecar miner 0.3.0-rc1 milestone

The 0.3.0-rc1 software candidate consolidates the PRL miner frontend and CPU verifier, supervised one-share canary guard, backend qualification artifact framework, offline FK33 fleet controller, and first-silicon benchmark/scaling subsystem.

- The full offline suite passes **244/244** tests.
- Fleet orchestration models guarded **1 → 2 → 4 → 8** expansion, card rollback, quarantine/rejoin, and telemetry. The deterministic mock fleet completed **10,000** work assignments.
- The five-hour miner reliability soak and 30-minute harness validation soak completed without genuine miner or harness failures.
- Benchmark ingestion and scaling models are ready for first-silicon timings. Synthetic examples are marked non-measured; missing real timings remain unknown.
- No live pool connection was used for this qualification.

## Qualification state and next gate

The real CUDA PearlHash backend remains unqualified. PHK1 physical RAW_BSCAN remains unqualified and no FPGA silicon qualification is claimed. The patched PHK1 candidate passed offline simulation, synthesis, implementation, timing, and DRC checks. Generating its VU33P bitstream is blocked because the available Vivado license does not permit `write_bitstream` for that target.

The next hardware milestone is a separately controlled one-card PHK1 qualification. Only after a valid result should its public-safe artifact and measured timings be imported, compared, and considered for the staged fleet rollout. This software milestone contains no hardware evidence, device identities, or bitstream files.
