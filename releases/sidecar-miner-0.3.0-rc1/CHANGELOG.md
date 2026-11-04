# Changelog

## 0.3.0-rc1 — Project Sidecar miner software candidate

- Consolidates the PRL miner frontend, job lifecycle, CPU PearlHash verification, share encoding, and supervised offline session flow.
- Adds explicit backend qualification artifacts and fail-closed live-mode policy. Real CUDA and physical PHK1 remain unqualified.
- Adds the guarded one-share canary launcher, supervisor state/recovery handling, and public-safe evidence model.
- Adds deterministic soak/fuzz tooling, retained false-positive replay, regression coverage, a completed five-hour miner reliability soak, and a 30-minute harness validation soak.
- Adds offline FK33 fleet lifecycle planning for 1/2/4/8 cards, staged rollout, per-card rollback, quarantine/rejoin, telemetry, and dry-run status/plan/watch commands; the mock fleet completed 10,000 synthetic work assignments.
- Adds first-silicon timing ingestion, end-to-end/component accounting, pipeline and conservative fleet scaling models, bottleneck classification, and safety-gated expansion advice.
- Adds schemas, package metadata, synthetic fixtures, and release documentation.

### Safety and known limitations

- No live pool operation is enabled by this candidate.
- Real CUDA execution is not qualified; this release does not execute CUDA.
- PHK1 physical RAW_BSCAN is not qualified. VU33P bitstream generation currently awaits a Vivado license supporting the target.
- Fleet performance and benchmark fixtures are synthetic model inputs, not hardware measurements. Missing timing remains UNKNOWN/INSUFFICIENT_DATA.
- Fleet commands are offline policy/model operations and do not program or access hardware.
