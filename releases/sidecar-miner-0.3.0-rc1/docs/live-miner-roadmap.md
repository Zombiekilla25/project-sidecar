# Sidecar live-miner roadmap

No stage below is marked complete by this offline integration. Completion requires the listed evidence and independent review.

1. **First correct PHK1 silicon vector** — capture the exact target/job identity, input, raw output, canonical composition, and reference agreement on hardware.
2. **Real PHK1 timing ingestion** — archive the fifth-canary result JSON with identity-bound timings; unknown FPGA compute remains `null`/`UNKNOWN` until observable.
3. **Measured GPU-versus-FK comparison** — collect matched end-to-end GPU and Sidecar timings for the same workload and batch size; retain correctness and transfer/compute breakdowns.
4. **Qualify CUDA on one idle GPU** — run exactly the prepared reference-vector selftest and publish a source/library/fixture-bound qualification artifact. Current state: runtime-test-ready, not qualified.
5. **Qualify PHK1 physical RAW_BSCAN** — complete physical HELLO/Vector001, exact raw/canonical result, CPU crosscheck, rollback, and recovery in the separate hardware workflow. Current state: pending physical qualification; VU33P bitstream generation requires an appropriate Vivado device license and is tracked separately.
6. **Compare measured backends** — ingest real CUDA and PHK1 end-to-end timings for matched work before allowing auto to choose FK.
7. **Offline full-job execution with qualified artifacts** — load imported artifacts, run the real selected compute backend with the mock pool, and retain CPU verification before submission eligibility.
8. **One controlled live Kryptex share canary** — after qualification and runtime integration, validate credentials and logs before connection, submit at most one locally verified share, record the response, and stop cleanly. See [one-share canary runbook](one-share-live-canary.md).
9. **Sustained mining soak** — only after the one-share canary succeeds and separately reviewed, demonstrate accepted-share behavior, reconnect/fallback handling, stale-job rejection, and telemetry over the approved soak interval.

The supervisor/controller, one-share launcher, public qualification-artifact ingestion, and mock flow are implemented offline. This does not qualify a backend, authorize live pool access, or complete any physical/live roadmap stage.
