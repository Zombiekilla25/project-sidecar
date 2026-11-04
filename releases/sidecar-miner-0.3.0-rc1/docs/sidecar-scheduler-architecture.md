# Project Sidecar scheduler and performance model

## Scope and evidence

This branch provides an offline decision and timing model. It does not drive a GPU, open an FPGA transport, connect to a pool, or touch the active canary. Local sources establish an FK33-capable PHK1 tile operation (24,576 operand bytes in; 64 raw result bytes out, with protocol framing around each). They do not establish that the full PearlHash search/proof path can be partitioned onto FK33. The scheduler therefore models the documented tile stage only and leaves whole-workload end-to-end qualification to measurements.

## Stages

`schemas/pearlhash-stages-v1.json` records each established stage, I/O type/size, implementations, batching/parallelization status, and correctness gate. GPU source supports PearlHash search/noise/GEMM and host proof construction. The PHK1 protocol supports a fixed operand tile and raw dot-product result. Host canonical composition remains a separate stage. The official CPU verifier is the final correctness reference. Variable-size proof/work data is marked as such instead of assigning invented byte counts.

## Runtime layout

- **GPU producer:** `GpuBackend` prepares a job and produces typed batches with job fingerprint, generation, identity, and timing.
- **FK fleet:** `Fk33Backend` accepts assigned high-level batches and returns raw/canonical result identities, health, and timing. The scheduler has no hardware transport concepts.
- **Queues:** bounded GPU→FK and FK→verify queues apply backpressure. Full queues reject more enqueue work, so producers must pause or retain work upstream. A new job generation clears queued and active batches; late responses fail generation checks.
- **Verification:** raw/canonical identities must match, job fingerprint/generation must match, backend must report correctness and health, then injected `ReferenceBackend` must accept the result. Failure never becomes a candidate.
- **Fallback:** timeout, unhealthy backend, excessive latency, incorrect/stale result, or lost fleet member marks that FK unhealthy. Healthy remaining FKs may continue; when none remain, controller selects GPU-only. FK failures do not block the GPU path.
- **Multi-FK:** assignment supports round-robin, least-loaded, and batch partition across 1/2/4/8 modeled devices. This is a software simulation, not concurrent hardware execution.

## Timing and decision rules

Schemas in `schemas/` accept microseconds, null/unknown components, logical bits, physical scan clocks, and JTAG clock frequency. PHK1 timing includes programming, backend open, target revalidation, hello, host packing, input stream, FPGA compute, output stream, host composition, verification, and end-to-end vector total. GPU timing records setup, H2D, kernel, D2H, verification, total, batch size, and throughput.

`vector_total_us` and GPU `total_us` are the decision basis. The scheduler recommends Sidecar only when both inputs are explicitly measured and the measured Sidecar end-to-end total is lower for the comparable batch. Missing totals or synthetic inputs yield `INSUFFICIENT_DATA`. Transfer means measured input and output streaming only. Host packing/composition, setup, and verification remain host overhead. Transfer and FPGA compute percentages are independently reported; transport is not relabeled as compute.

The batch simulator uses explicit fixed setup, per-item transfer, compute/composition, and verification terms. Pipeline modes are theoretical: serial uses the sum of GPU production, FK service, and host verification; double-buffered overlaps GPU and FK; pipelined uses the slowest stage as steady-state cycle. Outputs are labeled simulated. They never replace measured end-to-end totals.

## Canary ingestion

`load_phk1_canary()` consumes a future JSON document with schema `sidecar-phk1-canary-result-v1`, job fingerprint, result identity, status, and `timings_us`. It allows absent optional stage values and `fpga_compute_us: null`/unknown, while requiring job/result identity and a timing object with `vector_total_us` present (the value may be null). Once the fifth canary result exists, copy/select that artifact as input to the CLI; the parser does not search for it or interact with a running terminal.

## Synthetic fixtures

`fixtures/synthetic/` includes GPU-wins, FK-wins, transfer-dominated, compute-dominated, batching break-even, and fleet-scaling cases. Every fixture says `SYNTHETIC TEST FIXTURE ONLY`, has `measured: false`, and is refused for a production decision. Replace only with comparable, identity-bound measured data after canary evidence is available.
