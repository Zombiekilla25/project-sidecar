# First-silicon benchmark and scaling analysis

`sidecar-miner benchmark` ingests public-safe PHK1 timing artifacts and reports measured single-card accounting separately from theoretical multi-card models. It never probes hardware or mutates fleet state.

## Artifact and timing contract

The stable input is `schemas/first-silicon-benchmark-v1.schema.json`. `timings_us` carries host preparation, transport in, FPGA compute, transport out, composition, CPU verification, explicit end-to-end total, and (separately) backend vector total. Unknown values must be `null` or `UNKNOWN`. The adapter does not infer end-to-end time by summing phases and does not substitute vector time for end-to-end latency. If a phase is unavailable the corresponding percentages or throughput remain unknown.

Transport is input plus output transfer; compute is the reported FPGA compute field only. Host time comprises preparation, composition, and CPU verification. Component totals are compared with the explicit total and flagged when they exceed it. Unattributed end-to-end overhead is reported separately.

## Analysis models

The pipeline model reports serial, double-buffered, and ideal steady-state pipeline scenarios. Fleet scaling uses a deliberately conservative shared-host model: all non-FPGA-compute latency is serialized/shared and only FPGA compute is parallelized. These projections are explicitly simulated and are not measured throughput. The GPU/FK comparison schema leaves throughput, power, and throughput-per-watt unknown until supplied with measurements.

Bottleneck classification requires a complete component set and a consistent end-to-end total. Recommendations describe what to measure or profile; they do not make protocol, RTL, clock, or hardware changes.

Rollout expansion advice is advisory only. A `YES` requires a measured non-synthetic artifact with passing qualification, exact raw/canonical/CPU checks, rollback, healthy backend, zero stale results, matching active image/runner identity, a healthy fleet stage, and explicit minimum gain and efficiency thresholds. A known failed gate yields `NO`; missing measurements or thresholds yield `INSUFFICIENT_DATA`. The benchmark code never advances rollout state and cannot override fleet safety gates.

## CLI

```text
sidecar-miner benchmark ingest first-silicon.json
sidecar-miner benchmark show
sidecar-miner benchmark fleet --fleet-config fleet.json --minimum-gain 0.15 --minimum-efficiency 0.70 --minimum-stage-transactions 100 --minimum-observation-seconds 3600 \
  --maximum-timeout-rate 0.01 --maximum-transport-error-rate 0.01
sidecar-miner benchmark bottleneck
```

Artifacts are normalized into the XDG user data store at `project-sidecar/benchmarks/latest.json` by default; `--store` selects a different local path. Ingest is file-only and performs no network or device operations. `show`, `fleet`, and `bottleneck` emit machine-readable JSON suitable for a dashboard.

Synthetic examples in `fixtures/benchmark/` exercise analysis categories only. They carry `measured: false` and cannot support fleet expansion recommendations.
