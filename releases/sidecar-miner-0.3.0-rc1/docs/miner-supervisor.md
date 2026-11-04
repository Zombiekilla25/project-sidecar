# Miner supervisor

`SidecarMinerSupervisor` is the lifecycle owner above Stratum, job generation, scheduler/backend selection, CPU verification, PRL share encoding, and submission. It imports without opening network, CUDA, or USB resources. Execution uses an injected adapter; the live path cannot pass preflight until qualification artifacts validate.

## Lifecycle

```text
CREATED -> PREFLIGHT -> CONNECTING -> CONNECTED -> AUTHORIZED
        -> JOB_READY -> BACKEND_READY -> MINING -> SHARE_CANARY
        -> STOPPING -> STOPPED
```

Every edge is checked against the transition table in `sidecar_miner/supervisor.py`. Illegal edges raise. Failures move to `FAILED`, and a controlled recovery must pass through `RECOVERING`. Stop order is: stop work intake, cancel queued batches, wait for active work up to the configured bound, close backend, disconnect Stratum, flush evidence, then record clean shutdown.

| State | Allowed next states |
|---|---|
| CREATED | PREFLIGHT, STOPPING, FAILED |
| PREFLIGHT | CONNECTING, STOPPING, FAILED |
| CONNECTING | CONNECTED, RECOVERING, STOPPING, FAILED |
| CONNECTED | AUTHORIZED, RECOVERING, STOPPING, FAILED |
| AUTHORIZED | JOB_READY, RECOVERING, STOPPING, FAILED |
| JOB_READY | BACKEND_READY, RECOVERING, STOPPING, FAILED |
| BACKEND_READY | MINING, RECOVERING, STOPPING, FAILED |
| MINING | SHARE_CANARY, RUNNING, DEGRADED, RECOVERING, STOPPING, FAILED |
| SHARE_CANARY | RUNNING, STOPPING, FAILED |
| RUNNING | JOB_READY, DEGRADED, RECOVERING, STOPPING, FAILED |
| DEGRADED | RECOVERING, STOPPING, FAILED |
| RECOVERING | CONNECTING, JOB_READY, BACKEND_READY, FAILED, STOPPING |
| STOPPING | STOPPED, FAILED |
| FAILED | RECOVERING, STOPPING |
| STOPPED | terminal |

## Live backend policy

`--live` or `SIDECAR_LIVE_ENABLED=true` is required to request a future live startup. That alone does not enable network execution. Live preflight additionally requires pool host/port, wallet/user, worker, explicit GPU ID, writable structured log path, CPU verifier and share encoder. It validates a CUDA vector qualification artifact for GPU use and the existing source-pinned PHK1 physical qualification artifact for FK use. `gpu-only` requires qualified CUDA; `sidecar` requires qualified CUDA and FK; `auto` requires qualified CUDA fallback and may select FK only with valid FK qualification. Missing backend qualification aborts before connection.

The current CLI reports live operation as blocked and has no live adapter wired. Offline mode remains the default. `--dry-run --canary-shares 1` uses a loopback Stratum fixture and mock backends only.

## Canary and share gates

The canary verifies current job fingerprint and generation, sealed CPU/reference verification, candidate validity, and share target before encoding. It checks job currency again after encoding and immediately before submission. Stale or bad work consumes no attempt. The attempt counter increments only immediately before the submit call. One accepted share ends the canary and triggers clean shutdown; rejected/timeout/disconnect responses are recorded and do not cause retries.

## Recovery, status and evidence

JSONL events rotate at 1 MiB with three backups and redact wallet/password/identity-shaped fields. Optional atomic recovery metadata records pool state, generation, selected backend, last share ID/response, and shutdown cleanliness without credentials. `--status` prints a concise human view; `--status-json` emits its machine-readable equivalent.

Canary evidence follows `schemas/live-miner-canary-result-v1.schema.json`. It contains public-safe run timing, mode/backend, connection/job booleans, attempts, response class, and cleanup result. It does not contain a wallet, pool password, GPU UUID, USB selector, DNA, or other private hardware identity.

The current status is offline-only. No real CUDA backend or PHK1 physical protocol qualification is inferred by mock canary tests.
