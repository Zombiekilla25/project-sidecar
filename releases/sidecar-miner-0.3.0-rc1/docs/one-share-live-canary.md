# One-share live canary runbook

This runbook describes a future reviewed run. The current launcher refuses live operation before DNS or socket activity. The first production test always stops after one submitted share response.

## Required preparation

1. Complete one-vector CUDA qualification on an explicitly idle GPU and archive the schema-valid CUDA qualification artifact.
2. Complete PHK1 physical HELLO, Vector001, rollback, and recovery qualification in the separate hardware workflow. Archive its source-pinned artifact; never infer qualification from a mock.
3. Supply endpoint, wallet/user, worker, and password through protected local configuration. Do not put secrets in committed files, logs, or evidence.
4. Choose an explicit GPU ID and a writable bounded log/evidence directory. Verify no unrelated miner owns the selected device.
5. Review exact binary/source hashes, qualification artifacts, pool endpoint, mode, and the one-share limit.

## Bounded command shape

After the live adapter has been separately enabled and reviewed, the operator command will be:

```sh
sidecar-canary \
  --live \
  --mode <gpu-only|sidecar|auto> \
  --pool HOST:PORT \
  --wallet USER \
  --worker WORKER
```

The launcher always fixes the attempt limit at one; it has no unlimited mining mode. Supply the password, GPU ID, qualification artifact paths and identity hashes, and logical FK target through protected local configuration or non-secret options. Use `--check` to validate without connecting and inspect `CANARY_EXECUTION_PLAN.json`. Auto mode requires matched measured timings and the qualified GPU fallback, and may select FK only when FK qualification and timing data are valid. No command in the current build opens a live connection.

Qualification records are explicitly imported with `sidecar-miner qualification import`; see [backend qualification](backend-qualification.md). Use `sidecar-miner status` to inspect qualification state without device access.

## Expected sequence and aborts

Preflight validates runtime config, logging, CPU verifier/share encoder, explicit GPU selection, and qualification artifacts before DNS or socket activity. The eventual run connects, authorizes, waits for one job, selects a qualified backend, obtains work, verifies the candidate on CPU, checks current job generation and target, encodes the share, and submits at most one attempt. It records that pool response and stops intake, cancels queued work, waits boundedly, closes the backend, disconnects, and flushes evidence.

Abort before pool connection on missing/invalid credentials, missing GPU selection, unavailable verifier/encoder/log path, stale or mismatched qualification artifact, or no qualified backend. Abort without share submission on new clean job, stale generation, malformed candidate, backend error, failed CPU verification, target miss, or encoding failure. On a submitted rejection, timeout, server error, unauthorized response, or disconnect, record the public-safe response class and stop; do not retry automatically. Any shutdown failure is recorded as unclean and requires operator review before another attempt.

The evidence artifact is `LIVE_MINER_CANARY_RESULT.json` and must validate against `schemas/live-miner-canary-result-v1.schema.json`. A successful mock test is not live qualification and must not be substituted for pool evidence.
