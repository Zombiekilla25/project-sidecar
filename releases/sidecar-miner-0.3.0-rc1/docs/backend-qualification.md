# Backend qualification artifacts

The miner accepts the public artifact formats in schemas/phk1-physical-qualification-v1.schema.json and schemas/cuda-qualification-v1.schema.json. Both use the common sidecar-backend-qualification artifact type and a versioned backend identity. These fixture files are synthetic and do not qualify real hardware.

## PHK1 handoff

The hardware qualification session should export one sanitized file at:

    ~/.local/share/project-sidecar/qualification-handoff/phk1-physical-qualification-v1.json

It contains bitstream, runner, backend, transport and protocol identities, Vector001 raw and canonical exactness, CPU crosscheck, rollback status, and timestamp. It contains no USB serial, DNA, local evidence path, wallet, or private target identity. The miner does not read the research tree or scan this handoff directory automatically. Import is explicit:

    sidecar-miner qualification import PATH --expected-bitstream-sha256 SHA256

The loader checks the expected bitstream and current pinned RAW_BSCAN runner/backend hashes, plus protocol/transport/vector version and every pass gate. It stores the file under ~/.local/share/project-sidecar/qualifications/ and indexes only that explicit import. qualification list and qualification show phk1 print public-safe fields.

## CUDA qualification

CUDA follows the same public format with library/source/fixture/result hashes and explicit device selection evidence. Import requires all expected hashes:

    sidecar-miner qualification import cuda-qualification.json --expected-library-sha256 SHA256 --expected-source-sha256 SHA256 --expected-fixture-sha256 SHA256

This does not qualify CUDA now. No CUDA runtime, device enumeration, or kernel execution occurs during artifact import or status reporting.

## Configuration and status

Copy sidecar-miner.kryptex.example.json to ~/.config/project-sidecar/canary.json, replace placeholders locally, and restrict access to the file. The repository ignores local configuration and generated plans. For first production use, canary_shares must equal one.

sidecar-miner status --config FILE reports configured and qualification state without opening hardware. sidecar-miner qualification list shows imported records. The guarded launcher resolves the same store and artifact loader:

    bin/sidecar-canary --config ~/.config/project-sidecar/canary.json --check

Check validates selected backend qualifications and writes a public-safe plan; it does not resolve pool DNS, create a socket, initialize CUDA, or access USB. Live still fails closed before network activity in this build.

## Scheduling and live gates

Auto mode uses only qualified backends, measured matched timing, and a qualified GPU producer/fallback. FK-only qualification cannot become schedulable without qualified CUDA. Sidecar mode requires both CUDA and PHK1 qualification because the current mining flow uses GPU-produced PearlHash work. GPU-only requires CUDA qualification. The supervisor separately enforces identity-matched artifacts before preflight may connect. It rejects any offline fixture/mock adapter when live mode is requested.

The future first live attempt remains a one-share canary: validate artifacts and runtime target, connect, authorize, receive a job, verify the candidate with the CPU oracle, submit at most one share, record its response and clean shutdown, then stop. Synthetic fixture data never satisfies these qualification gates.

## Release

python tools/package_miner.py assembles a local dist/sidecar-miner-0.3.0-rc1/ layout and generates its release manifest from the checked-out commit. The package contains code, commands, schemas, docs, requirements, and the placeholder runtime config. It installs no services and performs no hardware or network operations.
