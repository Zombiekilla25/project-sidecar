# PHK2 host runtime

The isolated `host/phk2-runtime-20261108` worktree implements the frozen v1 production payload: `job_key[32]`, `generation_fence[u64 LE]`, `setup_seed64[u64 LE]`, `noise_seed_A[32]`, and `noise_seed_B[32]`. The profile is fixed by protocol version and is not repeated in the 112 bytes. Offsets are job key 0–31, generation 32–39, setup seed 40–47, A noise seed 48–79, B noise seed 80–111. Encoder/decoder reject incorrect lengths and the descriptor is tested against all 13 retained production capture manifests.

The CPU oracle adapter calls the copied qualified PHK2 `production_capture_oracle.py`: it expands the captured V64 recipe, generates the four operand ports, computes all 20 CPU transcripts and keyed digests, and compares them byte-for-byte with retained expected files. It predicts expected operands, compact results and canonical transcripts for a supplied descriptor at the origin tile or the 8×8 batch64 origin window. The batch64 model reproduces all 64 authoritative operand hashes and checks the 20 overlapping captured CPU transcripts and digests for the retained fixture. It rejects unsupported coordinate windows instead of estimating answers. All 13 retained descriptors are replayed and cross-checked. The full batch64 semantic mock tests protocol lifecycle and verifies all 64 mock results against an independent host mock oracle. Production CPU golden comparisons cover all 13 retained (0,0) 4x5 tile fixtures.

`MockDevice` implements LOAD_JOB, START_RANGE, STATUS, READ_RESULT and ABORT with strict generation and range identity checks. Mock result bytes are deterministic and labeled mock in evidence. The physical transport interface is a future adapter boundary; no BSCAN/XVC/direct hardware command is exposed. PHK2 backend selection remains disabled until both the host and image are physically qualified, and rollback always selects PHK1.

Commands (from repository root):

```sh
PHK2_PYTHON=.venv/bin/python tools/phk2-host check
PHK2_PYTHON=.venv/bin/python tools/phk2-host descriptor
PHK2_PYTHON=.venv/bin/python tools/phk2-host oracle --input fixtures/phk2-host-runtime/authoritative-vector-001/descriptor.bin --start 0 --count 1 --output /tmp/phk2-oracle.json
PHK2_PYTHON=.venv/bin/python tools/phk2-host dry-run --output /tmp/phk2-evidence.json
PHK2_PYTHON=.venv/bin/python tools/phk2-host replay --output /tmp/phk2-replay.json
PHK2_PYTHON=.venv/bin/python tools/phk2-host benchmark-ingest --input benchmark.json
```

Install `requirements.txt` in an isolated Python environment for BLAKE3 (`python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`). No command opens a device. The evidence structure is `docs/schemas/phk2-evidence-v1.schema.json`; benchmark records follow `docs/schemas/phk2-benchmark-v1.schema.json`. Unknown silicon measurements are null. Mock elapsed phases use measured wall time and carry `measurement_class: MOCK`.
