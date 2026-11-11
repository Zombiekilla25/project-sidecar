# PHK2 physical closure operator package

## Readiness boundary

This worktree does not contain the authenticated current 40-case qualification
matrix or its immutable source/hash. A repository and all-ref Git-object
search found case *kinds* in the templates, but no source-defined IDs,
criteria, TAP procedure, or exact BSCAN clock-observation requirement. Thus:

```text
CASE_A_ID=UNRECOVERED
CASE_A_PURPOSE=Physical adapter-pin TCK waveform/contract (matrix purpose text unavailable)
CASE_B_ID=UNRECOVERED
CASE_B_PURPOSE=Physical BSCAN/TCK interaction (matrix purpose text unavailable)
```

Do not substitute `SYNTH-A`/`SYNTH-B` from tests or invent criteria. The
existing closure verifier requires the exact source matrix and both complete
case definitions in the authenticated qualification manifest. The current
`PHK2_TCK_CLOSURE_MANIFEST.template.json` is intentionally synthetic and
non-qualifying.

An IDCODE-only scan can reset the TAP and observe the adapter-level TCK
waveform, but the retained runbook explicitly says that it does not select a
BSCANE2 USER chain and therefore cannot by itself demonstrate the internal
BSCAN/self-clock interaction. The current evidence does not establish that a
USER instruction is avoidable for Case B. If the matrix requires a USER
instruction, the instruction and exact read-only sequence must come from that
case definition and require separate case-bound authorization. Until then,
Case B has no executable sequence and the physical execution gate stays
closed.

## One operator entry point (prepared shape)

The intended single entry point is:

```sh
phk2_physical_close \
  --qualification /authorized/package/PHK2_TCK_CLOSURE_MANIFEST.json \
  --card /authorized/card/PHK2_TARGET_LOCK.json \
  --bridge-policy /authorized/bridge/PHK2_SQRL_XVC_POLICY.json \
  --bridge-attestation /authorized/bridge/bridge-attestation.json \
  --authorization /authorized/PHK2_PHYSICAL_AUTHORIZATION.json \
  --dry-run
```

The entry point is **not implemented as a physical executor** in this
worktree. The existing `physical_tck_preflight.py` provides local process,
socket, identity, lock, and artifact checks without protocol traffic. The
existing `phk2_close_tck_cases.py` verifies captured evidence and performs
offline promotion; it never connects. No installed capture backend combines
them into an authorized physical executor, so `PHYSICAL_CLOSURE_RUNNER_READY=false`.

After the matrix and a reviewed capture implementation exist, the same entry
point must be invoked with explicit physical authorization:

```sh
phk2_physical_close \
  --qualification /authorized/package/PHK2_TCK_CLOSURE_MANIFEST.json \
  --card /authorized/card/PHK2_TARGET_LOCK.json \
  --bridge-policy /authorized/bridge/PHK2_SQRL_XVC_POLICY.json \
  --bridge-attestation /authorized/bridge/bridge-attestation.json \
  --authorization /authorized/PHK2_PHYSICAL_AUTHORIZATION.json \
  --execute-physical
```

This command shape is not currently installed and must not be treated as
executable.

When the authenticated matrix and a reviewed capture backend exist, the same
entry point must default to dry-run and require `--execute-physical` before it
can open any transport. Before that flag can cause any connection, the runner
must pass, in order:

```text
V5_1_QUALIFIED_OFFLINE=true
TCK_INDEPENDENT_PASS=38
EXACT_BRIDGE_SHA_MATCH=true
PEER_EXCLUSION=true
NO_ACTIVE_XVC_CLIENT=true
ONE_CARD_SCOPE=true
ROLLBACK_READY=true
EVIDENCE_JOURNAL_READY=true
EXPLICIT_AUTHORIZATION=true
```

Any failed or indeterminate precheck stops before transport open. The
peer-exclusion software is the existing process/socket-only preflight; it
does not provide remote network ACL proof by itself. The deployment owner
must bind that proof into authorization and the evidence package.

## Case evidence to capture once the matrix is recovered

Case A must capture an externally measured TCK/SK waveform at the exact
authorized adapter pin, referenced to adapter ground, during only the
matrix-approved bounded activity. Preserve raw samples and instrument/probe,
bandwidth, sample rate, calibration, trigger, and capture-window metadata.
Record:

```text
MEASURED_TCK_HZ=
MEASURED_PERIOD_NS=
MEASURED_HIGH_NS=
MEASURED_LOW_NS=
MEASURED_DUTY_CYCLE=
JITTER_MIN_NS=
JITTER_MAX_NS=
MEASURED_JITTER_P2P_NS=
MEASURED_JITTER_RMS_NS=
```

Compare these values against the exact qualified route envelope in the
authenticated manifest. The SQRL/XVC ELF's `settck` response is an echo and
is not effective-clock evidence.

Case B must use the exact source-defined sequence, capture its TAP response,
and correlate the observed physical TCK with the interaction required by the
matrix. Start and finish at confirmed Run-Test/Idle, stop after the bounded
observation, and close once without retry/reconnect. No programming,
configuration instruction, image change, or workload change is permitted.
IDCODE-only is not claimed sufficient for BSCAN self-clock proof.

## Journal and promotion

The offline promotion verifier now requires provenance `PHYSICAL_REAL`, both
case results, raw waveform and TAP/correlation records, explicit flags for
unexpected TAP responses and USER instructions, and the exact close/idle
record. It requires `JITTER_MIN_NS` and `JITTER_MAX_NS` as well as peak-to-peak
and RMS jitter. A USER instruction requires separate authorization naming the
Case B ID. Promotion stages the bundle in a temporary directory, writes an
append-only SHA256 hash-chained journal, hashes the final tar, and atomically
renames the completed directory. A partial/aborted run cannot promote.

After both exact matrix cases pass, the offline result will include:

```text
TCK_CASE_A_PASS=true
TCK_CASE_B_PASS=true
QUALIFICATION_CASES=40
QUALIFICATION_CASES_PASS=40
QUALIFICATION_CASES_FAIL=0
PHYSICAL_HOST_TCK_CONTRACT_PROVEN=true
PHYSICAL_PROTOCOL_QUALIFIED=true
```

Only real evidence (`evidence_class=PHYSICAL_REAL`,
`synthetic_fixture=false`, `production_evidence=true`) may reach that state.
Mock evidence, stale evidence, aborts, unexpected responses/instructions,
partial records, and any hash mismatch refuse promotion.

## Offline negative coverage

The refusal suite covers bridge mismatch, active peer, peer-exclusion failure,
wrong card scope, wrong route artifact, TCK above envelope, duty violation,
unstable jitter, unexpected TAP response, unexpected USER instruction,
partial evidence write, and operator abort. Additional existing tests cover
wrong binary/service config, duplicate server, competing client, stale/live
foreign lock, missing/unqualified manifest, missing TCK envelope, missing
waveform/BSCAN evidence, mock-as-production, and stale evidence.

Nothing in this package authorizes or performs physical execution.
