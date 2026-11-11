# PHK2 FK0957 physical closure canary package

**Preparation status: OFFLINE ONLY. Physical-canary readiness: FAIL.** No
hardware, USB, XVC, JTAG, SSH, service, miner, or FPGA operation is part of this
preparation. Cases 40 and 33 remain `UNQUALIFIED`.

The plan is pinned to the immutable routed TCK envelope in local Git commit
`a01a735fb1e1d0e9b918a2d20c0733ba244b4ee0`, file
`results/phk2-v5_1-common-reset-20261110/tck_envelope/PHK2_V5_1_TCK_ENVELOPE.json`
(SHA256 `eea838b5d4dcf930b856299a909684a8eecc86f0d539bf9eb6cc7b8a26297e49`).
Its SHA256SUMS file binds 733 evidence entries and has SHA256
`7b0ba6de12201b93d40b8b6bc4ee7dd3adcfdf8d2b9420d15ed1823a0d4b7f09`.
The envelope uses source commit `5f65f0ec8900ecaae3c498223bef0efb2542c047`,
tree `dcc879775d80e07ab41bc9af955a29a3fd8ba6f9`, routed DCP SHA256
`0bd52785662a3c38f68667f85c75acdef33c109502794610669ab8e1cf61e9af`, target
`xcvu33p-fsvh2104-2-e`, and its envelope qualification commit is
`af539f88e99d4815010db7372dbc83decad2bd05`. This is routed STA evidence only.
It does not prove physical adapter behavior or jitter.

## Exact unresolved cases

| ID | Case | Current state | Purpose |
| --- | --- | --- | --- |
| 40 | `host_TCK_frequency_contract` | UNQUALIFIED | Measure the adapter pin waveform and compare every metric with the routed envelope. |
| 33 | `clock_interaction_no_unsafe` | UNQUALIFIED | Correlate physical TCK with the BSCAN/TCK interaction named by the routed clock-interaction report. |

The independent qualification remains **38/40** until both cases have authentic,
case-bound physical evidence and the signed promotion gate accepts it. Never
convert missing evidence, timing analysis, an XVC response, or an IDCODE-only
transcript into a PASS.

## Offline package verification

This command reads local Git objects and validates the immutable envelope and
its 733 SHA256SUMS entries. It does not access hardware or a network:

```sh
.venv/bin/python tools/phk2_host/phk2_physical_canary_plan.py
```

The command reports `physical_canary_readiness: FAIL`; it is not an executor.
There is intentionally no physical-execution flag or transport code in this
plan tool. The machine-readable package is
[`PHK2_FK0957_CANARY_PLAN.json`](../results/phk2-physical-canary/PHK2_FK0957_CANARY_PLAN.json).
The fixed one-card configuration is
[`PHK2_FK0957_CANARY_CONFIG.json`](../ops/phk2/PHK2_FK0957_CANARY_CONFIG.json),
the operator checklist is
[`PHK2_FK0957_PREPHYSICAL_CHECKLIST.md`](../ops/phk2/PHK2_FK0957_PREPHYSICAL_CHECKLIST.md),
and the append-only signed evidence contract is
[`PHK2_FK0957_EVIDENCE_SCHEMA.json`](../ops/phk2/PHK2_FK0957_EVIDENCE_SCHEMA.json).
The backend gap audit is
[`capture-backend-audit.json`](../results/phk2-physical-canary/capture-backend-audit.json).

## One-card scope and identity gates

The sole authorized target is FK0957, one card:

- Board/card ID: `153300000957`
- JTAG adapter serial: `153300000957A`
- Supplemental USB serial: `153300000957`
- Expected VU33P IDCODE: `04b69093` (family/model only; not unique)
- Historical FPGA DNA: `4000000001295d813c80a445`
- Part: `xcvu33p-fsvh2104-2-e`

The sealed identity record explicitly says current live v5.1 identity still
requires fresh observation; the historical DNA alone is not a live identity
proof. Before any future transport open, require a signed one-card target lock
that independently binds the adapter serial, board ID, target chain, deployed
bridge/service configuration, and expected current image. Obtain a fresh
identity observation through a separately reviewed method and compare the
IDCODE and DNA where that method permits. If the adapter-to-card mapping is
ambiguous, carrier identity is unknown, any second card/client is visible, or
any expected value differs, refuse before opening transport. USB path or
IDCODE alone is insufficient.

## Future preflight gates

A later authorized executor may proceed only after all of these pass from fresh,
content-verified evidence:

1. Immutable v5.1 source/tree/routed-DCP and the TCK-envelope commit/hash match
   the values above; the qualification is exactly 38 independent passes, zero
   independent failures, 38/40 overall, and two unresolved TCK cases.
2. Exact case IDs and definitions are 40 / `host_TCK_frequency_contract` and
   33 / `clock_interaction_no_unsafe`.
3. One-card authorization is authentic, unexpired, and bound to FK0957, the
   route, bridge hash/config, both cases, operator, session nonce, one-card
   scope, and operation. An operator-approved signing trust root must be pinned
   before this can pass.
4. Read-only process/socket inspection proves the expected SQRL/XVC server and
   exact bridge ELF/config, one listener, zero active clients, no competing
   local XVC/JTAG clients, a held OS exclusion lock, and network ACL/peer
   exclusion. No protocol probe is allowed during preflight.
5. A fresh signed live card/adapter identity matches FK0957 and no other card
   is in scope. A mismatch stops before any protocol bytes or TCK edges.
6. A reviewed physical capture backend and calibrated instrument are ready;
   the raw acquisition format, bandwidth, sample rate, threshold, calibration,
   and clock-control implementation are verified. The pre-transport journal
   is created and fsynced before any socket/USB/transport open.
7. The current image/workload baseline is attested and rollback/recovery
   instructions are ready. This test itself performs no programming or
   workload operation.

Any missing or ambiguous evidence means stop before transport. The present
closure executor does not meet these gates: its private physical opener
refuses, there is no instrument backend, and no authorization trust root is
pinned.

## First clock setting and Case A waveform

The conservative first planned rate is **5 MHz**, the lowest qualified
frequency point. Request a 200 ns period with 50% duty: 100 ns high and 100 ns
low. Run only one bounded 87-TCK scan, then stop. The allowed routed timing
rectangle is:

- Every measured period: **25–200 ns** (40–5 MHz).
- Every measured high pulse: **at least 10 ns**.
- Every measured low pulse: **at least 10 ns**.
- Every measured duty cycle: **40–60%**, inclusive.
- Jitter: compute and report minimum/maximum, peak-to-peak, and RMS from raw
  edges. **There is no qualified numeric physical jitter limit. Case A must
  refuse PASS until that limit and instrument uncertainty rule are added to an
  immutable qualification.**

The selected physical point should be 5 MHz / 50% only after an effective
adapter clock-control path has set it before the scan. The deployed SQRL/XVC
`settck` handler is known to echo its requested period without applying that
period to MPSSE; its response is never proof of rate. No effective MPSSE clock
setter exists in this closure backend today. Do not assume 5 MHz from an XVC
request. If the only available path would start at the bridge's nominal
configuration, refuse this conservative 5 MHz procedure until a reviewed
clock-control backend exists.

A future capture backend shall use a high-impedance, correctly rated probe at
the exact adapter TCK/SK output and adapter ground, with the adapter revision's
reviewed pinout. Use a single-shot acquisition triggered at the first rising
edge, 1 us pre-trigger and 20 us post-trigger, covering the single 87-clock
scan and idle tail. Preserve the native acquisition, plus lossless edge/sample
CSV (`sample_index,timestamp_ns,logic_level`) and instrument model/serial,
calibration certificate/hash and validity, probe/attenuation, bandwidth,
sample rate, threshold, coupling, channel, timebase, trigger settings, capture
window and software version. The instrument uncertainty and waveform threshold
must be stated, not guessed. Reject clipping, threshold ambiguity, missing or
extra edges, non-monotonic time, incomplete window, or disagreement between
raw data and derived summaries. Record measured frequency, period, high/low,
duty, jitter min/max, peak-to-peak and RMS. Every complete cycle must meet the
rectangle above; a missing jitter bound still blocks PASS.

## Case B sequence and observation

The currently approved bounded baseline is TAP reset, IDCODE instruction
`0x09`, 64-bit data capture under the pinned 87-cycle transcript, ending in
Run-Test/Idle. Capture the physical TCK waveform and semantic TMS/TDI/TDO
transcript in the same session, with timestamps/nonce linking both records.
Require expected IDCODE `04b69093`, exact clock count/vector and before/after
Run-Test/Idle state. No USER1, USER2, USER3, configuration instruction,
FPGA programming, or workload command is authorized by this package.

That baseline proves bounded TAP/IDCODE activity and pin waveform, but it does
**not** prove internal USER-branch behavior or clear the clock-interaction
criterion by itself. The matrix asks for physical waveform-to-BSCAN correlation.
The current design has three internal BSCANE2 clock branches; no reviewed
physical observer or exact expected BSCAN response is available here. A USER
instruction may be required to observe a fabric-side response, but the current
matrix/tooling does not supply an exact authorized opcode/transaction. Therefore
Case B remains blocked: do not guess a USER opcode or claim IDCODE alone is
sufficient. A separate immutable method/expected-response record and case-bound
authorization are prerequisites to any BSCAN-specific transaction.

## Stop and recovery rules

Stop immediately on identity/hash/config mismatch; unknown or expired
authorization; any peer/client/lock failure; unqualified clock-control path;
measured frequency/pulse/duty out of bounds; missing jitter policy; unexpected
TAP state, instruction, response or cycle; extra clock; capture/journal error;
disconnect/reconnect; or any evidence of image/workload change. Never retry a
partial/ambiguous scan, reconnect under the same session, start/stop services,
start/stop miners, reset/reprogram the FPGA, or continue into another
instruction. Return to Run-Test/Idle only if the bounded sequence completed as
specified, close the single transport, confirm no client remains, fsync and seal
the evidence, then release the exclusion lock. If idle, image, workload or peer
state cannot be confirmed, retain the lock and evidence and escalate to the
separately authorized recovery owner.

The test has no image mutation, so there is no programming rollback step. If
the current image differs from the authorized image, stop and use a separate
approved recovery procedure; this canary does not program the rollback image.

## Evidence and promotion

Before transport, create and fsync a `PRE_TRANSPORT` hash-chain journal. Append
preflight, authorization, envelope/qualification identity, bridge/card
identity, peer proof, clock-control setup, instrument metadata, raw waveform,
TAP transcript, each case result, and final idle/close. Hash every raw file and
the final bundle; sign role-bound capture/evidence records with an operator-
approved Ed25519 trust root. Promotion accepts Case A or B only when the
corresponding authentic physical capture parses, matches the exact case and
immutable route/envelope, passes every qualified numeric limit, and is signed
by the pinned capture/authorization roles. Strings such as `PHYSICAL_REAL`,
mock captures, hashes without raw data, or partial completion do not promote.
Both case results must pass for 40/40.

## Unresolved prerequisites

- Pinned operator authorization trust root and valid case-bound authorization.
- Reviewed physical waveform/TAP capture backend, instrument, calibration and
  authenticated raw acquisition.
- Effective 5 MHz adapter clock-control path; XVC `settck` readback is echo-only.
- A numeric qualified physical jitter limit and capture measurement-uncertainty
  policy.
- Fresh live FK0957 adapter/card/image identity proof.
- A matrix-approved BSCAN-specific observation method and exact expected
  response; USER instruction use remains unauthorized.

Until all are resolved, the package is prepared but **physical-canary readiness
is FAIL**, physical capture is not ready, and cases 40 and 33 remain
`UNQUALIFIED`.
