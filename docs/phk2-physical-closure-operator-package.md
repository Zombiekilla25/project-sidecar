# PHK2 physical closure package

## Immutable case binding

The v5.1 38/40 qualification record is pinned to commit
`6ad11b72fc62a452195245984b69f236d4d3b315` and SHA256
`25b875c707aaa1ee43ec1da064b3fec0b2297aed87be4aacb2c7c2260b26c90e`.
The exact unresolved cases in its retained qualification matrix are:

| ID | Matrix case | Purpose |
|---|---|---|
| 40 | `host_TCK_frequency_contract` | Measure the real host adapter-pin TCK waveform and establish it against the qualified routed timing envelope. |
| 33 | `clock_interaction_no_unsafe` | Resolve the routed BSCAN/TCK self-clock interaction under real, bounded TAP activity and correlate physical TCK with the BSCAN interaction. |

The gate binds these ordered definitions, full matrix SHA256, v5.1 source
commit/tree, routed DCP SHA256, and qualification record SHA256. It does not
accept synthetic IDs, reordered cases, substituted criteria, or route hashes
from another run.

The retained v5.1 route analyzes `bscan_tck` at 50 MHz (20 ns period, 0/10 ns
edges). The immutable qualification explicitly says the physical host TCK
contract is unproven. Therefore these are route-analysis facts, not a
qualified physical waveform envelope; no physical TCK measurement can pass
until a later immutable qualification record supplies limits.

## Fail-closed state

The command that exists today is an offline evidence promoter. It does not
capture measurements or open transport. The pre-transport master gate now
requires an opaque single-use permit, cryptographic signed authorization,
cryptographically signed peer/card evidence, rollback readiness, a qualified
physical envelope, a reviewed capture backend attestation, and a durable
`PRE_TRANSPORT` journal entry. The transport factory and guarded session
constructor reject legacy boolean-only gates.

Current blockers are external to this tooling:

1. No operator-approved Ed25519 trust-root file exists for authorization,
   peer/card evidence, or capture-backend attestations.
2. No reviewed physical capture backend is installed or attested.
3. v5.1 has no qualified physical TCK waveform limits.

Consequently `LIVE_EXECUTION_AUTHORIZED=false`,
`EVIDENCE_CAPTURE_READY=false`, and
`PHYSICAL_CLOSURE_RUNNER_READY=false`. Do not treat this as an executable
physical runbook.

## Transport entrypoint audit and capability boundary

The audited call graph is:

```text
first_silicon_cli --live -> hard refusal (legacy plugin route disabled)
board_transport.PhysicalBscanTransport -> hard refusal (no physical implementation)
physical_tck_preflight -> read-only process/socket inspection; no connection
phk2_close_tck_cases -> offline manifest/evidence validation; no transport

master_pretransport_gate
  -> signed immutable qualification, artifact, bridge, peer/card, authorization,
     rollback and capture-backend checks
  -> create + fsync PRE_TRANSPORT journal record
  -> privately construct a process-local sealed executor
  -> open the exact bound transport inside the gate before returning it
  -> return only the executor, which owns that exact transport instance
```

There is no capability record type and no module-global authority registry.
The master gate defines the executor class locally, closes over a one-time
issuer object, initializes and fsyncs the journal, then privately opens the
transport before returning the executor. Callers receive neither a permit
that can be recombined nor a transport factory. Audit metadata is serializable
but carries no execution authority. Copying and serialization of the live
executor are refused. Its state advances through OPEN, CASE_A, CASE_B, and
CLOSED, or to ABORTED on an invalidation. Case B requires completed Case A;
close/abort and failed live-state or journal checks prevent replay or reconnect.
Each operation rechecks immutable artifacts, authorization, peer/card/runtime
claims, journal integrity, and the capture-opener identity.

Before this fix, the independent audit's forgeable-permit route and the legacy
CLI plugin hook were reported ungated. The supported transport-opening route
is now the master gate's private executor construction path. The only module
opener in this checkout refuses because no reviewed physical capture backend
is installed; legacy session construction and CLI live routes also refuse.
Ordinary imported callers are the threat model. Arbitrary Python code
execution, memory introspection, or runtime patching inside this interpreter
is outside that boundary. Synthetic gate tests patch the private refusal seam
and use mock transports only; no physical backend or live path is enabled.

## Parsers and evidence provenance

The accepted waveform format is UTF-8 CSV with exactly
`sample_index,timestamp_ns,logic_level`. The parser requires contiguous sample
indices, strictly increasing timestamps, at least 30 samples and ten complete
periods, then derives TCK, period, high/low widths, duty, jitter extrema,
peak-to-peak/RMS jitter, and sample count from raw edges. Any supplied summary
must agree with those calculations. The XVC `settck` echo is not accepted as
clock evidence.

The TAP parser accepts a bounded 87-clock reset/IDCODE-only trace: five TMS
ones reset the TAP, the six-bit IDCODE instruction `0x09` is shifted, exactly
64 DR bits are captured and checked against the expected IDCODE plus zero
padding, and the trace ends in Run-Test/Idle. Its exact bit vector rejects
USER1/USER2/USER3, configuration instructions, and extra shift/clocks. This
sequence alone does not prove the internal BSCAN interaction; Case B also
requires signed physical-TCK/BSCAN correlation evidence. No USER instruction
is authorized or currently justified by the matrix evidence.

Physical captures require signed Ed25519 documents from configured trust
roots, role-bound payloads, exact qualification hash/case ID, raw capture
bytes and matching SHA256. A `PHYSICAL_REAL` string or boolean is insufficient.
Peer proof content must bind the expected SQRL process, executable/build and
service config, listening socket owner, zero clients/competitors, a fresh
timestamp, and a held local exclusion lock. Card evidence must match the
immutable canary card/adapter/IDCODE metadata and exact bridge hash.

The hash-chained evidence journal writes and fsyncs `PRE_TRANSPORT` before a
transport permit can be issued. Failure to create/fsync it refuses transport.
The final promotion path remains unavailable until the external blockers
above are resolved and real signed evidence is captured.

## Required later operator invocation

Once the missing qualification, trust roots, capture backend, and separate
physical authorization exist, a future reviewed executor may expose a single
command defaulting to dry-run and requiring `--execute-physical`. It must
verify exact v5.1 artifact and bridge identity, rows 40 and 33, no active
client, one-card scope, peer exclusion, rollback readiness, signed
authorization, capture backend readiness, and the durable pre-transport
journal before opening transport. No such physical executor is installed by
this change.

No hardware, live XVC, USB enumeration, JTAG, or FPGA programming was used to
prepare this package.
