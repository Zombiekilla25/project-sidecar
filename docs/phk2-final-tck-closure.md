# PHK2 final TCK closure harness

## Evidence available in this worktree

The exact 40-case qualification matrix and a qualified v4 routed report are
not present in this worktree. The retained
`results/phk2-fk33-physical-qualification.json` says route was `NOT_RUN`; the two `clock-interaction.json`
files under `results/phk2-overnight-readiness/rehearsals/` are synthetic
fixtures, not reports. The repository's general image manifest schema does not
carry the reported 37/40-to-38/40 case matrix or its last two case IDs.
Therefore exact `CASE_ID`, required inputs, numerical acceptance criteria and
the BSCAN interaction route cannot be responsibly filled from available
evidence. The runner requires those definitions and their hashed source matrix
inside the future authenticated closure manifest and refuses if they are
missing, ambiguous, or not exactly one `PHYSICAL_TCK_WAVEFORM` plus one
`BSCAN_CLOCK_INTERACTION` case.

The non-qualifying input shape is documented in
[`PHK2_TCK_CLOSURE_MANIFEST.template.json`](../ops/PHK2_TCK_CLOSURE_MANIFEST.template.json).

Current case-definition status (exact matrix fields unavailable):

| Field | Case A: physical TCK waveform | Case B: BSCAN clock interaction |
| --- | --- | --- |
| `CASE_ID` | Not present in retained matrix evidence | Not present in retained matrix evidence |
| Purpose | Measure adapter-pin TCK waveform against the routed qualified envelope | Demonstrate the routed BSCAN/self-clock relationship under actual TAP activity |
| Required inputs | Qualified v4 envelope, exact adapter/bridge identity, authorized peer-excluded capture | Authenticated matrix procedure, routed BSCAN/CDC assumptions, before/after TAP evidence, physical clock correlation |
| Required measurement | Frequency, period, high/low width, duty cycle, peak-to-peak and RMS jitter | The exact clock/event relation named by the qualified case; not specified in retained reports |
| Pass/fail criteria | Must be copied from the selected routed envelope and exact matrix row | Not inferable without the matrix and routed interaction report |
| Evidence output | Raw waveform plus instrument/probe/sample metadata and computed metrics | Bounded TAP transcript, clock correlation, before/after idle state and close evidence |

These are descriptive categories from the task and retained TCK work, not
substitute case requirements. The verifier requires the missing source-derived
`required_inputs`, `required_measurement`, `pass_criteria`, `fail_criteria`,
and `evidence_output` fields before accepting either case.

The RTL shows BSCANE2 chains 1, 2 and 3. Chain 2 is the USER input/command
path, chain 1 is the result/read path, and chain 3 is a synchronized status
path. An IDCODE-only TAP scan does not select any BSCANE2 USER chain and thus
cannot demonstrate BSCAN self-clock behavior. The exact BSCAN chain and
read-only sequence must be taken from the missing qualified case definition.
At least the corresponding USER instruction will be required unless that
qualified case source proves another safe observation is sufficient. No
USER1/USER2 or other USER instruction has been authorized here.

## Offline verifier contract

`tools/phk2_host/phk2_close_tck_cases.py` verifies already captured evidence;
it contains no USB/XVC/JTAG transport and cannot execute a test. The future
manifest is `PHK2-TCK-CLOSURE-MANIFEST-v1`; it must bind:

- `TCK_INDEPENDENT_PASS=38`, `TCK_INDEPENDENT_FAIL=0`, and independent result
  PASS;
- route-qualified routed DCP and configured image artifacts with matching
  hashes, target part, exact qualified TCK envelope, and a hashed authenticated
  case matrix defining precisely the two remaining cases;
- fresh bridge attestation matching the reviewed ELF SHA256 and Build ID;
- fresh, independently signature-verified one-card authorization bound to
  exact route/image/part, peer exclusion, workload preservation, and rollback;
- physical waveform and TAP/BSCAN evidence, preflight, exact adapter identity,
  no workload/image mutation, and clean idle close.

The verifier checks measured frequency, period, high/low widths, duty cycle,
and peak-to-peak/RMS jitter against that manifest envelope. `settck` response
is never accepted as a clock measurement. It rejects mock/synthetic evidence,
stale records, partial case completion, mismatch in route/image/bridge
identity, and an existing output directory. Successful promotion creates a
new evidence directory and a tar bundle with a SHA256; it reports 40/40 only
after both exact case IDs pass. Promotion is not possible from today's
templates or synthetic rehearsal reports.

Future invocation (not executed):

```sh
python3 tools/phk2_host/phk2_close_tck_cases.py \
  --qualification-manifest <qualified-v4-closure-manifest.json> \
  --bridge-attestation <bridge.json> \
  --authorization <future-authorization.json> \
  --evidence <completed-physical-evidence.json> \
  --output-dir <new-append-only-promotion-directory>
```

No physical action is authorized by this tool. The eventual BSCAN step must be
bounded by its authenticated case definition, preserve the current image and
workload, record TAP idle before/after and raw transaction evidence, and stop
after the required observation. If the case requires a mutating USER2 command,
or if its required sequence cannot be established as read-only, it remains
unauthorized until separately redesigned and approved.
