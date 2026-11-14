# FK0957 publication and supervisor operation contract audit

Date: 2026-11-14

## Scope

Offline software audit only. No FPGA hardware, production host, credentials,
or live service was accessed. The reviewed implementation commit is
`a4f544e49be858d41c70c216aea9e9a2aa2bbfc8`.

## Contract mismatch and correction

The supervisor held authoritative operation/authorization identity, child
process identity, terminal state, exit code, and child-result bytes. The
unprivileged supervisor client previously returned only child stdout and its
exit code. The RGB layer therefore lost the supervisor's terminal operation
contract before validating and signing the result. The separate RGB publisher
also tracked publication through a mutable string list rather than the same
operation-bound state used by acquisition.

The client now emits a canonical, bounded supervisor-result envelope. The RGB
orchestrator validates its exact schema and binds operation, authorization,
handoff, manifest, HEAD, transaction profile, target, child identity, terminal
state, exit code, and child-result digest to the request before exposing child
bytes. One operation-progress object carries confirmed supervisor state
through local result validation and signing. The publisher binds the signed
evidence digest and operation ID, advances through `SIGNED_STAGED`,
`PUBLISHING`, and `PUBLISHED`, and marks publication immediately after the
final destination identity has been verified. A subsequent observer or output
failure reports a post-success reporting fault and cannot downgrade the
published result to refusal.

Refusal and success status schemas reject unsigned stage, identity, status, or
code substitution. Malformed supervisor state values must fail through the
bounded refusal path rather than escaping as Python type errors.

## Verification

- Relevant FK0957/supervisor/endpoint/provenance suite: **229 tests passed**
  in **81.064 seconds**.
- Final full host suite: **418 tests**, **417 passed**, one unrelated error in
  `test_phk2_physical_close_guard...test_16_direct_factory_and_legacy_session_bypass_refuse` because the
  optional `blake3` module is not installed. It was not installed globally.
- Focused RGB CLI, RGB orchestrator, topology CLI, and supervisor suites passed
  (66 tests at the final focused checkpoint; subsequent type-guard regressions
  also passed in the 34-test focused run).
- Independent corrected state oracle: **28 valid**, **249,572 invalid**;
  **0 valid rejected**, **0 invalid accepted**. Candidate boundary,
  permit/candidate, open-state, partial scan, close-history, and no-generic-
  mutation checks passed.
- The independent oracle adapter was updated to map the pinned model's stage
  into the newly required `publication_state`; the pinned reference model and
  legality classifications were not changed.
- Deterministic malformed-envelope campaign, seed `20261113`: **2,858
  mutations rejected**, **0 unexpected acceptances**. It found an
  array-valued terminal-state `TypeError`; explicit string-type checks and a
  regression test now reject it cleanly.
- Scan transaction invariants remain **591 / 586 / 1177 TCK** with the
  reviewed transaction hashes unchanged.
- `compileall` and `git diff --check` passed.

## Remaining blockers

This is not production authorization or deployment evidence. Production trust
keys and the privileged supervisor installation still require authorized
provisioning and independent verification. The software audit does not
authorize a live topology operation; no such operation was attempted.

Known optional test environment issue: the full host suite's sole error is the
missing optional `blake3` import used by the unrelated keyed-BLAKE3 physical
close-guard test.
