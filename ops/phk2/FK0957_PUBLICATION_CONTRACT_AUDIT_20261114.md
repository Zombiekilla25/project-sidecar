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

- The previously blocked test,
  `test_phk2_physical_close_guard.PhysicalCloseGuardTests.test_16_direct_factory_and_legacy_session_bypass_refuse`, passed in the isolated
  venv: **1 test in 0.628 seconds**.
- Complete host suite in the isolated venv: **418 tests passed** in
  **102.015 seconds**. System Python was not modified and still does not
  import `blake3`.
- Relevant FK0957/supervisor/endpoint/provenance suite: **229 tests passed**
  in **81.064 seconds**.
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

## Audited source and test environment identity

- Exact implementation HEAD tested: `9c1c8e2ba70854b11416ec295f6fb80d71095767`.
- Its clean unsigned runtime-manifest snapshot identified **31 source files**
  and **10 native runtime objects**. Canonical snapshot SHA256:
  `4e15e48d951f66778e492bd90a9f1864faa79c03e86bbd787fa0c3c28084a42b`.
  This timestamped snapshot is unsigned and is not production authorization.
- The checked-in runtime manifest is only the non-production template;
  SHA256 `0d502ebb4c6db3dbe2b3d64b34fdbdea101ff7e9065f6c34944312fe1d62df0b`.
- `requirements.txt` SHA256:
  `a786ca4351aed15bf4d5bcac737b130478b8f78bf6c0f634847f3098ae070fde`.
- Isolated test environment: Python 3.12.3, blake3 1.0.11, cryptography
  46.0.7, cffi 2.1.1, pycparser 3.12. The environment was created under
  `/tmp/fk0957-audit-venv-20261114`; system Python remains unchanged.
- The reviewed native runtime snapshot contains 10 objects. It is an
  implementation inventory, not a newly authorized production pin set.

## Verdict

**OFFLINE SOFTWARE AUDIT: PASS.** The complete host suite and independent
publication-state oracle pass on the exact implementation HEAD above.

**PRODUCTION RELEASE / LIVE READINESS: BLOCKED.** No production issuer keys,
signed production manifest, privileged supervisor installation, or
independent deployment evidence was provisioned or verified in this task.

## Remaining blockers

This is not production authorization or deployment evidence. Production trust
keys and the privileged supervisor installation still require authorized
provisioning and independent verification. The software audit does not
authorize a live topology operation; no such operation was attempted.

Known optional test environment issue: the full host suite's sole error is the
missing optional `blake3` import used by the unrelated keyed-BLAKE3 physical
close-guard test.
