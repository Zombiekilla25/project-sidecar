# FK0957 offline integration and release-hardening milestone — 2026-11-14

**Status: software integration in progress; production release and live deployment BLOCKED.**

This public-safe progress report summarizes the three development-workstream terminal reports reviewed on November 14, 2026. The results are reported by the local workstreams and are **not** independent verification of the full private development workspace by this public repository. It is a development milestone, **not** a production release or authorization.

## Operations acceptance

- The operations integration workstream reported **768 operations tests passing**, plus **62 compatibility tests** against the independently audited publication response implementation.
- Publication/refusal contract integration and deterministic refusal/campaign evidence were committed locally.
- The operations branch was reported as contract-compatible but not Git-synchronized with the audit branch. Its checkout had no configured upstream; an offline bundle and patch series were prepared rather than pushed.
- The controller still pins an older production HEAD and invokes the older orchestrator. Integration of the audited one-shot CLI and exact release/source pins remains open.
- Refusal progress remains diagnostic evidence, not an authorization to restore operation. Trusted supervisor-status authorization binding for certain refusal/status paths remains open.

## Release-candidate integration

- The release-hardening workstream produced an integrated offline candidate and regenerated a current source manifest and handoff snapshot.
- Transactional disposable-install staging and rollback for recoverable faults had passed tests in the preceding iteration. Subsequent hard-kill testing identified a separate limit: crash leftovers can leave orphan staging siblings, and no cleanup/recovery route for these remnants was demonstrated.
- The historical split-manifest checker still refers to an earlier implementation and reported stale matches; the current manifest is separate. Its historical marker-scanning false positive remains an open tooling issue, not grounds to waive source verification.
- The offline release-candidate workstream reported passing software/oracle/source checks and unchanged golden-count evidence.
- The candidate and its local integration evidence were **not pushed** by that workstream.

## Independent audit

- The independent auditor previously completed **418/418 host tests** in an isolated Python environment and rejected **2,858 malformed-envelope inputs** with zero unexpected acceptances.
- The latest independent pass exercised the candidate integration and reported both baseline and expanded candidate suites. It independently identified the hard-kill orphan-staging cleanup gap.
- The auditor preserved an **unsigned** runtime-manifest snapshot as audit evidence only. It is not a production trust document or deployment authorization.
- No production host, hardware, USB/JTAG, signing-key provisioning, or live installation was used in the reported audit.

## Remaining gates

1. Synchronize the operations branch, audited implementation, controller, one-shot CLI, and exact release/source references at an identified common revision.
2. Fix or explicitly gate crash-leftover stage cleanup and retest interruption/recovery behavior.
3. Reconcile current and historical manifest checks without suppressing source-integrity failures.
4. Re-run operations, installer, host, and independent oracle tests against the **same exact candidate commit**.
5. Obtain genuine production authorization, signed manifest, privileged administrator installation, and independent real-deployment verification before any live-readiness claim.

**No FK0957 production release or live deployment is certified by this milestone.**

## GitHub publication process

A local Codex commit is not a published GitHub milestone. For each active development day, publish a dated, sanitized summary to this repository, document test results and outstanding blockers, and verify the resulting remote commit URL. Maintain implementation/release branches separately; do not merge unreviewed private code or publish raw machine evidence simply to satisfy the daily reporting cadence.

## Verified follow-up — offline release-candidate recovery — 2026-11-14

The isolated release worktree now has source candidate `50fe500558495273501f643e0a0024443e23e210` and a separate local evidence-metadata commit `684770dd9657d070c982ce98fe84c839016456a6`. These commits remain local; no implementation branch was published to this public repository.

- The exact-candidate FK0957 focused suite passed **473 tests** in 131.45 seconds. A fresh detached checkout repeated the same **473 tests** in 127 seconds; compile and whitespace checks passed there too.
- Disposable installer recovery passed **20 tests** in 18.464 seconds, including hard termination during source copying, first installation, launcher construction, publication, cleanup, and recovery retry. The previous complete release remained intact or the first-install destination remained absent/complete; neighboring paths were preserved.
- Operations acceptance passed **844 tests** across the targeted and three broad runs in 104.456 seconds.
- The corrected independent state oracle passed **28 valid states** and rejected **249,572 invalid states**, with zero mismatches.
- The canonical unsigned source manifest covers **31 source files** and **10 runtime objects**. Manifest SHA-256: `a3f4b8afc516213128faea59c5bdeac44226d3692d20423f0de505b33b7b6d16`. Three reordered passes checked every recorded source hash against the candidate Git blobs.
- Initial queue harness attempts had working-directory/output-path assumptions; those failures were retained in the private queue journal, the runner was corrected, and the completed candidate runs above passed.

The read-only operations compatibility checker accepts the candidate identity but still reports six deployment/integration blockers: there is no production manifest signature or provisioned trust root; the controller and transaction profile remain pinned to the prior production identity/entrypoint and source hashes; and the signed permit/handoff contract does not explicitly bind supervisor authorization identity. The current manifest is unsigned integrity evidence only. No production authorization, privileged installation, live permit, or live acquisition occurred. Production trust and deployment remain blocked.


## Independent audit addendum — 2026-11-14 (later checkpoint)

The independent workstream subsequently reviewed the same source candidate `50fe500` and release-evidence revision `684770d`, ran its **473-test host baseline** and a **170-checkpoint** disposable-install recovery campaign, and issued an explicit **FAIL** verdict. This supersedes any interpretation that Middle's earlier passing suites establish full candidate correctness.

- **Malformed refusal/status values** can raise uncaught `TypeError` exceptions. The operations/runtime boundary needs explicit input validation and regression tests for malformed data, with conservative refusal behavior.
- **Installer parent-path replacement** can leave orphan staging artifacts. Middle's passing hard-kill recovery tests do not cover every relevant path-identity/cleanup condition; recovery and path safety need a new independent test matrix.
- The audit-only changes were pushed to the existing auditor branch and verified remotely at `dde7430c48a39abdbdca09270baec450a1cceab2`. The public `main` documentation is a separate reporting channel, not proof that local candidate source was published.
- The independent background watcher/integration campaign was still running when the results were reviewed; its final results were not yet available.

**Next software gates:** preserve Right's minimal reproductions, fix workstream-owned code in isolated development trees, re-run relevant full suites, and have Right independently verify the **new exact integrated HEAD**. Keep production signing, installation, and deployment blocked.


## Verified follow-up — parent replacement recovery and refusal parsing — 2026-11-14

The local offline candidate has source commit `4135afc` and latest evidence-metadata revision `e2d8605` (superseding `fcb4626`). The implementation branch remains unpublished; this update is a sanitized progress report only.

- The independent parent-replacement reproducer was preserved and replayed. Before the fix, recovery at the recreated parent found no stages while a stage and owner marker remained under the renamed parent.
- The installer now writes a durable, inode-bound recovery locator before stage creation. Recovery searches only the verified grandparent anchor for the original parent identity, refuses ambiguous or out-of-anchor moves, and preserves a decoy release at the replacement path. Installer recovery passed **22 tests**, including parent replacement at two hard-exit points, locator-write/publication interruption, and idempotent repeat recovery. Moving the original parent outside the recorded anchor still requires manual recovery; the tool fails closed and does not search or delete elsewhere.
- Left's malformed refusal/status parsing correction (`7b28c11`) is integrated. The full focused FK0957 suite passed **473 tests**; operations acceptance passed **871 tests across four runs**; the corrected oracle accepted all **28 valid states** and rejected all **249,572 invalid states** with zero mismatches. Compile and whitespace checks passed.
- An unsigned canonical integrity manifest now binds the exact source candidate and covers **31 source files** and **10 runtime objects**. Its SHA-256 is `5c859b4fd22e63f67cac30926288cd16f8c382e4b43e5f09968454ca74a888ea`. This is not a production signature or trust authorization.
- Right's independent audit of this combined candidate is still pending. Production controller/profile alignment, production trust provisioning, administrator installation, and production authorization remain blocked.

No live acquisition, hardware/USB access, privileged installation, key provisioning, or production-main change occurred.

## Independent exact-candidate audit verdict — 2026-11-14 (latest)

An independent audit of the later evidence revision `e2d860584cbdcf74f58f4cf582214b8531528871`, whose source manifest pins `4135afc78319ff988a6eb8bcb37c618082e38ae7`, **still returns FAIL for release qualification**, despite substantial progress. This is newer than the earlier `50fe500` candidate notes above.

- **Refusal/status parsing fixed in the tested candidate:** the independent 237-case malformed-type matrix produced **zero uncaught exceptions** and **zero unexpected acceptances**.
- **Manifest integrity fixed in the tested candidate:** **31/31 source hashes** and **10/10 native runtime objects** matched; the manifest remains unsigned.
- **One installer issue remains:** of 36 disposable path-substitution cases, **22 falsely returned success** after the target parent pathname was replaced. In the minimal first-install case, substitution immediately after `after_installed_verify` led to success even though the requested release pathname did not exist. Decoy-symlink replacement also produced false success. The independent audit preserved a minimal deterministic reproducer at audit commit `44b3a5af65a13ce3bf3a10a51c9f1f8b7160991`.
- An earlier 24,024,072-scenario one-hour campaign reported zero unsafe outcomes, but it exercised an **older source revision**, and **does not certify this candidate**.
- A separate audit watcher was still running when this report was prepared. No live/hardware tests or production authorization are implied.

**Next qualification gate:** require path identity validation at the final success boundary, explicit failure when the intended target is absent or redirected, disposable-root adversarial retesting, and independent audit of the exact new HEAD. Production signing, authorization, privileged installation and real deployment remain BLOCKED.


## Verified follow-up — post-publication parent identity check — 2026-11-14

The independent auditor's exact reproducer was taken from audit commit `44b3a5a` and run against a clean checkout of the pre-fix evidence revision. The minimal case returned success after replacing the target parent, although the requested target was absent. The complete independent matrix reproduced **22 false successes in 36 cases**.

The local source candidate is now `be33af6`; its separate evidence revision is `6f0c27d`. Implementation source remains local and unpublished.

- The installer rechecks parent and target inode identity after the installed verification checkpoint, before removing the previous release, and before reporting success. Cleanup-error returns also revalidate the requested target.
- On the fixed candidate, the same minimal reproducer now refuses, and Right's exact 36-case matrix reports **zero false successes**. Regression coverage preserves existing releases and decoys on refusal and covers cleanup-path substitution.
- Offline qualification passed: **484 FK0957 focused tests**, **24 installer tests**, **871 operations acceptance tests across four runs**, and the corrected oracle (**28 valid accepted; 249,572 invalid rejected; zero mismatches**). Compile and diff checks passed.
- The unsigned canonical integrity manifest binds source candidate `be33af6`, with **31 source files** and **10 runtime objects**; SHA-256 `41aee5f94f4b355ba29afbb61378199ee8337c2e95e4520debefa3713fa1b4fe`. It is integrity evidence only, not production authentication.
- Right's final independent audit of `be33af6` remains pending. Production trust provisioning, controller/profile release alignment, administrator installation, and production authorization are still blocked.

No hardware, USB/JTAG, production host, privileged installation, key provisioning, or live acquisition was used. No production-main code was changed.