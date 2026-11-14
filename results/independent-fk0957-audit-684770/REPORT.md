# Independent FK0957 offline release audit

**Verdict: FAIL for software acceptance; BLOCKED for production deployment.**

## Audited identity and scope

- Exact release/evidence HEAD: `684770dd9657d070c982ce98fe84c839016456a6`.
- Runtime source revision named by its unsigned manifest: `50fe500558495273501f643e0a0024443e23e210` (ancestor of the audited HEAD). The 684770 commit updates release evidence and handoff documents; `git diff 50fe..684770 -- tools/phk2_host` is empty.
- Release branch `release/fk0957-candidate-20261115` remained at 684770 after the tests.
- Main PHK2 worktree remained clean at `3226bfc1474d6afa873fce7327ded6dac548baae`.
- No hardware, production host, SSH, USB/JTAG, signing-key provisioning, privileged install, or live service was accessed.
- Python 3.12.3 virtual environment was used; `blake3` was available. System Python was not modified.

## Results

- Candidate FK0957 host suite: **473 passed**, 119.454 seconds; log is preserved as `fk0957-host-suite-684770.log`.
- Independent state oracle: **28 valid / 249,572 invalid**, 0 valid rejected and 0 invalid accepted; 70 focused harness tests passed. Oracle classification was not changed. See `oracle-50fe.json` (runtime source is identical at 684770).
- Independent bounded worker, exact 684770: four tasks passed (oracle, manifest, 1,000 enumeration permutations, `git diff --check`). It enforced candidate SHA/cleanliness, per-task timeout, and checkpointed `state.json`/`journal.jsonl`. See `worker-state.json` and `worker-journal.jsonl`.
- Installer interruption campaign, exact 684770: **170 distinct checkpoints**, 340 hard-kill cases (first install and previously valid install), 680 recovery calls; repeated recovery passed, old install identity was preserved before publish, completed roots verified, and no staging/quarantine siblings remained. Runtime: 176.758 seconds. See `installer-hardkill-684770.json`.
- Enumeration campaign: 1,000 deterministic permutations (seed `1749512341`), 1,000 exact target selections, 2 expected refusals, zero device opens.
- Manifest/runtime audit: 31 source hashes and 10 runtime objects matched. All 10 ELF build IDs matched the independently checked files. Transaction profile hash and trust-template hash matched. Source manifest sidecar matched. The manifest is **unsigned**, and release/handoff production keys are unprovisioned; the manifest is integrity evidence only and cannot authorize production.
- Malformed input fuzz: 200,000 deterministic mutations. Refusal parser: seed `1749512342`, 100,000 cases, 43,040 uncaught `TypeError` cases and zero unexpected accepts. Supervisor status: seed `1749512343`, 100,000 cases, 16,023 `TypeError` cases and zero unsafe terminal-state accepts. Minimal reproducer: lists supplied as `local_state`, `publication_state`, or `supervisor_state` cause set-membership `TypeError` in `fk0957_publication_report_contract.refusal_diagnostic`; list-valued `code`, `publication_state`, `operation_state`, and `close_from_state` cause `TypeError` in `_refusal_is_prepublication`. The maintenance caller catches `ValueError` around the first parser, not `TypeError`, so malformed status can escape the bounded refusal boundary. This remains fail-closed for acquisition/signing, but violates the bounded malformed-result contract and produces a raw generic error at the outer CLI handler.
- Parent replacement reproduction: a hard kill after renaming/replacing the install parent leaves a stage directory and owner marker under the renamed original parent. Recovery at the replacement path cannot find them; explicit recovery at the original moved parent cleans them. This is a conditional recovery/manual-review limitation requiring parent replacement by an authorized owner or filesystem event; ordinary application users cannot rename the root-owned install parent. See `parent-rename-684770.json`.
- `git diff --check HEAD^ HEAD`: passed.

## Authorization and installation boundary

The integration tests confirm that missing production trust pins refuse before transport. The independently verified manifest says `manifest_authenticated=false`, the trust template contains no release/handoff public-key pins, and there is no production authorization or real installation evidence. Offline test fixtures do not change that status. Do not install or run live acquisition from this candidate.

## Test runtime

Measured exact-candidate test runtime was at least **310.2 seconds** (host suite 119.454s; installer interruption 176.758s; enumeration 0.758s; refusal fuzz 1.838s; status fuzz 8.890s; oracle worker 2.258s; manifest verifier 0.257s). This excludes review/setup time and the already-running integration-owned suite, whose result was not used as independent proof.

## Disposition

Do not declare release readiness. The candidate has strong offline evidence for state validation, enumeration, source/runtime integrity, transaction stability, and installer recovery under normal parent identity. Close the malformed-type exception defect and decide whether parent replacement cleanup needs a documented operator recovery procedure. Production issuer keys, authenticated release authorization, and administrator installation/verification remain deployment blockers.
