# FK0957 independent release package audit — 2026-11-15

## Verdict

**BLOCKED for final integrated software release and deployment.** The installer parent-path and target-inode substitution defects remain independently fixed on the tested source. The release package is not fully integrated/provenanced: the latest operations handoff is absent, the maintenance controller is not in the release source manifest, and its live path still selects the legacy orchestrator rather than the candidate RGB one-shot CLI. Production authorization is also unavailable and the manifest is unsigned.

## Exact revisions

- Tested source-tree commit: `8c8cd5022e799b13eb998795196c6c73b845f94d` (test-only child of evidence commit `6f0c27da54de098c9de43fe8d0311d9889f0efbf`). Its manifested production source revision is `be33af695079847cfab6a1dd6310a27cc31a4ca9`.
- Current evidence revision: `eb534fff681e23fb24bd821e1d09a21a1b15a1a3`; its parent `d5d3007` updates evidence for source `8c8cd50`. Its changes are under `results/` only.
- Source manifest SHA-256: `416c96afddce7926a77209720c0a505f5057295ed1cd707b55f4a9f209bcbce6` (sidecar matched). Manifest source head is exactly `8c8cd50` and the manifest is unsigned.
- Main worktree remains at `3226bfc1474d6afa873fce7327ded6dac548baae`, clean and unchanged.

## Operations lineage and integration

- Left's publication-progress code commit `4d760d542534ee518219511ab57a0b3e7216965e` is an ancestor of `8c8cd50`; its state/progress changes are covered by the 144-test controller, publication, and supervisor-status rerun below.
- The later operations handoff commit `4dddb8e9527dad782ff7aab56ac12a3c06ceee24` is **not** an ancestor of `8c8cd50` or `eb534f`. Its two handoff documents are not present in the release tree. The release package therefore does not include the latest operations handoff.
- The tested controller's `_live()` path builds the fixed legacy `phk2_fk0957_remote_orchestrator.py` invocation. The RGB one-shot CLI tests pass, but the maintenance live path does not invoke that RGB CLI.
- The controller pins the orchestrator SHA-256 as `b6ed4477…`; the candidate manifest records the candidate orchestrator bytes as `4a0324e9…`. This is a fail-closed pin mismatch that prevents the current controller/candidate pair from being treated as integrated.
- The manifest's 31 listed source hashes and 10 runtime hashes/build IDs match the exact checkout and local pinned files. However, it omits security-relevant local integration files: `fk0957_maintenance_controller.py` (SHA-256 `e1cc1395…`), `fk0957_publication_report_contract.py` (`6b4558e2…`), and `fk0957_supervisor_status_contract.py` (`25e1df2c…`). Matching listed hashes does not establish complete source closure.
- The manifest's transaction profile SHA-256 matches the actual profile bytes (`695870565b971d3b…`).

## Exact-candidate verification

On source candidate `8c8cd50`:

- Original parent substitution: **36 cases, zero violations**.
- Expanded parent substitution: **42 cases, zero unsafe outcomes**.
- Original target-inode substitution: **12 cases, zero violations**.
- Expanded target-inode substitution: **18 cases, zero unsafe outcomes**; displaced complete releases were preserved in upgrade cases.
- Malformed refusal/status campaign: **237 cases**, zero uncaught exceptions, zero unexpected accepts (previous exact-candidate run).
- Controller, publication report, supervisor status, admin install acceptance, live CLI, and RGB CLI targeted suite: **144 passed** in 1.412 s. It covers unsigned/unprovisioned issuer refusal and unsigned stage substitution.
- Exact candidate previous full-suite results: **589 host tests**, **871 operations tests**, **28 valid / 249,572 invalid oracle states with zero mismatches**, and **25 installer tests**. No source files changed between that exact-source campaign and the current evidence revision; this report-only evidence refresh did not trigger a redundant full-suite rerun.
- Launcher package rebuild in a disposable directory was byte-identical twice: SHA-256 `603a57568f5ab09c700223ce3ddae48954540e22e4242d2141a35da92f4dd33f`. The launcher was not executed.
- An initial focused-test command named a compatibility module absent from the candidate checkout and produced an import error; the corrected exact-candidate command passed all 144 tests. This was a command selection error, not a candidate test failure.

## Required external gates before installation

1. Integrate the current operations handoff and resolve the controller-to-RGB CLI/orchestrator selection and hash pins.
2. Extend/rebuild the authenticated runtime manifest to cover the maintenance controller and its publication/supervisor-status contracts, then independently verify the full dependency closure.
3. Obtain authorized production issuer/trust-root provisioning and a valid signature binding the exact source/evidence identities. The current manifest is unsigned; test fixtures do not supply production authority.
4. Have an authorized administrator perform and verify the privileged package installation, ownership/mode/service boundary, and rollback/recovery checks. None was performed here.
5. Obtain separate explicit authorization for any later production or physical operation. This audit grants none.

No production host, hardware, USB/JTAG, privileged install, signing key, or live service was accessed. The hardening watcher PID `1170327` was preserved and remains running.
