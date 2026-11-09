# Public milestone diff review

Review scope: public `main` at `976ebbb` plus this documentation and repository-hygiene update.

## Proposed contents

- Summarize PHK1 candidate-aware diagnostics, Evidence-v2, target-host no-hardware qualification, the completed offline reliability campaign, and the current preflight blocker.
- Summarize PHK2 production-capture recovery, CPU golden-model work, offline core RTL qualification, batch-64 exactness, and the initial VU33P synthesis resource baseline.
- State clearly that PHK1 physical protocol qualification is incomplete; PHK2 timing, routing, and silicon qualification remain unproven.
- Add a dated detailed milestone, update the README/changelog/release-note draft, and maintain ignore rules for private/generated artifacts.

## Verification

- Documentation/native public offline tests: Python raw identity runner 4/4; MPSSE mock 18/18; USB selection mock 7/7.
- `git diff --check`: PASS.
- Public-content scan: PASS; no private IPs, hardware serials/DNA, USB topology, wallet values, credentials, private absolute paths, lock contents, or private image/binary artifacts appear in the new milestone content.
- Artifact review: documentation and `.gitignore` only; no FPGA image, DCP, private runner binary, fixture payload, production capture, or license file is added.
- Claim review: each status claim is qualified as offline software/RTL, synthesis-only, or not yet silicon-qualified. The PHK1 physical error remains unresolved; the reported preflight blocker is explicitly before programming.

No private local implementation or raw evidence bundle is copied into this public branch.
