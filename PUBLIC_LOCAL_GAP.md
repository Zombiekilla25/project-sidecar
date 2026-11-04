# Public vs. local gap

Comparison date: 2026-11-04.

## References compared

- Public `main`: `976ebbb` (`feat: qualify live RAW_BSCAN identity path`).
- Public `release/sidecar-miner-0.3.0-rc1`: `1131b98` (`chore: ignore local release worktree artifacts`). This branch is four commits ahead of public `main` and contains the RC1 package snapshot; the two refs differ in package contents and branch purpose.
- Current local committed tip inspected: `4e6f59f`, two commits ahead of public `main`.

## Local changes missing from public main

The two local commits on `fix/phk1-candidate-aware-v2-lock` are `bf5c568` (`fix: integrate candidate-aware v2 canary lock`) and `4e6f59f` (`fix: bind authoritative peer identity into v2 canary lock`). Together they add a PHK1 candidate/current/rollback lock flow, peer identity binding, a bounded single-card canary runner, recovery roles, and offline tests for those flows. The software concepts are relevant to the next public milestone.

The current local commits are not suitable to promote as-is. Their added scripts and tests contain concrete hardware serials and DNA values, USB topology paths, candidate and rollback image hashes, local filesystem locations, and operational evidence handling. Those are excluded from this public update. No raw trace, private evidence bundle, bitstream, checkpoint, or local-only implementation file is copied into this worktree.

Public `main` already contains the qualified software-level RAW_BSCAN identity path and its existing offline tests. The safe public delta prepared here is a high-level milestone and status update, plus ignore rules and release documentation. A future source-code update requires a sanitized implementation extracted from the local lock work, with tests that use synthetic identities and fixtures only.

## Public delta in this preparation

- README status, architecture, qualification state, limitations, and next work updated.
- Public-safe PHK1 milestone draft, changelog entry, and release-candidate notes added.
- `.gitignore` added for local evidence, generated outputs, FPGA artifacts, and credentials.

This inventory is complete. It does not claim that the local v2 implementation has been published.
