# Changelog

Project changes are recorded here when prepared for public release. This file does not itself announce a published release.

## Unreleased — 2026-11-12

- Record PHK1 diagnostic launcher, Evidence-v2 capture, bounded transport, fail-closed target/peer controls, rollback modeling, and the completed 72-hour offline reliability campaign.
- Clarify that PHK1 physical protocol qualification remains incomplete and that the current identify-phase evidence/attestation preflight mismatch blocks a live canary before programming.
- Record PHK2 production-capture recovery, CPU golden-model work, offline core RTL qualification, and batch-64 exactness within the tested scope.
- Publish the initial PHK2 VU33P synthesis resource baseline and its limits: timing and routing were not established, and the result motivates sequential work generation.
- Update the architecture roadmap and explicitly separate offline qualification, synthesis, routing, and silicon qualification.
- Add the PHK2 fail-closed pre-live physical-qualification control path, including explicit separation of owner-approved physical limits from offline software qualification.
- Add a single-target descriptor identity observer/backend with source/hash pinning, peer-device refusal, no descriptor-path programming/reset/JTAG capability, and local-only evidence signing.
- Harden remote acquisition with pinned SSH host authentication, replay/nonce checks, symlink/hardlink refusal, atomic evidence output, and independent adversarial regression coverage.
- Record the first live descriptor preflight stopping safely before device access when no suitable remote checkout was present.
- Add a no-checkout ephemeral remote collector/bundle mode; independent audit remains in progress, so no live descriptor result or silicon qualification is claimed.
