# Release-candidate notes draft

Status: draft for the next Sidecar Miner release candidate. No public release or tag has been created.

## Summary

This milestone records software and release-preparation progress for experimental PHK1 work. It covers the v2 candidate/current/rollback lock architecture, peer protection, bounded RAW_BSCAN transport qualification, and a single-card canary design with rollback. A PHK1 candidate has routed at 200 MHz, and software can generate a patched bitstream candidate.

## Qualification and limitations

First-silicon correctness remains under qualification. Routing and software-side checks do not establish correct PHK1 operation on physical silicon. This candidate makes no PHK1 physical-correctness, production-readiness, or speedup claim. The single-card canary remains gated, with rollback required. Production service restoration to the 8/8 worker baseline after controlled tests is complete.

## Package contents

This public update contains status and release documentation only. It does not include FPGA binaries, raw hardware traces, private evidence, or the unsanitized local v2 live-runner implementation. The software changes described here remain subject to public source review before a later package includes them.
