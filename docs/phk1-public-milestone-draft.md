# PHK1 milestone draft

Project Sidecar has advanced its PHK1 experimental FPGA and software release work. A PHK1 candidate has completed routing at 200 MHz, and the software has a patched-bitstream generation capability. A v2 candidate/current/rollback lock architecture binds candidate use to an explicit current-image baseline and preserves a separate rollback image. Peer protection is part of the lock and canary design.

The bounded RAW_BSCAN transport path is qualified at the software/transport level. The planned single-card canary has a rollback path, and production service restoration to the 8/8 worker baseline after controlled tests is complete.

These results do not establish PHK1 correctness on physical silicon. First-silicon correctness remains under qualification. No PHK1 physical-correctness, production-readiness, or performance claim is made here.

This summary omits machine identities, raw traces, bitstreams, private test artifacts, and operator-specific environment details.
