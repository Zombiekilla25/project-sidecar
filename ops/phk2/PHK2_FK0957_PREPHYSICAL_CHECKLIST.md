# FK0957 prephysical closure checklist

**Offline preparation checklist. Do not perform the checkboxes in this phase.**
All items must be evidence-backed before a future separately authorized run.
A blank, stale, ambiguous, or failed item stops the run before transport.

## Immutable qualification and scope

- [ ] v5.1 source/tree/routed DCP match the immutable handoff.
- [ ] TCK envelope commit/hash match `PHK2_FK0957_CANARY_CONFIG.json`; all 733 bound entries verify.
- [ ] Qualification is 38/40, with cases 40 and 33 the only unresolved items.
- [ ] Exactly one signed target scope: FK0957 / board `153300000957` / adapter `153300000957A`.
- [ ] Fresh current adapter/card/image identity binds to the same canary; IDCODE alone is not treated as unique identity.

## Authorization, bridge, and peers

- [ ] Operator-approved Ed25519 trust root is pinned and authenticates a single-session authorization for these cases and this card.
- [ ] Running bridge ELF hash/build ID and service/config hash match the reviewed identity.
- [ ] Effective MPSSE clock control is verified; XVC `settck` echo is not used as evidence.
- [ ] Local process/socket ownership, no competing server/client, one listener, exclusive lock, and signed peer/network ACL proof all pass without protocol probes.
- [ ] Rollback/recovery owner and current-image/workload baseline are recorded; this test cannot program or mutate workload.

## Capture and Case A

- [ ] Reviewed instrument backend is installed and authenticates native raw acquisition.
- [ ] Instrument/probe calibration, bandwidth, sample rate, threshold, trigger, uncertainty, channel and capture metadata are complete.
- [ ] Pre-transport evidence journal is created and fsynced before any future transport open.
- [ ] Effective initial 5 MHz (200 ns, 100 ns high/100 ns low) setting is applied by a reviewed clock-control path.
- [ ] One bounded 87-cycle capture is evaluated cycle by cycle: period 25–200 ns, high/low at least 10 ns, duty 40–60%.
- [ ] A numeric physical jitter limit and instrument uncertainty acceptance rule are immutable and qualified. **Currently missing; Case A cannot pass.**

## Case B and close

- [ ] Matrix-approved BSCAN observer, exact instruction/sequence, and expected response are pinned and separately authorized. **Currently missing; do not guess or select USER1/2/3.**
- [ ] Physical TCK and semantic TAP/BSCAN evidence share a signed nonce/timebase; the IDCODE-only transcript alone does not prove internal BSCAN behavior.
- [ ] Final TAP state is Run-Test/Idle, transport closed, zero sessions remain, and image/workload match their before snapshots.
- [ ] Raw files, metadata, authorization, preflight and results are hash-chained, signed, and bundled immutably.
- [ ] Cases 40 and 33 independently parse and pass before any 40/40 promotion.

## Immediate stop

Stop without retry/reconnect on any identity or hash mismatch, authorization or peer failure, unexpected instruction/state/response, extra/missing clock, out-of-envelope waveform, missing jitter policy, malformed/incomplete capture, journal failure, disconnect, image/workload change, or uncertain final idle state. Preserve the lock and evidence. Do not reset/program the FPGA or start/stop services/miners as part of recovery.
