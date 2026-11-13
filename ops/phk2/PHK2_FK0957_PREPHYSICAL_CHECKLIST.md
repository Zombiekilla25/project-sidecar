# FK0957 identity and BSCAN prephysical checklist

**Offline preparation only. Do not perform any hardware-facing checkbox in
this phase.** This document stops before the first real access to FK0957. A
blank, stale, ambiguous, simulated, or failed item blocks the later run.

The current topology-discovery CLI can establish signed USB adapter/interface
identity and report reset-default DR topology only. It does not establish FPGA
DNA, IDCODE qualification, FPGA part, or current-image identity, and does not
satisfy the later FPGA identity/current-image checklist items. Those remain
separate physical qualification steps.

## Exact one-card identity tuple

The pinned historical tuple is an expected-value reference, not proof of what
is currently connected or programmed:

| Field | Pinned expected value | How it is used |
| --- | --- | --- |
| Canary name | `FK0957` | Human-readable scope label |
| Board/card ID | `153300000957` | Must be freshly observed and signed |
| JTAG adapter serial | `153300000957A` | Must be freshly observed and signed |
| Supplemental USB serial | `153300000957` | Must be freshly observed if the selected identity method exposes it |
| FPGA DNA | `4000000001295d813c80a445` | Historical reference only; current DNA must be freshly read and match |
| FPGA IDCODE | `04b69093` | Must be freshly read; family/model check only, never unique card identity |
| Target part | `xcvu33p-fsvh2104-2-e` | Immutable expected part plus freshly attested observed part |
| JTAG chain/topology | Exact expected chain has not been pinned in this package | Must be independently observed and bound before any transport action |
| Current configured image | Exact current-image digest is not pinned in this package | Must be identified by a fresh signed current-image attestation and matched to the authorized image |

The signed live identity record must bind all available observed identifiers
to the same physical card/adapter mapping, the exact current image, the
reviewed bridge/service configuration, one-card scope, session nonce, and
capture time. A serial from a host configuration file, historical DNA, USB
path, or IDCODE alone cannot satisfy this check. Do not use a missing expected
image digest as permission to accept whatever image is present.

### Historical versus fresh evidence

- Historical immutable evidence supplies the expected board ID, adapter
  serial, supplemental serial, DNA, IDCODE family value, and target part.
- Before any later physical session, freshly observe the board ID, adapter
  serial, available supplemental serial, JTAG chain/topology, IDCODE, DNA,
  target part, current image identity, and deployed bridge/service identity.
- The expected tuple and the observed tuple must be recorded separately and
  compared field by field. Any unavailable required field or mismatch is a
  refusal. Historical evidence is never a substitute for current observation.
- Current v5.1 target identity and image observation are absent. No identity
  observer command/backend is installed or approved in this package.

## Immutable qualification and scope

- [ ] v5.1 source/tree/routed DCP match the immutable handoff.
- [ ] TCK envelope commit/hash match `PHK2_FK0957_CANARY_CONFIG.json`; all 733 bound entries verify.
- [ ] Qualification is 38/40, with cases 40 and 33 the only unresolved items.
- [ ] Exactly one signed target scope: FK0957 / board `153300000957` / adapter `153300000957A`.
- [ ] Fresh signed identity matches every available field in the tuple above; current image digest and chain mapping are explicitly bound.
- [ ] IDCODE `04b69093` is used only as a family/model check, never as unique identity.

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
- [ ] The BSCAN method records the selected TAP instruction/register, exact TMS/TDI vector and cycle bound, expected TDO/observation values, before/after TAP state, and proof that the observation is read-only and workload/image preserving. **No approved values or sequence are present in the immutable matrix/report.**
- [ ] Physical TCK and semantic TAP/BSCAN evidence share a signed nonce/timebase and contain hash-verified raw correlation bytes. The IDCODE-only transcript alone does not prove internal BSCAN behavior.
- [ ] Final TAP state is Run-Test/Idle, transport closed, zero sessions remain, and image/workload match their before snapshots.
- [ ] Raw files, metadata, authorization, preflight and results are hash-chained, signed, and bundled immutably.
- [ ] Cases 40 and 33 independently parse and pass before any 40/40 promotion.

## Immediate stop

Stop without retry/reconnect on any identity or hash mismatch, authorization or peer failure, unexpected instruction/state/response, extra/missing clock, out-of-envelope waveform, missing jitter policy, malformed/incomplete capture, journal failure, disconnect, image/workload change, or uncertain final idle state. Preserve the lock and evidence. Do not reset/program the FPGA or start/stop services/miners as part of recovery.

## Hard stop before physical access

The first physical action in any future procedure would be to invoke a
separately reviewed, read-only FK0957 identity observer to acquire the fresh
signed card/adapter/chain/IDCODE/DNA/part/current-image record described above.
This package contains no approved observer or executable command for that
operation. **Stop here; do not substitute USB enumeration, XVC, JTAG, or a
guessed command.** The subsequent gated transport open is also unavailable:
the reviewed physical capture backend and authorization trust root are absent.

Case B has no approved BSCAN observation sequence or exact expected response.
The available qualification row names a `bscan_tck` clock-interaction timing
finding but does not authorize a TAP instruction, define a BSCAN response, or
state an observable acceptance threshold. RTL branch names and an IDCODE scan
do not fill those gaps. Therefore no Case B sequence is specified here and
Case B must remain `UNQUALIFIED` until the qualification owner publishes an
immutable, case-bound read-only method and expected response.

### Evidence refusal conditions

The current software checks reject Case B evidence unless the capture has a
trusted capture-role signature, fresh capture timestamp, exact Case B ID and
v5.1 qualification hash, current session nonce, nonempty raw transcript whose
digest matches, and a correlation artifact whose bytes match its signed
SHA256. The TAP parser checks the transcript rather than trusting a producer
PASS field; final evidence must also prove the specified idle/closed state and
the existing hash-chain journal. A transcript from another nonce/session,
stale capture, simulated fixture, altered response, IDCODE-only record, or
missing/mismatched correlation artifact must refuse.

This is not permission to create or submit evidence: the approved signer trust
root, capture backend, and matrix-approved BSCAN method are all absent. The
software additionally refuses Case B while the immutable case binding lacks
both an approved observation schema and an exact expected observation. A
trusted signer/backend must attest real acquisition; a `PHYSICAL_REAL` string
or a `synthetic_fixture: false` field by itself is not provenance.
