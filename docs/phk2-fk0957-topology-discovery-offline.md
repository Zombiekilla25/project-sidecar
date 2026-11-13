# FK0957 reset-default DR topology discovery

## Production software status

The one-shot local topology transport and CLI are integrated in production
code commit `dd51f7eb7a0c1956e0691c35de83905291e0fc42`. The transport uses the
pinned native FTDI/libusb runtime, exact descriptor-bound FK0957 selection,
the fixed two-scan MPSSE plan, local validation, local signing, and atomic
evidence publication. The CLI has no scan or transport override options.

The corrected independent state model at
`ea2104c55a1d4dafe6da91c6d5ac28447ec336c1` reports 28 valid and 249,572
invalid boundary states; production accepts all 28 valid states and rejects
all invalid states. The focused production suite passed 187 tests, including
enumeration, refusal, permit/replay, library provenance, transaction, and
evidence atomicity coverage. Right's independent review reported
`READY_FOR_PRODUCTION_INTEGRATION=YES` and all corresponding invariants passed.

This is a software qualification record only. It does not issue a permit,
perform a live acquisition, or authorize hardware access.

The deterministic hashes and local host-key pin provenance recorded for this
integration are in
[`results/fk0957-topology-software-handoff.json`](../results/fk0957-topology-software-handoff.json).

## MPSSE edge decision

The existing FK33 source is `tools/phk1_raw_bscan/mpsse_backend.cpp`:

| Literal | Use | LSB first | Output edge | Input edge | Start level |
|---|---|---|---|---|---|
| `80 08 0b` | Set low-byte GPIO value/direction | N/A | N/A | N/A | sets TCK low; TDI low; TMS high |
| `4b` | Fixed TMS navigation, no read (new census plan) | yes | falling | none | low |
| `6b` | Existing TMS plus read; final DR exit bit | yes | falling | rising | low |
| `39` | Existing byte data in/out | yes | falling | rising | low |
| `3b` | Existing bit data in/out (not needed by this byte-aligned census) | yes | falling | rising | low |

FTDI AN_108's JTAG command family agrees with these literal command bytes and
the backend's `0x80 0x08 0x0b` pin setup. The older idle-high claim is in
`/home/rmann/project-sidecar/sidecar-evidence/phk1-first-hello-analysis-20261103/EDGE_MODEL_REPORT.md`
and `EDGE_ACCURATE_BSCAN_AUDIT.json`; it applies a generic edge-pair rule
without distinguishing the low-start JTAG command family. The later
`phk1-tck-phase-20261103/EDGE_MODEL_REPORT.md` explicitly corrects that blanket
inference and cites FTDI AN_108/AN_129. For this backend, idle-low is the
documented command start state. The old claim is a mistaken generalization,
not evidence of a different current transport.

## Discovery method and bounded contract

No existing project implementation was found that censuses an unknown chain.
The prior `identify_only.cpp` forces a six-bit IR and a 64-bit DR read, so it
is not reused.

The proposed census begins by clocking TMS high five times to enter
Test-Logic-Reset, then follows the standard path into Capture-DR/Shift-DR.
It never enters Shift-IR and never updates an instruction. Under the standard
reset-default rule, a TAP with IDCODE support selects its 32-bit IDCODE DR;
a TAP without IDCODE support selects the one-bit BYPASS DR. The census shifts
two fixed complementary de Bruijn TDI patterns through that reset-default DR
chain. The second scan lets the parser reject a false delay caused by arbitrary
captured bits: reset capture contents must match between scans while each
output tail must match its own input pattern at the same delay.

Each scan captures 577 TDO bits. The parser accepts a unique aggregate DR
length in `[1, 512]`; values beyond the bound or non-unique/inconsistent
responses are `INCONCLUSIVE`. This is a parser/operation bound, not an
assumed TAP count. The captured stream is partitioned TDO-to-TDI: a leading
`1` denotes the mandatory IDCODE-register marker and consumes a 32-bit word;
a leading `0` is the reset capture value of a one-bit BYPASS element. The
parser preserves both raw streams and makes no comparison with the expected
FK0957 IDCODE. If the marker/length partition fails, topology remains
inconclusive. IR lengths are not observed. Individual bypass devices cannot
be distinguished from each other by this scan; only their one-bit positions
and count in the ordered stream are reported.

The fixed transaction contains 1,177 TCKs: initial reset/navigation (9),
first DR scan (577), TAP-state return to reset (5), second scan navigation
(4), second DR scan (577), and final TAP-state return (5). The last bit of
each scan uses fixed `0x6b` TMS=1 to leave Shift-DR; all other data clocks use
`0x39`. `0x4b` emits bounded TMS state-navigation clocks without reading TDO.
No arbitrary IR, DR, TMS, TDI, or clock setting is exposed.

The five TMS-high clocks synchronize/reset the **TAP state machine only**.
They are not FPGA reset, reconfiguration, or programming. The DR update state
is traversed under the reset-selected IDCODE/BYPASS instructions only.

## Permit and record boundary

`issue_permit` validates the signed descriptor using the existing embedded
trusted signer pin, binds FK0957, both serial namespaces, VID/PID, path,
manufacturer/product/interface, descriptor SHA256, one nonce, and a 120-second
maximum expiry. It retires the generic IDCODE permit and issues a separate
single-use topology permit. The mock runner consumes it before enumeration;
multiple FTDI candidates or any descriptor mismatch refuse before open; a
transport error consumes the permit and closes the mock handle.

The unsigned record schema preserves both complete raw TDO bitstreams, parsed
reset-default topology (or an inconclusive status), descriptor SHA, permit
nonce/freshness, signer fingerprint, algorithm/transaction/command hashes,
and mutation counters. It explicitly says topology discovery only, IDCODE
qualification failed/not performed, and DNA/image/bitstream identity not
observed. The transport source hash remains null until a reviewed production
adapter exists; caller-supplied hashes are rejected by design. No remote
signing code exists here.

## Readiness boundary

The production path and its offline invariants are present and independently
reviewed. A live topology read remains a separate physical operation requiring
the applicable operator authorization and live preflight. This software
qualification performed no USB, JTAG, or hardware access. Do not extend this
path to IR-length discovery, IDCODE qualification, DNA, or image identity
without a separate review and authorization.
