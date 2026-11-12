# FK0957 IDCODE qualification: offline status

This is an offline preparation record. It does not authorize or perform USB,
JTAG, XVC, or FPGA access.

## Trusted descriptor signer and evidence binding

The policy gate embeds the Ed25519 SubjectPublicKeyInfo DER and pins its
SHA256 as `8bc668e59192ed62070138bb70be70073b9757943697f039c9db9bd27b9ab9f9`.
The verification API accepts no public key argument. Descriptor bytes must
match the caller's expected SHA256, verify under that embedded key, match the
exact FK0957/card/adapter/USB serial/VID/PID/manufacturer/product/interface
fields, have zero mutation counters, and be no more than ten minutes old.
The resulting permit carries the descriptor SHA and a fresh, one-use nonce.

The fixed transaction is represented as 87 semantic TMS/TDI bit pairs,
LSB-first. Its seven segments are:

| Segment | TMS | TDI | Edges |
| --- | --- | --- | ---: |
| TAP Test-Logic-Reset then Idle | `111110` | `000000` | 6 |
| Idle to Shift-IR | `1100` | `0000` | 4 |
| Six-bit IDCODE IR scan, opcode `0x09` | `000001` | `100100` | 6 |
| Update-IR to Idle | `10` | `00` | 2 |
| Idle to Shift-DR | `100` | `000` | 3 |
| 64-bit IDCODE DR scan | 63 zeroes then one | 64 zeroes | 64 |
| Update-DR to Idle | `10` | `00` | 2 |

Total: 87 TCK edges. Initial TAP state is unknown; the first five high TMS
clocks force Test-Logic-Reset, and the sixth enters Run-Test/Idle. The final
state is Run-Test/Idle. The DR response is interpreted LSB-first as one
32-bit IDCODE word followed by 32 zero bits by the legacy implementation.
The vector definition hash is
`bcc12df9f88baa27ca65ed4c03156a4132c5005760cc5fdfa61d56083b9323c0`.

The exact TDO capture edge is not stated in the retained reviewed PHK2 source.
The legacy implementation uses FTDI MPSSE byte/bit clock-in/out commands, but
the retained code and test mock do not independently establish the electrical
sampling edge. This must be resolved against a pinned FTDI specification or
qualified transport record before live use.

## Transport and topology limits

`LibFtdiIo` enumerates `0403:6010`, reads candidate descriptor identity,
requires exactly one exact serial/path/manufacturer/product/interface-A match,
then opens that exact enumerated `libusb_device`. This is a useful source-level
pre-open selection property. It is not yet connected to a signed permit by a
dedicated qualification adapter. The expected binary at
`/tmp/sidecar-raw-id-build/raw-jtag-identify` is absent, and the required
libftdi/libusb development headers are unavailable here. No reviewed binary
hash or runnable narrow adapter exists.

The existing `MpsseTap` type exposes `shift_ir` and `shift_dr` publicly, and
its IR allowlist includes PHK1 USER instructions. The new qualification gate
does not expose or call those methods, but a dedicated adapter that hides them
has not been implemented. No physical observation result is accepted or
signed by the gate.

The repository contains an expected value and a one-TAP model in the PHK2
canary plan, plus a legacy 64-bit IDCODE-plus-zero-padding assumption in the
PHK1 utility and mock tests. These are plans and implementation assumptions,
not an independently authorized FK0957 JTAG enumeration. Historical bridge
logs and the 2026-11-03 summary report IDCODE observations but retain no raw
chain enumeration establishing TAP count/order, IR lengths, or bypass devices.
The physical runbook explicitly says USB path or IDCODE alone is insufficient
and requires a separately reviewed target-chain binding. Therefore there is
no trustworthy topology source to authorize the one-TAP acceptance rule.

## Required eventual signed physical record

After an independently authorized topology contract and pinned single-purpose
transport exist, the local RGB signer may sign only a canonical record with
these fields: schema/version, descriptor evidence SHA256, FK0957/card and
adapter/USB serial/interface/path identity, one-use permit nonce, trusted
signer fingerprint, transport source/binary hash, fixed transaction hash,
timestamp/freshness, observed TAP count/order/IDCODEs, and zero write/reset/
program counters. Validation must precede signing. The schema must reject
DNA, loaded-image, and bitstream-identity claims. No remote signing is allowed.

## Decision

The signer pin and generated vector are suitable for continued offline work.
Live qualification remains blocked on (1) an independent chain topology
record, (2) an adapter that binds the signed descriptor permit to the exact
pre-open FTDI selection and returns internally generated data, and (3) a
reviewed TDO capture-edge definition. No live scan should be attempted until
all three are closed.
