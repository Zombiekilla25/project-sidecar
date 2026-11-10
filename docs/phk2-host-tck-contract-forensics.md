# SQRL/XVC TCK contract forensics

## Result

The locally retained SQRL bridge release binary has a parseable XVC `settck`
command, but the handler only echoes the requested period. It does not apply
that value to the FTDI MPSSE clock. The reviewed binary separately configures
the MPSSE divisor to zero, which is a **nominal 30 MHz setting** in its
30 MHz-divisor model. That is a static binary finding; it is not a measured
pin rate and does not prove that the executable currently installed on the
testbench has the same hash. Therefore the PHK2 physical TCK contract remains
unproven.

## Exact implementation inspected

The local static-review artifact is
`/home/rmann/Downloads/fk33-sqrl-bridge-static-review/sqrl_bridge_rawjtag_coe`,
SHA256 `8c7230f0bf586e9297dc0e568bd19278aeeb7cff8dbb3dde150811f11393218a`,
ELF BuildID `b0562d538761373e2f1025c8bc8d8188ff8a0c40`. Sidecar launch/recovery
scripts identify the executable as `sqrl_bridge_rawjtag_coe` and launch its XVC
listener with `-j` (the retained one-card scripts use port 2542). The binary
contains `SQCoEStartXVC` and `_xvcThread`; debug symbols identify `sqrl_xvc.cpp`,
but the corresponding source file was not found. Thus source is unavailable;
the conclusions below come from disassembly of this hash-pinned ELF.

At `SQCoEStartXVC` address `0x28645`, the command prefix `se` selects the
`settck` handler at `0x28c40`. It reads the remaining nine bytes of the
11-byte XVC request (`ttck:` plus four value bytes), loads the 32-bit value,
and writes those same four bytes back. The handler does not call the MPSSE
clock setup or store the value into the device/session clock configuration.
The XVC value convention is a period in nanoseconds. The examined handler
copies it as an opaque host little-endian 32-bit word. It performs no clamp or
rounding and echoes even zero or `0xffffffff`; that is parser behavior, not a
claim those values are meaningful XVC periods. The four-byte response is an
echo, not trustworthy effective-rate readback.

The separate FTDI setup in `SQRLJtagGetDeviceCount` around `0x1ed6d` computes
`divisor = 30,000,000 / requested_clock - 1`, then emits MPSSE commands `0x97,
0x8a, 0x86, divisor_lo, divisor_hi`. `addDevice` passes 30,000,000 in its
generic branch (`0x16148`). A descriptor containing `JCC4P` selects 20,000,000
(`0x157a0`–`0x157c3`). Both integer calculations select divisor zero, so this
binary configures a nominal 30 MHz MPSSE TCK in either branch. `0x97` and
`0x8a` select the high-speed MPSSE clock base used by this calculation.
Consequently, `settck` does not control that configured rate. No returned
`settck` value reports the effective rate.

## Answers

| Field | Finding |
| --- | --- |
| `XVC_IMPLEMENTATION` | `sqrl_bridge_rawjtag_coe`, local static-review ELF SHA above; SQRL bridge with `SQCoEStartXVC` / `_xvcThread` |
| `XVC_IMPLEMENTATION_SOURCE_AVAILABLE` | `false` (ELF symbols/disassembly available, implementation source absent) |
| `SETTCK_IMPLEMENTED` | `true` (request parser and four-byte echo exist) |
| Request / response | ASCII `settck:` + 4-byte period; response is the same 4 bytes |
| Value meaning | XVC convention: period; units ns. In the handler it is copied as opaque bytes. |
| Clamp / rounding | None in the handler; no effective clock update is performed. |
| Minimum requestable period | No minimum validation; parser echoes any uint32, including zero. A semantic positive-period minimum is not established by this binary. |
| TCK source | FTDI MPSSE initialization, fixed divisor-zero configuration in the reviewed binary |
| Nominal configured TCK | 30,000,000 Hz, derived from binary divisor setup; not pin-measured |
| Server-enforced upper bound | No `settck` upper-bound check. The fixed divisor-zero setup is not an XVC request limit. |
| `TCK_CONTRACT_PROVEN` | `false` for physical PHK2 use: live executable identity is not freshly attested, `settck` echo is not rate readback, and pin rate is unmeasured. |

There are no retained local `settck` request/response transactions. The
retained scripts and lifecycle guard bind process, listener, port, and target,
but do not inspect XVC command payloads. The reviewed XVC loop closes its
listening socket after `accept` and recreates it after the client session ends;
it serves one connected client at a time, then permits a later client. On
this exact binary a later peer cannot change the MPSSE TCK using `settck`, but
can issue JTAG `shift` operations after reconnect. Therefore peer/client
exclusion remains mandatory for safe JTAG ownership.

The XVC `shift` command is a raw scan operation translated into SQRL chain/TMS
shifts. It does not assign semantic meaning to FPGA instructions such as
USER1 or USER2; the client selects those through the ordinary JTAG IR scan.
The binary contains no `settck` transaction history. Its `getinfo` response
and listener log strings do not report a clock rate.

## Sidecar enforcement point

Current Sidecar wrappers are not an XVC protocol proxy and cannot lock the
clock setting at the command boundary. They also cannot trust `settck` echo as
verification. The precise safe enforcement point is the sole transport
endpoint owned by a Sidecar adapter/proxy: it must bind the reviewed server
binary hash and target, reject or validate `settck` requests, independently
verify the effective rate (or require pin measurement where the adapter has
no trustworthy readback), and prevent any second client from reaching the
server for the session. A process/port check alone is insufficient. Any peer
with network access to the listener can reconnect after disconnect and issue
JTAG commands, even though this reviewed handler's `settck` is a no-op.

Sidecar can send the XVC `settck` request, but this SQRL handler only echoes
it. Sidecar cannot establish the effective rate from that response or prevent
a later client from accessing the listener with the current lifecycle wrapper.
It can enforce a contract only after it owns the endpoint boundary and has an
independent rate observation. A peer cannot change TCK via `settck` on this
binary, but the peer must still be excluded from the shared JTAG endpoint.

## Offline model and tests

`tools/phk2_host/sqrl_xvc_contract.py` models only the reviewed handler's
request shape and echo, pinned to the ELF hash above. Its tests verify the
four-byte echo, no clamping, malformed request refusal, and that requested
periods do not alter the modeled fixed MPSSE clock. They do not open a socket,
execute the bridge, access hardware, or qualify TCK.

## Required physical check

Before PHK2 physical use, freshly attest the executable hash bound to the
selected endpoint. Under a separately authorized bounded adapter test,
capture the `settck` exchange, then issue a known bounded JTAG clock pattern
and measure TCK at the adapter pins. Confirm no other client can reach or
reconnect to the listener during the transaction. Until then, no PHK2 numeric
TCK limit is qualified and the prior 1 MHz analysis value remains an
unverified assumption.
