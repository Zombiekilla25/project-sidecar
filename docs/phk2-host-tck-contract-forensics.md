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

### Identity and provenance boundary

The retained file is 398,768 bytes, ELF64 little-endian PIE for x86-64,
BuildID `b0562d538761373e2f1025c8bc8d8188ff8a0c40`. It is not stripped and
retains a symbol table and the source-file string `sqrl_xvc.cpp`; these are
function/source-name symbols, not the implementation source or DWARF line
tables. Dynamic `DT_NEEDED` libraries are `libncurses.so.5`, `libtinfo.so.5`,
`libpthread.so.0`, `libstdc++.so.6`, `libm.so.6`, `libgcc_s.so.1`, and `libc.so.6`.
FTDI D2XX and libusb routines are defined in the ELF, not external dynamic
dependencies.

The retained launcher `tools/phk1_one_fk_canary_remote.sh` names
`$HOME/civiclight-testbench/bin/sqrl_bridge_rawjtag_coe`, sets XVC port 2542,
and appends `-j <port>` for XVC runs. Its no-bitstream diagnostic records
`[binary, -s, <serial>, -p, <UART-port>, -j, 2542, -f, <log>]`. Multiple
retained FK33 release/canary copies have the same SHA-256 as the static-review
ELF. This proves the filename/hash is a retained FK33 bridge artifact used by
the scripts. The exact remote executable currently deployed on the testbench
is **not** proven: the launcher's remote path was not acquired or hash-attested,
and no SSH or service-host inspection was performed. No systemd unit was found
in the reviewed evidence set. Treat pinned-ELF conclusions as conditional on
that deployed-hash match.

### Reproduction commands and XVC command logic

These are local read-only inspection commands; none executes the ELF:

```sh
file "$ELF"; sha256sum "$ELF"
readelf -h -d -n -s "$ELF"; nm -C "$ELF"; strings -a -t x "$ELF"
objdump -d -C --start-address=0x282d0 --stop-address=0x28e10 "$ELF"
objdump -d -C --start-address=0x1ed6b --stop-address=0x1ee75 "$ELF"
```

In `SQCoEStartXVC` (`0x282d0`), the first two command bytes dispatch on `ge`,
`se`, or `sh` (`0x28636`–`0x2865d`). `getinfo` (`0x28a70`) consumes six more
bytes, formats `xvcServer_v1.0:4096\n`, and writes that ASCII response.
`settck` (`0x28c40`) consumes the remaining nine bytes, takes the four-byte
field at request offset 7 as a native little-endian DWORD on this x86-64 ELF,
and writes those same four bytes. The handler has no numeric comparison,
clamp, rounding, or call into MPSSE clock configuration. Byte swapping is
applied to the listener port, not the period field.

For `shift`, it reads a 32-bit bit count, then `ceil(bits/8)` bytes of TMS and
the same number of TDI bytes. It passes these as raw TMS/TDI shifts into
`CoE_ShiftTMS` / `CoE_ShiftChain` and returns captured TDO bytes. The XVC
server does not interpret FPGA USER instructions: clients select IR/DR
instructions through raw JTAG scan bits. The handler rejects a negative signed
bit count and checks its internal buffer bounds. `getinfo` advertises a fixed
4096-byte maximum shift chunk, unrelated to TCK.

### MPSSE rate setup and overrides

`addDevice` calls `SQRLJtagCreate` with 30,000,000 for its generic branch
(`0x16148`). A `JCC4P` descriptor selects 20,000,000 (`0x157a0`–`0x157c3`).
Both enter `SQRLJtagGetDeviceCount` during FTDI initialization. At `0x1ed6d`
the ELF computes `floor(30,000,000 / requested_clock) - 1`, rejects values
above 16 bits, then queues bytes `0x97 0x8a 0x86 divisor_low divisor_high`
and flushes them (`0x1ed9a`–`0x1ee15`). Both requests integer-divide to
divisor zero.

`0x8a` disables FTDI MPSSE divide-by-five mode; `0x97` disables adaptive
clocking; `0x86` sets the TCK/SK divisor. In high-speed MPSSE mode the 60 MHz
base is divided by two and by `(divisor+1)`, matching the code's 30 MHz
calculation. The binary-configured nominal TCK is therefore 30,000,000 Hz for
both branches. This confirms this ELF's configuration, not adapter-pin TCK or
a physical maximum. The setup queues MPSSE bytes directly; `FT_SetDivisor` is
not called by it. The binary contains other JTAG clock/shift routines, but the
reviewed XVC `settck` handler calls none of them and does not enter this setup.

CLI strings document `-r/-R <latency>` as the FTDI JTAG bus latency option
(help text says default 4), and `-o/-O <latency>` for UART latency. The launcher
may pass these, but no CLI option or retained config for TCK/divisor was found.
Device descriptor classification selects the 30 MHz versus 20 MHz request,
but integer rounding leaves divisor zero in both cases. Latency changes
buffering/response timing, not the divisor. `-j <port>` enables XVC and picks
the listener port.

## Client ownership and interference

The XVC routine creates a listener, accepts one peer, closes the listening
socket, services that connected descriptor, closes it at session end, then
loops to create/listen/accept again. It does not multiplex connected clients
or replace a live session. A later peer may reconnect after disconnect. There
is no evidence in the reconnect path that it resets the JTAG TAP or restores
a known FPGA instruction. Any accepted peer can send raw `shift` commands and
change TAP/IR/DR state, including USER1/USER2 selection and data shifts. On
this ELF `settck` cannot change the divisor, but peer exclusion is still
required to prevent JTAG interference and reconnect races.

The lifecycle wrapper checks process, listener, port, and target binding. It
does not proxy XVC commands or reserve the socket against another network
peer. Process/port ownership is therefore not equivalent to exclusive XVC
client ownership.

## Derived offline contract

| Field | Offline finding |
| --- | --- |
| `XVC_BINARY_PROVEN` | false for currently deployed binary; retained FK33 artifact identity and script use are proven, but remote hash is unproven |
| `RETAINED_XVC_BINARY_PROVEN` | true: path, size, hash, ELF architecture, and BuildID recorded |
| `SETTCK_IMPLEMENTED` | true: request parsed and four bytes returned |
| `SETTCK_CHANGES_HARDWARE` | false in inspected ELF: no MPSSE/divisor call from handler |
| `SETTCK_ECHO_ONLY` | true |
| `SETTCK_REQUEST_AFFECTS_HARDWARE` | false |
| `SETTCK_RESPONSE_MATCHES_REQUEST` | true |
| `SETTCK_RESPONSE_MATCHES_EFFECTIVE_TCK` | false |
| `MPSSE_TCK_CONFIGURATION_FOUND` | true: initialization queues `0x97 0x8a 0x86 00 00` for both observed descriptor branches |
| `CONFIG_CALLED_AT_STARTUP` | true: device creation invokes setup during bridge initialization |
| `CONFIG_CALLED_BY_SETTCK` | false |
| `MPSSE_BASE_CLOCK_HZ` | 60 MHz high-speed FTDI base; 30 MHz after the MPSSE divide-by-two convention |
| `MPSSE_DIVISOR` | 0 |
| `EFFECTIVE_TCK_HZ` | 30,000,000 nominal for the reviewed ELF configuration |
| `EFFECTIVE_TCK_HZ_PROVEN` | false as a physical pin rate; ELF configuration only is proven |
| `THIRTY_MHZ_NOMINAL_CONFIRMED` | true for the hash-pinned ELF configuration |
| `SIDECAR_CAN_VERIFY_TCK_FROM_XVC_RESPONSE` | false: response echoes requested period |
| `SIDECAR_CAN_VERIFY_TCK_FROM_SOFTWARE_STATE` | false with current wrapper: it neither owns XVC commands nor reads the configured divisor |
| `PHYSICAL_PIN_MEASUREMENT_REQUIRED` | true |
| `PEER_CAN_CHANGE_TCK` | false via `settck` on this ELF |
| `PEER_CAN_INTERFERE_WITH_JTAG` | true via raw `shift` |
| `PEER_EXCLUSION_REQUIRED` | true |

No live XVC exchange exists in retained logs, so request/response behavior is
static-disassembly evidence only. The exact running binary and physical TCK
remain unproven.

## Minimum future physical measurement (not performed)

At a later separately authorized qualification, first hash the executable
bound to the selected endpoint and confirm it matches this reviewed ELF. Keep
the FPGA image and miner workload unchanged. Probe adapter TCK/SK to adapter
ground with an oscilloscope or logic analyzer. With exclusive peer access,
issue one bounded, read-only IDCODE scan using the documented target
chain/opcode, then leave the TAP in Run-Test/Idle. This selects IDCODE rather
than USER1/USER2 and does not program or alter the image; confirm the chain's
IDCODE instruction semantics from target documentation before the physical
step. Capture idle plus the short TCK burst and record high/low periods,
frequency, probe point, instrument/sample settings, and bridge hash. Optionally
capture one `settck` echo to document the protocol mismatch, but do not treat
it as a rate measurement. Verify at the host socket/firewall boundary that no
other peer can reach or reconnect to the listener during measurement. This
procedure was not executed in this offline audit.

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
