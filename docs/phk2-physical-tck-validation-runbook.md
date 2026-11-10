# PHK2 physical TCK validation and exclusive access runbook

**Prepared only. Not executed. Physical authorization is required.** This
runbook describes one bounded, read-only IDCODE scan and external measurement
of adapter TCK/SK. It does not program the FPGA, alter its image, select USER1
or USER2, or change mining/workload state.

## Readiness and evidence boundary

`PHYSICAL_TCK_TEST_READY=false` for execution today. This worktree has no
current PHK2 physical adapter target lock, no fresh hash attestation of the
remote SQRL executable, and no routed 50 MHz report attached to the PHK2 host
evidence. The retained FK33 script names `$HOME/civiclight-testbench/bin/`
`sqrl_bridge_rawjtag_coe` and uses XVC port 2542; that is not proof of the
current deployed executable or the exact current adapter. At execution time,
the operator must provide the active, authorized target lock and route report
with hashes. If any identity or evidence is absent, stale, ambiguous, or
mismatched, stop before opening XVC.

The offline preflight tooling and synthetic refusal tests are in
[`physical_tck_preflight.py`](../tools/phk2_host/physical_tck_preflight.py).
At a future authorized physical run, require a fresh target lock, bridge policy
and qualified package passed with `--qualification-manifest <file>`. See the
fail-closed schemas in
[`PHK2_PHYSICAL_TCK_TARGET_LOCK.template.json`](../ops/PHK2_PHYSICAL_TCK_TARGET_LOCK.template.json),
[`PHK2_SQRL_XVC_BRIDGE_POLICY.template.json`](../ops/PHK2_SQRL_XVC_BRIDGE_POLICY.template.json),
and [`PHK2_QUALIFICATION_MANIFEST.template.json`](../ops/PHK2_QUALIFICATION_MANIFEST.template.json).
The qualification manifest binds `SOURCE_COMMIT`, source tree archive/hash,
routed DCP/hash, constraint model/hash, `TARGET_PART`, the qualified TCK
analysis envelope and timing report/hash, `QUALIFICATION_STATUS`, and
independent promotion evidence/hash/linkage. Evidence files must be regular
package files and hash-match. No v3 artifact is pinned; the manifest must name
the actual promoted route, including a future v4.

The task context says the routed design passed timing/reset analysis through
50 MHz. Treat 50 MHz as a reported analysis point only. It is not a selected
production maximum. The PHK2 board evidence currently in this worktree says
board synthesis/route were not run. Bind acceptance to the exact routed
qualification report and an explicitly approved electrical timing envelope
for period, high/low pulse width, duty cycle, and jitter. If that envelope is
not specified, the result is `NOT_QUALIFIED` regardless of measured average
frequency.

## Exact target and adapter binding

Before the procedure, obtain the current separately authorized PHK2 target
lock. Record and compare, without USB enumeration:

- USB path, FTDI serial, VID/PID, FTDI interface/channel, and bridge endpoint
  from the lock;
- board/target identity, expected IDCODE, DNA if already attested, and current
  image SHA-256 from that same lock;
- SQRL executable path, `/proc/<pid>/exe` target, command line, PID, and SHA-256
  read from the running process; require the exact approved binary hash;
- XVC TCP port from the process command line/lock (2542 only if the lock
  explicitly says 2542);
- a before-test workload/process snapshot and current-image SHA evidence.

The existing VU33P-only identity code uses a six-bit IR and IDCODE opcode
`0x09`; it reads 64 DR bits and requires the first word to match the expected
IDCODE and the second word to be zero padding. Apply that sequence only if the
active PHK2 lock and target chain documentation confirm this exact chain
topology and IDCODE instruction. Do not copy a PHK1 fixture IDCODE into a
PHK2 lock. Otherwise, stop and obtain target-specific reviewed chain
documentation first.

## Exclusive-access preflight (no protocol traffic)

Acquire the lab/Sidecar exclusive maintenance lock for this exact adapter,
target, and XVC endpoint. Stop unrelated XVC clients and any automatic
reconnect supervisors under the authorized maintenance procedure. Do not
probe XVC or send `getinfo`/`settck` during preflight.

On the SQRL server host, capture read-only snapshots as the account that can
see the full process and socket ownership. Substitute the lock's port for
`<PORT>`:

```sh
date -u +%FT%TZ
ps -eo pid=,ppid=,args=
ss -Hltpn '( sport = :<PORT> )'
ss -Htnp state established '( sport = :<PORT> or dport = :<PORT> )'
nft list ruleset
```

The future local-only preflight command is:

```sh
python3 tools/phk2_host/physical_tck_preflight.py \
  --target-lock /authorized/evidence/current-target-lock.json \
  --bridge-policy /authorized/evidence/deployed-bridge-policy.json \
  --qualification-manifest /authorized/evidence/qualified-route/manifest.json \
  --lock-dir /run/user/$(id -u)/phk2-exclusive-locks
```

It reads `ps`, `ss`, `/proc`, the bridge ELF Build ID and hashed service
configuration; it makes no socket connection. It takes a per-target OS
`flock` and waits for Enter before releasing it, so keep that process alive for
the whole separately authorized maintenance window. A stale metadata PID is
never used to declare ownership: metadata is reclaimed only after acquiring
the OS lock, and malformed or foreign-target metadata refuses. The tool checks
local process/socket state only. Remote peer exclusion still requires
independently verified network ACL evidence and a maintenance lock; if those
cannot be established, do not open XVC.

On the operator/client host, capture the same `ps` and established-socket
snapshot. These commands inspect local process/socket/firewall state only;
they do not send XVC protocol bytes or enumerate USB devices.

Preflight may pass only when all of these facts are evidenced:

1. The unique listener belongs to the intended SQRL PID and its executable,
   command line, binary hash, XVC port, and FTDI serial/channel all match the
   target lock.
2. No other SQRL bridge or XVC client process for this endpoint is active.
   There are zero established sessions before the measurement client starts.
3. Host firewall/network policy admits only the named operator host to the
   XVC port for the maintenance window and blocks every other source. A
   wildcard listener alone is not exclusive access.
4. The operator host has no other established connection to the target and
   exactly one designated, non-reconnecting XVC client will be started.
5. Process/socket visibility is complete and the exclusive maintenance lock
   is held. If ownership is hidden, output is ambiguous, a peer is present, or
   network ACLs cannot be verified, fail closed without opening XVC.

The reviewed server accepts one client at a time and closes its listener while
that client is connected, then recreates the listener after disconnect. That
does not exclude a remote peer or stop reconnects. Keep the network ACL in
place throughout and after the scan until the lock is explicitly handed back.

## Bounded IDCODE sequence and expected TAP transitions

Connect one operator client only after peer preflight passes. Set no clock with
`settck`. Send exactly the following semantic XVC `shift` scans. XVC packs TMS
and TDI bits least-significant-bit first; each scan transmits a 32-bit bit
count, `ceil(count/8)` TMS bytes, and the same number of TDI bytes.

| Step | TMS bits | TDI bits | Expected transition / purpose |
| --- | --- | --- | --- |
| 1 | `1,1,1,1,1,0` | six zeroes | Any state → Test-Logic-Reset on five ones → Run-Test/Idle on zero |
| 2 | `1,1,0,0` | four zeroes | Run-Test/Idle → Select-DR → Select-IR → Capture-IR → Shift-IR |
| 3 | `0,0,0,0,0,1` | six LSB-first bits of `0x09`: `1,0,0,1,0,0` | Shift six-bit IDCODE IR; final one enters Exit1-IR |
| 4 | `1,0` | two zeroes | Exit1-IR → Update-IR → Run-Test/Idle |
| 5 | `1,0,0` | three zeroes | Run-Test/Idle → Select-DR → Capture-DR → Shift-DR |
| 6 | 63 zeroes then one | 64 zeroes | Shift 64 IDCODE DR bits; final one enters Exit1-DR; capture TDO |
| 7 | `1,0` | two zeroes | Exit1-DR → Update-DR → Run-Test/Idle |

This is **87 TCK edges total**. It selects only the documented IDCODE
instruction, clocks zero data into the IDCODE scan, and returns the TAP to
Run-Test/Idle. It has no USER1/USER2 selection, USER data, configuration
instruction, erase, program, or bitstream operation. Verify the returned TDO
chain against the locked expected IDCODE and one-device zero-padding model.
Any mismatch, unexpected extra device, malformed response, short/extra TDO,
disconnect, or ambiguous completion means stop immediately; do not retry or
reconnect. An incomplete/ambiguous scan is a failed evidence record.

## Measure and stop

Use an oscilloscope or logic analyzer on the exact locked adapter's TCK/SK
output pin referenced to adapter ground. Record the instrument, probe/ground
points, bandwidth/sample rate, capture window, and calibration state. Capture
the IDCODE burst and enough edges to calculate:

```text
MEASURED_TCK_HZ = observed edge count / elapsed capture time
MEASURED_HIGH_NS = high pulse width per edge (min, max, and mean)
MEASURED_LOW_NS = low pulse width per edge (min, max, and mean)
MEASURED_DUTY_CYCLE = 100 * high_ns / (high_ns + low_ns), per edge and summary
JITTER_OBSERVED = period variation (report peak-to-peak and RMS, with sample count)
```

Preserve raw scope/logic-analyzer samples. Report minimum/maximum period,
frequency, high and low widths, duty cycle, and period jitter over the full
burst, not just a single average. Leave the FPGA configuration and workload
unchanged.

Immediately after the final IDCODE scan, close the single client once. Do not
retry. Confirm the TAP is left in Run-Test/Idle from the completed scan, the
operator socket is gone, and no established XVC peer remains. The server may
reopen its listener; keep the ACL blocking new clients and retain the
exclusive lock until the bridge owner explicitly accepts the handoff. No
transport traffic follows the IDCODE response.

## Acceptance and evidence

Fill [the evidence template](../ops/PHK2_PHYSICAL_TCK_EVIDENCE.template.json)
with target lock, bridge hash, process/socket/firewall snapshots, the selected
routed report and signed envelope, scan transcript, unchanged image/workload
proof, and raw waveform. Record these values explicitly:

```text
MEASURED_TCK_HZ=
MEASURED_HIGH_NS=
MEASURED_LOW_NS=
MEASURED_DUTY_CYCLE=
JITTER_OBSERVED=
```

The physical contract passes only if every worst-case measurement lies inside
the ultimately selected routed/electrical envelope. A route result through 50
MHz alone does not set the production limit. If the only selected bound is
50 MHz, treat it as an approved test ceiling only after the qualification
owner signs off the waveform constraints; do not infer duty/jitter/pulse-width
limits from frequency alone. `settck` is omitted from the procedure because
this ELF echoes the request without reprogramming MPSSE. Even if an echo is
captured for documentation, Sidecar must never treat it alone as effective
TCK proof.

## Required disposition

```text
EXCLUSIVE_PREFLIGHT_READY=true       # implemented and synthetic dry-run tested only
PEER_EXCLUSION_READY=true            # local process/socket/lock checks implemented; not run against a host
BRIDGE_ATTESTATION_READY=true        # schema pins reviewed ELF hash and Build ID
ARTIFACT_ATTESTATION_READY=true      # manifest schema/hash gates implemented
PHYSICAL_TCK_RUNBOOK_READY=true
PHYSICAL_TCK_TEST_SOFTWARE_READY=true
LIVE_EXECUTION_AUTHORIZED=false
PHYSICAL_TCK_TEST_READY=false        # exact adapter/deployment/envelope not yet bound
FPGA_PROGRAMMING_REQUIRED=false
USER_INSTRUCTION_REQUIRED=false
WORKLOAD_CHANGE_REQUIRED=false
SETTCK_RESPONSE_TRUSTED=false
MEASUREMENT_REQUIRED=true
PHYSICAL_AUTHORIZATION_REQUIRED=true
HARDWARE_ACCESS_COUNT=0
LIVE_XVC_CONNECTIONS=0
JTAG_TRANSACTIONS=0
```

No physical authorization is implied by this runbook. Do not execute without
separate physical authorization and all fail-closed preconditions above.
