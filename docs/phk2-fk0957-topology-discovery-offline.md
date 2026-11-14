# FK0957 reset-default DR topology discovery

## Production software status

The reviewed topology transaction remains fixed at 591 TCK for Scan A and
586 TCK for Scan B (1,177 total), with exact FK0957 descriptor selection and
atomic evidence publication. The corrected independent state model at
`ea2104c55a1d4dafe6da91c6d5ac28447ec336c1` previously matched all 28 valid
and 249,572 invalid boundary states.

The current hardening branch is not a live-ready release. It adds a static
launcher and a fail-closed remote unsigned-acquisition endpoint, but approved
issuer pins have not been provisioned and the RGB orchestrator is not wired to
the endpoint. Signed bridge ownership handoff, immutable release authorization,
complete release-manifest authority, and remote cleanup proof are still
required. Do not run an acquisition command or issue a permit until those
items are implemented and independently reviewed. No launcher binary was
built into or installed on the production host by this offline work.

The static launcher source is `tools/phk2_host/fk0957_safe_launcher.c` and
its bootstrap is `tools/phk2_host/fk0957_safe_bootstrap.py`. The build requires
an explicit absolute bootstrap path; it never embeds a checkout or detached
worktree path. An administrator deployment builds the launcher with
`--bootstrap-path /usr/local/lib/sidecar/fk0957/fk0957_safe_bootstrap.py`
after placing the reviewed bootstrap there, then installs the launcher and
bootstrap under a root-owned, non-writable directory. The static launcher
pins the bootstrap SHA256 and passes the already-verified open descriptor to
Python, avoiding a pathname reopen between verification and execution.
Offline tests use a temporary installed-path fixture and verify bootstrap
replacement refusal, environment sanitization, and prestart runtime pin
refusal. The launcher has not been deployed on the production host; this does
not authorize hardware access.

The launcher has not been installed or protected on the production host. Until
an administrator deploys it at a reviewed absolute path, direct Python
invocation is unsupported and refuses with `TRUSTED_LAUNCHER_REQUIRED`. No
production command line is published for a live operation.

The local remote-acquisition orchestrator validates the RGB-local
`SSH_AUTH_SOCK` and passes it to the local SSH client. Its SSH arguments retain
`ForwardAgent=no`; the socket is not forwarded to the testbench. This only
supports the existing descriptor-oriented SSH flow. Topology acquisition is
not yet split into an unsigned testbench record and RGB-only signing.

The physical topology adapter now lives in
`tools/phk2_host/phk2_fk0957_topology_transport.py`; local Ed25519 signing has
been moved to the separate
`tools/phk2_host/phk2_fk0957_topology_signing.py` module. The physical module
does not import the RGB orchestrator or signing module and has no signing-key
path. The current checked-in CLI still performs local acquisition followed
by local signing. A separate testbench endpoint now validates one-shot signed
authorization/handoff/manifest envelopes and emits only a canonical unsigned
record. The source pins a canonical trust-configuration template with empty
issuer key slots; acquisition remains fail-closed until the approved
maintenance/release authority provisions real keys and updates the reviewed
configuration pin. The RGB SSH-to-unsigned-record
orchestration and remote-process-exit cleanup proof are not yet connected.

The deterministic hashes and local host-key pin observation from the earlier
software integration are recorded in
[`results/fk0957-topology-software-handoff.json`](../results/fk0957-topology-software-handoff.json).
That historical record does not prove current remote acquisition or bridge
ownership readiness.

The handoff identifies production main as
`3226bfc1474d6afa873fce7327ded6dac548baae`; the separate WIP branch is
`hardening/fk0957-production-20261113`. Its current candidate head and source
hashes are recorded in the handoff JSON. Do not treat those candidate hashes
as an authenticated release manifest: no trusted signed manifest currently
authorizes the exact source bytes or clean Git state.

The host's verified `libc6:amd64` update from `2.39-0ubuntu8.9` to
`2.39-0ubuntu8.12` has been independently requalified for the WIP native
library loader. The libc SHA256/build ID are now pinned to the installed
package bytes in this branch; Right's result was reproduced with 173 tests in
a disposable production-baseline copy. The static launcher source now checks
the pinned Python, loader, libc, libftdi, and libusb hashes/build IDs before
starting Python. Its wrong-pin tests refuse before Python startup. The exact
`.deb` was not cached, and the launcher has not been administrator-deployed,
so this does not establish an installed production trust boundary or
authorize a live operation.
See [`FK0957_NATIVE_RUNTIME_REQUALIFICATION.md`](handoffs/FK0957_NATIVE_RUNTIME_REQUALIFICATION.md)
and [`fk0957-native-runtime-pin-qualification.json`](../results/fk0957-native-runtime-pin-qualification.json).
The older `fk0957-native-library-requalification-required.json` records the
original mismatch and remains historical evidence.

The interpreter, ELF loader, and pinned native-library state are inventoried in
[`fk0957-native-runtime-inventory.json`](../results/fk0957-native-runtime-inventory.json).
That inventory now reflects the qualified libc pin; the tested launcher source
enforces the loader pin before Python, but is not deployed. Review of Left's operations candidate is in
[`FK0957_LEFT_OPERATIONS_PATCH_REVIEW.md`](handoffs/FK0957_LEFT_OPERATIONS_PATCH_REVIEW.md).

## Live command status

No live command is published while the remote acquisition split, bridge
handoff binding, exact production source manifest, and protected launcher
deployment are incomplete. The old direct-Python command is obsolete and
fails closed with `TRUSTED_LAUNCHER_REQUIRED`. Keep the fixed transaction
hashes and counts below as regression references only.

For example, a prelive refusal has this exact field set and bounded values;
later phases use the same schema with their validated progress:

```json
{"status":"REFUSED","phase":"PRELIVE_VALIDATION","code":"TRANSACTION_PIN_MISMATCH","evidence_path":"none","signature_verified":false,"return_code":null,"target_candidates":0,"device_opened":0,"scan_a_started":0,"scan_a_tck_emitted":0,"scan_b_started":0,"scan_b_tck_emitted":0,"transport_closed":0,"permit_consumed":0,"operation_state":"PRELIVE","close_from_state":null,"publication_state":"NOT_STARTED"}
```

`publication_state` is an internally derived monotonic progress marker. The
allowed refusal values are `NOT_STARTED`, `SIGNED_STAGED`, and `PUBLISHING`.
The terminal `PUBLISHED` state is not a refusal-envelope value. Publishing
requires the signed staging state. This preserves the distinction between a
pre-staging signing refusal and a publish attempt; the field is diagnostic
progress, not an authorization or signing capability.

The success summary contains `status`, `target`, the three TCK counts, both
transaction hashes, raw-capture byte lengths and hashes, `parse_status`,
`evidence_path`, `evidence_sha256`, `signature_verified`, and three zero
mutation counters (`write_count`, `reset_count`, and `program_count`). The
fixed two-scan topology transaction is counted separately as
`jtag_operation_count=1`; that counter records the one fixed read-only
topology transaction and does not grant a generic arbitrary-JTAG capability.
The signed file at
`evidence_path` contains the full raw captures and parsed topology.

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
observed. The pure parser/mock record in `phk2_fk0957_topology_discovery.py`
intentionally leaves `transport_source_sha256` null because that helper has no
physical transport provenance. The supervised production endpoint instead
computes a non-null `transport_source_sha256()` over the clean exact Git HEAD,
complete production source closure, and pinned native runtime; RGB validation
rejects a missing or mismatching value. Caller-supplied hashes are rejected.

## Readiness boundary

The production path and its offline invariants are present and independently
reviewed. A live topology read remains a separate physical operation requiring
the applicable operator authorization and live preflight. This software
qualification performed no USB, JTAG, or hardware access. Do not extend this
path to IR-length discovery, IDCODE qualification, DNA, or image identity
without a separate review and authorization.
