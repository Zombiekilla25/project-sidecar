# FK0957 long-run offline adversarial findings

Audited production tree: `/home/rmann/project-sidecar-phk2-first-silicon-host-20261109`
at `4d9a222db332b35f605a06a0f05dc2cdc331c940` (production code candidate
`dd51f7eb7a0c1956e0691c35de83905291e0fc42` is an ancestor). No production
source was edited by this audit. At the latest check, unrelated documentation
files were modified but the production code diff was clean.

## Reproduced blockers

### High: interpreter startup environment executes code before application checks

The live CLI has no isolated launcher. Running it with a temporary `PYTHONPATH`
containing `ctypes.py` executes that module before the CLI reaches `main`; a
`sitecustomize.py` in the same path also executes before the script. A benign
test shared object supplied through `LD_PRELOAD` executes its constructor
before Python starts. The transport later refuses when it sees loader override
variables, but that check occurs after the preloaded code has already run.
These reproductions use only `--help`, temp files and a harmless marker; no
permit or device operation occurs.

The production code needs a reviewed isolated entry point that starts Python
with a fixed executable and isolated/no-site flags from a sanitized environment.
An in-process check cannot undo `LD_PRELOAD` execution that already occurred.

### Medium: evidence publication race in the reviewed `25b2d126` snapshot

On the initial audited snapshot, `_publish_evidence_atomic` checked that the
output name was absent, then called `os.replace`. A deterministic injected
writer created the destination between those operations; its file was
overwritten and publication reported success. This was reproduced on the
reviewed `25b2d126` snapshot.

During the campaign, real main advanced and commit
`4d9a222db332b35f605a06a0f05dc2cdc331c940` replaced `os.replace` with atomic
no-replace `os.link` and added a concurrent-output regression. The independent
race reproduction against the new implementation refuses and preserves the
competing file. The 42 focused CLI/transport tests and 209-test broader FK0957
suite passed against this implementation.

A separate directory-rename race remains: after `_open_path_parent` returns a
directory FD, moving that directory and replacing its original path with a
symlink causes publication to succeed under the moved directory while the
requested pathname resolves elsewhere and contains no record. The FD prevents
writing through the replacement symlink, but the CLI does not revalidate that
the pathname still names the directory it published in. Include the resulting
path/inode identity in the success decision and report.

The independent selection campaign also exercised 120 permutations of one
target plus four peers and 120 permutations with duplicate exact targets. The
unique target was selected in all peer-orderings; all duplicate exact targets
refused before the fake open.

Additional path probes refused pre-existing output symlinks/hardlinks,
symlinked parents, a colliding temporary directory, and symlink/hardlink
signing-key paths. A separate fake-backend signing test passed and confirms
the runtime seam can produce a signed record without opening a native device.

### Low: direct malformed-envelope validator calls can raise

Across 10,000 deterministic type mutations, `_bounded_envelope` raised
`TypeError` 413 times for unhashable values in phase/code/state positions.
Across all 9,480 noncanonical/rejected cases, the production refusal wrapper
returned a generic internal refusal; no traceback or raw exception text
escaped. The validator itself is not total over arbitrary JSON values and
merits a regression test/hardening.

## Other software readiness blockers

The checked-in topology CLI performs direct native FTDI acquisition and local
signing in one process. It has no pinned SSH transport for acquiring on the
authorized testbench while keeping signing on RGB. No bridge-owner or
cross-process exclusivity precondition is wired into the CLI. These remain
independent blockers to the requested first live read.

Documentation at `docs/phk2-fk0957-topology-discovery-offline.md` says the
transport source hash remains null until a production adapter exists, while
the production transport has a native adapter and computes that hash. The
documentation should be reconciled with code before a live run.

## Still passing

- Independent corrected state oracle: 28 valid accepted, 249,572 invalid
  rejected, repeated deterministically.
- Fixed transaction: 591 / 586 / 1,177 TCK; Scan A and Scan B hashes match
  reviewed golden values.
- Focused mock suites: state, enumeration, refusal, atomic publish, runtime
  pins and output failure tests pass, except for the documented optional
  `blake3` import-only environment error in one physical-close test.
- The complete 233-test selected suite had 232 passing tests and one error
  from that same optional `blake3` dependency; excluding only that unrelated
  import-only test, all 23 physical-close tests passed.
- No SSH, USB, JTAG, permit issuance, or hardware access occurred.

## Additional provenance finding

`transport_source_sha256()` hashes the transport/discovery modules, IDCODE
gate, remote orchestrator, historical native source, and pinned libraries; it
does not hash `phk2_fk0957_topology_live_cli.py` or require a Git HEAD/clean
tree check. The topology record therefore does not bind the CLI validation,
signing orchestration, and publish code to its transport hash. The operator
can perform a manual HEAD review, but the documented invocation does not
enforce that precondition.

The production transport also retains `_run_with_backend(permit, backend)`,
which accepts an arbitrary backend object. The committed transport tests use
that seam with `FakeBackend`, then call `sign_local_discovery_record` and
verify a signed topology record. The normal CLI does not call this helper, but
it remains importable and callable in production Python; a caller can bypass
the native-device path and produce a signed record from synthetic backend
bytes. Move this seam to test-only code or otherwise make the production
signing path accept observations only from the native adapter.

## Long-run campaign update against production HEAD `3226bfc1474d6afa873fce7327ded6dac548baae`

The corrected independent oracle was rerun twice against the actual clean main
tree after its documentation-only integration commit. Both runs tested all 28
valid and 249,572 invalid states with zero valid rejections and zero invalid
acceptances; each also reran 1,015 malformed-envelope cases and 42 focused
CLI/transport tests. The separate deterministic mutation campaign generated
10,000 malformed type cases: 9,480 were rejected/noncanonical and safely
converted to bounded refusal output, with zero unsafe fallback failures. The
validator raised `TypeError` for 413 unhashable field values, but the outer
refusal wrapper contained each exception.

The expanded audit harness independently decodes the literal MPSSE command
framing and recomputes both reviewed scan manifest hashes. It confirms 591,
586, and 1,177 TCK respectively and exact equality with the reviewed golden
hashes. It also re-ran 120 peer orderings (all selected the unique exact target)
and 120 duplicate-target orderings (all refused before fake open).

The latest race campaign confirms the no-replace publish correction preserves
a competing destination. It also reproduces the parent-directory move race:
the publisher writes via the safely held directory FD and returns success,
while the requested pathname now resolves elsewhere. The record is not written
through the replacement symlink, but the path reported to the operator no
longer names the published record. Evidence publication path identity therefore
remains a blocker even though destination overwrite is fixed.

The independent campaign found no change to the topology transaction and no
enumeration-order or peer-selection defect. Offline-only blockers remain the
startup injection routes, missing SSH/RGB separation and bridge ownership
enforcement, incomplete source binding, callable fake-backend signing seam,
and evidence parent-path identity race. No permit was issued and no physical
operation was attempted.

The audit script initially rejected a valid TMS command because it treated
MPSSE's separate TDI bit (bit 7) as excess TMS payload. This was corrected in
the audit worktree only; no production code or reference oracle was changed.

## Executable acceptance campaign

`tests/reference/fk0957_independent_acceptance.py` encodes the remaining
readiness findings as repeatable temporary-fixture attacks and source gates.
Run it with the production repository path. Against `3226bfc1474d6afa873fce7327ded6dac548baae`, it produced these results:

- Harmless sentinels executed via `PYTHONPATH` (`ctypes.py`), `sitecustomize`,
  `usercustomize`, `LD_PRELOAD`, `LD_LIBRARY_PATH` name resolution, PATH
  substitution, and a substituted `.venv/bin/python` fixture. An invalid
  `PYTHONHOME` altered interpreter startup (exit 1); the environment was not
  cleared by a trusted launcher.
- Seven mocked bridge cases (missing/stale handoff, wrong bridge, competing or
  unknown owner, different permit, and different target) all reached the
  acquisition boundary. The transport was replaced with a refusal sentinel;
  no hardware operation occurred.
- The existing production-importable fake-backend seam signed a synthetic
  observation in its regression test using an ephemeral test key. No operator
  key was read. This demonstrates the seam is callable, not that the native
  library preflight currently passes.
- 20,000 malformed envelope/type variations yielded zero escaping exceptions,
  zero noncanonical outputs, and zero exception-text leaks at `_safe_refusal`.
- A one-byte transport-source fixture changed the calculated source hash, but
  the source hash does not cover the CLI, backend, observer, collector,
  launcher, or manifest/configuration. There is no dirty-tree or expected-HEAD
  enforcement.
- The current runtime-library pin check returned a bounded `Refusal` before any
  device operation. Independent ELF/package inspection found libftdi
  `1.5-6build5` and libusb `2:1.0.27-1` match the reviewed hashes/build IDs.
  Installed libc is `2.39-0ubuntu8.12`, SHA256
  `755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a`, build
  ID `8cebda42d140fc2b09639f8b13a5d5f2e617ef09`; both differ from the pinned
  libc SHA/build ID. This causes the focused transport suite to fail 11 of 21
  tests in the current environment. The correct action is deliberate pin
  requalification, not silently approving these bytes.
- Documentation still recommends `PYTHONPATH=tools/phk2_host` and retains a
  stale claim that transport hash is null until a production adapter exists.
- The handoff JSON's four recorded executable-source hashes still match the
  current files. Its `production_code_head` is `4d9a222...`, while current main
  is `3226bfc...`; the intervening commit is documentation-only. The handoff
  explicitly says its SSH pin was not consumed by the local CLI. Its
  `READY_FOR_PRODUCTION_INTEGRATION=YES` describes software integration, not
  authorization/readiness for a first physical run.

This campaign is an independent audit artifact and does not alter production
or the corrected reference model. No SSH, permit issuance, USB, or hardware
operation was performed.

## Native runtime requalification

Independent runtime requalification passed for a **proposed** pin set only.
The libc change is explained by the recorded Ubuntu unattended upgrade from
`2.39-0ubuntu8.9` to `2.39-0ubuntu8.12` at 2026-11-13 06:10. The reviewed pin
commit predates that upgrade. Paths did not change. The updated noble-updates
and noble-security InRelease signatures verify with the local Ubuntu archive
keyring; the local `Packages` index SHA256 matches the signed InRelease; apt's
libc package record identifies version `.12`; and `dpkg -V` plus the installed
package MD5 manifest show no local file difference. The exact `.deb` is not
cached, so the package archive SHA is recorded but was not independently
recomputed from the archive.

The installed candidate libc advertises all GLIBC symbol versions required by
the pinned libftdi/libusb binaries. All adapter-required FTDI/libusb symbols
resolved. The production FD-based loader loaded the approved native objects
and verified their file hashes, pre/post stat identity, and mapped realpaths;
setting `LD_LIBRARY_PATH`, `LD_PRELOAD`, or `LD_AUDIT` after process startup
caused refusal. No FTDI context was created and no USB function was called.
With only the libc hash/build ID updated in a disposable copied test tree,
173 FK0957 library, CLI, transport, discovery, observer, backend, collector,
and orchestrator tests passed.

Proposed runtime pin data is in
`results/fk0957-proposed-native-pin-set.json`; full inventory and test evidence
is in `results/fk0957-native-runtime-requalification.json`. **No production
pin was changed.** The current production pin preflight continues to refuse
the installed libc, as it should until a reviewed pin update is integrated.
The proposal does not close the separate startup-injection finding: a trusted
isolated launcher must validate the dynamic loader before untrusted Python or
loader environment code can run. Therefore this runtime result does not make
the overall FK0957 path ready for live operation.

`tests/reference/watch_fk0957_hardening_heads.py` watches only the local
production HEAD. For each new SHA stable across polls it creates a new detached
worktree and runs the corrected oracle, this acceptance campaign, the long-run
attack campaign, and `git diff --check`; results stay in ignored audit output
directories. It has an exact `--expected-head` guard in the acceptance runner.

The current watcher remains active against the local production HEAD. The
acceptance harness now additionally mutates one byte, in-memory only, across
the live CLI, remote orchestrator, transport, backend, observer, collector,
discovery/schema, handoff manifest, and configuration categories. The runtime
source digest changes for the orchestrator, transport, and discovery/schema;
it does not change for the CLI, backend, observer, collector, launcher, or
manifest/config. It also reports no Git HEAD/clean-tree gate. Local source
checks find no SSH/SSH_AUTH_SOCK, handoff issuer/authenticator, operation-ID
binding, or remote-signing protocol. The fixed local signer and sealed-result
checks exist, but there is no remote acquisition/ RGB-signing boundary; this
remains an open architecture finding. The updated machine-readable campaign
is `results/fk0957-independent-acceptance-3226bfc.json`.
