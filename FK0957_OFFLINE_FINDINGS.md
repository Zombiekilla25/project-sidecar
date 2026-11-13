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
