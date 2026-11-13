# FK0957 long-run offline adversarial findings

Audited production tree: `/home/rmann/project-sidecar-phk2-first-silicon-host-20261109`
at `25b2d1260267cd484f1ecb74e96420bbd7504965` (production code candidate
`dd51f7eb7a0c1956e0691c35de83905291e0fc42`). No production source was edited.

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

At the start of this campaign, `_publish_evidence_atomic` checked that the
output name was absent, then called `os.replace`. A deterministic injected
writer created the destination between those operations; its file was
overwritten and publication reported success. This was reproduced on the
reviewed `25b2d126` snapshot.

During the campaign, real main advanced to `895654a4303064ecef6eb363e08bd28c96852bb7`
and received uncommitted changes that replace `os.replace` with `os.link` and
add a concurrent-output regression. The independent reproduction against
that working-tree version now refuses and preserves the competing file. These
changes are not ours and remain uncommitted; this report does not certify that
candidate until the full suite and source review complete.

### Low: direct malformed-envelope validator calls can raise

Across 10,000 deterministic type mutations, `_bounded_envelope` raised
`TypeError` 413 times for unhashable values in phase/code/state positions. Its
only production call site currently catches exceptions and emits a generic
internal refusal, so this did not reproduce an external traceback or leak.
Still, the validator is not total over arbitrary JSON values and merits a
regression test/hardening.

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
- No SSH, USB, JTAG, permit issuance, or hardware access occurred.
