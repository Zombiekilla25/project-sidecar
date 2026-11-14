# FK0957 read-only pre-live verification

**Status: not ready. This procedure is a readiness review only. It does not
authorize or perform a topology acquisition.** Current result must remain
`READY_FOR_AUTHORIZED_ONE_SHOT=NO` until the production trust roots, signed
exact-HEAD manifest, protected installation, and an independently reviewed
automated pre-live verifier are available.

This document is deliberately limited to read-only checks. Do not run the RGB
one-shot CLI, remote endpoint, transport, collector, or any command that
consumes authorization or starts the supervisor child. Do not enumerate USB
devices or call FTDI, MPSSE, JTAG, XVC, or BSCAN interfaces as part of this
check.

## Offline source and artifact integrity

In the reviewed hardening checkout, record the full `HEAD` and verify the tree
is clean:

```sh
git rev-parse --verify HEAD
git status --porcelain=v1
```

The software tree before this procedure was added was
`de06a94450c8cd4623aa3c123fa289e2533a7167`; its test-only signed manifest
artifact outside the repository had SHA256
`b44991431adcc75fa7718dc6ea60a521fbcadef7ec5722cd11b3326d2e279de4`; its
metadata explicitly records `TEST_ONLY=true` and `PRODUCTION_KEY=false`. This
signature is evidence of offline verifier behavior only. It is not an
installer input, production release authorization, or live-operation permit.
Adding this procedure changes `HEAD`, so that artifact is now historical and
must not be used as an exact-HEAD manifest for the updated tree. Any further
commit also invalidates an exact-HEAD claim; regenerate the unsigned candidate
manifest and repeat integrity checks after the last commit.

The canonical trust template hash is
`64ced3c5dafb6d585d3ffa10c022599722dd85e2313bb68bb4bcae6f57a22dc1`. Both
issuer-key hash slots are empty. The production endpoint must refuse with
`ISSUER_KEYS_NOT_PROVISIONED`; an empty template is not a trust root.

## Checks available after an administrator deployment

These commands are read-only; do not add `--apply`, invoke an acquisition
command, or use `systemctl start`, `enable`, `restart`, or `stop`:

```sh
/usr/local/bin/fk0957-safe-launcher --verify-runtime-manifest
/usr/local/bin/fk0957-safe-launcher --supervisor-client status <operation-id>
systemctl is-active fk0957-supervisor.service
```

The first command verifies the installed signed runtime manifest and runtime
pins. The status command is a read-only supervisor query; `UNKNOWN`, missing,
or mismatched status is a refusal and never authorizes restoration. The
service query reports state only. None of these commands checks live USB
identity or performs a topology scan.

Before deployment, `install_fk0957_supervisor.py --dry-run` prints the declared
layout and validates source packaging. Its `--stage-root` mode is a disposable
filesystem rehearsal, not a real install or proof of kernel ownership. Its
`--verify` mode checks selected installed ownership, modes, identities, and
ACL conditions. The implementation intentionally refuses `--apply`; it has
no backup/rollback transaction. Do not treat the stage rehearsal as an
administrator installer. An injected failure before source validation writes
nothing; an injected launcher-build failure after copying leaves a partial
disposable tree. The stage root must therefore be disposable and removed after
any failed rehearsal. This test does not establish rollback behavior for a
real installation because the real apply path does not exist.

## Readiness gates that cannot currently be checked read-only

There is no checked-in FK0957 pre-live executable that validates all of the
following without starting acquisition:

* signed descriptor evidence and the FK0957/adapter/USB-serial tuple;
* fresh, operation-bound release authorization and maintenance handoff;
* installed protected supervisor and all effective ownership/mode policy;
* production trust roots and a production-authenticated exact-HEAD manifest;
* bridge release and USBFS ownership observations for the intended window.

The current production trust template has no issuer keys, and the available
installer cannot apply a release. Do not try to fill these gaps by invoking
the one-shot CLI: that command is an acquisition path and may consume
authorization. Until an independent pre-live verifier exists and every gate
passes, the only valid readiness report is:

```text
READY_FOR_AUTHORIZED_ONE_SHOT=NO
```

This procedure does not inspect hardware, open a device, consume a permit,
issue authorization, change service state, or sign evidence.
