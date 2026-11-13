# FK0957 supervisor deployment package (not installed)

This package defines the authority boundary; no issuer keys or live release
authorization are included. Production remains fail-closed until administrators
provision the independently approved trust material and install the files.

## Layout and ownership

| Path | Owner:group | Mode | Purpose |
| --- | --- | --- | --- |
| `/usr/local/bin/fk0957-safe-launcher` | `root:root` | `0755` | Static pre-start launcher |
| `/usr/local/lib/sidecar/fk0957/tools/phk2_host/` | `root:root` | `0755` | Runtime modules, files `0644` or stricter |
| `/usr/local/lib/sidecar/fk0957/ops/phk2/` | `root:root` | `0755` | Service template |
| `/etc/systemd/system/fk0957-supervisor.service` | `root:root` | `0644` | Installed supervisor unit |
| `/etc/sidecar/fk0957/` | `root:root` | `0750` | Provisioned trust/runtime configuration |
| `/etc/udev/rules.d/90-sidecar-fk0957-supervised.rules` | `root:root` | `0644` | Exact serial USB ACL for non-login runner |
| `/run/sidecar/` | `root:sidecar-acquire` | `0750` | IPC socket parent |
| `/run/sidecar/fk0957-supervisor.sock` | `root:sidecar-acquire` | `0660` | Narrow local IPC |
| `/var/lib/sidecar/fk0957/supervisor/` | `root:root` | `0700` | Authoritative operation journals |
| `/var/lib/sidecar/fk0957/consumed-release-authorizations/` | `root:root` | `0700` | Single-use authorization ledger |

The service is deliberately root-owned to retain exclusive authority over
state and the authorization ledger. IPC callers use the unprivileged
`sidecar-acquire` account; each acquisition child is dropped to the distinct
non-login `sidecar-fk0957-runner` account and receives only the
`fk0957-device` supplementary group. The proposed udev rule grants that group
access only to the exact USB descriptor serial. The runner cannot write root
state. These accounts, rule, and service are not installed by this change.
No `launch_closed`, exit, or restore claim is accepted from IPC.

## Installer and verifier

`tools/phk2_host/install_fk0957_supervisor.py --dry-run` prints the planned
layout and verifies source/unit presence without writing. `--verify` checks an
already installed layout. The script intentionally refuses `--apply`; package
installation requires a separately reviewed administrator deployment.

The service unit has `Restart=no`: a daemon restart cannot reinterpret an
incomplete journal as a confirmed terminal result. Unknown or missing state
must be handled as manual recovery. A successful run is only confirmed after
the supervisor's exact `Popen` child is waited/reaped and its exit is journaled.

## Maintenance status API

The maintenance controller uses the installed `fk0957-safe-launcher
--supervisor-client status <operation-id>` command. This is a read-only query;
the IPC request has exactly `schema`, `command`, and `operation_id`, and the
kernel peer credential must identify `sidecar-acquire`. The caller cannot
submit a child state, exit code, launch-closed assertion, or restore decision.

The client returns canonical JSON with schema
`fk0957-maintenance-status-v1`, the queried `operation_id`, `state`, `terminal`,
and `restore_eligible`. For `RUNNING`, it also returns `child_identity`. A
terminal response includes authorization, handoff, manifest, target, and
transaction bindings; exact child identity; exit code; registration and reap
timestamps; and the bounded unsigned result. `restore_eligible` is computed
by the client only when the response is an exact, internally consistent
`EXITED_SUCCESS`, `EXITED_REFUSAL`, or `EXITED_FAILURE` record with the pinned
child identity and reap metadata. Every malformed, missing, mismatched,
incomplete, or unavailable status is projected to `state=UNKNOWN`,
`terminal=false`, `restore_eligible=false`. Controllers must restore shared
USB ownership only when the operation ID matches and `restore_eligible` is
exactly `true`; all other states require manual recovery.

## Authorization identity and consumption

The signed release authorization's `authorization_id`, canonical payload
SHA256, `operation_id`, and `nonce` are copied unchanged into the immutable
topology permit. The permit also binds the signed descriptor digest and is
checked against the supervisor-validated request before it is attached to the
one-shot transport call. The transport consumes that same permit object once
before constructing its native backend; it does not issue a replacement
permit. The transport observation and unsigned acquisition record carry the
same four authorization identity fields, which RGB validates against its
original signed request before signing. The handoff references the same
`authorization_id`; the signed release authorization binds the canonical
handoff digest, avoiding a circular hash dependency.

The release authorization ledger has one consumption point: the protected
supervisor's exclusive ledger create, after full request, handoff, target,
manifest, profile, and freshness validation and before child launch. Endpoint
and transport validation are non-consuming checks. A mismatch at those
boundaries refuses before native backend construction/open. The local
descriptor/topology permit is a single-use execution capability derived from
the same release authorization, not a second release authorization.

## Current provisioning state

The issuer pin is unset in the remote endpoint source and the root-owned
configuration/issuer keys are not provisioned. Therefore supervisor requests
currently fail before child launch. This is intentional; do not generate
replacement keys as part of this software package.
