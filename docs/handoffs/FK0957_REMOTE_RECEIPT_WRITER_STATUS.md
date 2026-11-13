# FK0957 remote process status and receipt authority

This document supersedes the earlier same-UID receipt-store proposal. The
legacy `ReceiptStore` and cleanup-protocol modules are not authoritative: they
cannot prove child exit, their terminal-state claims are not restorable, and
the former `launch_closed` caller assertion has been removed. A caller-written
receipt or missing PID must never authorize shared USB ownership restoration.

The hardening source package now contains a root-service supervisor, a narrow
Unix-socket client protocol, a systemd unit, a fixed root-owned state layout,
and dry-run/verification tooling. The supervisor derives terminal state from
the child it launched and successfully waited for. It records process identity
including the post-exec Python executable and argv identity; PID absence by
itself is not exit proof. A supervisor restart cannot reconstruct a `wait()`
result, so in-flight journal entries become `UNKNOWN`. Unknown state blocks
automatic restore. The client rejects untrusted lifecycle fields and accepts
only a supervisor response with the expected operation, executable identity,
and reaped terminal result.

These are source/package properties, not deployment claims. The supervisor
has not been installed or started with privileges, the service account and
protected directories have not been provisioned, and the release/handoff
trust roots remain unconfigured. Consequently remote cleanup is not enabled
for a live operation. Until an administrator installs and verifies the
package and approved trust roots are provisioned, any lost or ambiguous SSH
session remains `REMOTE_STATE_UNKNOWN`; do not restore shared ownership
automatically.

The `fk0957_remote_receipts` and `fk0957_remote_cleanup_protocol` modules are
retained only as quarantined legacy compatibility code and regression
fixtures. They cannot authorize restoration. The supported status authority
is the protected supervisor IPC path; it must be installed and independently
verified before operational use.
