# FK0957 remote receipt writer status

The WIP hardening branch now contains a local filesystem receipt-store helper
and regression tests for atomic one-shot state transitions. The helper is not
yet called by the installed remote acquisition endpoint, and there is no
installed, separately supervised status-query command. It is therefore a
protocol implementation component, not proof that remote cleanup is ready.

The helper deliberately does not treat an absent `/proc/<pid>` entry as proof
that the remote operation is safe to restore: absence alone cannot establish
that launch is closed, rule out a delayed child, or determine the endpoint exit
class. A terminal receipt is restorable only when a caller with independent
launcher/supervisor knowledge explicitly reports `launch_closed=true`, and
the exact recorded process identity is no longer present. `launch_closed`
defaults to false. SSH exit status 255 always remains unknown.

Process inspection is tri-state: only an actual `ENOENT` is represented as an
absent process; permission, I/O, decoding, and malformed `/proc` results become
`STATUS_INSPECTION_FAILED`. That state, transport failure (including SSH 255),
`UNKNOWN`, and PID identity mismatch are all non-restorable. The protocol
exposes distinct confirmed terminal statuses (`CONFIRMED_NOT_STARTED` and
`CONFIRMED_EXITED_*`) and `CONFIRMED_RUNNING` so callers cannot treat a query
failure as a process result.

The receipt directory must be private to the dedicated remote acquisition
account. A process with that same account can otherwise forge its own local
receipt. The current helper has no root-owned supervisor, receipt signing key,
or remote status command, so it cannot establish authenticity against a
compromised acquisition account. No shared USB ownership restoration is
authorized by this helper alone.

The status-store update still has a destination-entry race against a
concurrent process running as the same acquisition UID: a replacement after
the last inode/content check can be overwritten by the atomic rename. The
private directory and dirfd handling protect against other UIDs and parent
path substitution, but they cannot isolate files from the directory owner.
Accordingly `RECEIPT_REPLACEMENT_RACE_POSSIBLE=YES` until a root-owned
supervisor/service owns the receipt directory and performs conditional state
transitions. Do not use this prototype to authorize restoration.

Before remote cleanup can be marked ready, a separately provisioned endpoint
must atomically claim the signed one-shot authorization, write RUNNING before
device access, record its terminal state, and be supervised so a fresh
challenge-bound status query can prove launch closure and process exit. Failure
to obtain that proof must remain `REMOTE_STATE_UNKNOWN` and require manual
recovery.
