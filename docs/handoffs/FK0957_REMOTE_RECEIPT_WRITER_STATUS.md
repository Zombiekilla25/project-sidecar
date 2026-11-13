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

The receipt directory must be private to the dedicated remote acquisition
account. A process with that same account can otherwise forge its own local
receipt. The current helper has no root-owned supervisor, receipt signing key,
or remote status command, so it cannot establish authenticity against a
compromised acquisition account. No shared USB ownership restoration is
authorized by this helper alone.

Before remote cleanup can be marked ready, a separately provisioned endpoint
must atomically claim the signed one-shot authorization, write RUNNING before
device access, record its terminal state, and be supervised so a fresh
challenge-bound status query can prove launch closure and process exit. Failure
to obtain that proof must remain `REMOTE_STATE_UNKNOWN` and require manual
recovery.
