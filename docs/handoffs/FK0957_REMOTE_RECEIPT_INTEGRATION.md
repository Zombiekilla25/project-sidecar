# FK0957 remote status integration history

The Left cleanup contract at `2474ebba421f14ce7e1d63cb32816310aefc9adb`
(parent `8da668970f58c2ad458c171e046b7cfa3618cd3b`) supplied the initial
operation/authorization/manifest/target binding, challenge nonce, and process
identity fields. It remains useful as historical schema and regression
coverage, but it is no longer the production authority model.

Subsequent hardening commits added the protected supervisor and routed the RGB
orchestrator's status request through its Unix-socket client. Caller-provided
`launch_closed` and terminal-state claims are rejected. The older filesystem
receipt protocol is quarantined and cannot authorize restore. The supervisor
owns operation state and the child lifecycle; only its successful wait/reap
of the exact child can establish a terminal exit. SSH status 255, inspection
failure, PID absence, supervisor restart with an in-flight child, and any
other uncertainty remain non-restorable.

The supervisor package is not privileged-installed or active in this
environment. The runtime trust roots also remain unprovisioned. Therefore the
source integration is not operational authorization: after SSH loss, do not
restore shared USB ownership automatically unless a separately deployed,
approved supervisor has returned a validated terminal result. Otherwise the
state is `REMOTE_STATE_UNKNOWN` and requires manual recovery.

No SSH, service, bridge, USB, JTAG, or hardware action was performed while
updating this handoff.
