# Left FK0957 operations candidate review

Offline review; no SSH, bridge/client action, USB, JTAG, or hardware access.
Left's final reviewed commit is `dfd1f3b1f4530663f0b512ca3e5e01a9c657cd53`
(parent `18c8a0d4b653985d3cc4422f2e19bbfdd8ab0573`, stable patch-id
`25dd3c7ee15c81a0ddd5a3f1b2c76cf75c9341fa`). It adds a permissive GNOME
agent-socket permission rule and related tests/docs. Its other commits are
listed below with their stable patch IDs. None was cherry-picked wholesale.

That final commit's exact changed paths are:
`docs/handoffs/FK0957_MIDDLE_OPERATIONS_INTEGRATION.md`,
`docs/handoffs/FK0957_REMOTE_OPERATION_CONTROL_CONTRACT.md`,
`tools/phk2_host/fk0957_maintenance_controller.py`,
`tools/phk2_host/phk2_fk0957_remote_orchestrator.py`,
`tools/phk2_host/test_fk0957_maintenance_controller.py`, and
`tools/phk2_host/test_phk2_fk0957_remote_orchestrator.py`.

## Local SSH agent

Left's new case accepts a socket with group/other access when the immediate
parent is a private user-owned directory. The tests cover the typical 0775
GNOME socket, public parent, stale socket, and replacement. The implementation
uses path-based `lstat` checks; the check of the parent inode is not held by a
dirfd across validation and invocation, so namespace replacement has a wider
race than the hardening branch's no-follow dirfd walk and inode revalidation.

The hardening branch reimplemented the useful rule with descriptor-relative,
`O_NOFOLLOW` ancestor traversal; it pins the final parent `(device,inode)`,
checks the socket inode twice, requires the socket owner to be the effective
user, and accepts group/other socket bits only when an owner-owned 0700
ancestor protects the endpoint. The observed `/run/user/1000/keyring/ssh`
socket is uid/gid 1000, mode 0775, under a uid 1000 mode 0700 parent. New
regressions cover wrong owner/type, symlink, socket and parent-directory inode replacement, unsafe shared parent, missing
socket, and stale/unresponsive socket. SSH receives this socket
only in the local child environment; `ForwardAgent=no` and
`ClearAllForwardings=yes` remain required, and the remote command/stdin do not
contain the socket path or key material.

**Trust boundary:** local processes already running under the authenticated
RGB user's UID are treated as the same trusted principal. The pathname-based
SSH agent protocol cannot eliminate a race against a malicious process with
that same UID after the final pre-`exec` inode check. The validator protects
against other users and namespace substitution across validation by using
no-follow dirfd traversal, checking ownership/type, and rechecking the socket
inode immediately before launching OpenSSH. The 0775 socket is accepted only
because its containing keyring directory is owner-only 0700. If hostile
same-UID processes enter the threat model, this path-based OpenSSH agent
interface must be replaced by a broker or inherited connected descriptor;
the current code does not claim to defend that principal.

## Remote-operation and handoff contract: not integrated

The operation-contract/profile commits remain design input, not a production
acquisition path. The profile hardcodes an older production HEAD and an
incomplete source set. Its self-hash is not a signature from a protected
maintenance authority. The latest signed-envelope draft takes the trusted
public key/fingerprint from caller arguments, so it does not establish a trust
root. The operations contract is not wired through a remote topology
acquisition and RGB signing invocation. Existing remote collector behavior is
descriptor-only. The draft also modeled JTAG operation count as zero, while a
successful fixed topology-discovery record correctly has three zero mutation
counters and `jtag_operation_count=1`.

The maintenance controller, recovery campaign, and emergency-restore code can
perform service/client and bridge actions when explicitly invoked. They were
not imported into the hardening production path; their live-control entry
points were not run or integrated. Trusted handoff issuer keys and a signed,
complete source manifest are still absent. Thus Left's contract cannot satisfy
the requested trusted handoff or remote topology acquisition gates.

## Left commit series reviewed

| Commit | Stable patch-id | Disposition |
|---|---|---|
| `2832a78c6e7ce084da0119cc5476246914e9cdf3` | `74ac0254a005663eb3b88930fd4744cb25d496ac` | Ephemeral descriptor bundle; not a remote topology transaction |
| `8f108c13aaaadae33ed28be942942f3ac61d2f62` | `941af420f9798a46ac4f90e1dcdf43655e04dc31` | Handoff/docs snapshot with stale source authority |
| `a48698ad354ef69992f4d5474458ab65acd2525b` | `d68f963425f8bab26a3555790da00950b670fa76` | Handoff refresh, same trust limitations |
| `14258638f283576f8017ce284c44ef925b9374d6` | `910e138bce394789b9d010b2448ab1cb218304b0` | Guarded maintenance controller; service-management surface not imported |
| `c559ee355bd6cfad46c31c0c3ff4e81e1ba31a82` | `90710b5a9070fa5874ea354c9b099b18c600353b` | Recovery/emergency restore, not integrated |
| `45f52c075396396348841741cf1fd11de2726684` | `c3f637313d056032510c7c0ebddf0ccbd3870608` | Maintenance wiring, not integrated |
| `c00a0b795a334b1ff888d614636d2710b3c55f31` | `5d56cbe64bb76c86a743f1b97e52bcd65ed70376` | Runbook timeout clarification |
| `7ab491f1385a960c133b58134e18c2fec6a5b95b` | `bf2aa89400d6ab25c870ab297b0bcc90c28ae9a4` | Contract not wired and lacking pinned trust root |
| `18c8a0d4b653985d3cc4422f2e19bbfdd8ab0573` | `fbce178c00d526ddeacb6eda461828c89268d0fa` | Profile pins stale/incomplete; issuer arguments are caller-supplied |
| `dfd1f3b1f4530663f0b512ca3e5e01a9c657cd53` | `25dd3c7ee15c81a0ddd5a3f1b2c76cf75c9341fa` | Socket behavior reviewed; stricter local equivalent implemented |

The agent behavior has local regressions; the remaining operations contract,
trusted issuer, remote topology acquisition, and complete manifest are not
claimed complete.

## Latest deployment/recovery candidate (`a6b2cb30ca6e93cce597f3ef609f77d0cc8f2302`)

This candidate adds a read-only protected-layout preflight and adjusts the
maintenance controller's system `cryptography` import. Its focused offline
preflight/controller suites pass 56 tests. The layout checker validates a
caller-supplied out-of-band digest and fails on missing roles, extra files,
symlinks, hardlinks, mode/owner mismatches, and noncanonical manifests. It is
not an authenticated release-manifest authority and its path checks are a
preflight, not an openat/dirfd execution pin; it does not close runtime path
replacement races after the check.

The controller still does not prove that the remote acquisition process has
exited before restoring the bridge after SSH loss. `terminate_bound_operation`
only binds and terminates the local Python/SSH orchestrator PID. In the
`finally` path, the controller may then issue `RESTORE_COMMAND` and verify
bridge state without a remote-process exit acknowledgement. A disconnected
SSH command can leave the remote process state unknown; this fails the
required `REMOTE_CLEANUP_PROVEN_BEFORE_RESTORE` invariant. Therefore the
candidate is not integrated into the production topology path. Its
system-cryptography version check is also not a substitute for the hardening
branch's pinned native/runtime manifest.

Exact final candidate paths: `docs/FK0957_MAINTENANCE_WINDOW_RUNBOOK.md`,
`docs/FK0957_DEPLOYMENT_AND_RECOVERY_PACKAGE.md`,
`docs/FK0957_MIDDLE_OPERATIONS_INTEGRATION.md`,
`tools/phk2_host/fk0957_deployment_preflight.py`,
`tools/phk2_host/fk0957_maintenance_controller.py`,
`tools/phk2_host/test_fk0957_deployment_preflight.py`, and
`tools/phk2_host/test_fk0957_maintenance_controller.py`.
