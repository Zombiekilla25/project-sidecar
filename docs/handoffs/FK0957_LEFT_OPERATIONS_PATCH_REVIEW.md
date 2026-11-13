# Left FK0957 operations candidate review

Reviewed candidate commit: `7ab491f1385a960c133b58134e18c2fec6a5b95b`
on Left's isolated `codex/fk0957-ephemeral-bundle` worktree. Review was
offline; no bridge, SSH, device, or hardware operation was run.

## SSH agent boundary

The candidate preserves the local `SSH_AUTH_SOCK`, keeps
`ForwardAgent=no` and `ClearAllForwardings=yes`, and checks the local agent's
identity-list response. The hardening branch independently implements this
minimal useful behavior while retaining its no-follow dirfd parent walk and
before-invocation inode revalidation. Offline fakes exercise a valid identity,
an empty identity list, and refusal before the SSH runner. Tests also assert
that the local socket path is not in remote command arguments or stdin and
that key material stays out of remote arguments/stdin. The socket path is
present only in the local child process environment for OpenSSH to connect to
the local agent.

## Remote operation contract: not integrated

The new `fk0957_remote_operation_contract.py` tests strict record shapes and
freshness, but it is not wired into the orchestrator's acquisition/signing
path. Its release manifest is self-hashed, not authenticated by a pinned
maintenance-authority signature; anyone able to supply the JSON can recompute
that hash. Its source list has six entries and omits the trusted launcher,
live CLI, schema/validator, handoff verifier, and configuration. It therefore
does not establish the required complete source authority or trusted bridge
handoff.

The proposed unsigned result also has no remote topology acquisition
implementation behind it. The existing remote collector remains a descriptor
collector. Its mutation schema labels `JTAG_OPERATIONS` zero, while the actual
fixed two-scan topology record reports `jtag_operation_count=1`; applying the
descriptor counter rule to topology would contradict the production behavior.
The topology operation is fixed and read-only, but it is still one JTAG
operation. The candidate contract must be revised to model that distinction.

Left's contract and handoff documents are retained as review input only. They
must not be presented as a trusted issuer, a production manifest, or a ready
remote topology acquisition path. Production main remains unchanged.
