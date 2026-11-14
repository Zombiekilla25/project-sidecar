# Independent FK0957 hardening audit: a1c9b4b

Audited exact committed HEAD: `a1c9b4b11d7755807a47f8a24f7e06b9df657da6`.
A fresh detached candidate worktree was clean. The current hardening checkout has
uncommitted edits; they were not included in this audit. Refreshed `origin`
remains at the audited SHA. Watcher PID 1170327 remains running against
`origin/hardening/fk0957-production-20261113`.

No production files, hardware, testbench, USB, or JTAG were accessed.

## Results

- Corrected state oracle: 28 valid and 249,572 invalid states; zero mismatches.
- Independent adversarial corpus: 1,015 cases, including 120 target-order
  permutations and 120 duplicate-target permutations; 20,000 malformed
  boundary values produced zero escaped exceptions, raw exception leaks, or
  unsafe/noncanonical outputs.
- Candidate focused suite: 68 tests passed. Independent acceptance suite:
  passed on the clean detached candidate. Runtime provenance audit and
  `git diff --check` completed without errors.
- Permit/token continuity: PASS in the supervisor-authorized test route.
  Mutations at the tested authorization boundary are refused before consume
  and before fake transport/backend; duplicate/replay is refused. Internal
  invocation without a registered signed request refused with zero simulated
  device opens. This is software-route evidence, not production issuer
  provisioning.
- Manifest source coverage: PASS for the 28 declared source files, including
  live CLI, launcher, supervisor, endpoint, transport, RGB signing and
  orchestrator. All 28 one-byte source mutations were detected. Exact HEAD and
  dirty-tree gates are present.
- Release/handoff verification logic: PASS with test-only generated keys.
  Missing, unsigned, stale, mismatched, replayed, competing-owner, and unknown
  USBFS handoffs were refused before fake transport (zero calls).
- Production release/handoff authority: NOT PROVISIONED. The pinned canonical
  trust template SHA256 is
  `54f448b1b04385c267c20525738195610c96875b056da83ad16bf7f68dc0b019`, but both
  issuer public-key slots are empty. Therefore the production route fails
  closed; test-key success does not establish trusted production authority.
- Supervisor ownership model: PASS as a documented/package model: root-owned
  service, distinct `sidecar-acquire` IPC group, runner dropped to
  `sidecar-fk0957-runner`, root-owned 0700 operation and authorization state,
  root:group 0750 IPC directory, 0660 socket. Real installation was not
  performed or verified.
- Startup: unsupported direct Python/bootstrap routes fail to obtain operation
  authority; the official design uses a static launcher and sanitized
  bootstrap. Harmless environment sentinels do execute in some intentionally
  unsupported Python/venv/PATH routes before refusal. This is not evidence of
  an authority bypass, but it means those routes must remain unsupported and
  the installed launcher boundary remains a deployment gate.
- Signing separation and synthetic seam: PASS. Remote signing/private-key
  transmission code absent; production native factory is fixed; no
  production-importable backend injection seam or synthetic production
  observation path found. Evidence path symlink/hardlink and publication-race
  tests passed.
- Native runtime: libftdi/libusb and the currently pinned loader/libc/libcap/
  libudev/Python binaries matched their pins. The launched Python ELF also
  depends on `libexpat.so.1`, `libm.so.6`, and `libz.so.1`, which are not pinned
  by the launcher/runtime manifest. Complete loader dependency provenance is
  therefore OPEN.
- Documentation consistency: OPEN. `docs/phk2-fk0957-topology-discovery-offline.md`
  still claims the transport source hash remains null until a production
  adapter exists, while the candidate has the production adapter and computes
  a transport source hash.
- Physical transaction invariants: unchanged golden transactions; Scan A 591
  TCK, Scan B 586 TCK, total 1177 TCK.

## Software defect scoreboard

`ORIGINAL_SOFTWARE_DEFECTS_CLOSED=5/8`

1. Startup injection: CLOSED as an authority-bypass defect; unsupported launch
   routes refuse before operation authority. Installed launcher deployment
   remains unverified.
2. Acquisition/signing separation: CLOSED.
3. Bridge ownership binding: CLOSED in verifier logic with test keys; real
   trusted handoff issuer/config and installation remain pending.
4. Complete provenance: OPEN (production trust keys unprovisioned and Python
   dynamic dependency closure incomplete).
5. Synthetic backend/signing seam: CLOSED.
6. Evidence path identity/race: CLOSED by independent adversarial fixtures.
7. Native library provenance: OPEN (Python's libexpat/libm/libz are not pinned).
8. Launch/documentation consistency: OPEN (stale transport-hash statement).

## Disposition

`FINAL_SOFTWARE_HARDENING_AUDIT_PASS=NO`
`READY_FOR_ADMIN_INSTALL=NO` until source/runtime provenance and documentation
blockers are fixed and authenticated production trust material is reviewed.
`REAL_DEPLOYMENT_VERIFIED=NO`
`READY_FOR_LIVE=NO`

Next blocker: pin the complete Python native dependency closure, correct the
stale transport-hash documentation, then provision independently approved
release/handoff issuer keys and verify the real supervisor installation.
