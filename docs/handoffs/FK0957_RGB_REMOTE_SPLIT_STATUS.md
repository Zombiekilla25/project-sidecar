# FK0957 remote acquisition and RGB signing WIP

This note records the offline implementation milestone on the hardening
branch. It is not production authorization and does not permit a live read.

## Implemented path

The testbench endpoint is `phk2_fk0957_remote_topology_endpoint.py`. Its fixed
entrypoint accepts one canonical request, verifies signed release authorization,
handoff and runtime manifest records, consumes a durable authorization ledger
entry before transport acquisition, invokes one fixed topology transaction,
and emits an unsigned result. It has no signing import or arbitrary vector
interface.

The RGB entrypoint is `phk2_fk0957_topology_rgb_cli.py`, selected by the safe
bootstrap. It uses the pinned SSH policy with `ForwardAgent=no`, keeps the
validated agent socket in the local SSH child environment, validates the
returned unsigned record and raw TDO locally, signs on RGB, verifies the signed
envelope and atomically publishes evidence. Refusals and SSH timeouts do not
sign or publish; timeout means remote state is unknown and must not trigger
ownership restoration. The prior combined local acquisition/signing API now
fails closed.

The fixed transaction remains Scan A 591 TCK, Scan B 586 TCK, total 1177 TCK.
No physical operation was run for this milestone.

## Offline checks

At the current implementation milestone, FK0957 test discovery passed 223
tests, followed by 20 complete FK0957 suite runs under `PYTHONHASHSEED=1..20`
(4,460 test executions). The corrected independent state oracle was rerun
against the hardening candidate: 28 valid states accepted, 249,572 invalid
states rejected, zero mismatches. The safe-launcher suite passed 5 tests and
Python compileall plus `git diff --check` passed. No physical transport was
opened.

## Remaining deployment gates

This code is intentionally non-operational until the following trusted
deployment inputs and integration work exist:

* `TRUST_CONFIG_SHA256` in the remote endpoint is empty. The protected release
  and handoff issuer public-key pin file and corresponding administrator-held
  issuer keys have not been provisioned. The endpoint therefore refuses before
  transport open.
* The runtime-manifest payload builder now enumerates the RGB launcher,
  bootstrap, SSH policy, both CLIs, RGB orchestrator/signer, remote endpoint,
  transport, observer/identity gate, and discovery source hashes, plus native
  runtime pins and the fixed transaction profile. The RGB checkout verifies
  the full source set; a checkout-free testbench bundle verifies its deployed
  source subset against the same signed manifest. However, the trust-file pin
  is still empty, so no issuer-signed manifest is accepted in production.
* The reviewed maintenance authority has not been integrated as a trusted
  handoff issuer. Caller-supplied bridge state is not an authority.
* There is no remote supervisor/status protocol that proves the acquisition
  process exited after SSH loss. The RGB path fails closed and requires manual
  recovery; it cannot automatically restore shared USB ownership.
* The administrator-owned static launcher and protected `/etc` and `/var/lib`
  layouts still require deployment on the RGB and testbench hosts.
* Before Python starts, the static launcher pins the interpreter, loader,
  native libraries, and bootstrap bytes. It does not yet pin every imported
  application module before Python imports them; administrator-owned immutable
  install paths and a pre-start full-source-manifest check remain required.
* The production paths are not installed in this environment: the issuer trust
  file, authorization ledger, endpoint executable, and RGB launcher are all
  absent. The authenticated endpoint cannot be used until these protected
  administrative artifacts are provisioned and reviewed.
* Left's latest operations candidate `a6b2cb30ca6e93cce597f3ef609f77d0cc8f2302`
  was reviewed but not integrated wholesale: its cleanup path does not prove
  the remote child has exited before restoration, and its handoff does not
  provide the missing pinned issuer authority.

Production main was not modified. No SSH to the testbench, network acquisition,
USB, JTAG, bridge/client action, or hardware access occurred.
