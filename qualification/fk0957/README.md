# FK0957 fresh-tree release qualification

This directory qualifies production source at
`3226bfc1474d6afa873fce7327ded6dac548baae`. It is an audit artifact in a
separate detached worktree; it does not change or advance that production
commit. No test in this qualification opens libftdi or USB, and there is no
SSH or network test.

## Exact offline commands

From the repository root, with the system interpreter used for this run:

```sh
python3 --version
python3 -c 'import cryptography; print(cryptography.__version__, cryptography.__file__)'
python3 -m unittest discover -s tests/reference -p 'test_fk0957_topology_state_model.py'
python3 -m unittest discover -s tools/phk2_host -p 'test_*fk0957*.py'
python3 -m compileall -q tools/phk2_host
git diff --check
python3 qualification/fk0957/build_release_manifest.py
sha256sum -c qualification/fk0957/RELEASE_CANDIDATE_MANIFEST.json.sha256
```

Repeat the unittest, compileall, and diff-check commands three times for the
recorded qualification cycles. The FK0957 suite contains the complete
corrected state-model corpus, transport, refusal, CLI/evidence, enumeration,
permit/replay, and library-pin tests. Its seeded regression runs 20 fixed
seeds; each seed checks 20 randomized peer-device orderings and shuffles 15
fault-injection tests. No `PYTHONPATH`, user-site package, temporary source,
or prior implementation worktree is required.

The exact independent model, its own tests, and the audit harness are
preserved byte-for-byte in `../../tests/reference/` from model commit
`ea2104c55a1d4dafe6da91c6d5ac28447ec336c1` and audit-harness commit
`c7c1f7fd015149c3ce60a1401bb50682153b8c48`. The release test adapter maps
each model scan stage to the production validator's granular operation-state
name and each cleanup history to its actual prior state. It does not modify
the oracle model. The separate audit helper's older quick-check projection
uses a coarse scan-active name and is not used for this corrected comparison.

## Dependencies observed in the fresh tree

- Interpreter: `/usr/bin/python3`, Python 3.12.3.
- FK0957 runtime and test dependency: `cryptography` 41.0.7 from the system
  Python distribution.
- Other modules imported by this path are Python standard-library modules.
- Repository-wide `requirements.txt` also lists `blake3`; the FK0957 focused
  modules do not import it. This fresh interpreter does not have `blake3`,
  and the full host-tool suite is outside this FK0957 qualification command.
- Physical execution, when separately authorized, additionally requires the
  absolute-path native library pins listed in the release manifest. The ABI
  tests load the approved shared-library objects and bind function prototypes,
  but never call libftdi/libusb discovery or open functions. There is no device
  handle, USB transaction, or JTAG clock in this qualification.
- Host-key provenance is taken from the checksum-verified tracked handoff
  manifest. Rebuilding this release manifest does not require the operator's
  home directory or access to the local known-hosts file.

## Runtime dependency inventory

| Classification | FK0957 paths and role |
| --- | --- |
| PRODUCTION | `phk2_fk0957_topology_live_cli.py`, `phk2_fk0957_topology_transport.py`, `phk2_fk0957_topology_discovery.py`, and `phk2_fk0957_idcode_gate.py`: local one-shot descriptor-bound topology operation. `phk2_fk0957_remote_orchestrator.py` supplies canonical serialization and hardened paths imported by this CLI. |
| PRODUCTION | `phk2_fk0957_identity_observer.py`, `phk2_fk0957_readonly_backend.py`, and `phk2_fk0957_remote_collector.py`: separately scoped remote descriptor-only acquisition chain. |
| PRODUCTION | `phk2_fk0957_ephemeral_bundle.py` and `phk2_fk0957_ephemeral_runner.py`: pinned bundle builder and remote isolated runner used by the remote orchestrator. |
| PRODUCTION | `/usr/bin/ssh` and the dedicated `fk0957-testbench-known_hosts` pin are external dependencies of the separate remote descriptor acquisition path. No SSH process is started by this qualification. |
| TEST_ONLY | `test_phk2_fk0957_*.py`, this release oracle/seed test, and the two `tests/reference/` inputs. `phk2_fk0957_ephemeral_stage_diagnostic.py` is exercised only by its diagnostic test and is not imported by a production entry point. |
| DOCUMENTATION | FK0957 runbooks, canary/evidence schemas, candidate planning records, and this release qualification manifest. These files do not execute. |
| HISTORICAL | `docs/phk2-fk0957-idcode-offline-qualification.md` is explicitly marked superseded. Its old 87-TCK IDCODE proposal and `/tmp/sidecar-raw-id-build/raw-jtag-identify` string are not current commands. |
| DEAD | No FK0957 runtime file was classified as dead after checking import and execution references. The diagnostic module is test-only, not an active production dependency. |

The exact test-only source paths are `tools/phk2_host/test_phk2_fk0957_ephemeral_stage_diagnostic.py`, `test_phk2_fk0957_idcode_gate.py`, `test_phk2_fk0957_identity_observer.py`, `test_phk2_fk0957_readonly_backend.py`, `test_phk2_fk0957_remote_collector.py`, `test_phk2_fk0957_remote_orchestrator.py`, `test_phk2_fk0957_topology_discovery.py`, `test_phk2_fk0957_topology_libraries.py`, `test_phk2_fk0957_topology_live_cli.py`, `test_phk2_fk0957_topology_transport.py`, and `test_fk0957_release_oracle.py`.

The exact documentation and policy artifact paths are `docs/phk2-fk0957-idcode-offline-qualification.md`, `docs/phk2-fk0957-topology-discovery-offline.md`, `ops/phk2/PHK2_FK0957_CANARY_CONFIG.json`, `ops/phk2/PHK2_FK0957_CASE_B_CANDIDATE_METHOD.json`, `ops/phk2/PHK2_FK0957_CASE_B_METHOD_SCHEMA.json`, `ops/phk2/PHK2_FK0957_CASE_B_QUALIFICATION_OWNER_INPUT.json`, `ops/phk2/PHK2_FK0957_CASE_B_QUALIFICATION_SPEC.json`, `ops/phk2/PHK2_FK0957_EVIDENCE_SCHEMA.json`, `ops/phk2/PHK2_FK0957_PREPHYSICAL_CHECKLIST.md`, `results/phk2-physical-canary/PHK2_FK0957_CANARY_PLAN.json`, and `results/fk0957-topology-software-handoff.json` with its `.sha256` sidecar.

The local topology CLI does not import the test suite or oracle. The remote
descriptor chain is a separate CLI path and does not call the local topology
transport. The maintenance-controller reference in the manifest is a
separate, non-integrated source reference; it is not imported, executed, or
needed by this offline qualification.

The CLI comparison found one handoff wording error: the production topology
document says the success summary has four zero mutation counters, while the
actual summary has three zero counters and `jtag_operation_count=1`. This is
recorded in the manifest; the production document is left untouched until
Right's audit finishes.

## CLI/report consistency

The prepared CLI command and success/refusal/reporting-fault formats are
documented in `docs/phk2-fk0957-topology-discovery-offline.md`. The local CLI
requires descriptor evidence and a new output path; it has no scan, device,
library-path, or retry override. This qualification does not issue a permit
and does not run the CLI against a device.
