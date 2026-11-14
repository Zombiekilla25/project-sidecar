# FK0957 independent adversarial audit: a1c9b4b

Scope: exact hardening SHA `a1c9b4b11d7755807a47f8a24f7e06b9df657da6` in its fresh detached worktree. Offline only: no production modification, testbench SSH, USB/JTAG, or hardware.

## SHA, lineage, watcher

- Parent: `5aea8812129570c8e0f59b3662f5abd3e4001408`.
- Subject: `Add operator runtime manifest verifier`.
- Remote ref and hardening checkout advanced to a1c9; watcher remained running and had already created a fresh detached worktree for it.
- No `COMPLETE_HARDENED_CANDIDATE` declaration was present.

## Permit identity continuity

The endpoint/transport implementation is unchanged from the audited 5aea path. Independent simulated endpoint execution carried authorization ID, operation ID, descriptor SHA, and nonce through the permit, transport result, and unsigned record. Mutated permit identity fails before backend reach; replay and parallel-use tests restrict the authorization to one transport execution. **Permit identity continuity: CLOSED for the tested simulated route.**

## Runtime manifest and new verifier

The endpoint release inventory is now 28 files, adding `tools/phk2_host/verify_fk0957_runtime_manifest.py` to the 27-file inventory from 5aea. It includes the live CLI, transport, supervisor/client, launcher/bootstrap/builder, endpoint, observer, collector, RGB signer/orchestrator, evidence schema, transaction profile, and the verifier. A fresh manifest built from a clean candidate tree listed all 28. Independent one-byte mutations of all 28 paths each refused with `RUNTIME_SOURCE_HASH_MISMATCH`.

The runtime inventory has seven pinned objects: Python 3.12, the dynamic loader, libc, libcap, libftdi, libudev, and libusb. Python 3.12's `DT_NEEDED` set also includes libexpat, libm, and libz; those three remain unpinned. The new verifier validates a signed manifest and exact source/runtime inventory, but no authorized signed production manifest or issuer key set is provisioned. Thus declared source coverage is materially improved, while **complete authenticated runtime provenance remains OPEN**.

The prior campaign's transport-local hash still omits the CLI and is only a subset digest. The signed release manifest is the broader source-set mechanism; the transport hash must not be presented alone as complete provenance. The independent campaign's earlier 12-path equality check was corrected in the audit harness: the 12 paths are now a required subset of the expanded release set, with full inventory existence and actual issuer-key material checked separately.

## Trust and handoff authority

The pinned trust-template hash matches its exact canonical bytes (`54f448b1…dc0b019`), but the template has empty release and handoff key slots. `TRUST_CONFIG_SHA256` is nonempty because it pins this non-production template; it does not establish an issuer. The endpoint rejects empty/non-32-byte Ed25519 keys. The new runtime verifier therefore cannot authenticate an operational production manifest yet. **Trusted release authority: FAIL / not provisioned.**

The updated broad acceptance corpus passed. It used disposable generated signing keys to test signed handoff binding/refusal for missing or unsigned handoff, stale handoff, bridge hash/state, clients, lanes, operation mismatch, unknown/competing USBFS ownership, and replay. Refusals produced zero fake transport calls. This validates parser and binding logic; it does not prove deployed trust-root or bridge ownership. **Trusted handoff authority: FAIL operationally.**

## Supervisor and startup package

A disposable-root rehearsal returned `FK0957_SUPERVISOR_STAGE=PASS`, and the staged launcher is static ELF with no `PT_INTERP`. The standalone static-launcher hostile environment test passed for LD_PRELOAD, PATH, PYTHONPATH, PYTHONHOME, and user-site/customize sentinels. The staged launcher itself refused with code 126 before Python and ran no preload sentinel because the corresponding absolute production bootstrap and manifest files are not installed. Therefore the staged binary did not exercise a successful installed startup route.

The package stage verifier checks file type, content, link count, mode, and static ELF form, but not staged UID/GID. In the actual disposable root, the status/authorization state directories were mode 0700 and owned by UID 1000 (the ordinary invoking user); that user could write/replace those directories. The stage test asserts modes/content only. The installed verifier requires root ownership, but the real installed package is absent and privileged apply is not implemented. **Supervisor trust boundary: FAIL.**

Direct Python/CLI/bootstrap sentinel tests still execute harmless payloads before the untrusted process refuses. The static supported-launcher test blocks those payloads, but the approved launcher is not installed at its reviewed path; only a staging build was available. **Startup trust/deployment: OPEN.**

## Independent results

- Corrected oracle: 28 valid and 249,572 invalid states; zero mismatches; 1,015 additional cases.
- Candidate-focused suite: 67 passed.
- Independently rerun release-manifest, launcher, and supervisor-package tests: 14 passed.
- Independent campaign rerun: broad handoff acceptance passed; 20,000 malformed records produced zero escaped exceptions or unsafe/noncanonical outputs; 120 unique-target enumerations selected and 120 duplicate-target enumerations refused.
- 28/28 source tamper cases refused.
- Native pin preflight passed for the listed pins, but unpinned Python dynamic dependencies remain.
- Scan A/B/total unchanged at 591/586/1177 TCK; golden hashes remained `81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2` and `08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a`.

## Recalculated original eight-class scoreboard

1. Startup injection: **OPEN** — supported static launcher fixture blocks injection, but deployed launcher is absent and direct startup payloads execute before refusal.
2. Acquisition/signing separation: **CLOSED in reviewed code** — remote endpoint emits unsigned records, has no signing protocol/key, and RGB performs validation then local signing.
3. Bridge ownership binding: **OPEN operationally** — signed claim binding tests pass with fixture keys; real authority and ownership state are not provisioned/observed.
4. Runtime/source provenance: **OPEN** — 28 declared sources tamper-check, but no production issuer/signed manifest and three Python dynamic dependencies are unpinned.
5. Synthetic backend/signing seam: **CLOSED for production route** — no production-importable fake backend injection/signing path; the fake transport is a test fixture.
6. Evidence path identity/races: **CLOSED for tested attacks** — existing path and publish race corpus refuses replacement/overwrite.
7. Native library pin: **OPEN** — seven listed native/runtime objects are pinned, but libexpat, libm, and libz in Python's dynamic dependency set are not.
8. Launch/documentation consistency: **OPEN** — staging reports PASS without ownership validation; real installed verification/deployment has not run.

Score remains **3/8**. Permit identity continuity is an additional finding and closed in the simulated route. The staging verifier's omission of UID/GID remains a concrete audit defect in the rehearsal's ownership claim; it does not prove the absent real installation is vulnerable, but it cannot be used to claim the intended boundary.
