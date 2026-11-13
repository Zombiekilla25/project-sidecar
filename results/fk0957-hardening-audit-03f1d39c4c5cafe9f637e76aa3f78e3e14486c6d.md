# Independent FK0957 hardening audit — `03f1d39c4c5cafe9f637e76aa3f78e3e14486c6d`

Audited in a fresh detached worktree on 2026-11-13. No production modification, testbench SSH, network, USB, or hardware access occurred. No `COMPLETE_HARDENED_CANDIDATE=<sha>` declaration exists in this commit.

## Candidate delta

This commit adds a documented SSH agent trust boundary, refreshes the handoff snapshot and randomized-case count, and changes only the remote orchestrator docstring. The code acknowledges that a malicious process with the authenticated RGB UID can race the pathname-based agent socket after the final check; that UID is inside the declared trust boundary. OpenSSH forwarding remains disabled. The tested behavior and physical transaction are unchanged from `b76179de...`.

## Results

- Corrected independent oracle: **PASS**, 28 valid states and 249,572 invalid states; zero mismatches; 49 focused tests pass; 1,015 additional adversarial cases.
- Independent acceptance/campaign: **PASS as harnesses**. Open security gates remain open as listed below. Acceptance generated 20,000 malformed cases; long-run campaign generated 10,000 more, with 120 target orderings and 120 duplicate-target orderings.
- Native runtime: **PASS for pinned libraries**, 187 tests pass in a temporary candidate copy, and no USB enumeration or FTDI context creation occurred. Pre-start loader trust remains open.
- Diff check: **PASS**.
- Transactions unchanged: Scan A 591 TCK, Scan B 586 TCK, total 1,177. Golden transaction hashes remain A `81f0fb9eefad365e50d8cdbe855274bdf408104158ac193a50798e0aaba778f2`; B `08534f71229a30798c82cc7518a934ada0113d38ba351ddb577ddd02a845336a`.
- The forged launcher environment still permits an `LD_PRELOAD` constructor to execute before bootstrap refusal. The missing-handoff/owner attack cases still reach the acquisition boundary. The internal `_run_consumed_permit()` test still accepted the same fabricated unregistered permit twice using fake transport, returning two sealed observations without registering or consuming the token.

## Per-SHA status

`DEFECT_1_STARTUP_INJECTION=OPEN`
`DEFECT_2_ACQUISITION_SIGNING=OPEN`
`DEFECT_3_BRIDGE_OWNERSHIP=OPEN`
`DEFECT_4_RUNTIME_PROVENANCE=OPEN`
`DEFECT_5_SYNTHETIC_SIGNING=CLOSED at explicit backend API boundary`
`DEFECT_6_EVIDENCE_PATH_RACE=CLOSED for tested cases`
`DEFECT_7_NATIVE_LIBRARY_PIN=OPEN` (dynamic loader not enforced pre-start)
`DEFECT_8_LAUNCH_DOCUMENTATION=OPEN`

`NEW_DEFECTS=unconsumed internal transport entrypoint permits repeated acquisition`
`VALID_STATE_REJECTED=0`
`INVALID_STATE_ACCEPTED=0`
`READY_FOR_LIVE=NO`

At the time of this audit, the hardening worktree later became dirty (launcher source deleted after this commit). That uncommitted state was not audited or modified. The watcher tracks committed HEADs only.
