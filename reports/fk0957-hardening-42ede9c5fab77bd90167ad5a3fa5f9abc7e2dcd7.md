# Independent review: 42ede9c5fab77bd90167ad5a3fa5f9abc7e2dcd7

This is the latest stable committed SHA at review time; it adds an endpoint authorization-order regression test on top of `7c3f229`. The hardening branch already contains further uncommitted edits, which were not inspected as a candidate. No production/hardening files were changed by this audit. No hardware, testbench SSH, USB, or JTAG occurred.

## Independent results

- Corrected oracle: 28 valid and 249,572 invalid states, zero mismatch; 1,015 additional deterministic state cases.
- Focused endpoint, live CLI, transport, launcher suites: 64 passed when run from the candidate root (the endpoint fixture uses repository-relative paths). Native runtime suite: 188 passed. Candidate transactions remain Scan A 591, Scan B 586, total 1177 TCK with reviewed golden hashes.
- Startup attacks: direct bootstrap accepted a forged `FK0957_TRUSTED_LAUNCHER=1` marker and reached a mocked acquisition boundary. `PYTHONPATH`, sitecustomize, usercustomize, `PYTHONUSERBASE`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, and PATH substitution sentinels ran before unsupported routes refused or completed harmless startup. `/usr/local/bin/fk0957-topology-live-one-shot` is absent. The static launcher tests pass in a temporary fixture, but there is no installed supported entrypoint.
- Permit attacks: a fabricated permit is rejected by public `run_fk0957_topology_discovery` before fake open; wrong-target and expired variants also refuse before open; copied/serialized permit refuses. Public replay and concurrent public consumption each allow one fake open only. In contrast, directly calling importable `_run_consumed_permit` twice with the same fabricated unregistered permit produced two sealed observations and two fake opens while the permit remained unregistered/unconsumed. The local route accepts a fake clean `f…f` HEAD. Operation ID and immutable release authorization are absent from the local route.
- Endpoint: no signing private key or signing imports. The default empty trust pin returns `ISSUER_PINS_NOT_PROVISIONED` with zero transport calls. A fully synthetic signed fixture validates; the durable ledger consumes one request, rejects replay, and calls mocked transport once. All four endpoint-manifest source tamper cases, native-pin tamper, and wrong current HEAD refuse; 48 malformed top-level type cases refuse with no escaping exception. The endpoint does not have an RGB result consumer at this SHA.
- Handoff values: unsigned/mutated owner, state, operation, and target inputs refuse. A handoff signed by the configured test authority with arbitrary bridge executable hash, client, or lane values is accepted as an issuer assertion; there are no local expected-value pins or live ownership observation. In production the trust pins are empty, so no such signed request can currently be used. This remains an authority-policy dependency that needs explicit review.
- Additional endpoint attacks: operation mismatch, wrong card/adapter/USB serial/VID/PID/interface, stale/active handoff, unknown/competing USBFS ownership, source-file tamper, native pin tamper, wrong current HEAD, authorization replay, and 48 malformed top-level type substitutions. They refused as expected. A fully signed fixture request with a fake transport acquired once, then replay refused before a second transport call.
- Provenance/docs: endpoint manifest covers four endpoint-side source files, but no RGB orchestration consumer. Local transport hash covers only transport/discovery/ID gate, excluding live CLI and signing module; it computes from any clean HEAD rather than an immutable expected release pin. The offline document still claims transport source hash is null although the implementation computes it.
- Existing campaign: 120 orderings select the exact target and 120 duplicate-target permutations refuse; 10,000 malformed envelope cases and filesystem publication/path attacks pass; native runtime pins match locally; no device enumeration was called.

## Acceptance status

`STARTUP_TRUST_BYPASS_POSSIBLE=YES`

`FABRICATED_PERMIT_ACCEPTED=NO` through the public route; `UNREGISTERED_PERMIT_ACCEPTED=YES` through the internal helper.

`PERMIT_DOUBLE_CONSUMPTION_POSSIBLE=YES` through direct internal transport; `DIRECT_INTERNAL_TRANSPORT_BYPASS=YES`.

`HANDOFF_AUTHORITY_PASS=NO` for readiness: the endpoint relies on an unprovisioned issuer pin, accepts issuer-asserted ownership fields, and has no RGB orchestration integration. `FULL_PROVENANCE_PASS=NO`. `DOCUMENTATION_CONSISTENCY_PASS=NO` due stale null-hash claim.

No complete hardened candidate declaration was present. This candidate is not ready for live use.
