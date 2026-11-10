# PHK2 host identity and recovery readiness

Offline/mock-only qualification; no physical endpoint discovery or hardware I/O occurred.

- Durable identity model: PASS (8/8)
- Recovery edge matrix: PASS (256/256 legal and illegal transitions checked)
- Work/session/result continuity: PASS (15/15)
- Crash/journal reconciliation: PASS (5/5)
- Deterministic combined-fault scenarios: PASS (64/64)
- Physical access / program / HELLO counts: 0 / 0 / 0

## Durable identity

The model binds configured logical card, FPGA family, board/carrier, stable transport/device identity, JTAG identity when available, protocol, loaded image label and SHA256, and session. The transient endpoint locator is recorded for diagnostics but excluded from durable identity. Reconnect requires the same card and image/protocol identity and a fresh session. Endpoint reordering and disappearance/reappearance do not establish identity by themselves.

## Recovery and continuity

Every declared state edge and every omitted edge was checked. Ambiguous delivery cannot return to READY. The append-only journal is fsynced and hash chained. A send-begin record reconciles as MAY_HAVE_BEEN_SENT until acknowledgement/result evidence makes delivery definite; it is never retried. Work, session, and result uniqueness fences reconstruct from the journal after restart.

## Host-side blockers remaining

- A real routed PHK2 image and its independently verified qualification package are required before image intake can pass.
- Authorized physical access is required to qualify the real card identity/adapter binding and verify PHK2 rollback/recovery and workload continuity on the physical system.

Everything in this change is a software model. It does not qualify a routed image, physical adapter, card identity, rollback, or workload continuity on silicon.
