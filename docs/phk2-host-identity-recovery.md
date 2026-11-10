# PHK2 host identity, recovery, and evidence contract

This contract is host-side policy and mock qualification. It does not discover
endpoints or implement a physical transport.

## Identity

`CardIdentity` records the configured logical card name; FPGA family; board and
carrier identity; stable transport/device identity; JTAG identity when
available; protocol identity; loaded-image label and immutable SHA256; current
session ID; and an endpoint locator for diagnostics. The endpoint locator is
transient and is excluded from the durable card key. Enumeration order, USB
path, XVC address/port, and a cached endpoint are never identity evidence.
Reconnect requires the same durable card key and image/protocol binding, plus a
new session ID. Any mismatch refuses the session.

## Recovery state graph

The machine begins at `PRECHECK` and may only advance through `IDENTIFY`,
`OPEN`, `HELLO`, `READY`, `WORK_SENT`, `RESULT_PENDING`,
`RESULT_RECEIVED`, and `CLOSE`. `ABORTING`, `DISCONNECTED`, `RECOVERING`,
`ROLLBACK_REQUIRED`, `ROLLBACK_COMPLETE`, `QUARANTINED`, and `FAILED_CLOSED`
are explicit recovery states. The authoritative edge table is `EDGES` in
`tools/phk2_host/transaction_safety.py`; all omitted edges are illegal. In
particular, no disconnect, timeout, restart, or ambiguous I/O path can jump to
`READY`. Ambiguous work delivery requires reconciliation; it is never retried.
Rollback is legal only from `CLOSE`, `ABORTING`, or `DISCONNECTED`, and a
successful rollback terminates through `CLOSE`/`FAILED_CLOSED`.

## Exactly-once and crash rules

The journal fsyncs each JSONL record and its containing directory. Each row is
SHA256 chained to its predecessor. `transaction_created` reserves unique
evidence/work/session identifiers. `work_send_begin` means the request may
have reached the device; after that point a crash is `MAY_HAVE_BEEN_SENT`
unless a durable acknowledgement/result proves `DEFINITELY_SENT`. A result is
bound to transaction, work ID, session ID, image SHA, and response hash. A
verified result becomes `RESULT_VERIFIED`; duplicate/stale or mismatched
results refuse. On restart the ledger rebuilds uniqueness fences from the
journal. A truncated or altered journal fails closed.

The journal event fields support image manifest/hash, expected and observed
identity, authorization state/token reference, session/work/evidence IDs,
request/response hashes, timestamps, transitions, errors, recovery actions,
and terminal disposition. Secrets should be represented by a non-reversible
authorization reference/hash, not copied into public logs.

## Qualification

Run from this worktree:

```sh
PYTHONPATH=tools/phk2_host python3 tools/phk2_host/qualify_transaction_safety.py
```

This suite uses synthetic identities and temporary local journals only. Passing
it qualifies the software model, not a card, endpoint, physical adapter, image,
rollback, or mining-workload recovery on hardware.
