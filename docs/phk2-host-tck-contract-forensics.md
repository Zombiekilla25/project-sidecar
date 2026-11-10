# PHK2 host TCK contract audit

**Result: the PHK2 host TCK contract is not proven.** The available host worktree has no physical BSCAN, USB, or XVC transport implementation. `tools/phk2_host/board_transport.py` intentionally exposes only the software emulator; `physical_adapter_boundary.py` defines a transport interface but does not discover or open endpoints. The image/CDC qualification records mark the 1 MHz BSCAN clock as an unqualified analysis assumption.

## Findings

| Question | Finding |
| --- | --- |
| Fixed or client-controlled? | PHK2: unknown because its physical host adapter is absent. In the legacy direct FTDI/MPSSE backend, callers pass a requested rate to `synchronize_and_configure`; the identity runner fixes this call to 100,000 Hz. |
| XVC `settck` implemented? | Unknown. Sidecar contains SQRL launch/port-ownership wrappers and opaque bridge references, but not the SQRL bridge source or an XVC request/response trace. Do not assume either implementation or absence. |
| Accepted/returned XVC period? | Not established. No local source or retained response establishes a `settck` value. |
| Current PHK2 default? | Unknown. No physical PHK2 transport exists in the host worktree. Legacy identity-only FTDI runner requests 100,000 Hz. |
| Maximum PHK2 host rate? | Unknown. The separate legacy FTDI backend accepts requested values from 100,000 through 1,000,000 Hz, but that is not a PHK2 limit and is not a measured pin-rate qualification. |
| Minimum PHK2 period? | Unknown. The legacy backend's 1 MHz requested upper bound corresponds to a nominal 1,000 ns period in its 30 MHz MPSSE model. |
| Is 1 MHz enforced for PHK2? | No. The 1 MHz value is an offline timing assumption, not a proven PHK2 host or adapter ceiling. |
| Can Sidecar enforce a limit? | Yes, if the eventual adapter is owned by the guarded Sidecar path and exposes an independently verified effective rate. Preflight now requires proof-backed policy and rate-observation objects before endpoint discovery; it fails closed by default. The passing preflight case in the existing regression uses synthetic-only policy data. |
| Can an external client bypass it? | Not excluded. The legacy scripts can start a SQRL XVC listener, and the bridge implementation is unavailable for audit. Until a proxy/server boundary is proven to enforce the same policy, an external client may bypass a Sidecar-only check. |

The retained successful FK33 BSCAN record is a read-only IDCODE/DNA identity scan configured at 100 kHz; it did not run PHK2 work and does not establish a maximum. The direct MPSSE source computes a divisor from the requested rate and sends the FTDI MPSSE clock command. It does not read back or independently measure the resulting pin rate. Therefore its 1 MHz software request ceiling is narrower evidence than a measured hardware TCK maximum.

## Required later physical/adapter query

Before any PHK2 physical invocation, identify the exact transport implementation and version bound to the selected endpoint. Inspect the SQRL/XVC implementation/configuration or obtain its documented `settck` behavior; issue a non-work `settck` query only under a separately authorized physical qualification procedure, record both requested and returned period, then generate a bounded clock pattern and measure TCK at the adapter pins. If the server does not report an effective period or the pin rate cannot be verified, the PHK2 adapter must refuse. The same max-rate check must sit at the endpoint boundary so a separate XVC client cannot bypass it.

## Offline enforcement added

`tools/phk2_host/tck_contract.py` accepts only a policy with provenance, transport binding, a known maximum, and a verified effective rate. It rejects missing values, values above policy, changed rate after authorization, changed rate after reconnect, and failed verification. Its unit-test maximum is synthetic and explicitly does not define PHK2's limit. The physical preflight gate `tck_contract_valid` defaults false and must be populated only by a future proof-backed adapter.

No physical query, USB access, JTAG/XVC connection, or FPGA operation was performed for this audit.

A source/history search of the available Project Sidecar trees found no `settck` implementation or XVC clock-setting response trace. The Sidecar XVC lifecycle wrapper verifies the bridge process, listener, port, and target binding, but it does not inspect or constrain clock-setting requests. This confirms that the wrapper alone cannot establish an external-client rate ceiling.


The updated host qualification passed 19/19 fail-closed checks and the existing 100,000-event mock stress with zero unexpected failures. TCK boundary tests use a synthetic 1 MHz ceiling solely to test below/at/above behavior; they do not qualify that value for PHK2.
