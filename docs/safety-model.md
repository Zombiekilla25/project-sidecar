# Safety Model

Project Sidecar hardware bring-up is fail-closed.

## Principles

- Authenticate the intended bitstream and source/release manifests before programming.
- Bind operations to the expected USB/JTAG/DNA/IDCODE identity.
- Keep recovery ownership independent from the main runtime.
- Keep public submission disabled during transport and sidecar qualification.
- Preserve a known-good rollback image.
- Retain BSCAN/JTAG as an independent recovery path when PCIe is under test.
- Never use global process kills for card recovery.

## Job renewal

Long-running FPGA jobs use bounded renewal.

A valid same-generation renewal is bound to:
- boot identity
- run identity
- lease session
- independent supervisor instance
- exact active hardware generation
- freshness window

The host must not fabricate a new hardware generation just to keep a watchdog alive.

## Recovery

If coordinator ownership or safety supervision is lost:
- stop the scoped runtime
- perform authenticated rollback
- verify device identity after re-enumeration
- disarm the lease only after verified safe recovery
- return the recovery supervisor to an accepting state

## PCIe bring-up

The first PCIe canary should:
- use one card
- avoid flash programming
- avoid HBM dependency
- validate endpoint identity before DMA
- use bounded test buffers
- retain JTAG/BSCAN recovery
- stop before broader fleet deployment if any identity or recovery ambiguity remains
