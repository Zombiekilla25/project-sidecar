# Hardware Priority and Idle Fallback

Project Sidecar has exclusive first priority over FPGA hardware.

An operator may run a local fallback workload while hardware is otherwise idle. In the current development environment, XBT mining is used for that purpose as a private/test workload. XBT is **not** a Project Sidecar dependency, feature, benchmark target, or production requirement.

## Ownership rule

The hardware ownership contract is:

1. **Sidecar claim** — before any real USB/JTAG/programming/canary action, Sidecar claims the affected hardware resource.
2. **Fallback preemption** — any fallback workload mapped to that resource must stop and fully release its worker/bridge ownership before Sidecar proceeds.
3. **Sidecar exclusive ownership** — while the claim is present, fallback workloads must remain stopped.
4. **Sidecar release** — after the hardware operation finishes, including required rollback/recovery verification, Sidecar releases the resource.
5. **Idle grace period** — the resource remains idle for a short guard interval.
6. **Fallback resume** — only after the guard interval, and only when its own backend is healthy, may the operator-local fallback workload resume.
7. **Fail closed** — ambiguous ownership, stale state, failed recovery, failed authentication, or an unhealthy fallback backend leaves the hardware idle rather than allowing concurrent access.

## Scope

Claims should support card, pod, and global scope so a single-card canary does not unnecessarily preempt unrelated hardware while pod-level experiments can reserve coordinated devices together.

Offline simulation, root-namespace qualification, static analysis, and other work that does not access physical FPGA hardware do not require a hardware claim.

Recovery/watchdog processes that are intentionally always present are not, by themselves, evidence that Sidecar currently owns a card. Ownership must be represented by an explicit claim or an equivalent authenticated hardware-operation state.

## Local fallback example: XBT

The development operator currently uses XBT mining to avoid leaving otherwise-idle FK33 hardware unused.

This fallback is intentionally subordinate:

- Sidecar may preempt it at any time.
- XBT must not initiate or retain hardware ownership while a Sidecar claim exists.
- XBT-specific pool, wallet, LAN, serial-number, service, and machine configuration remains local/private and is not part of this repository.
- Sidecar qualification results must never depend on XBT being installed or available.

This keeps the repository focused on GPU + FPGA cooperative compute research while still allowing the development hardware to do useful work between Sidecar hardware tests.

## Safety invariant

**At most one hardware owner may exist for a resource at a time.**

If the arbiter cannot prove that Sidecar is released and the fallback is safe to start, the correct state is idle.
