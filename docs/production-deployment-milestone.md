# Initial Production Deployment Milestone

_Last updated: 2026-11-01_

## Status

Project Sidecar's initial production deployment is **complete**.

The final guarded production transaction committed successfully, the production supervisor/worker runtime started under the qualified privilege boundary, the installed files passed integrity and metadata checks, and a subsequent 15-minute read-only soak remained stable.

This milestone closes the initial deployment phase. It does not authorize new FPGA/JTAG activity or a separately gated hardware canary.

## Public-safe production results

The successful deployment recorded:

- planned production mutations: **60**
- actual production mutations: **60**
- unexpected production mutations: **0**
- installed-file verification: **40/40 PASS**
- production transaction journal: **COMMITTED**
- supervisor startup: **PASS**
- worker startup: **PASS**
- worker privilege drop: **PASS**
- supervisor/worker runtime handoff: **PASS**
- READY handshake: **PASS**
- service crash loop: **not observed**
- rollback triggered on successful deployment: **no**
- emergency rollback path: **retained and qualified**
- shared-ancestor metadata mutations: **0**

The successful deployment followed earlier failure-closed attempts whose rollback paths restored the pre-transaction state. Those failures were treated as qualification findings rather than bypassed.

## Post-install soak

A read-only production soak was run after installation.

Result:

- duration: **15 minutes**
- Sidecar supervisor remained active
- production runtime remained active
- worker remained present
- Sidecar restart counters remained unchanged
- protected-workload process identities remained stable
- supporting service health remained stable
- bridge/listener identity remained preserved
- shared-ancestor metadata remained unchanged
- no files were written or deleted by the soak
- no service restart was requested by the soak
- no FPGA programming occurred
- no JTAG access occurred
- no mining configuration change occurred

Final classification:

**PRODUCTION SOAK VERIFICATION: PASS**

**INITIAL PRODUCTION DEPLOYMENT: COMPLETE**

## Security properties retained

The production milestone preserves the project's fail-closed security model:

- root supervisor and unprivileged worker responsibilities remain separated;
- worker privilege drop is enforced;
- runtime descriptor/handoff validation remains in place;
- authenticated enrollment/release binding remains part of production startup;
- rollback is authenticated and retained;
- pre-existing shared filesystem ancestors are not repurposed by the installer;
- protected workloads are treated as external invariants rather than installation targets.

## Operational baseline

The installed production runtime should now be treated as the known-good Sidecar baseline.

Ordinary future work should prefer read-only observability and narrowly scoped, separately qualified changes rather than reopening the production installer architecture.

Any new hardware execution, FPGA/JTAG access, or canary operation remains separately gated.

## Next engineering milestone

With deployment complete, engineering effort returns to the core Sidecar objective:

1. maintain lightweight production health monitoring;
2. qualify the next safe GPU↔FK33 transport/data-path step;
3. measure real transfer and synchronization overhead;
4. exercise a real GPU-produced PearlHash intermediate through the FK33 path when separately authorized;
5. determine whether the cooperative path produces positive end-to-end throughput improvement.

A Sidecar acceleration result is only successful if the complete system wins after transport, synchronization, scheduling, FPGA work, and return-path overhead are counted.

## Scope note

This document is intentionally public-safe. It excludes private runtime evidence, local host paths and addresses, credentials, private authority material, machine-specific identifiers, proprietary binaries, and FPGA bitstreams.
