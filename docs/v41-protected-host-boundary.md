# V4.1 Protected Host Boundary Milestone

_Last updated: 2026-10-28_

## Status

Project Sidecar has reached the protected-host installation checkpoint for the FK0957 V4.1 qualification path.

The integrated candidate is fixture-qualified and the protected production boundary has been installed on the development host. The one-card hardware canary remains deliberately unauthorized and has not been executed.

## Integrated qualification

The integrated candidate combines:

- static native pre-interpreter admission
- fresh environment enrollment
- hash-bound interpreter and candidate identity
- generation and attempt binding
- D01 hash-bound target policy
- three-principal authority binding
- V4.1 two-inventory regeneration transaction
- authenticated rollback and next-start recovery behavior

The current integrated fixture result reports:

- base regression group: **35/35 PASS**
- secondary regression group: **16/16 PASS**
- failure regression group: **644/644 PASS**
- two-output transaction model: **37/37 PASS**
- native-admission adversarial group: **44/44 PASS**
- D01 target-policy checks: **105 PASS**
- prestart/environment checks: **23 PASS**
- refusal-path checks: **17 PASS**
- new integrated failure-injection group: **PASS**
- known bypass paths closed in the fixture model: **5/5**
- placeholder success paths remaining: **0**

The regeneration scope is exactly two inventory outputs. INPUT_AUTHENTICATION is preserved and ACTIVE3 remains unchanged/deferred.

## Protected installation

The protected installation completed successfully with the following public-safe properties:

- candidate file verification: **6,278 files verified**
- static native admission installed
- protected release ownership enforced
- direct unprivileged candidate access denied
- direct unprivileged native-admission execution denied
- no service restart
- no network action
- no FPGA programming
- no JTAG/hardware access
- no mining change
- live project source unchanged

The installation authorization was scoped to the protected host boundary only. It did **not** authorize the FK0957 one-card canary.

## Current gate

The next required milestone is independent qualification of the installed production boundary.

Before any one-card hardware canary:

1. independently verify the installed protected boundary and release identity;
2. verify direct invocation remains denied outside the admitted path;
3. verify the installed production boundary matches the fixture-qualified contract;
4. verify rollback/recovery prerequisites remain intact;
5. obtain a separate explicit owner authorization for the one-card canary.

Until those gates pass, hardware execution remains blocked.

## Scope note

This repository records public-safe architecture and summarized qualification results only. It intentionally excludes protected authorization artifacts, private runtime evidence, machine-specific paths, credentials, vendor binaries, FPGA bitstreams, and other local-only material.
