# Release-candidate notes draft

Status: draft for a future Sidecar Miner release candidate. No release or tag has been created.

## Summary

This documentation milestone records offline PHK1 diagnostic-runtime reliability work and PHK2 production-work-generation/core RTL progress. It also reports an initial PHK2 VU33P synthesis resource measurement and the resulting move toward sequential work generation.

## Qualification and limitations

The PHK1 launcher and target-host fixtures are software-qualified, but PHK1 physical protocol qualification is still open. A previous silicon tile-0 error remains unresolved, and a later fail-closed preflight blocked before FPGA programming because diagnostic evidence/attestation integration did not match the required identify-phase contract.

PHK2 production operand and core RTL checks passed within their documented offline scope, including the tested batch-64 flow. Initial PHK2 synthesis completed, but timing analysis and routing did not. No PHK2 bitstream or silicon result is claimed. Neither project has a demonstrated end-to-end acceleration result.

## Package contents

This update contains public-safe status and milestone documentation only. It contains no FPGA images, raw hardware traces, private evidence bundles, credentials, or private runtime binaries.
