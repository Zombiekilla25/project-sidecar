# Sanitized public diff review

Review scope: public `main` at `976ebbb` to the files prepared in this branch.

## Proposed changes

- Replace the README's detailed deployment and qualification inventory with a concise architecture, software status, experimental FPGA status, qualification boundary, limitations, and next-work summary.
- Add a public-safe PHK1 milestone draft, an unreleased changelog entry, release-candidate notes, and a public/local gap inventory.
- Add ignore rules for generated build output, FPGA files, raw traces, local evidence, credentials, and local/vendor license artifacts.

The public update is documentation and repository hygiene only. It contains no private evidence, hardware identity values, raw traces, bitstreams, or local live-runner code. The unsafe local v2 commits are not ancestors of this branch.

## Checks

- Changed-content leak scan: PASS; no IP addresses, numeric serial values, DNA values, USB topology paths, wallet addresses, credential assignments, private absolute paths, or binary artifacts were found in proposed files.
- Ignore probes: PASS for FPGA outputs, traces, evidence directories, environment files, and local license artifacts.
- Python offline tests: 4/4 PASS.
- Native MPSSE mock suite: 18/18 PASS.
- Native USB selection mock suite: 7/7 PASS.
- `git diff --check`: PASS.

No package manifest or root build target exists on public `main`. The available package tests were run directly. The FTDI context lifetime fixture could not be built in this environment because the libftdi1 and libusb development packages are unavailable; it does not contact hardware.

## Disposition

PASS for this sanitized documentation-only diff. The local candidate-aware lock implementation remains a source-code gap and needs a synthetic-identity public extraction and review before it is included in a future software package.
