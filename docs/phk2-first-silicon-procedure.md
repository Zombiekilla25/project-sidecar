# PHK2 first-silicon procedure

This procedure is a host handoff. Do not enable a physical transport until the image has an independently recorded physical qualification and explicit device identity.

1. Archive the image, bitstream SHA-256, source commit, toolchain, board identity, clock and tile count. Bind those values to `target_image_identity` in Evidence-v1.
2. Select the PHK2 transport adapter behind the existing interface. Preserve the PHK1 backend as the default and rollback target. Confirm adapter identity and a read-only attach/identity check before commands.
3. Load a retained authoritative 112-byte descriptor and require its exact generation acknowledgement. Start one 64-coordinate range; retain every STATUS response and generation.
4. Read the complete compact result set. Reject duplicates, missing slots, mismatched range IDs and stale generations. Abort on a protocol error; do not retry a command with ambiguous transport progress.
5. Run `phk2-host oracle --input descriptor.bin --start 0 --count 64` for each qualified range, compare raw compact bytes and canonical transcript bytes, and retain all mismatch details.
6. Capture separate monotonic timings for host packing, descriptor transfer, FPGA work, result transfer, host verification and total elapsed time. Keep every component measured; never derive FPGA timing from a mock.
7. Write an Evidence-v1 manifest and a Benchmark-v1 record. Capture power only when supplied by a calibrated measurement source. Ingest matching PHK1 first-silicon records and PHK2 records with the comparison reporter.
8. On any identity, generation, result, timeout, device or CPU mismatch, stop PHK2 and roll back to PHK1. Preserve the failed evidence bundle.

No PHK2 silicon measurement is present in this worktree. The first run must remain gated on independent image and board qualification.
