# PHK2 physical-image intake and one-card precheck

## Qualification manifest

The machine format is
docs/schemas/phk2-physical-image-manifest-v1.schema.json. Each package has
manifest.json, its adjacent manifest.sha256, the source snapshot, XDCs,
synthesis/routed checkpoints, bitstream, and evidence/ reports plus an
evidence file-hash manifest. The record binds the source commit and recomputed
tree digest, top/part/Vivado/clock, artifact hashes (optional LTX), protocol and
descriptor versions, board/adapter compatibility ID, synthesis/implementation/
route/DRC/CDC/clock/hold statuses, WNS/TNS, unsafe CDC and unconstrained
endpoint counts, Gray-pointer/reset CDC decisions, independent qualification
commit/harness hash, timestamp, and evidence hashes.

Intake requires a caller-supplied expected manifest SHA, expected source and
independent qualification commits, qualification-harness hash, board/adapter
compatibility ID, FPGA part, and protocol version. The caller must obtain these
trust anchors independently of the candidate directory. The adjacent digest
detects accidental changes; the external expected digest prevents a changed
manifest and changed adjacent digest from being silently accepted. Intake
recomputes source-tree, checkpoint, bitstream, XDC, and evidence hashes. Paths
must stay inside the package and symlinks are rejected. Only literal PASS
qualifies a gate; UNKNOWN, NOT_RUN, missing, negative timing, nonzero
unsafe-CDC, or unconstrained endpoint counts refuse the package. Manifests older
than 30 days or with future timestamps refuse by default.

The command is offline and emits a boolean result plus reasons:

    tools/phk2-image-intake PACKAGE \
      --expected-manifest-sha256 SHA256 \
      --expected-source-commit SHA1 \
      --expected-qualification-commit SHA1 \
      --expected-qualification-harness-sha256 SHA256 \
      --expected-board-compatibility-id ID \
      --expected-fpga-part xcvu33p-fsvh2104-2-e \
      --expected-protocol-version 1

The tests build synthetic packages in temporary directories. Even when every
synthetic qualification field is marked PASS, intake keeps
physical_image_qualified=false.

## One-card precheck

tools/phk2-canary-precheck defaults to metadata-only dry-run. It does not
discover endpoints. The expected target identifier is configured as FK0957
metadata, not read from a card. The check requires a physically qualified
intake result bound to the expected manifest and candidate SHA; host and
adapter-boundary readiness; a fresh, single-use authorization bound to image,
manifest, and configured target; exactly one card; peer exclusion; rollback,
recovery, and evidence readiness; and matching protocol version. The live path
is intentionally compiled disabled in this worktree. --live always refuses
before endpoint discovery or adapter import while
PHYSICAL_QUALIFICATION_AVAILABLE=false.

No real PHK2 bitstream or physical qualification package is included by this
work. No package in the synthetic test suite is a live candidate.
