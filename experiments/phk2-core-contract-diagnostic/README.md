# PHK2 core-contract diagnostic (not a physical source set)

This copied RTL is for an offline integration experiment only. It is sourced
from `project-sidecar-phk2-v1-rtl` commit
`84ef0eb998077270c4eef6b95f107c18cac70438` and is deliberately excluded from
the FK33 physical source manifest. The transaction wrapper in this directory
was not qualified for board use.

The experiment drives the routed analysis datapath from the current 112-byte
host descriptor and compares the result to the host CPU oracle. It reproduced
the retained 4x8 operand tile, but the tile transcript and digest did not match
the CPU oracle result. Consequently, this source must not replace the board
stub or be synthesized as the real PHK2 endpoint. The mismatch identifies an
unresolved compute/result contract, not a wire-encoding fix.

Reproduce the count-1 diagnostic from the integration worktree with:

```sh
PYTHONPATH=tools/phk2_host:/home/rmann/project-sidecar-miner-integration/.venv/lib/python3.12/site-packages \
  python3 tools/phk2_host/qualify_timing_core.py --count 1
```

No physical operation is performed by this test.
