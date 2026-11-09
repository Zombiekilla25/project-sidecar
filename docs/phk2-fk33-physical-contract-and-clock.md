# PHK2 FK33 physical contract and 175 MHz clock

## Recovered board constraints

The authoritative primary source is the qualified PHK1 board XDC:

- Source: `/home/rmann/project-sidecar/sidecar-evidence/phk1-patched-bitstream-handoff-20261103/constraints/PHK1_FK33_BOARD_CONSTRAINTS.xdc`
- SHA-256: `16a5c6b05ac43f9fffeeb95b1b0b8490d3ce0884843f7a239a2d9d9d085770e7`
- The same XDC hash is recorded by the PHK1 routed checkpoint evidence and retained in `constraints/reference/PHK1_FK33_BOARD_CONSTRAINTS.xdc` byte-for-byte.

The previously reviewed PHK2 board-clock fragment is installed unchanged at
`constraints/phk2-fk33-board-clock-contract.xdc` (SHA-256
`97c25163f6176271d93c727a54eb49116e4131cefc8d4c01c68aa44f29eee473`). It
assigns `clk_p=BC26`, `clk_n=BC27`, `IOSTANDARD=LVDS`, and a 5.000 ns input
clock on `clk_p`. The independent routed Stage 4A contract agrees on BC26/BC27,
LVDS, 200 MHz, target part `xcvu33p-fsvh2104-2-e`.

The complete PHK1 XDC is retained as provenance. Its LOC and false-path entries
refer to PHK1-specific cell names and are not applied to the PHK2 hierarchy.
The board contract has no external reset pin; reset is derived from PLL lock.

## PHK2 clock implementation

The PHK2 clock generator is in `rtl/phk2_board/phk2_fk33_clockgen.sv` and uses
the reset-release block in `rtl/phk2_board/phk2_pll_reset_release.sv`:

```text
clk_p/clk_n -> IBUFDS -> PLLE4_ADV -> BUFG -> 175 MHz core clock
```

Parameters are `CLKIN_PERIOD=5.000 ns`, `DIVCLK_DIVIDE=2`,
`CLKFBOUT_MULT=14`, and `CLKOUT0_DIVIDE=8`. The phase-frequency detector is
100 MHz and the VCO is 1.4 GHz; the output is 175 MHz (5.714 ns). Vivado 2026.1
synthesized the exact clock-generator source for `xcvu33p-fsvh2104-2-e`,
recognized the generated output clock, and reported no DRC violations in the
clock-only legality top. The inherited XDC property `DIFF_TERM=TRUE` produces
a Vivado warning that it is translated to `TERM_100` for UltraScale; this is
also present in the known-good board XDC.

Reset asserts asynchronously when `LOCKED` drops and releases synchronously
after four core-clock edges. `tests/phk2_board/tb_phk2_pll_reset_release.sv`
passes all four startup, release, loss-of-lock, and relock checks.

## Qualification boundary

The clock legality run synthesizes only the clock generator and a kept internal
probe. It is not the PHK2 board-core synthesis and provides no integrated timing
or resource result. Board-level endpoint single-item/control tests, the
Batch64 CPU-exact replay, and variable-clock CDC/backpressure stress are
simulation evidence. The 12,000-command CDC campaign used HELLO traffic while
the real core remained bound but idle; the separate Batch64 simulation exercised
its result path through the asynchronous FIFOs.

The full board-core synthesis remains gated on completed physical structural
validation and vendor CDC review. No placement, routing, bitstream generation,
or hardware activity was performed.
