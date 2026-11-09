# PHK2 FK33 175 MHz clock plan and legality result

The authoritative FK33 input is the 200 MHz differential pair `clk_p/clk_n` on
BC26/BC27 with LVDS. The input pin and clock constraints are installed from the
exact previously reviewed PHK2 board-clock fragment. The full qualified PHK1
XDC is preserved byte-for-byte for provenance; PHK1-only placement and timing
exception selectors are not applied to PHK2.

The PHK2-specific clock path is:

```text
clk_p/clk_n -> IBUFDS -> PLLE4_ADV -> BUFG -> core_clk
```

`PLLE4_ADV` uses `CLKIN_PERIOD=5.000 ns`, `DIVCLK_DIVIDE=2`,
`CLKFBOUT_MULT=14`, and `CLKOUT0_DIVIDE=8`. This yields a 100 MHz PFD,
1.4 GHz VCO, and 175 MHz output (5.714 ns). This is a new PHK2 choice derived
from the established board input; it is not a historical PHK1 clock setting.

Vivado 2026.1 synthesized the exact `phk2_fk33_clockgen` and reset-release RTL
in the clock-only checker for `xcvu33p-fsvh2104-2-e`. The generated 5.714 ns
clock was recognized, check_timing found no missing clocks or unconstrained
internal endpoints, and the clock-only DRC reported zero violations. The
reports and repeatable Tcl are under `results/phk2-fk33-clock-legality/` and
`tools/vivado_phk2_clock_legality.tcl`.

The only XDC warning is the existing `DIFF_TERM=TRUE` property: Vivado
translates it to `DIFF_TERM_ADV=TERM_100` for UltraScale. The source property
was preserved unchanged because it is in the recovered qualified board
constraint fragment.

PLL lock loss asynchronously asserts the PHK2 reset. Reset deassertion takes
four core-clock edges. The standalone reset test passes initial-unlocked,
release delay, asynchronous lock-loss assertion, and relock release (4/4).

This clock-only check is not a full PHK2 board-core synthesis or an integrated
timing result. Full physical-top structural validation and vendor CDC review
are still required before the 175 MHz board synthesis gate. No placement,
routing, or bitstream generation was performed.
