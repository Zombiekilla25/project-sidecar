# PHK2 FK33 175 MHz clock plan

The recovered board input is a 200 MHz differential clock. The PHK2 RTL now
proposes this clock path:

```text
clk_p/clk_n -> IBUFDS -> PLLE4_ADV -> BUFG -> core_clk
```

`PLLE4_ADV` settings are `DIVCLK_DIVIDE=2`, `CLKFBOUT_MULT=14`, and
`CLKOUT0_DIVIDE=8`, giving `200 MHz / 2 × 14 / 8 = 175 MHz`. The PLL VCO is
1.4 GHz by arithmetic. Reset asserts while `LOCKED` is low and releases through
a four-stage core-clock synchronizer.

This is a new PHK2 clock choice based on the recovered board input, not an
historically qualified PHK1 clock configuration. Vivado primitive legality,
clock interaction, and timing constraints have not been checked. The current
PHK2/FK33 integration worktree contains no authoritative XDC (`find . -name
'*.xdc'` returns none), so board synthesis and physical timing claims remain
blocked until the authoritative constraints are restored into this worktree.
