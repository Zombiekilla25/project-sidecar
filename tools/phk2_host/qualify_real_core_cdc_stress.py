#!/usr/bin/env python3
"""Run bounded, variable-phase CDC/backpressure stress with the actual PHK2 endpoint/core bound."""
from __future__ import annotations
import os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
RTL=[
 'rtl/phk2_board/phk2_async_fifo.sv','rtl/phk2_board/phk2_protocol_decoder.sv',
 'rtl/phk2_board/phk2_protocol_response_encoder.sv','rtl/phk2_board/phk2_core_contract_adapter.sv',
 'rtl/phk2_board/phk2_core/phk2_blake3_keyed_block_seq.sv','rtl/phk2_board/phk2_core/phk2_philox4x32_10_seq.sv',
 'rtl/phk2_board/phk2_core/phk2_production_operand_seq.sv','rtl/phk2_board/phk2_core/vendor_phk1/packed_mul2.sv',
 'rtl/phk2_board/phk2_core/vendor_phk1/packed_tile.sv','rtl/phk2_board/phk2_core/phk2_tile_adapter.sv',
 'rtl/phk2_board/phk2_core/phk2_compact_result.sv','rtl/phk2_board/phk2_core/phk2_result_filter.sv',
 'rtl/phk2_board/phk2_core/phk2_timing_core_contract.sv','rtl/phk2_board/phk2_real_core_endpoint.sv',
 'tests/phk2_board/tb_real_core_cdc_stress.sv']
with tempfile.TemporaryDirectory(prefix='phk2-real-cdc-') as tmp:
 d=Path(tmp);cmd=['verilator','--binary','--timing','-Wno-fatal','--top-module','tb_real_core_cdc_stress','--Mdir',str(d/'obj')]+[str(ROOT/x) for x in RTL]
 subprocess.run(cmd,cwd=ROOT,check=True,capture_output=True,text=True)
 r=subprocess.run([str(d/'obj'/'Vtb_real_core_cdc_stress')],cwd=ROOT,capture_output=True,text=True)
 print(r.stdout.strip())
 if r.returncode: print(r.stderr.strip());raise SystemExit(r.returncode)
