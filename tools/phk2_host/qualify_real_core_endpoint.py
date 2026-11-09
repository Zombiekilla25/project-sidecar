#!/usr/bin/env python3
"""Run the real command parser/endpoint/core/response path in Verilator."""
from __future__ import annotations
import argparse, os, subprocess, tempfile
from pathlib import Path
from runtime import Descriptor, Result, fixture_descriptor
from batch64_oracle import predict_batch64

ROOT=Path(__file__).resolve().parents[2]
RTL=[
 'rtl/phk2_board/phk2_async_fifo.sv',
 'rtl/phk2_board/phk2_protocol_decoder.sv',
 'rtl/phk2_board/phk2_protocol_response_encoder.sv',
 'rtl/phk2_board/phk2_core_contract_adapter.sv',
 'rtl/phk2_board/phk2_core/phk2_blake3_keyed_block_seq.sv',
 'rtl/phk2_board/phk2_core/phk2_philox4x32_10_seq.sv',
 'rtl/phk2_board/phk2_core/phk2_production_operand_seq.sv',
 'rtl/phk2_board/phk2_core/vendor_phk1/packed_mul2.sv',
 'rtl/phk2_board/phk2_core/vendor_phk1/packed_tile.sv',
 'rtl/phk2_board/phk2_core/phk2_tile_adapter.sv',
 'rtl/phk2_board/phk2_core/phk2_compact_result.sv',
 'rtl/phk2_board/phk2_core/phk2_result_filter.sv',
 'rtl/phk2_board/phk2_core/phk2_timing_core_contract.sv',
 'rtl/phk2_board/phk2_real_core_endpoint.sv',
 'tests/phk2_board/tb_real_core_endpoint.sv',
]

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--count',type=int,choices=(1,64),required=True);ap.add_argument('--descriptor',type=Path);a=ap.parse_args()
 desc=Descriptor.decode(a.descriptor.read_bytes()) if a.descriptor else fixture_descriptor()
 batch=predict_batch64(desc,desc.noise_seed_A,desc.noise_seed_B,0,64)
 records=[Result(desc.generation,1,i,i//8,i%8,batch['digests'][i],batch['transcripts'][i]).encode() for i in range(a.count)]
 with tempfile.TemporaryDirectory(prefix='phk2-real-endpoint-') as temp:
  td=Path(temp);(td/'descriptor.mem').write_text('\n'.join(f'{b:02x}' for b in desc.encode())+'\n')
  (td/'expected_results.mem').write_text('\n'.join(f'{b:02x}' for rec in records for b in rec)+'\n')
  cmd=['verilator','--binary','--timing','-Wno-fatal','--top-module','tb_real_core_endpoint','--Mdir',str(td/'obj_dir')]+[str(ROOT/p) for p in RTL]
  subprocess.run(cmd,cwd=ROOT,check=True,capture_output=True,text=True)
  env=os.environ.copy();env['PYTHONPATH']=f"{ROOT/'tools/phk2_host'}:{env.get('PYTHONPATH','')}"
  run=subprocess.run([str(td/'obj_dir'/'Vtb_real_core_endpoint'),f'+COUNT={a.count}'],cwd=td,capture_output=True,text=True,env=env)
  print(run.stdout.strip())
  if run.returncode:
   print(run.stderr.strip());raise SystemExit(run.returncode)
if __name__=='__main__': main()
