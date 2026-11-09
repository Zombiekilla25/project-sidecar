#!/usr/bin/env python3
"""CPU-oracle differential simulation for the imported routed PHK2 datapath wrapper."""
from __future__ import annotations
import argparse, re, subprocess, tempfile
from pathlib import Path
from runtime import fixture_descriptor, fixture_path, Result
from oracle import predict

ROOT=Path(__file__).resolve().parents[2]
RTL=[
'experiments/phk2-core-contract-diagnostic/rtl/phk2_blake3_keyed_block_seq.sv',
'experiments/phk2-core-contract-diagnostic/rtl/phk2_philox4x32_10_seq.sv',
'experiments/phk2-core-contract-diagnostic/rtl/phk2_production_operand_seq.sv',
'experiments/phk2-core-contract-diagnostic/rtl/vendor_phk1/packed_mul2.sv',
'experiments/phk2-core-contract-diagnostic/rtl/vendor_phk1/packed_tile.sv',
'experiments/phk2-core-contract-diagnostic/rtl/phk2_tile_adapter.sv',
'experiments/phk2-core-contract-diagnostic/rtl/phk2_compact_result.sv',
'experiments/phk2-core-contract-diagnostic/rtl/phk2_result_filter.sv',
'experiments/phk2-core-contract-diagnostic/rtl/phk2_timing_core_contract.sv',
'tests/phk2_board/tb_timing_core_contract.sv']

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--count',type=int,choices=(1,64),required=True);args=ap.parse_args()
    desc=fixture_descriptor(); expected=predict(desc,0,args.count)
    if expected['checks'].get('exact') is False: raise SystemExit('CPU oracle fixture not exact')
    with tempfile.TemporaryDirectory(prefix='phk2-core-contract-') as td:
        td=Path(td)
        (td/'descriptor.mem').write_text('\n'.join(f'{b:02x}' for b in desc.encode())+'\n')
        operand_bytes=(fixture_path()/'operand_tile.bin').read_bytes()
        if len(operand_bytes)!=4096*12: raise SystemExit('authoritative operand tile has wrong size')
        (td/'operands.mem').write_text('\n'.join(operand_bytes[i:i+12][::-1].hex() for i in range(0,len(operand_bytes),12))+'\n')
        cmd=['iverilog','-g2012','-s','tb_timing_core_contract','-o',str(td/'sim.vvp')]+[str(ROOT/p) for p in RTL]
        subprocess.run(cmd,check=True,cwd=ROOT)
        run=subprocess.run(['vvp',str(td/'sim.vvp'),f'+COUNT={args.count}','+CHECK_OPERANDS'],check=True,cwd=td,text=True,capture_output=True)
        observed={}
        for m in re.finditer(r'^RESULT_(\d+)=([0-9a-fA-F]{224})$',run.stdout,re.M):
            observed[int(m.group(1))]=bytes.fromhex(m.group(2))[::-1]
        if len(observed)!=args.count: raise SystemExit(f'missing results: {len(observed)}/{args.count}; {run.stdout[-1000:]}')
        for i in range(args.count):
            row,col=divmod(i,8)
            wanted=Result(desc.generation,1,i,row,col,expected['expected_compact_result'][i],expected['canonical_result'][i]).encode()
            if observed[i]!=wanted:
                off=next((j for j,(a,b) in enumerate(zip(observed[i],wanted)) if a!=b),min(len(observed[i]),len(wanted)))
                got,exp=observed[i],wanted
                raise SystemExit(
                    f'mismatch slot={i} offset={off} got={got[off:off+8].hex()} expected={exp[off:off+8].hex()} '
                    f'metadata_match={got[:16]==exp[:16]} digest_match={got[16:48]==exp[16:48]} '
                    f'transcript_match={got[48:]==exp[48:]} got_digest={got[16:48].hex()} '
                    f'exp_digest={exp[16:48].hex()} got_transcript={got[48:].hex()} exp_transcript={exp[48:].hex()}')
        print(f'REAL_DATAPATH_RESULT_ORACLE=PASS COUNT={args.count}')
        print(f'RTL_CORE_CYCLES={re.search(r"TIMING_CORE_CONTRACT_SIM=PASS COUNT=\\d+ CYCLES=(\\d+)",run.stdout).group(1)}')
if __name__=='__main__': main()
