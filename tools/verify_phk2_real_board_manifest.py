#!/usr/bin/env python3
"""Fail closed if the real PHK2 board source set drifts or includes its stub."""
from __future__ import annotations
import hashlib, json, sys
import argparse
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/'handoff/PHK2_REAL_BOARD_SOURCE_MANIFEST.json'

def main() -> int:
    ap=argparse.ArgumentParser();ap.add_argument('--physical-sources',nargs='*',default=[]);args=ap.parse_args()
    m=json.loads(MANIFEST.read_text())
    sources=m['board_transport']+m['real_core']
    forbidden=set(m['test_only_stub'])
    if any(Path(p).name=='phk2_core_stub.sv' for p in args.physical_sources):
        raise ValueError('explicit test stub path supplied as a physical source')
    top=(ROOT/m['physical_top']).read_text()
    if forbidden.intersection(sources): raise ValueError('test stub appears in real physical source set')
    if 'phk2_real_core_endpoint' not in top or 'phk2_core_stub' in top:
        raise ValueError('physical top does not bind only the real endpoint')
    for rel in sources+list(m['test_only_stub']):
        actual=hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()
        if actual!=m['source_sha256'][rel]: raise ValueError(f'source hash mismatch: {rel}')
    constraints_ok=bool(m['constraints'])
    for rel in m['constraints']:
        path=ROOT/rel
        if not path.is_file(): raise ValueError(f'missing physical constraint: {rel}')
        actual=hashlib.sha256(path.read_bytes()).hexdigest()
        if actual!=m.get('constraint_sha256',{}).get(rel): raise ValueError(f'constraint hash mismatch: {rel}')
    ref=m.get('provenance_reference_xdc')
    if ref:
        path=ROOT/ref
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=m.get('provenance_reference_xdc_sha256'):
            raise ValueError('authoritative reference XDC missing or hash mismatch')
    ready=constraints_ok and m.get('clock_legality')=='PASS' and m.get('board_synthesis_gates_complete') is True
    print(json.dumps({'REAL_CORE_INCLUDED':'PASS','TEST_STUB_EXCLUDED':'PASS','SOURCE_HASHES':'PASS','XDC_HASHES':'PASS' if constraints_ok else 'FAIL','physical_rtl_files':len(sources),'constraints':len(m['constraints']),'physical_synthesis_ready':ready},sort_keys=True))
    return 0

if __name__=='__main__':
    try: raise SystemExit(main())
    except (AssertionError,KeyError,ValueError,json.JSONDecodeError) as e:
        print(json.dumps({'status':'FAIL','reason':str(e)},sort_keys=True));raise SystemExit(1)
