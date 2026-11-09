import json, subprocess, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
GUARD=ROOT/'tools/verify_phk2_real_board_manifest.py'
def main():
    good=subprocess.run([sys.executable,str(GUARD)],capture_output=True,text=True,check=True)
    result=json.loads(good.stdout)
    assert result['REAL_CORE_INCLUDED']=='PASS' and result['TEST_STUB_EXCLUDED']=='PASS'
    bad=subprocess.run([sys.executable,str(GUARD),'--physical-sources','rtl/phk2_board/phk2_core_stub.sv'],capture_output=True,text=True)
    assert bad.returncode!=0 and 'stub' in bad.stdout.lower()
    print('REAL_BOARD_SOURCE_GUARD_TESTS=2/2')
if __name__=='__main__': main()
