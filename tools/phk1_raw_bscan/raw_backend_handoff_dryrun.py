#!/usr/bin/env python3
"""Fail-closed model for programmer-to-raw-backend handoff; no hardware I/O."""
import copy
import json
from pathlib import Path

LOCK=Path(__file__).resolve().parents[2]/'ops/current-phk1-target-lock.json'
EXPECTED=json.loads(LOCK.read_text())
FAULTS=(
 'stale_lock','wrong_usb_path','wrong_ftdi_serial','wrong_idcode','wrong_dna',
 'peer_selected','usb_reenumeration','program_failure','program_raw_identity_mismatch',
 'mpsse_sync_failure','chain_mismatch','hello_timeout','hello_mismatch',
 'vector_timeout','raw_result_mismatch','canonical_result_mismatch',
 'unexpected_pmic','recovery_failure')

def validate(lock):
    return (lock.get('status')=='PASS' and lock.get('match_count')==1 and
            lock.get('run_id')==EXPECTED.get('run_id') and
            lock.get('captured_utc')==EXPECTED.get('captured_utc') and
            lock.get('peer_distinct') is True and lock.get('peer_handle_open') is False and
            lock.get('raw_device_handle_count')==0 and
            lock.get('target')==EXPECTED['target'] and lock.get('peer')==EXPECTED['peer'])

def simulate(fault=None):
    events=['fresh_target_lock']
    if fault in ('stale_lock','wrong_usb_path','wrong_ftdi_serial','wrong_idcode','wrong_dna','peer_selected','usb_reenumeration'):
        events.append('abort_before_program')
    else:
        events.extend(['maintenance','program_once','programmer_closed','raw_open_exact_target','identity_reverified'])
        if fault=='program_failure': events.append('abort_recover')
        elif fault=='program_raw_identity_mismatch': events.extend(['abort_recover'])
        else:
            events.extend(['mpsse_sync','chain_check'])
            if fault in ('mpsse_sync_failure','chain_mismatch'): events.append('abort_recover')
            else:
                events.append('hello_once')
                if fault in ('hello_timeout','hello_mismatch'): events.append('abort_recover')
                else:
                    events.append('vector001_once')
                    if fault in ('vector_timeout','raw_result_mismatch','canonical_result_mismatch'):
                        events.append('abort_recover')
                    else:
                        events.append('raw_close')
                        events.append('restore_failed' if fault=='recovery_failure' else 'restore')
                if fault=='unexpected_pmic': events=['fresh_target_lock','maintenance','unexpected_pmic','abort_recover']
    if 'maintenance' in events and 'restore' not in events and 'abort_recover' not in events:
        events.append('restore')
    return {'fault':fault or 'none','events':events,'hardware_io':False,
            'pmic_transaction_expected_count':0,'user_ir_selected':False,
            'program_attempts_model_only':int('program_once' in events)}

def main():
    assert validate(EXPECTED)
    stale=copy.deepcopy(EXPECTED); stale['run_id']='old-run'
    assert not validate(stale)
    cases={name:simulate(name) for name in FAULTS}
    cases['nominal']=simulate()
    assert all(case['hardware_io'] is False for case in cases.values())
    assert all(case['pmic_transaction_expected_count']==0 for case in cases.values())
    assert all(case['events'].count('program_once')<=1 for case in cases.values())
    assert all(case['events'].count('hello_once')<=1 for case in cases.values())
    assert all(case['events'].count('vector001_once')<=1 for case in cases.values())
    assert 'programmer_closed' in cases['nominal']['events']
    assert cases['nominal']['events'].index('programmer_closed') < cases['nominal']['events'].index('raw_open_exact_target')
    print(f'RAW_BSCAN_HANDOFF_DRYRUN=PASS ({len(cases)}/{len(cases)} cases)')
    print('HARDWARE_IO=false')

if __name__=='__main__': main()
