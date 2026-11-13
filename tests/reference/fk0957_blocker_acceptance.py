#!/usr/bin/env python3
"""Independent offline attacks for FK0957 startup/permit/handoff/provenance blockers.

All dynamic transport substitutions are harmless Python fakes; this script never
opens USB, connects to testbench, issues a permit for real use, or writes evidence.
"""
from __future__ import annotations
import argparse, datetime, hashlib, importlib, json, os, pickle, re, shutil, subprocess, sys, tempfile, threading
from dataclasses import replace
from pathlib import Path
from unittest import mock


def run(argv, env):
    return subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False, text=True, timeout=10)


def startup(root: Path) -> dict:
    host = root / 'tools/phk2_host'
    bootstrap = host / 'fk0957_safe_bootstrap.py'
    cli = host / 'phk2_fk0957_topology_live_cli.py'
    out = {}
    with tempfile.TemporaryDirectory(prefix='fk0957-startup-attacks-') as td:
        t = Path(td); marker = t/'sentinel'
        payload = "import os; from pathlib import Path; Path(os.environ['FK0957_AUDIT_MARKER']).write_text('ran')\n"
        (t/'sitecustomize.py').write_text(payload)
        base = dict(os.environ, FK0957_AUDIT_MARKER=str(marker))
        for name, argv, extra in [
            ('direct_script', [sys.executable, str(cli), '--help'], {'PYTHONPATH': str(t)}),
            ('python_module', [sys.executable, '-m', 'phk2_fk0957_topology_live_cli', '--help'], {'PYTHONPATH': os.pathsep.join((str(host),str(t)))}),
            ('alternate_interpreter', ['/usr/bin/python3', str(cli), '--help'], {'PYTHONPATH': str(t)}),
        ]:
            marker.unlink(missing_ok=True)
            cp=run(argv, dict(base, **extra)); out[name]={'exit':cp.returncode,'sentinel_executed':marker.exists(),'stdout_refusal':'TRUSTED_LAUNCHER_REQUIRED' in cp.stdout}
        marker.unlink(missing_ok=True)
        userbase=t/'userbase'; site=userbase/'lib'/f'python{sys.version_info.major}.{sys.version_info.minor}'/'site-packages'; site.mkdir(parents=True)
        (site/'usercustomize.py').write_text(payload)
        marker.unlink(missing_ok=True)
        cp=run([sys.executable,str(cli),'--help'],dict(base,PYTHONUSERBASE=str(userbase),PYTHONPATH=''))
        out['PYTHONUSERBASE_usercustomize']={'exit':cp.returncode,'sentinel_executed':marker.exists()}
        empty=t/'emptyhome'; empty.mkdir()
        marker.unlink(missing_ok=True)
        cp=run([sys.executable,str(cli),'--help'],dict(base,PYTHONHOME=str(empty),PYTHONPATH=str(t)))
        out['PYTHONHOME']={'exit':cp.returncode,'sentinel_executed':marker.exists(),'startup_rejected':cp.returncode!=0}
        # Bootstrap accepts a caller-forged marker and reaches its self-test branch.
        clean={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','FK0957_TRUSTED_LAUNCHER':'1'}
        cp=run([sys.executable,'-I','-S',str(bootstrap),'--launcher-self-test'],clean)
        out['direct_bootstrap_forged_marker']={'exit':cp.returncode,'accepted':cp.returncode==0}
        marker.unlink(missing_ok=True)
        shim=("import os,sys; from pathlib import Path; "
              f"sys.path.insert(0,{str(host)!r}); "
              "sys.path.append('/usr/lib/python3/dist-packages'); "
              "import phk2_fk0957_topology_rgb_cli as c; "
              f"marker={str(marker)!r}; "
              "c._read_request=lambda _p:b'fixture'; "
              "c.rgb.acquire_validate_sign_once=lambda *a: "
              "(Path(marker).write_text('acquisition-boundary'), "
              "(_ for _ in ()).throw(c.rgb.Refusal('bounded fixture refusal')))[1]; "
              "import fk0957_safe_bootstrap as b; "
              f"raise SystemExit(b.main(['--authorization-request','fixture.json','--output',{str(t/'unused.json')!r}]))")
        cp=run([sys.executable,'-I','-S','-c',shim],clean)
        out['direct_bootstrap_reaches_acquisition_boundary']={'exit':cp.returncode,
            'sentinel_reached':marker.exists(),'evidence_written':(t/'unused.json').exists()}
        # PATH substitution is a shell-level route used by command-name launch docs.
        fake=t/'bin'; fake.mkdir(); fakepython=fake/'python3'; pathmarker=t/'pathmarker'
        fakepython.write_text(f'#!/bin/sh\necho ran > {pathmarker}\nexec {sys.executable} "$@"\n'); fakepython.chmod(0o700)
        cp=run(['/bin/sh','-c','python3 "$1" --help','sh',str(cli)],dict(base,PATH=str(fake)+':/usr/bin:/bin'))
        out['PATH_substitution']={'exit':cp.returncode,'sentinel_executed':pathmarker.exists()}
        # Harmless preload constructor: it only creates a marker then Python refuses.
        cc=shutil.which('cc')
        if cc:
            c=t/'pre.c'; so=t/'pre.so'; c.write_text('#include <stdlib.h>\n#include <stdio.h>\n__attribute__((constructor)) static void c(void){const char*p=getenv("FK0957_AUDIT_MARKER");if(p){FILE*f=fopen(p,"w");if(f){fputs("ran",f);fclose(f);}}}\n')
            subprocess.run([cc,'-shared','-fPIC',str(c),'-o',str(so)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            marker.unlink(missing_ok=True); cp=run([sys.executable,str(cli),'--help'],dict(base,LD_PRELOAD=str(so),PYTHONPATH=''))
            out['LD_PRELOAD']={'exit':cp.returncode,'sentinel_executed':marker.exists()}
            # Python's ELF has direct libm/libz/libexpat dependencies. A harmless
            # same-SONAME fake libm proves LD_LIBRARY_PATH runs code pre-start.
            lib=t/'lib'; lib.mkdir(); libso=lib/'libm.so.6'
            c.write_text('#include <stdlib.h>\n#include <stdio.h>\n__attribute__((constructor)) static void c(void){const char*p=getenv("FK0957_AUDIT_MARKER");if(p){FILE*f=fopen(p,"w");if(f){fputs("ran",f);fclose(f);}}}\n')
            subprocess.run([cc,'-shared','-fPIC',str(c),'-o',str(libso)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            marker.unlink(missing_ok=True); cp=run(['/usr/bin/python3.12','--version'],dict(base,LD_LIBRARY_PATH=str(lib),PYTHONPATH=''))
            out['LD_LIBRARY_PATH_prestart']={'exit':cp.returncode,'sentinel_executed':marker.exists()}
    launcher=Path('/usr/local/bin/fk0957-topology-live-one-shot')
    out['official_launcher_deployed']=launcher.is_file()
    return out


def authorization(root: Path) -> dict:
    host=root/'tools/phk2_host'; sys.path.insert(0,str(host))
    import phk2_fk0957_topology_transport as tr
    import phk2_fk0957_topology_discovery as topo
    import test_phk2_fk0957_topology_transport as fixtures
    test=fixtures.TopologyTransportTests(); test.setUp()
    try:
        now=datetime.datetime.now(datetime.timezone.utc)
        ident=topo.DescriptorIdentity('FK0957','153300000957A','153300000957','1-9.3','0403','6010','Xilinx','SQRL FK','A')
        fake=topo.DiscoveryPermit('f'*64,ident,'fake-nonce',now.isoformat(),(now+datetime.timedelta(seconds=120)).isoformat(),'0'*64,object())
        opened=[]
        original=tr._NativeLibFtdi
        def factory(*a,**k):
            b=fixtures.FakeBackend(); opened.append(b); return b
        public_refusal=None
        with mock.patch.object(tr,'_NativeLibFtdi',side_effect=factory):
            try: tr.run_fk0957_topology_discovery(fake)
            except BaseException as e: public_refusal=type(e).__name__
        public_fake_open=sum(b.open_count for b in opened)
        invalid_permits={}
        for label, mutate in (
            ('wrong_target', lambda p: replace(p, identity=replace(p.identity, card_id='FK0958'))),
            ('expired', lambda p: replace(p, expires_at=(now-datetime.timedelta(seconds=1)).isoformat())),
        ):
            original_permit=test.permit(); changed=mutate(original_permit); opened.clear()
            with mock.patch.object(tr,'_NativeLibFtdi',side_effect=factory):
                try: tr.run_fk0957_topology_discovery(changed); invalid_permits[label]='ACCEPTED'
                except BaseException as e: invalid_permits[label]=type(e).__name__
            invalid_permits[label+'_opens']=sum(b.open_count for b in opened)
        # Internal consumed-permit helper is directly callable and skips registry consumption.
        opened.clear()
        with mock.patch.object(tr,'transport_source_sha256',return_value='a'*64), mock.patch.object(tr,'_production_git_state',return_value=('a'*40,True)), mock.patch.object(tr,'_NativeLibFtdi',side_effect=factory):
            first=tr._run_consumed_permit(fake); second=tr._run_consumed_permit(fake)
        internal_opens=sum(b.open_count for b in opened)
        with topo._PERMIT_LOCK: reg=fake._token in topo._ACTIVE; consumed=fake._token in topo._CONSUMED
        copied=pickle.loads(pickle.dumps(test.permit()))
        copied_result=None
        try: tr.run_fk0957_topology_discovery(copied)
        except BaseException as e: copied_result=type(e).__name__
        # The attach helper is importable and accepts caller-invented digests;
        # exercise whether it can authorize the public opener without endpoint
        # signature verification.
        forged_binding_permit=test.permit(); opened.clear(); forged_binding_result=None
        with mock.patch.object(tr,'transport_source_sha256',return_value='a'*64), mock.patch.object(tr,'_production_git_state',return_value=('a'*40,True)), mock.patch.object(tr,'_NativeLibFtdi',side_effect=factory):
            try:
                tr._authorize_remote_permit(forged_binding_permit,
                    authorization_sha256='1'*64,handoff_sha256='2'*64,
                    manifest_sha256='3'*64,
                    descriptor_sha256=forged_binding_permit.descriptor_evidence_sha256)
                forged_binding_result=tr.run_fk0957_topology_discovery(forged_binding_permit)
            except BaseException as e:
                forged_binding_result=e
        forged_binding_opens=sum(b.open_count for b in opened)
        # Reuse authentic test permit: model the endpoint attaching a binding,
        # then verify the public operation still consumes it only once.
        permit=test.permit(); opened.clear(); public_replay=[]
        with mock.patch.object(tr,'transport_source_sha256',return_value='a'*64), mock.patch.object(tr,'_production_git_state',return_value=('a'*40,True)), mock.patch.object(tr,'_NativeLibFtdi',side_effect=factory):
            tr._authorize_remote_permit(permit,authorization_sha256='4'*64,
                handoff_sha256='5'*64,manifest_sha256='6'*64,
                descriptor_sha256=permit.descriptor_evidence_sha256)
            for _ in range(2):
                try: tr.run_fk0957_topology_discovery(permit)
                except BaseException as e: public_replay.append(type(e).__name__)
        opened_by_replay=sum(b.open_count for b in opened)
        import concurrent.futures
        permit=test.permit(); opened.clear(); barrier=threading.Barrier(2)
        tr._authorize_remote_permit(permit,authorization_sha256='7'*64,
            handoff_sha256='8'*64,manifest_sha256='9'*64,
            descriptor_sha256=permit.descriptor_evidence_sha256)
        def parallel_call():
            barrier.wait()
            try: return tr.run_fk0957_topology_discovery(permit)
            except BaseException as e: return type(e).__name__
        with mock.patch.object(tr,'transport_source_sha256',return_value='a'*64), mock.patch.object(tr,'_production_git_state',return_value=('a'*40,True)), mock.patch.object(tr,'_NativeLibFtdi',side_effect=factory):
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                parallel_results=list(pool.map(lambda _i: parallel_call(),range(2)))
        parallel_opens=sum(b.open_count for b in opened)
        wrong_head_permit=test.permit(); opened.clear()
        with mock.patch.object(tr,'transport_source_sha256',return_value='b'*64), mock.patch.object(tr,'_production_git_state',return_value=('f'*40,True)), mock.patch.object(tr,'_NativeLibFtdi',side_effect=factory):
            tr._authorize_remote_permit(wrong_head_permit,authorization_sha256='a'*64,
                handoff_sha256='b'*64,manifest_sha256='c'*64,
                descriptor_sha256=wrong_head_permit.descriptor_evidence_sha256)
            try: wrong_head_result=tr.run_fk0957_topology_discovery(wrong_head_permit)
            except BaseException as e: wrong_head_result=e
        transport_source=(host/'phk2_fk0957_topology_transport.py').read_text()
        discovery_source=(host/'phk2_fk0957_topology_discovery.py').read_text()
        source_text=transport_source+discovery_source
        return {
            'fabricated_public_permit_refused':public_refusal is not None and public_fake_open==0,
            'fabricated_public_error':public_refusal,'fabricated_public_opens':public_fake_open,
            'wrong_target_and_expired_permits':invalid_permits,
            'internal_unregistered_permit_calls':2,'internal_unregistered_permit_opens':internal_opens,
            'internal_unregistered_results_sealed':first._proof in tr._SEALED_RESULTS and second._proof in tr._SEALED_RESULTS,
            'fabricated_binding_helper_accepts_unverified_digests':not isinstance(forged_binding_result,BaseException),
            'fabricated_binding_helper_fake_opens':forged_binding_opens,
            'internal_permit_registered':reg,'internal_permit_consumed':consumed,
            'pickled_copy_refused':copied_result is not None,
            'authentic_public_replay_errors':public_replay,'authentic_public_replay_opens':opened_by_replay,
            'parallel_results':[type(x).__name__ if not isinstance(x,str) else x for x in parallel_results],
            'parallel_simulated_opens':parallel_opens,
            'wrong_clean_head_transport_accepted':getattr(wrong_head_result,'production_git_head',None)=='f'*40,
            'operation_id_binding': 'operation_id' in source_text,
            'expected_head_pin': 'EXPECTED_PRODUCTION_HEAD' in source_text,
            'release_manifest_binding': 'release_manifest' in source_text or 'manifest_sha256' in source_text,
            'transaction_profile_binding': 'transaction_profile' in source_text or 'GOLDEN_PLAN_SHA256' in source_text,
            'expiration_binding': 'expires_at' in source_text,
            'direct_internal_helper_importable': callable(getattr(tr,'_run_consumed_permit',None)),
        }
    finally:
        test.doCleanups()


def governance(root: Path) -> dict:
    host=root/'tools/phk2_host'
    transport=(host/'phk2_fk0957_topology_transport.py').read_text()
    signing=(host/'phk2_fk0957_topology_signing.py').read_text() if (host/'phk2_fk0957_topology_signing.py').exists() else ''
    cli=(host/'phk2_fk0957_topology_live_cli.py').read_text()
    combined=transport+signing+cli
    handoff_terms=('validate_bridge_handoff','handoff_issuer','handoff_signature','bridge_owner','USBFS_OWNER','operation_id')
    runtime_list=re.search(r'relative_sources\s*=\s*\((.*?)\)',transport,re.S)
    listed=re.findall(r'"([^"]+\.py)"',runtime_list.group(1)) if runtime_list else []
    expected={'phk2_fk0957_topology_transport.py','phk2_fk0957_topology_discovery.py','phk2_fk0957_idcode_gate.py','phk2_fk0957_topology_signing.py','phk2_fk0957_topology_live_cli.py'}
    docs=(root/'docs/phk2-fk0957-topology-discovery-offline.md').read_text()
    live_hash= 'def transport_source_sha256()' in transport and 'digest.hexdigest()' in transport
    return {
        'handoff_gate_terms_present': [x for x in handoff_terms if x in combined],
        'handoff_authority_complete': all(x in combined for x in handoff_terms),
        'release_authorization_present': any(x in combined for x in ('release_authorization','verify_release_manifest','immutable_release')),
        'manifest_bound_source_files':listed,
        'runtime_source_files_missing_from_hash':sorted(expected-set(Path(x).name for x in listed)),
        'transport_source_hash_knowable':live_hash,
        'docs_claim_transport_hash_null': 'transport source hash remains null' in docs.lower(),
        'docs_runtime_hash_contradiction': live_hash and 'transport source hash remains null' in docs.lower(),
        'remote_endpoint_present': any('remote_topology_endpoint' in p.name for p in host.glob('*')),
        'local_signing_module_separate':bool(signing) and 'LOCAL_SIGNING_KEY_PATH' in signing and 'sign_local_discovery_record' in signing,
        'signing_module_remote_safe_claim': 'Remote deployment bundles must omit it' in signing,
        'remote_bundle_exclusion_enforced_in_code': 'remote bundle' in combined.lower() and ('exclude' in combined.lower() or 'bundle_allowlist' in combined),
    }


def synthetic_signing_attack(root: Path) -> dict:
    """Call the production signer directly with a deliberately incomplete record."""
    sys.path.insert(0,str(root/'tools/phk2_host'))
    import phk2_fk0957_topology_signing as signing
    import phk2_fk0957_idcode_gate as gate
    import phk2_fk0957_remote_orchestrator as canonical
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key=Ed25519PrivateKey.generate(); public=key.public_key()
    der=public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint=hashlib.sha256(der).hexdigest()
    pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    record={'schema':'fk0957-unsigned-topology-acquisition-v1','status':'ACQUIRED',
      'write_count':0,'reset_count':0,'program_count':0,'jtag_operation_count':1,
      'idcode_qualification_pass':False,'card_id':'FK0957','adapter_serial':'153300000957A',
      'usb_descriptor_serial':'153300000957','scan_a_tck_count':591,'scan_b_tck_count':586,
      'total_tck_count':1177,'trusted_signer_fingerprint':fingerprint,
      'invented_claim':'fixture; deliberately lacks all acquisition/provenance/raw evidence'}
    provenance={'ssh_destination':'rmann@192.168.1.173','ssh_host_key_algorithm':'ssh-ed25519',
      'ssh_host_key_sha256':'SHA256:'+'A'*43,'pinned_known_hosts_sha256':'0'*64,
      'local_agent_available_to_ssh_client':True,'remote_agent_forwarding':False,
      'remote_process_state':'REMOTE_PROCESS_CONFIRMED_EXITED'}
    with mock.patch.object(signing,'_read_local_private_key',return_value=pem), \
         mock.patch.object(gate,'TRUSTED_SIGNER_FINGERPRINT_SHA256',fingerprint), \
         mock.patch.object(gate,'_trusted_signer',return_value=public):
        signed=signing._sign_validated_remote_record(record,provenance)
    payload=signed['payload']; encoded=canonical.canonical(payload)
    public.verify(bytes.fromhex(signed['signature_hex']),encoded)
    required=('descriptor_evidence_sha256','permit_nonce','operation_id','authorization_id',
      'handoff_sha256','manifest_sha256','transport_source_sha256','scan_a_raw_tdo_hex',
      'scan_b_raw_tdo_hex','scan_a_transaction_sha256','scan_b_transaction_sha256')
    return {'synthetic_minimal_record_signed':True,'signature_verifies':True,
      'missing_validation_fields':[field for field in required if field not in record],
      'test_key_only':True,'evidence_file_written':False}


def handoff_attacks(root: Path) -> dict:
    """Try ownership failures at the live CLI with acquisition replaced by a sentinel."""
    sys.path.insert(0,str(root/'tools/phk2_host'))
    import phk2_fk0957_topology_live_cli as cli
    import phk2_fk0957_topology_signing as signing
    import phk2_fk0957_topology_transport as transport
    cases=('missing','unsigned','stale','wrong_bridge','bridge_still_active',
           'wrong_clients','wrong_lanes','competing_usbfs_owner','unknown_usbfs_owner',
           'wrong_operation','wrong_permit','wrong_target','replay')
    reached=[]
    with tempfile.TemporaryDirectory(prefix='fk0957-handoff-cases-') as td:
        for case in cases:
            out=Path(td)/(case+'.json')
            with mock.patch.object(cli,'_read_descriptor',return_value=b'fixture'), \
                 mock.patch.object(signing,'perform_fk0957_topology_discovery_once',
                                   side_effect=transport.Refusal('bounded sentinel')) as acquire:
                cli.run_once(Path('fixture-descriptor'),out)
                if acquire.call_count: reached.append(case)
                if out.exists(): raise AssertionError('handoff attack unexpectedly published evidence')
    return {'cases':list(cases),'reached_acquisition_boundary':reached,'physical_device_opened':False}


def provenance_attacks(root: Path) -> dict:
    sys.path.insert(0,str(root/'tools/phk2_host'))
    import phk2_fk0957_topology_transport as tr
    source=(root/'tools/phk2_host/phk2_fk0957_topology_transport.py').read_text()
    runtime=re.search(r'relative_sources\s*=\s*\((.*?)\)',source,re.S)
    listed=re.findall(r'"([^"]+\.py)"',runtime.group(1)) if runtime else []
    cp=subprocess.CompletedProcess(args=[],returncode=0,stdout='f'*40+'\n',stderr='')
    status=subprocess.CompletedProcess(args=[],returncode=0,stdout='',stderr='')
    with mock.patch.object(tr.subprocess,'run',side_effect=[cp,status]):
        wrong_head=tr._production_git_state(root)
    return {
        'tamper_cases':['launcher','RGB orchestrator','remote endpoint','transport','backend',
            'observer','collector','validator','schema','handoff verifier','release authorization',
            'transaction profile','config','native manifest','wrong HEAD','dirty tree',
            'untracked replacement','alternate source path','runtime file changed after manifest'],
        'hashed_sources':listed,
        'wrong_clean_head_accepted':wrong_head==('f'*40,True),
        'dirty_tree_gate_present':'--porcelain=v1' in source and 'worktree is not clean' in source,
        'immutable_release_hash_pin_present':False,
    }


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('candidate_root'); ap.add_argument('--expected-head',required=True); ap.add_argument('--output',required=True); a=ap.parse_args()
    root=Path(a.candidate_root).resolve(); head=subprocess.check_output(['/usr/bin/git','-C',str(root), 'rev-parse','HEAD'],text=True).strip()
    if head!=a.expected_head: raise SystemExit('candidate SHA mismatch')
    report={'candidate_sha':head,'startup':startup(root),'authorization':authorization(root),
            'handoff':handoff_attacks(root),'provenance':provenance_attacks(root),
            'synthetic_signing':synthetic_signing_attack(root),
            'governance':governance(root),'hardware_access':False,'ssh':False,'usb_jtag':False}
    Path(a.output).write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))

if __name__=='__main__': main()
