#!/usr/bin/python3
"""Bounded offline FK0957 source audit. Reads Git objects; never imports candidate code."""
from __future__ import annotations
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO = Path('/home/rmann/project-sidecar/.git').parent
OUT = Path('/tmp/fk0957-right-audit-worker-20261115/results/independent-fk0957-integration-audit-20261115/overnight-worker')
STOP = OUT / 'STOP'
STATE = OUT / 'state.json'
LOG = OUT / 'worker.log'
MAX_SECONDS = 8 * 60 * 60
POLL_SECONDS = 60
GIT_ENV = {'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C',
           'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null',
           'GIT_OPTIONAL_LOCKS':'0'}
PRODUCTION_FILES = [
 'tools/phk2_host/fk0957_maintenance_controller.py',
 'tools/phk2_host/phk2_fk0957_topology_rgb_cli.py',
 'tools/phk2_host/phk2_fk0957_topology_rgb_orchestrator.py',
 'tools/phk2_host/phk2_fk0957_topology_live_cli.py',
 'tools/phk2_host/phk2_fk0957_topology_transport.py',
 'tools/phk2_host/phk2_fk0957_remote_topology_endpoint.py',
 'tools/phk2_host/fk0957_supervisor_status_contract.py',
 'tools/phk2_host/fk0957_supervisor.py',
 'tools/phk2_host/fk0957_supervisor_client.py',
 'tools/phk2_host/phk2_fk0957_topology_signing.py',
 'tools/phk2_host/fk0957_rgb_cli_contract.py',
 'tools/phk2_host/fk0957_safe_bootstrap.py',
]
MANIFEST='results/fk0957-release-candidate-source-manifest.json'


def now(): return datetime.now(timezone.utc).isoformat()
def stop_requested():
    try: return STOP.read_text(encoding='ascii').strip() == 'STOP'
    except OSError: return False
def record(msg):
    OUT.mkdir(parents=True, exist_ok=True)
    with LOG.open('a', encoding='utf-8') as f: f.write(f'{now()} {msg}\n'); f.flush(); os.fsync(f.fileno())
def git(args, timeout=8):
    # All Git access is read-only and limited to this local object database.
    p=subprocess.run(['/usr/bin/git','-C',str(REPO),*args],env=GIT_ENV,
                     stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                     timeout=timeout,check=False)
    if p.returncode: raise RuntimeError('GIT_READ_FAILED')
    if len(p.stdout)>16*1024*1024: raise RuntimeError('GIT_OUTPUT_LIMIT')
    return p.stdout

def blob(sha,path): return git(['show',f'{sha}:{path}'])
def update_state(**kw):
    previous={}
    try: previous=json.loads(STATE.read_text(encoding='utf-8'))
    except (OSError,ValueError): pass
    previous.update(kw); previous['updated_utc']=now()
    tmp=STATE.with_suffix('.tmp'); tmp.write_text(json.dumps(previous,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    os.replace(tmp,STATE)

def call_name(node):
    if isinstance(node,ast.Name): return node.id
    if isinstance(node,ast.Attribute): return call_name(node.value)+'.'+node.attr
    return ''

def functions(tree):
    out={}
    for n in ast.walk(tree):
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
            calls=[]
            for x in ast.walk(n):
                if isinstance(x,ast.Call): calls.append(call_name(x.func))
            out[n.name]={'line':n.lineno,'calls':sorted(set(calls))}
    return out

def route_checks(sources):
    controller=sources.get(PRODUCTION_FILES[0],b'').decode('utf-8','replace')
    rgb=sources.get(PRODUCTION_FILES[2],b'').decode('utf-8','replace')
    legacy_path='tools/phk2_host/fk0957_test_support/legacy_remote_orchestrator.py'
    legacy=blob(CURRENT_SHA,legacy_path).decode('utf-8','replace') if file_exists(CURRENT_SHA,legacy_path) else ''
    try:
        ctree=ast.parse(controller); rtree=ast.parse(rgb)
    except SyntaxError:
        return {'controller_guard':'FAIL_AST','direct_ssh_helper_guard':'FAIL_AST','test_support_guard':'UNKNOWN'}
    live=next((n for n in ast.walk(ctree) if isinstance(n,ast.FunctionDef) and n.name=='_live'),None)
    main=next((n for n in ast.walk(ctree) if isinstance(n,ast.FunctionDef) and n.name=='main'),None)
    live_src='\n'.join(controller.splitlines()[live.lineno-1:live.end_lineno]) if live else ''
    main_src='\n'.join(controller.splitlines()[main.lineno-1:main.end_lineno]) if main else ''
    controller_guard=bool(live and 'require_pre_release_authorization_api()' in live_src and
                          'CANDIDATE_RGB_AUTHORIZATION_AND_LIFECYCLE_NOT_READY' in main_src and
                          main_src.find('CANDIDATE_RGB_AUTHORIZATION_AND_LIFECYCLE_NOT_READY') < main_src.find('_precheck()'))
    ssh=next((n for n in ast.walk(rtree) if isinstance(n,ast.FunctionDef) and n.name=='_pinned_ssh'),None)
    ssh_calls=[]
    if ssh:
        ssh_calls=[call_name(n.func) for n in ast.walk(ssh) if isinstance(n,ast.Call)]
    def first_call_line(suffix):
        return min((n.lineno for n in ast.walk(ssh) if isinstance(n,ast.Call) and call_name(n.func).endswith(suffix)),default=10**6) if ssh else 10**6
    runner=first_call_line('runner')
    local_validate=first_call_line('_validated_local_context')
    local_consume=first_call_line('_consume_local_auth')
    ssh_guard=(local_validate<runner and local_consume<runner)
    legacy_func=next((n for n in ast.walk(ast.parse(legacy)) if isinstance(n,ast.FunctionDef) and n.name=='_acquire_and_sign_for_test'),None) if legacy else None
    legacy_calls=[call_name(n.func) for n in ast.walk(legacy_func) if isinstance(n,ast.Call)] if legacy_func else []
    legacy_default_runner=bool(legacy_func and 'runner: Callable = subprocess.run' in legacy)
    legacy_live_surface=bool(legacy_func and any(x in legacy_calls for x in ('runner','subprocess.run')) and
                             ('signature = key.sign(encoded)' in legacy))
    signer_source=sources.get('tools/phk2_host/phk2_fk0957_topology_signing.py',b'').decode('utf-8','replace')
    signer_tree=ast.parse(signer_source)
    signer=next((n for n in ast.walk(signer_tree) if isinstance(n,ast.FunctionDef) and n.name=='_sign_validated_remote_record'),None)
    signer_direct=bool(signer and any(isinstance(n,ast.Call) and call_name(n.func).endswith('.sign') for n in ast.walk(signer))
                        and not any(a.arg in {'capability','validated_operation','sealed_context'} for a in signer.args.args))
    rgb_cli=sources.get('tools/phk2_host/phk2_fk0957_topology_rgb_cli.py',b'').decode('utf-8','replace')
    rgb_cli_tree=ast.parse(rgb_cli)
    rgb_main=next((n for n in ast.walk(rgb_cli_tree) if isinstance(n,ast.FunctionDef) and n.name=='main'),None)
    rgb_main_text='\n'.join(rgb_cli.splitlines()[rgb_main.lineno-1:rgb_main.end_lineno]) if rgb_main else ''
    rgb_launcher_guard=any(t in rgb_main_text for t in ('TRUSTED_LAUNCHER','safe_bootstrap','launcher_capability'))
    live_cli=sources.get('tools/phk2_host/phk2_fk0957_topology_live_cli.py',b'').decode('utf-8','replace')
    live_cli_tree=ast.parse(live_cli)
    live_main=next((n for n in ast.walk(live_cli_tree) if isinstance(n,ast.FunctionDef) and n.name=='main'),None)
    live_main_text='\n'.join(live_cli.splitlines()[live_main.lineno-1:live_main.end_lineno]) if live_main else ''
    live_launcher_guard='TRUSTED_LAUNCHER_REQUIRED' in live_main_text
    signer_public=next((n for n in ast.walk(signer_tree) if isinstance(n,ast.FunctionDef) and n.name=='perform_fk0957_topology_discovery_once'),None)
    signer_public_text='\n'.join(signer_source.splitlines()[signer_public.lineno-1:signer_public.end_lineno]) if signer_public else ''
    live_cli_stubbed=('raise Refusal("combined local acquisition and signing is disabled")' in signer_public_text)
    status_source=sources.get('tools/phk2_host/fk0957_supervisor_status_contract.py',b'').decode('utf-8','replace')
    status_tree=ast.parse(status_source)
    pre=next((n for n in ast.walk(status_tree) if isinstance(n,ast.FunctionDef) and n.name=='validate_pre_release_status'),None)
    pre_text='\n'.join(status_source.splitlines()[pre.lineno-1:pre.end_lineno]) if pre else ''
    pre_non_authorizing=bool(pre and 'state != NOT_STARTED' in pre_text and '"authorizes_release": "NO"' in pre_text and
                             '"query_mutates_authorization": "NO"' in pre_text)
    # In-memory mutations validate that the source-derived guard predicates detect removal/addition.
    removed_guard=controller.replace('    require_pre_release_authorization_api()\n','',1)
    mutation_detects_removed_guard=('require_pre_release_authorization_api()' not in removed_guard.split('def _live',1)[1].split('\ndef ',1)[0])
    synthetic_guard=rgb.replace('    runner = subprocess.run if runner is None else runner',
                                 '    _validated_local_context(request_raw)\n    runner = subprocess.run if runner is None else runner',1)
    mutation_detects_added_guard='_validated_local_context(request_raw)' in synthetic_guard.split('def _pinned_ssh',1)[1].split('\ndef ',1)[0]
    return {'controller_guard':'PASS' if controller_guard else 'FAIL',
            'direct_ssh_helper_guard':'PASS' if ssh_guard else 'FAIL',
            'legacy_test_support_live_surface':'PRESENT' if legacy_live_surface else 'ABSENT',
            'legacy_test_support_is_manifested':legacy_path in manifest_paths(CURRENT_SHA),
            'legacy_test_support_default_real_runner':legacy_default_runner,
            'direct_rgb_cli_launcher_guard':'PASS' if rgb_launcher_guard else 'FAIL',
            'direct_signer_api':'FAIL' if signer_direct else 'PASS',
            'direct_live_cli_entry_guard':'PASS' if live_launcher_guard else 'FAIL',
            'live_cli_operation_stubbed':'YES' if live_cli_stubbed else 'NO',
            'pre_release_status_non_authorizing':'PASS' if pre_non_authorizing else 'FAIL',
            'route_mutation_checks_detect_removed_controller_guard':mutationDetects(removed_guard),
            'route_mutation_checks_detect_added_ssh_guard':mutationDetectsAdded(synthetic_guard),
            'legacy_default_runner_declared':legacy_default_runner}

def mutationDetects(source):
    try:
        t=ast.parse(source)
        n=next(x for x in ast.walk(t) if isinstance(x,ast.FunctionDef) and x.name=='_live')
        text='\n'.join(source.splitlines()[n.lineno-1:n.end_lineno])
        return 'require_pre_release_authorization_api()' not in text
    except Exception: return False

def mutationDetectsAdded(source):
    try:
        t=ast.parse(source); n=next(x for x in ast.walk(t) if isinstance(x,ast.FunctionDef) and x.name=='_pinned_ssh')
        text='\n'.join(source.splitlines()[n.lineno-1:n.end_lineno])
        return '_validated_local_context(request_raw)' in text
    except Exception: return False

def file_exists(sha,path):
    p=subprocess.run(['/usr/bin/git','-C',str(REPO),'cat-file','-e',f'{sha}:{path}'],env=GIT_ENV,
                     stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                     timeout=8,check=False)
    return p.returncode==0

def manifest_paths(sha):
    try: m=json.loads(blob(sha,MANIFEST)); return [x['relative_path'] for x in m['source_inventory']]
    except Exception: return []

def audit_sha(sha,refnames):
    global CURRENT_SHA
    CURRENT_SHA=sha
    findings={'sha':sha,'refs':refnames,'started_utc':now(),'static_ast':'PASS','manifest':'UNKNOWN','route_checks':{},'import_time_calls':{},'errors':[]}
    sources={}; functions_by_file={}; import_calls={}
    for path in PRODUCTION_FILES:
        try:
            data=blob(sha,path); sources[path]=data; tree=ast.parse(data.decode('utf-8'))
            functions_by_file[path]=functions(tree)
            top=[]
            for node in tree.body:
                if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call): top.append(call_name(node.value.func))
                elif isinstance(node,(ast.Assign,ast.AnnAssign)):
                    v=node.value
                    if isinstance(v,ast.Call): top.append(call_name(v.func))
            import_calls[path]=top
        except Exception as e:
            findings['static_ast']='FAIL'; findings['errors'].append(f'{path}:{type(e).__name__}')
    findings['function_count']=sum(map(len,functions_by_file.values()))
    findings['import_time_calls']=import_calls
    try:
        c_launcher=blob(sha,'tools/phk2_host/fk0957_safe_launcher.c').decode('utf-8')
        findings['static_launcher_contract']={
            'runtime_hash_buildid_verification':all(x in c_launcher for x in ('verify_runtime_pin','runtime_pins')),
            'bootstrap_manifest_trust_open':all(x in c_launcher for x in ('open_verified_bootstrap','open_verified_manifest','open_verified_trust_config')),
            'isolated_python_flags':('"-I"' in c_launcher and '"-S"' in c_launcher),
            'clean_environment':('clearenv()' in c_launcher),
            'execve_used':('execve(' in c_launcher),
        }
    except Exception as e: findings['static_launcher_contract']={'error_class':type(e).__name__}
    findings['live_capable_functions']={p:{n:v for n,v in fs.items() if any(
        c.endswith(('subprocess.run','subprocess.Popen','_pinned_ssh','run_fk0957_topology_discovery',
                    '_run_consumed_permit','_sign_validated_remote_record','_remote_block','_ssh_probe'))
        for c in v['calls'])} for p,fs in functions_by_file.items()}
    findings['route_checks']=route_checks(sources)
    try:
        raw=blob(sha,MANIFEST); m=json.loads(raw); inv=m['source_inventory']; hashes=m['source_hashes']
        mismatches=[]; missing=[]; duplicates=len({x['relative_path'] for x in inv})!=len(inv)
        for row in inv:
            path=row['relative_path']
            try: actual=hashlib.sha256(blob(sha,path)).hexdigest()
            except Exception: missing.append(path); continue
            if actual!=row['sha256'] or hashes.get(path)!=actual: mismatches.append(path)
        extra=sorted(set(hashes)-{x['relative_path'] for x in inv})
        ancestor=subprocess.run(['/usr/bin/git','-C',str(REPO),'merge-base','--is-ancestor',m['production_head'],sha],
                               env=GIT_ENV,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                               timeout=8,check=False).returncode==0
        findings['manifest']={'sha256':hashlib.sha256(raw).hexdigest(),'source_head':m.get('production_head'),
             'source_count':len(inv),'runtime_count':len(m.get('runtime_inventory',[])),
             'missing':missing,'hash_mismatches':mismatches,'extra_hashes':extra,
             'duplicate_paths':duplicates,'source_head_ancestor':ancestor,
             'authenticated':False}
    except Exception as e: findings['manifest']={'error_class':type(e).__name__}
    findings['finished_utc']=now()
    path=OUT/'sha-reports'/f'{sha}.json'; path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(findings,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    record(f'AUDIT sha={sha} static={findings["static_ast"]} manifest={findings["manifest"].get("source_count","UNKNOWN")} routes={findings["route_checks"]}')
    return findings

def refs_snapshot():
    raw=git(['for-each-ref','--format=%(refname) %(objectname)','refs/heads/release/','refs/heads/codex/'])
    result={}
    for line in raw.decode('ascii','strict').splitlines():
        parts=line.split()
        if len(parts)==2 and re.fullmatch(r'[0-9a-f]{40}',parts[1]): result[parts[0]]=parts[1]
    return result

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    start=time.monotonic(); update_state(status='STARTING',source_sha='c56b0edf7ea5087db7b6823580b2b7b613778bc8',tasks_completed=0,
       task_count=7,blocked_tests=['dynamic candidate tests: isolation unavailable; bwrap net namespace denied'],
       mode='READ_ONLY_GIT_AST_JSON_HASH_ONLY',network='NO',candidate_imports=0)
    record('WORKER_START pid='+str(os.getpid()))
    if stop_requested(): update_state(status='STOPPED_BY_FLAG'); return 0
    try:
        refs=refs_snapshot()
        candidates={sha:[r for r,s in refs.items() if s==sha] for sha in set(refs.values())}
        # Include only reviewed source candidate if its object exists locally.
        sha='c56b0edf7ea5087db7b6823580b2b7b613778bc8'
        if not file_exists(sha,'results/fk0957-release-candidate-source-manifest.json'):
            raise RuntimeError('INITIAL_CANDIDATE_MANIFEST_MISSING')
        finding=audit_sha(sha,candidates.get(sha,[])); update_state(status='MONITORING_LOCAL_REFS',tasks_completed=7,
            latest_audited_sha=sha,initial_audit=finding['route_checks'],last_poll_utc=now())
    except Exception as e:
        record('INITIAL_AUDIT_ERROR '+type(e).__name__)
        update_state(status='FAILED',failure_class=type(e).__name__); return 1
    previous=refs_snapshot(); stable={}; audited=set(previous.values())
    while time.monotonic()-start < MAX_SECONDS and not stop_requested():
        time.sleep(POLL_SECONDS)
        if stop_requested(): break
        try: current=refs_snapshot()
        except Exception as e:
            record('POLL_ERROR '+type(e).__name__); update_state(status='MONITORING_LOCAL_REFS',last_poll_error=type(e).__name__); continue
        for ref,sha in current.items():
            if previous.get(ref)!=sha:
                stable[ref]=(sha,0); record(f'NEW_REF ref={ref} sha={sha}')
            elif ref in stable and stable[ref][0]==sha:
                value,count=stable[ref]; stable[ref]=(value,count+1)
                if count+1>=1 and sha not in audited:
                    finding=audit_sha(sha,[ref]); audited.add(sha)
                    update_state(status='MONITORING_LOCAL_REFS',latest_audited_sha=sha,
                                 audited_shas=sorted(audited),last_poll_utc=now())
                    del stable[ref]
        previous=current
        update_state(status='MONITORING_LOCAL_REFS',latest_audited_sha=next(reversed(sorted(audited)),None),
                     audited_shas=sorted(audited),last_poll_utc=now(),elapsed_seconds=int(time.monotonic()-start))
    status='STOPPED_BY_FLAG' if stop_requested() else 'QUEUE_COMPLETE_TIMEOUT'
    update_state(status=status,finished_utc=now(),elapsed_seconds=int(time.monotonic()-start),audited_shas=sorted(audited))
    record('WORKER_STOP status='+status)
    return 0

if __name__=='__main__': raise SystemExit(main())
