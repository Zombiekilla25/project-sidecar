from __future__ import annotations
import argparse,json,sys
from dataclasses import replace
from .config import Config

def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0]=="qualification":
        from .qualification_cli import qualification_main
        return qualification_main(argv[1:])
    if argv and argv[0]=="status":
        from .qualification_cli import status_main
        return status_main(argv[1:])
    if argv and argv[0]=="fleet":
        from .fleet_cli import main as fleet_main
        return fleet_main(argv[1:])
    if argv and argv[0]=="benchmark":
        from .benchmark_cli import main as benchmark_main
        return benchmark_main(argv[1:])
    p=argparse.ArgumentParser(prog='sidecar-miner',description='Offline-first Project Sidecar PRL miner')
    p.add_argument('--version',action='store_true')
    p.add_argument('--config');p.add_argument('--pool');p.add_argument('--wallet');p.add_argument('--worker');p.add_argument('--gpu');p.add_argument('--gpu-id',type=int)
    p.add_argument('--mode',choices=('auto','gpu-only','sidecar'));p.add_argument('--fk-count',type=int,choices=(1,2,4,8))
    p.add_argument('--gpu-timing');p.add_argument('--fk-timing');p.add_argument('--dry-run',action='store_true',help='run one local mock PRL job and share; never connects to a pool')
    p.add_argument('--canary-shares',type=int,help='bounded share attempt limit for a supervised canary')
    p.add_argument('--live',action='store_true',help='explicitly request live mode; execution remains gated and is not enabled in this build')
    p.add_argument('--state-file',default='sidecar-miner-recovery.json',help='public-safe supervisor recovery/status snapshot')
    status=p.add_mutually_exclusive_group();status.add_argument('--status',action='store_true');status.add_argument('--status-json',action='store_true')
    p.add_argument('--fk-fixture',choices=('operand-vector-001',),help='run the offline PHK1 fixture adapter; requires --mode sidecar and --dry-run')
    p.add_argument('--show-config',action='store_true',help='print redacted effective configuration')
    a=p.parse_args(argv)
    if a.version:
        from .release_info import version_line
        print(version_line());return 0
    c=Config.load(a.config)
    c=replace(c,**{k:v for k,v in {'pool':a.pool,'wallet':a.wallet,'worker':a.worker,'gpu':a.gpu,'gpu_id':a.gpu_id,'mode':a.mode,'fk_count':a.fk_count,'gpu_timing':a.gpu_timing,'fk_timing':a.fk_timing,'canary_shares':a.canary_shares,'live_enabled':True if a.live else None}.items() if v is not None})
    if c.mode not in ('auto','gpu-only','sidecar') or c.fk_count not in (1,2,4,8):p.error('invalid mode or FK count')
    if c.canary_shares<0 or c.canary_shares>1000:p.error('--canary-shares must be between 0 and 1000')
    if a.status or a.status_json:
        from .supervisor import SidecarMinerSupervisor,load_recovery_status
        supervisor=SidecarMinerSupervisor(c);state=load_recovery_status(a.state_file,c)
        print(json.dumps(state,sort_keys=True) if a.status_json else supervisor.render_status_text_from(state))
        return 0
    if a.show_config:
        print(json.dumps({'pool_configured':bool(c.pool),'wallet_configured':bool(c.wallet),'worker_configured':bool(c.worker),'gpu':c.gpu,'gpu_id':c.gpu_id,'mode':c.mode,'fk_count':c.fk_count,'fk_devices':list(c.fk_devices),'gpu_timing_configured':bool(c.gpu_timing),'fk_timing_configured':bool(c.fk_timing)},sort_keys=True));return 0
    if a.live and not a.dry_run:
        print(json.dumps({'status':'BLOCKED','reason':'live execution is not enabled by this build; no network connection attempted','live_pool_connections':0},sort_keys=True))
        return 2
    if not a.dry_run:
        print('sidecar-miner live pool connections are disabled; use --dry-run for the offline fixture')
        return 0
    try:
        if a.canary_shares is not None or c.canary_shares:
            from .offline import run_supervised_offline_canary
            r=run_supervised_offline_canary(c.mode,c.canary_shares)
            print(json.dumps(r,sort_keys=True));return 0 if r['success'] else 1
        if a.fk_fixture:
            if c.mode!='sidecar':p.error('--fk-fixture requires --mode sidecar')
            from .offline import run_fk_fixture_session
            r=run_fk_fixture_session()
            out={'offline':True,'status':'PASS' if r['accepted'] else 'FAIL','mode':r['choice'].mode,
                 'scheduler_decision':r['choice'].decision.value,'accepted':r['accepted'],
                 'job_generation':r['job'].generation,'fk_backend':r['fk_result'].backend_id,
                 'raw_result_identity':r['fk_result'].raw_result_identity,
                 'canonical_result_identity':r['fk_result'].canonical_result_identity,
                 'share_submissions':len(r['server'].submissions),'live_pool_connections':0}
            print(json.dumps(out,sort_keys=True));return 0 if r['accepted'] else 1
        from .offline import run_offline_session
        r=run_offline_session(c.mode,c.fk_count,c.gpu_timing or None,c.fk_timing or None)
    except Exception as e:
        print(json.dumps({'offline':True,'status':'FAIL','error':str(e),'live_pool_connections':0},sort_keys=True));return 1
    out={'offline':True,'status':'PASS' if r['accepted'] else 'FAIL','mode':r['choice'].mode,'scheduler_decision':r['choice'].decision.value,'accepted':r['accepted'],'job_generation':r['job'].generation,'gpu_batches':r['telemetry'].gpu_batches,'fk_batches':r['telemetry'].fk_batches,'fallback_count':r['telemetry'].fallback_count,'share_submissions':len(r['server'].submissions),'wallet_configured':bool(c.wallet),'live_pool_connections':0}
    print(json.dumps(out,sort_keys=True));return 0 if r['accepted'] else 1
if __name__=='__main__':raise SystemExit(main())
