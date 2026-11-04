"""Read-only and policy-only command line for the offline FK33 fleet model."""
from __future__ import annotations
import argparse
import json
import time

from .fleet import FleetController,RolloutStage,QualificationGateError,NEXT_STAGE

def _controller(config_path,state_path=None):
    c=FleetController.from_config(config_path)
    if state_path:c.restore_state(state_path)
    return c

def _text_status(status):
    f=status["fleet"]
    print(f"stage={status['rollout_stage']} active={f['active_fk_count']}/{f['card_count']} qualified={f['qualified_fk_count']} queue={f['scheduler_queue_depth']} stale={f['stale_result_count']} hardware_access=none")
    print("CARD STATE       QUALIFIED HEALTH       JOB_FINGERPRINT   LATENCY_US ERRORS ROLLBACKS")
    for c in status["cards"]:
        t=c["telemetry"];lat=t["average_latency_us"]
        print(f"{c['logical_id']:<4} {c['state']:<14} {str(c['qualified']).lower():<9} {c['health']:<12} "
            f"{(c['job_fingerprint'] or '-')[:16]:<16} {lat if lat is not None else 'UNKNOWN':>10} "
            f"{c['error_count']:>6} {c['rollback_count']:>9}")

def main(argv=None):
    p=argparse.ArgumentParser(prog="sidecar-miner fleet",description="Offline FK33 fleet lifecycle model")
    p.add_argument("--fleet",help="public-safe fleet JSON configuration")
    p.add_argument("--state-file",help="optional public-safe persisted fleet state")
    sub=p.add_subparsers(dest="command",required=True)
    def scoped(cmd):
        cmd.add_argument("--fleet",dest="fleet",default=argparse.SUPPRESS,help="public-safe fleet JSON configuration")
        cmd.add_argument("--state-file",dest="state_file",default=argparse.SUPPRESS,help="optional public-safe persisted fleet state")
    status=sub.add_parser("status");scoped(status);status.add_argument("--json",action="store_true")
    plan=sub.add_parser("plan");scoped(plan);plan.add_argument("--stage",choices=[s.value for s in RolloutStage])
    rollout=sub.add_parser("rollout");scoped(rollout);rollout.add_argument("--dry-run",action="store_true",required=True)
    disable=sub.add_parser("disable");scoped(disable);disable.add_argument("--card",required=True)
    enable=sub.add_parser("enable");scoped(enable);enable.add_argument("--card",required=True)
    watch=sub.add_parser("watch");scoped(watch);watch.add_argument("--interval",type=float,default=2.0);watch.add_argument("--iterations",type=int,default=0);watch.add_argument("--json",action="store_true")
    a=p.parse_args(argv)
    if not getattr(a,"fleet",None):p.error("--fleet is required")
    if a.command=="watch" and (a.interval<=0 or a.iterations<0):p.error("watch interval must be positive; iterations nonnegative")
    try:c=_controller(a.fleet,a.state_file)
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(json.dumps({"status":"CONFIG_ERROR","reason":str(exc),"hardware_access":"none"},sort_keys=True));return 2
    try:
        if a.command=="status":
            status=c.status()
            if a.json:print(json.dumps(status,sort_keys=True))
            else:_text_status(status)
            return 0
        if a.command=="plan":
            stage=RolloutStage(a.stage) if a.stage else c.stage
            out=c.rollout_plan(stage);nxt=NEXT_STAGE[c.stage];out["next_stage"]=nxt.value if nxt else None
            out["health_gate_required_before_expansion"]=stage!=c.stage
            print(json.dumps(out,sort_keys=True));return 0
        if a.command=="rollout":
            out=c.rollout_plan();out["mock_actions_only"]=True
            print(json.dumps(out,sort_keys=True));return 0
        if a.command=="disable":
            c.disable_card(a.card)
            if a.state_file:c.persist_state(a.state_file)
            print(json.dumps({"status":"DISABLED_FROM_SCHEDULER","card":a.card,"hardware_access":"none"},sort_keys=True));return 0
        if a.command=="enable":
            c.enable_card(a.card)
            if a.state_file:c.persist_state(a.state_file)
            print(json.dumps({"status":"READY_FOR_GUARDED_ROLLOUT","card":a.card,"hardware_access":"none"},sort_keys=True));return 0
        if a.command=="watch":
            iteration=0
            while a.iterations==0 or iteration<a.iterations:
                value=c.status()
                print(json.dumps(value,sort_keys=True) if a.json else f"{value['rollout_stage']} active={value['fleet']['active_fk_count']} qualified={value['fleet']['qualified_fk_count']} queue={value['fleet']['scheduler_queue_depth']} state={value['scheduler']['state']}",flush=True)
                iteration+=1
                if a.iterations==0 or iteration<a.iterations:time.sleep(a.interval)
            return 0
    except (ValueError,KeyError,TypeError,QualificationGateError,RuntimeError) as exc:
        print(json.dumps({"status":"REJECTED","reason":str(exc),"hardware_access":"none"},sort_keys=True));return 3
    return 2

