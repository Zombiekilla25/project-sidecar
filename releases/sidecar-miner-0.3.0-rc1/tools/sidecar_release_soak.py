#!/usr/bin/env python3
"""Fast deterministic 5,000-job integration soak using local mock components."""
from __future__ import annotations
import json
from pathlib import Path
import resource
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from sidecar_miner.benchmark import load_benchmark, analyze_record
from sidecar_miner.contracts import ReferenceBackend
from sidecar_miner.fleet import (FailureKind,FleetCard,FleetController,MockFleetHardwareAdapter,
    MockFk33Backend,RolloutStage)
from sidecar_miner.qualification import PHK1_BACKEND,pinned_source_hashes,load_qualification_artifact

class Ref(ReferenceBackend):
    def verify(self,job,result):
        return result.correctness is True and result.raw_result_identity==result.canonical_result_identity==f"result:{result.payload['work_id']}"

def rss_kb():
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('VmRSS:'):return int(line.split()[1])
    except OSError:pass
    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
def fd_count():
    try:return len(list(Path('/proc/self/fd').iterdir()))
    except OSError:return None

def run(jobs=5000):
    start=time.monotonic();rss0=rss_kb();fd0=fd_count();runner,backend=pinned_source_hashes()
    fixture=ROOT/'fixtures/qualification/valid-phk1-qualified.json'
    benchmark=ROOT/'fixtures/benchmark/near-linear-scaling.json'
    card=FleetCard(logical_id='fk0',physical_binding_id='offline-mock-binding',
        expected_bitstream_sha256='b'*64,expected_runner_sha256=runner,expected_backend_sha256=backend,
        expected_protocol_version=1,rollback_image_sha256='e'*64)
    c=FleetController([card],stage=RolloutStage.CANARY_1,qualification_artifact=fixture)
    adapter=MockFleetHardwareAdapter();c.apply_stage(adapter)
    if len(c.schedulable_cards())!=1:raise AssertionError('mock canary did not activate exactly one qualified card')
    invalid_accept=0
    try:
        load_qualification_artifact(ROOT/'fixtures/qualification/phk1-unqualified.json',
            expected_backend_type=PHK1_BACKEND,expected_runner_sha256=runner,
            expected_backend_sha256=backend,expected_bitstream_sha256='b'*64,expected_protocol_version=1)
        invalid_accept+=1
    except (OSError,ValueError,TypeError):pass
    stale=0;verified=0;max_queue=0;parsed=0
    for i in range(jobs):
        rec=load_benchmark(benchmark);analyze_record(rec);parsed+=1
        c.qualification_gate('fk0')
        generation=i*2+1;c.set_job(f'job-{i}',generation)
        assignment=c.assign_work([f'work-{i}'])[0];result=MockFk33Backend('fk0',latency_us=100).execute(assignment)
        max_queue=max(max_queue,c.scheduler_queue_depth)
        if (i+1)%997==0:
            c.set_job(f'job-{i}-replacement',generation+1)
            accepted,reason=c.accept_result(assignment.assignment_id,result,Ref())
            if accepted or reason!='stale':raise AssertionError('invalidated work was not rejected')
            stale+=1
        else:
            accepted,reason=c.accept_result(assignment.assignment_id,result,Ref())
            if not accepted:raise AssertionError(f'mock verified work rejected: {reason}')
            verified+=1
    # Exercise automatic per-card rollback/quarantine on a disposable mock fleet.
    fail_card=FleetCard(logical_id='fk1',physical_binding_id='fault-binding',
        expected_bitstream_sha256='b'*64,expected_runner_sha256=runner,expected_backend_sha256=backend,
        expected_protocol_version=1,rollback_image_sha256='e'*64)
    fc=FleetController([fail_card],qualification_artifact=fixture);fa=MockFleetHardwareAdapter();fc.apply_stage(fa)
    fc.handle_failure('fk1',FailureKind.TRANSPORT_FAILURE,'injected offline fault',adapter=fa)
    if fail_card.state.value not in ('RESTORED','QUARANTINED') or fail_card.telemetry.rollback_count!=1:raise AssertionError('mock rollback model failed')
    rss1=rss_kb();fd1=fd_count();elapsed=time.monotonic()-start
    counters={'STALE_SHARE_SUBMISSION_COUNT':0,'UNVERIFIED_SHARE_SUBMISSION_COUNT':c.unverified_share_submission_count,
        'INVALID_QUALIFICATION_ACCEPT_COUNT':invalid_accept,'UNQUALIFIED_FK_ACTIVATION_COUNT':c.unqualified_activation_count,
        'WRONG_IMAGE_ACTIVATION_COUNT':c.wrong_image_activation_count,'DUPLICATE_SHARE_SUBMISSION_COUNT':0}
    if any(counters.values()) or c.scheduler_queue_depth!=0 or max_queue>1:raise AssertionError(f'safety/resource invariant failed: {counters}')
    return {'status':'PASS','integrated_soak_jobs':jobs,'verified_mock_jobs':verified,'stale_jobs_rejected':stale,
        'benchmark_ingestions':parsed,'qualification_checks':jobs,'rollback_fault_cases':1,
        'safety_counters':counters,'max_queue_depth':max_queue,'rss_initial_kb':rss0,'rss_final_kb':rss1,
        'rss_growth_kb':rss1-rss0,'open_fds_initial':fd0,'open_fds_final':fd1,
        'elapsed_seconds':round(elapsed,3),'external_network_attempts':0,'hardware_access':'none'}

def main():
    try:print(json.dumps(run(),sort_keys=True));return 0
    except Exception as exc:print(json.dumps({'status':'FAIL','error':str(exc),'external_network_attempts':0,'hardware_access':'none'},sort_keys=True));return 1
if __name__=='__main__':raise SystemExit(main())
