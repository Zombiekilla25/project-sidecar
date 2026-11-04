"""Full loopback-only offline PRL session for application dry-run."""
from __future__ import annotations
import pearl_mining as pm
from .models import MiningJob,Candidate
from .backends import MockGpuBackend,MockFk33Backend
from .integrated_scheduler import IntegratedScheduler,load_timing_inputs
from .integrated_miner import IntegratedMiner
from .mock_stratum import MockKryptexServer
from .pearlhash import PearlHashCpuVerifier
from .pearlhash_fields import proof_context
from .stratum import StratumClient
from .telemetry import Telemetry
from .fk33_backend import (Fk33TargetConfig, TargetLockEvidence, MockPhk1Transport,
    RawBscanFk33Backend, Fk33VectorWork)
from .contracts import WorkBatch
import time

FIXTURE_TARGET=(0xffff<<240)
def fixture_job_payload(sequence=1):
    h=pm.IncompleteBlockHeader(0,b'\0'*32,b'1'*32,0x66666666,0x2100ffff).to_bytes()
    return MiningJob('offline-integrated-job',sequence,h,FIXTURE_TARGET,12345,2,clean=True)
def fixture_candidate(job):
    rows=pm.PeriodicPattern.from_list(list(range(16)))
    config=pm.MiningConfiguration(2048,128,pm.MMAType.Int7xInt7ToInt32,rows,rows)
    proof=pm.mine(256,256,2048,pm.IncompleteBlockHeader.from_bytes(job.header),config,cert_version=job.cert_version)
    _,_,sigma,b_seed,_=proof_context(job,proof,pm)
    return Candidate(job.job_id,job.fingerprint,proof,0,1,sigma,b_seed,job.generation)

def run_offline_session(mode='auto',fk_count=1,gpu_timing_path=None,fk_timing_path=None,reject_shares=False,fk_fault=None,fk_unavailable=False,candidate_factory=None,reference_verify=None,fk_on_execute=None,gpu_backend=None):
    job=fixture_job_payload();server=MockKryptexServer(job,reject_shares=reject_shares);telemetry=Telemetry()
    client=StratumClient('127.0.0.1',server.port,'offline.worker',timeout=3,telemetry=telemetry)
    if fk_on_execute=='new-clean':
        def fk_on_execute(batch):
            current=client.current_job
            client._dispatch({'id':None,'method':'mining.notify','params':{'job_id':'offline-clean-replacement','header':current.header.hex(),'target':f'{current.target:064x}','height':current.height,'cert_version':current.cert_version,'clean':True}})
    fks=[MockFk33Backend(f'fk-mock-{i}',fault=fk_fault,on_execute=fk_on_execute) for i in range(0 if fk_unavailable else fk_count)]
    gpu_timing,fk_timing=load_timing_inputs(gpu_timing_path,fk_timing_path)
    scheduler=IntegratedScheduler(mode,gpu_timing,fk_timing,fks)
    miner=IntegratedMiner(scheduler,gpu_backend or MockGpuBackend(candidate_factory or fixture_candidate),reference_verify or PearlHashCpuVerifier().verify,telemetry,current_job_provider=lambda:client.current_job)
    try:
        client.add_job_listener(miner.on_job);client.connect();received=client.next_job(timeout=3)
        outcome=miner.process_job(received,submitter=client)
        return {'accepted':bool(outcome.submissions and outcome.submissions[-1].get('result') is True),'choice':outcome.choice,'outcome':outcome,'telemetry':telemetry,'server':server,'job':received}
    finally:
        client.close();server.close()

def run_fk_fixture_session(fault=None, backend_override=None):
    """Loopback PRL + scheduler + mock PHK1 vector gate + CPU proof/share path.

    The fixed PHK1 vector validates protocol integration only; it is not claimed
    to be a transform of the separately generated mining candidate.
    """
    from .fk33_backend import VECTOR_ID
    from .integrated_scheduler import IntegratedScheduler
    from .verification import verify_candidate
    from pathlib import Path
    job_hint=fixture_job_payload();server=MockKryptexServer(job_hint);telemetry=Telemetry()
    client=StratumClient('127.0.0.1',server.port,'offline.worker',timeout=3,telemetry=telemetry)
    config=Fk33TargetConfig('fk-fixture-0','fixture-selector',0x12345678,None,1)
    evidence=TargetLockEvidence(1,0x12345678,None,1,time.monotonic())
    transport=MockPhk1Transport(fault=fault)
    backend=backend_override or RawBscanFk33Backend(config,transport,evidence)
    job=None; hello=None; fk_result=None; verification=None; submission=None; choice=None
    try:
        backend.initialize();hello=backend.hello()
        scheduler=IntegratedScheduler('sidecar',fk_backends=[backend])
        client.connect();job=client.next_job(timeout=3)
        choice=scheduler.choose(job)
        if choice.mode!='sidecar':raise RuntimeError('fixture run did not select Sidecar')
        backend.prepare_job(job)
        payload=(Path(__file__).resolve().parents[1]/'fixtures/operand-vector-001/FK_INPUT_PAYLOAD.bin').read_bytes()
        batch=WorkBatch.create(job.fingerprint,job.generation,f'{job.generation}-fk-fixture-0',payload,8,
            assignment=(backend.backend_id,),context=Fk33VectorWork(payload,VECTOR_ID))
        fk_result=backend.execute_batch(batch)
        if fk_result.correctness is not True:raise RuntimeError('PHK1 vector fixture verification failed')
        # Mining candidate is independently generated and CPU-verified; fixed
        # vector result is a transport/protocol gate, not its proof digest.
        candidate=fixture_candidate(job)
        verification=verify_candidate(job,candidate,PearlHashCpuVerifier().verify,telemetry)
        if not verification.accepted:raise RuntimeError('CPU PearlHash candidate verification failed')
        submission=client.submit(verification)
        return {'accepted':submission.get('result') is True,'choice':choice,'job':job,
                'hello':hello,'fk_result':fk_result,'verification':verification,
                'submission':submission,'server':server,'telemetry':telemetry}
    except Exception as exc:
        return {'accepted':False,'choice':choice,'job':job,'hello':hello,
                'fk_result':fk_result,'verification':verification,'submission':submission,
                'error':str(exc),'server':server,'telemetry':telemetry}
    finally:
        backend.close();client.close();server.close()


def run_supervised_offline_canary(mode="gpu-only",canary_shares=1,gpu_timing_path=None,fk_timing_path=None,
                                  reject_shares=False,stale_before_submit=False,backend_failure=False):
    """Run the supervisor against loopback Stratum and mock backends only."""
    from .config import Config
    from .supervisor import (BackendQualificationState,OfflineFixtureAdapter,SidecarMinerSupervisor,SignalStopController)
    from .verification import verify_candidate
    from pathlib import Path

    job_hint=fixture_job_payload();server=MockKryptexServer(job_hint,reject_shares=reject_shares)
    telemetry=Telemetry();client=StratumClient("127.0.0.1",server.port,"offline.worker",timeout=3,telemetry=telemetry)
    fk=None
    class Adapter(OfflineFixtureAdapter):
        def __init__(self):self.selected_backend="gpu"
        @property
        def backend_name(self):return "mock-fk" if self.selected_backend=="gpu+fk" else "mock-gpu"
        def connect(self):client.connect()
        def authorize(self):return client.connected
        def receive_job(self,timeout):return client.next_job(timeout=timeout)
        def backend_ready(self,selected_mode):
            nonlocal fk
            self.selected_backend=selected_mode
            if selected_mode!="gpu+fk":return True
            from .fk33_backend import Fk33TargetConfig,TargetLockEvidence,MockPhk1Transport,RawBscanFk33Backend
            fk=RawBscanFk33Backend(Fk33TargetConfig("fk-offline","fixture-selector",0x12345678,None,1),
                MockPhk1Transport(),TargetLockEvidence(1,0x12345678,None,1,time.monotonic()))
            fk.initialize();fk.hello();return fk.healthy
        def execute_job(self,job):
            if backend_failure:raise RuntimeError("fixture backend failure")
            if self.selected_backend=="gpu+fk":
                from .contracts import WorkBatch
                from .fk33_backend import Fk33VectorWork,VECTOR_ID
                payload=(Path(__file__).resolve().parents[1]/"fixtures/operand-vector-001/FK_INPUT_PAYLOAD.bin").read_bytes()
                fk.prepare_job(job)
                batch=WorkBatch.create(job.fingerprint,job.generation,f"{job.generation}-offline-fk",payload,8,
                    assignment=(fk.backend_id,),context=Fk33VectorWork(payload,VECTOR_ID))
                result=fk.execute_batch(batch)
                if result.correctness is not True:raise RuntimeError("mock FK vector gate failed")
            candidate=fixture_candidate(job)
            return verify_candidate(job,candidate,PearlHashCpuVerifier().verify,telemetry)
        def current_job(self):return client.current_job
        def encode_share(self,verification):
            if stale_before_submit:
                current=client.current_job
                client._dispatch({"id":None,"method":"mining.notify","params":{
                    "job_id":"offline-clean-replacement","header":current.header.hex(),
                    "target":f"{current.target:064x}","height":current.height,
                    "cert_version":current.cert_version,"clean":True}})
            from .share_encoder import build_prl_submit_params
            return build_prl_submit_params(client.current_job,verification.share.candidate,telemetry)
        def submit_encoded(self,verification,encoded,*,on_attempt):return client.submit_encoded(verification,encoded,on_attempt=on_attempt)
        def stop_accepting_work(self):pass
        def cancel_queued(self):pass
        def wait_active(self,timeout):pass
        def close_backend(self):
            if fk:fk.close()
        def disconnect(self):client.close();server.close()
        def flush_evidence(self):pass

    config=Config(pool=f"127.0.0.1:{server.port}",wallet="offline.fixture",worker="offline.worker",
        mode=mode,gpu_id=0,canary_shares=canary_shares,live_enabled=False,
        gpu_timing=gpu_timing_path or "",fk_timing=fk_timing_path or "")
    use_fk=mode=="sidecar" or (mode=="auto" and bool(gpu_timing_path and fk_timing_path))
    ready=BackendQualificationState(True,use_fk,"fixture-gpu-qualification",
        "fixture-fk-qualification" if use_fk else None)
    supervisor=SidecarMinerSupervisor(config,qualifications=ready,canary_shares=canary_shares)
    adapter=Adapter()
    try:
        with SignalStopController(supervisor):
            result=supervisor.run_one_share_canary(adapter,live=False)
        return {"offline":True,"success":result.success,"state":supervisor.state.value,
            "mode":mode,"backend":adapter.backend_name,"share_attempts":result.share_attempts,
            "share_verified":result.share_verified,"share_submitted":result.share_submitted,
            "pool_response":result.pool_response,"shutdown_clean":result.shutdown_clean,
            "error":result.error,
            "events":list(supervisor.events.records),
            "mock_pool_submissions":len(server.submissions),"live_pool_connections":0,
            "scheduler_choice":"SIDECAR_MOCK" if adapter.selected_backend=="gpu+fk" else "GPU_ONLY"}
    finally:
        client.close();server.close()
