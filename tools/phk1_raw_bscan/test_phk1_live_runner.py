import datetime as dt
import hashlib
import json
import tempfile
import unittest
import io
import os
from pathlib import Path
from unittest import mock
from types import SimpleNamespace

os.environ.setdefault("PHK1_ROLLBACK_BITSTREAM", "/tmp/XBT_V4P1_lock_rehearsal.bit")
os.environ.setdefault("PHK1_MAINTENANCE_GENERATION", "fixture-run-001")

from tools.phk1_raw_bscan.phk1_live_runner import (AUTHORITATIVE_MAP_PATH, BITSTREAM_SHA, CANONICAL_SHA, HELLO_FIXTURE,
    CANDIDATE_BITSTREAM, CANDIDATE_MANIFEST, QUALIFICATION_MANIFEST, ROLLBACK_BINDING, ROLLBACK_BITSTREAM,
    RAW_SHA, VECTOR_FIXTURE, VECTOR_SHA, RunnerError, run_operation,
    RpcBackend, validate_target_lock, normalize_idcode, _transcript_check)

ROOT = Path(__file__).resolve().parents[2]
_LOCAL_PAYLOAD = Path("/home/rmann/fk0957-v7-build-20261026T124916Z/manual-v2r2-broker-batch4-20261029T222312Z-workspace/sidecar-evidence/fk-operand-contract-20261101T214800Z/operand-vector-001/FK_INPUT_PAYLOAD.bin")
PAYLOAD = _LOCAL_PAYLOAD if _LOCAL_PAYLOAD.is_file() else Path("/home/rmann/civiclight-testbench/phk1-ops/vector/FK_INPUT_PAYLOAD.bin")
RESPONSES = Path(os.environ.get("PHK1_RUNNER_RESPONSE_FIXTURE",
    str(ROOT/"sidecar-evidence/phk1-live-runner-fixture-responses.bin")))


def fresh_lock() -> dict:
    from tools.phk1_raw_bscan.target_lock_v2 import build_lock, canonical_sha256
    authority=json.loads(AUTHORITATIVE_MAP_PATH.read_text())
    cards=(authority["card_a"],authority["card_b"]); canary=authority["phk1_canary_physical_id"]
    peer_id=authority["phk1_peer_physical_id"]
    def phys(identity):
        card=next(c for c in cards if c["ftdi_serial"]==identity["ftdi_serial"])
        return {"usb_path":identity["usb_path"],"ftdi_serial":identity["ftdi_serial"],
            "vid":card["vid"],"pid":card["pid"],"interface":card["ftdi_interface"],
            "idcode":identity["idcode"],"dna":identity["dna"],
            "bridge_lane":card["bridge_endpoint"],"workload_binding":card["miner_binding"]}
    now=dt.datetime.now(dt.timezone.utc)
    cm=json.loads(CANDIDATE_MANIFEST.read_text())
    qm=QUALIFICATION_MANIFEST
    rb=ROLLBACK_BINDING
    candidate={"role":"CANDIDATE_IMAGE_TO_PROGRAM","image_id":cm["candidate_id"],"sha256":BITSTREAM_SHA,
        "size":28329335,"target_part":"xcvu33p-fsvh2104-2-e","path":str(CANDIDATE_BITSTREAM.resolve())}
    rollback={"role":"ROLLBACK_IMAGE","image_id":"XBT_V4P1_KNOWN_GOOD","sha256":"f9812864d13a6963700f60709507ff85ee660fb77e846e51be533b2d479502df",
        "size":ROLLBACK_BITSTREAM.stat().st_size,"target_part":"xcvu33p-fsvh2104-2-e","path":str(ROLLBACK_BITSTREAM.resolve())}
    current={"role":"CURRENT_LOADED_IMAGE",**{k:candidate[k] for k in ("image_id","sha256","size","target_part","path")}}
    lock=build_lock(target_identity=phys(canary),peer_identity=phys(peer_id),current_image=current,
        candidate_image=candidate,rollback_image=rollback,created_utc=now.isoformat(),
        expires_utc=(now+dt.timedelta(seconds=300)).isoformat(),maintenance_generation="fixture-run-001",
        candidate_manifest_sha256=__import__('hashlib').sha256(CANDIDATE_MANIFEST.read_bytes()).hexdigest(),
        qualification_sha256=__import__('hashlib').sha256(qm.read_bytes()).hexdigest(),current_image_evidence="fixture:programmed-candidate-log",
        rollback_authority="sha256:"+__import__('hashlib').sha256(rb.read_bytes()).hexdigest(),intended_action="VERIFY_CANDIDATE",run_id="fixture-run-001")
    return lock

def target_projection(lock):
    p=lock["target_identity"]
    return {"usb_path":p["usb_path"],"ftdi_serial":p["ftdi_serial"],"vid":p["vid"],"pid":p["pid"],
        "interface":p["interface"],"idcode":p["idcode"],"dna":p["dna"],"role":"PHK1_CANARY",
        "bridge_endpoint":p["bridge_lane"],"miner_binding":p["workload_binding"],
        "expected_phk1_bitstream_sha256":BITSTREAM_SHA}


class MockUserBackend:
    def __init__(self, target, *, bad_hello=False, bad_raw=False, short_result=False, live_prime=False):
        self.target = target
        self.identity_verified = True
        self.sync_ns = 100; self.identity_ns = 200
        self.scans=[]; self.protocol_scans=[]; self.closed=False
        self.bad_hello=bad_hello; self.bad_raw=bad_raw
        self.short_result=short_result
        self.live_prime=live_prime
        self.tile=0
        self.responses=RESPONSES.read_bytes()
        if bad_raw:
            import frame_protocol as fp
            from frame_protocol import parse_response, vector_transaction_id
            txid=vector_transaction_id("operand-vector-001",VECTOR_SHA)
            frames=[]
            for i in range(8):
                words=parse_response(self.responses[i*96:(i+1)*96],txid,i)
                words[0] ^= 1
                payload=b"".join(v.to_bytes(4,"little") for v in words)
                header=fp.RESPONSE_HEADER.pack(fp.RESPONSE_MAGIC,fp.VERSION,0,0x8001,txid,i,0,16,32,0,64)
                frames.append(header+fp.crc32(header).to_bytes(4,"little")+payload+fp.crc32(payload).to_bytes(4,"little"))
            self.responses=b"".join(frames)

    def user_scan(self, chain, data):
        if chain == 3:
            if self.bad_hello: rx=(0).to_bytes(4,"little")
            elif len(data)==4 and self.tile==0 and not self.protocol_scans: rx=(0x11).to_bytes(4,"little")
            elif len(data)==4: rx=(0x15 if self.tile else 0x11).to_bytes(4,"little")
            else: raise AssertionError("unexpected USER3 framing")
        elif chain == 2:
            if len(data)==1: rx=b"\x01" if self.live_prime else b"\0"
            elif len(data)==24608:
                rx=bytes(len(data)); self.tile += 1
            else: raise AssertionError("unexpected USER2 framing")
        elif chain == 1:
            if len(data)==1: rx=b"\x01" if self.live_prime else b"\0"
            elif len(data)==96:
                idx=self.tile-1
                rx=self.responses[idx*96:(idx+1)*96]
                if self.short_result: rx=rx[:-1]
            else: raise AssertionError("unexpected USER1 framing")
        else: raise AssertionError("unapproved USER chain")
        ir={1:0x02,2:0x03,3:0x22}[chain]
        self.protocol_scans.append({"chain":f"USER{chain}","ir":f"0x{ir:02x}",
            "bits":len(data)*8,"tx":data.hex(),"rx":rx.hex()})
        return rx

    def close(self): self.closed=True


class MockRpcBackend(RpcBackend):
    """Exercise the real protocol-to-RPC adapter with a deterministic FTDI
    endpoint that reconstructs TDO from the PHK1 fixture model."""
    def __init__(self,target,*,bad_hello=False,bad_raw=False,short_result=False):
        self.target=target; self.identity_verified=True
        self.open_ns=10; self.sync_ns=20; self.identity_ns=30
        self.scans=[]; self.protocol_scans=[]; self.closed=False
        self.device=MockUserBackend(target,bad_hello=bad_hello,bad_raw=bad_raw,short_result=short_result)
        self.current_ir=None; self.responses=[]
        self.proc=SimpleNamespace(returncode=0,stdin=self,wait=lambda timeout=None:0,
                                  poll=lambda:None,kill=lambda:None)
        self.timeout_s=1
        self._readline=self._next_response

    def write(self,line):
        fields=line.strip().split()
        if fields[0]=="IR":
            self.current_ir=int(fields[1],16); self.responses.append("IR 00")
        elif fields[0]=="DR":
            bits=int(fields[1]); data=bytes.fromhex(fields[2])
            if bits!=len(data)*8: raise AssertionError("RPC scan length mismatch")
            chain={0x02:1,0x03:2,0x22:3}.get(self.current_ir)
            rx=self.device.user_scan(chain,data)
            self.responses.append("DR "+rx.hex()); self.current_ir=None
        elif fields[0]=="QUIT":
            self.responses.append("BYE"); self.closed=True; self.proc.poll=lambda:0
        else: raise AssertionError("unexpected RPC command")

    def flush(self): pass
    def _next_response(self): return self.responses.pop(0)


class LiveRunnerTests(unittest.TestCase):

    def test_rpc_child_broken_pipe_preserves_exit_and_stderr(self):
        backend=RpcBackend.__new__(RpcBackend)
        class ClosedInput:
            def write(self,_): raise BrokenPipeError(32,"Broken pipe")
            def flush(self): pass
        backend.proc=SimpleNamespace(stdin=ClosedInput(),poll=lambda:20,
                                     wait=lambda timeout=None:20,stderr=io.StringIO("RPC_FAILURE=vector tile response deadline expired\n"))
        with self.assertRaises(RunnerError) as ctx:
            backend._write_command("DR 32 00000000\n")
        self.assertIn("returncode=20",str(ctx.exception))
        self.assertIn("vector tile response deadline expired",str(ctx.exception))

    def test_rpc_session_mode_has_deadline_not_poll_count_cap(self):
        source=(Path(__file__).resolve().parent/"raw_bscan_rpc.cpp").read_text()
        self.assertIn('mode!="session"',source)
        self.assertIn('mode=="session" && !hello_done',source)
        self.assertIn('std::chrono::seconds(120)',source)
        self.assertNotIn("status_polls>=100",source)

    def test_first_silicon_hello_replay_through_corrected_runner(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); lock=d/"lock.json"; lock.write_text(json.dumps(fresh_lock())); e=d/"run"
            run_operation("identify",lock_path=lock,evidence_dir=e,backend_factory=MockUserBackend)
            hello=run_operation("hello",lock_path=lock,evidence_dir=e,
                                backend_factory=lambda t:MockUserBackend(t,live_prime=True))
            self.assertEqual(hello["status"],"PASS")
            self.assertEqual(hello["hello"]["status_word"],"0x00000011")
            self.assertEqual([s["rx"] for s in hello["scans"]],
                             ["11000000","11000000","01","01","11000000"])

    def test_live_hello_prime_tdo_is_discarded_but_protocol_scans_stay_exact(self):
        fixture=json.loads(HELLO_FIXTURE.read_text())
        scans=[]
        for ir,dr in zip(fixture["ir_sequence"],fixture["dr_shifts"]):
            rx=dr.get("rx","01" if dr.get("rx_policy")=="discarded_prime_do_not_compare" else "")
            scans.append({"chain":dr["chain"],"ir":ir["ir"],"bits":dr["bits"],"tx":dr["tx"],"rx":rx})
        self.assertTrue(_transcript_check(scans,"hello"))
        wrong=list(scans)
        wrong[4]=dict(wrong[4]); wrong[4]["rx"]="12000000"
        self.assertFalse(_transcript_check(wrong,"hello"))
        wrong_tdi=list(scans)
        wrong_tdi[2]=dict(wrong_tdi[2]); wrong_tdi[2]["tx"]="01"
        self.assertFalse(_transcript_check(wrong_tdi,"hello"))
        truncated=list(scans)
        truncated[2]=dict(truncated[2]); truncated[2]["rx"]="0"
        self.assertFalse(_transcript_check(truncated,"hello"))

    def test_idcode_leading_zero_is_numeric_representation(self):
        self.assertEqual(normalize_idcode("4b69093"), normalize_idcode("04b69093"))
        self.assertEqual(normalize_idcode("0x04B69093"), 0x04b69093)
        self.assertNotEqual(normalize_idcode("04b69093"), normalize_idcode("0362d093"))

    def test_lock_enforcement_and_stale_rejection(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"lock.json"; lock=fresh_lock(); p.write_text(json.dumps(lock))
            parsed,h=validate_target_lock(p)
            self.assertEqual(parsed["run_id"],"fixture-run-001")
            self.assertEqual(len(h),64)
            from tools.phk1_raw_bscan.target_lock_v2 import canonical_sha256
            lock["expires_utc"]="2020-01-01T00:00:00+00:00"; lock.pop("lock_sha256"); lock["lock_sha256"]=canonical_sha256(lock); p.write_text(json.dumps(lock))
            with self.assertRaises(RunnerError): validate_target_lock(p)

    def test_full_mock_e2e_identify_hello_vector(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); lock=d/"lock.json"; lock.write_text(json.dumps(fresh_lock()))
            evidence=d/"run"; opened=[]
            def factory(target):
                obj=MockRpcBackend(target); opened.append(obj); return obj
            ident=run_operation("identify",lock_path=lock,evidence_dir=evidence,backend_factory=factory)
            hello=run_operation("hello",lock_path=lock,evidence_dir=evidence,backend_factory=factory)
            vector=run_operation("vector001",lock_path=lock,evidence_dir=evidence,backend_factory=factory,payload_path=PAYLOAD)
            self.assertEqual(ident["status"],"PASS")
            self.assertTrue(hello["transcript_match"])
            self.assertEqual(hello["logical_scan_bits"],112)
            self.assertEqual(vector["raw_result_sha256"],RAW_SHA)
            self.assertEqual(vector["canonical_result_sha256"],CANONICAL_SHA)
            self.assertEqual(vector["logical_scan_bits"]["input"],1574912)
            self.assertEqual(vector["logical_scan_bits"]["output"],6144)
            self.assertEqual([x.closed for x in opened],[True,True,True])
            self.assertEqual(json.loads((evidence/"hello.json").read_text())["status"],"PASS")
            self.assertEqual(json.loads((evidence/"vector001.json").read_text())["status"],"PASS")

    def test_requires_identify_then_hello(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); lock=d/"lock.json"; lock.write_text(json.dumps(fresh_lock()))
            with self.assertRaises(RunnerError):
                run_operation("hello",lock_path=lock,evidence_dir=d/"run",backend_factory=MockUserBackend)
            with self.assertRaises(RunnerError):
                run_operation("vector001",lock_path=lock,evidence_dir=d/"run",backend_factory=MockUserBackend,payload_path=PAYLOAD)

    def test_hello_failure_prevents_vector(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); lock=d/"lock.json"; lock.write_text(json.dumps(fresh_lock())); e=d/"run"
            run_operation("identify",lock_path=lock,evidence_dir=e,backend_factory=MockUserBackend)
            with self.assertRaises((RunnerError, ValueError)):
                run_operation("hello",lock_path=lock,evidence_dir=e,
                              backend_factory=lambda t:MockUserBackend(t,bad_hello=True))
            self.assertFalse((e/"vector001.json").exists())

    def test_operation_and_peer_allowlists(self):
        with self.assertRaises(ValueError):
            from transport import validate_operation
            validate_operation("arbitrary")
        from tools.phk1_raw_bscan.target_lock_v2 import canonical_sha256
        lock=fresh_lock(); lock["peer_identity"]["dna"]=lock["target_identity"]["dna"]
        lock.pop("lock_sha256"); lock["lock_sha256"]=canonical_sha256(lock)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"lock.json"; p.write_text(json.dumps(lock))
            with self.assertRaises(RunnerError): validate_target_lock(p)

    def test_failure_matrix_bad_result_and_target_identity(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); lock=d/"lock.json"; lock.write_text(json.dumps(fresh_lock())); e=d/"run"
            run_operation("identify",lock_path=lock,evidence_dir=e,backend_factory=MockUserBackend)
            run_operation("hello",lock_path=lock,evidence_dir=e,backend_factory=MockUserBackend)
            with self.assertRaises(RuntimeError):
                run_operation("vector001",lock_path=lock,evidence_dir=e,
                              backend_factory=lambda t:MockUserBackend(t,bad_raw=True),payload_path=PAYLOAD)

    def test_target_binding_negative_cases(self):
        from tools.phk1_raw_bscan.target_lock_v2 import canonical_sha256
        mutations = [
            lambda x:x["target_identity"].update(idcode="00000000"),
            lambda x:x["target_identity"].update(dna="wrong-dna"),
            lambda x:x["target_identity"].update(ftdi_serial="peer-serial"),
            lambda x:x["target_identity"].update(usb_path="1-9.4"),
            lambda x:x["peer_identity"].update(dna=x["target_identity"]["dna"]),
            lambda x:x.update(max_programmed_device_count=2),
        ]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"lock.json"
            for mutate in mutations:
                lock=fresh_lock(); mutate(lock); lock.pop("lock_sha256"); lock["lock_sha256"]=canonical_sha256(lock); p.write_text(json.dumps(lock))
                with self.assertRaises(RunnerError): validate_target_lock(p)

    def test_backend_and_identity_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); p=d/"lock.json"; p.write_text(json.dumps(fresh_lock()))
            with self.assertRaises(RunnerError):
                run_operation("identify",lock_path=p,evidence_dir=d/"open",
                    backend_factory=lambda t:(_ for _ in ()).throw(RunnerError("backend","open failed")))
            bad=MockUserBackend(target_projection(fresh_lock())); bad.identity_verified=False
            with self.assertRaises(RunnerError):
                run_operation("identify",lock_path=p,evidence_dir=d/"identity",backend_factory=lambda t:bad)
            self.assertTrue(bad.closed)

    def test_failure_does_not_reopen_or_retry(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); p=d/"lock.json"; p.write_text(json.dumps(fresh_lock())); e=d/"run"
            run_operation("identify",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            run_operation("hello",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            calls=[]
            def fail_once(t):
                calls.append(t)
                raise RunnerError("mpsse","sync failure")
            with self.assertRaises(RunnerError):
                run_operation("vector001",lock_path=p,evidence_dir=e,backend_factory=fail_once,payload_path=PAYLOAD)
            self.assertEqual(len(calls),1)

    def test_user_scan_allowlist_rejects_arbitrary_frames_before_rpc(self):
        backend=RpcBackend.__new__(RpcBackend)
        with self.assertRaises(RunnerError): backend.user_scan(4,b"\0"*4)
        with self.assertRaises(RunnerError): backend.user_scan(2,b"arbitrary")
        with self.assertRaises(RunnerError): backend.user_scan(1,b"x"*96)

    def test_vector_short_result_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); p=d/"lock.json"; p.write_text(json.dumps(fresh_lock())); e=d/"run"
            run_operation("identify",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            run_operation("hello",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            with self.assertRaises(RunnerError):
                run_operation("vector001",lock_path=p,evidence_dir=e,
                    backend_factory=lambda t:MockUserBackend(t,short_result=True),payload_path=PAYLOAD)

    def test_vector_raw_oracle_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); p=d/"lock.json"; p.write_text(json.dumps(fresh_lock())); e=d/"run"
            run_operation("identify",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            run_operation("hello",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            with self.assertRaises(RunnerError) as ctx:
                run_operation("vector001",lock_path=p,evidence_dir=e,
                    backend_factory=lambda t:MockUserBackend(t,bad_raw=True),payload_path=PAYLOAD)
            self.assertEqual(ctx.exception.kind,"raw_mismatch")

    def test_vector_canonical_oracle_mismatch_fails_closed(self):
        import transport
        # The protocol module binds its oracle directly in code. Replace only
        # its hash namespace; preserve payload and raw hashes, fail canonical.
        import hashlib as hashlib_module
        original=hashlib_module.sha256
        calls=[0]
        class WrongDigest:
            def __init__(self, real): self._real=real
            def hexdigest(self): return "0"*64
        class HashNamespace:
            @staticmethod
            def sha256(data):
                calls[0]+=1
                return WrongDigest(original(data)) if calls[0]==3 else original(data)
        with tempfile.TemporaryDirectory() as d:
            d=Path(d); p=d/"lock.json"; p.write_text(json.dumps(fresh_lock())); e=d/"run"
            run_operation("identify",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            run_operation("hello",lock_path=p,evidence_dir=e,backend_factory=MockUserBackend)
            try:
                transport.hashlib=HashNamespace
                with self.assertRaises(RunnerError) as ctx:
                    run_operation("vector001",lock_path=p,evidence_dir=e,
                        backend_factory=MockUserBackend,payload_path=PAYLOAD)
                self.assertEqual(ctx.exception.kind,"canonical_mismatch")
            finally:
                transport.hashlib=hashlib_module

    def test_exit_code_model_is_explicit_and_unique(self):
        from tools.phk1_raw_bscan.phk1_live_runner import EXIT
        self.assertEqual(EXIT["success"],0)
        for key in ("usage","lock","target","backend","mpsse","identity","hello",
                    "vector","raw_mismatch","canonical_mismatch","cleanup"):
            self.assertIn(key,EXIT)
            self.assertNotEqual(EXIT[key],0)
        self.assertEqual(len(set(EXIT.values())),len(EXIT))


if __name__ == "__main__":
    unittest.main(verbosity=2)
