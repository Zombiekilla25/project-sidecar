import base64, gzip, hashlib, json, unittest
from pathlib import Path
from tests.reference_support import fixture_job,canonical_proof,candidate_for
from sidecar_miner.share_encoder import build_prl_submit_params,canonical_submit_message
from sidecar_miner.telemetry import Telemetry

ROOT=Path(__file__).resolve().parents[1]

class PrlShareEncoderTests(unittest.TestCase):
    def test_captured_kryptex_envelope_and_deterministic_proof(self):
        job=fixture_job(); proof=canonical_proof(job); candidate=candidate_for(job,proof,nonce=0x1234)
        telemetry=Telemetry(); params=build_prl_submit_params(job,candidate,telemetry)
        self.assertEqual(set(params),{'job_id','plain_proof'})
        packed=base64.b64decode(params['plain_proof'],validate=True)
        self.assertEqual(gzip.decompress(packed),base64.b64decode(proof.to_base64(),validate=True))
        self.assertEqual(params,build_prl_submit_params(job,candidate))
        message=canonical_submit_message(21,params)
        self.assertEqual(message,json.dumps(json.loads(message),sort_keys=True,separators=(',',':')))
        self.assertEqual(json.loads(message)['method'],'mining.submit')
        self.assertIn('submission_encoding',telemetry.stage_seconds)

    def test_accepted_kryg_proof_fixture_is_canonical_native_proof(self):
        import pearl_mining as pm
        fixture=ROOT/'fixtures/prl-accepted-share'
        plain=(fixture/'plain_proof.bin').read_bytes(); captured_gzip=(fixture/'plain_proof.gz').read_bytes()
        manifest=json.loads((fixture/'manifest.json').read_text())
        self.assertEqual(hashlib.sha256(plain).hexdigest(),manifest['plain_proof_sha256'])
        self.assertEqual(hashlib.sha256(captured_gzip).hexdigest(),manifest['krig_gzip_sha256'])
        self.assertEqual(gzip.decompress(captured_gzip),plain)
        proof=pm.PlainProof.from_base64(base64.b64encode(plain).decode('ascii'))
        self.assertEqual(base64.b64decode(proof.to_base64(),validate=True),plain)
        job=fixture_job(); from sidecar_miner.models import Candidate
        candidate=Candidate(job.job_id,job.fingerprint,proof,0,0,b'\0'*32,b'\0'*32,job.generation)
        params=build_prl_submit_params(job,candidate)
        self.assertEqual(set(params),set(manifest['captured_submission_params']))
        self.assertEqual(gzip.decompress(base64.b64decode(params['plain_proof'])),plain)

    def test_mismatched_generation_and_invalid_candidate_fail_encoder(self):
        from dataclasses import replace
        job=fixture_job(); proof=canonical_proof(job); candidate=candidate_for(job,proof)
        with self.assertRaises(ValueError): build_prl_submit_params(job,replace(candidate,generation=0))
        with self.assertRaises(ValueError): build_prl_submit_params(job,replace(candidate,backend_valid=False))
