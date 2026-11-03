import json,unittest
from pathlib import Path
import blake3, numpy as np, pearl_mining as pm
from sidecar_miner.pearlhash import PearlHashCpuVerifier
from sidecar_miner.verification import verify_candidate
from tests.reference_support import fixture_job,canonical_proof,candidate_for
FIX=Path(__file__).parent.parent/'fixtures'/'operand-vector-001'
class CpuReferenceVectorTests(unittest.TestCase):
    def test_existing_operand_commitment_vector(self):
        ctx=json.loads((FIX/'CONTEXT.json').read_text())
        A=np.fromfile(FIX/'A.bin',dtype=np.int8).reshape(ctx['m'],ctx['k']); B=np.fromfile(FIX/'B.bin',dtype=np.int8).reshape(ctx['k'],ctx['n'])
        key=blake3.blake3(bytes.fromhex(ctx['header_hex'])+bytes.fromhex(ctx['config_hex'])).digest()
        def pad(x): return x+b'\0'*((-len(x))%1024)
        ha=blake3.blake3(pad(A.tobytes()),key=key).digest(); hb=blake3.blake3(pad(np.ascontiguousarray(B.T).tobytes()),key=key).digest()
        b=blake3.blake3(key+hb).digest(); a=blake3.blake3(b+ha).digest()
        self.assertEqual(b.hex(),ctx['noise_seeds']['b_noise_seed_hex']); self.assertEqual(a.hex(),ctx['noise_seeds']['a_noise_seed_hex'])
    def test_official_cpu_mine_and_cert_verifier_agree(self):
        job=fixture_job(); proof=canonical_proof(job); candidate=candidate_for(job,proof)
        verified=verify_candidate(job,candidate,PearlHashCpuVerifier(pm).verify)
        self.assertTrue(verified.accepted,verified.reason)
        decoded=pm.PlainProof.from_base64(proof.to_base64())
        self.assertTrue(pm.verify_plain_proof_for_cert_version(2,pm.IncompleteBlockHeader.from_bytes(job.header),decoded,nbits_override=0x2100ffff)[0])
