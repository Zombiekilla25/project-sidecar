"""Deterministic Kryptex PRL mining.submit object encoder."""
from __future__ import annotations
import base64, gzip, json, time

def _plain_proof_bytes(proof):
    if isinstance(proof,str): encoded=proof
    elif hasattr(proof,"to_base64"): encoded=proof.to_base64()
    else: raise ValueError("PRL share requires canonical PlainProof.to_base64()")
    try: raw=base64.b64decode(encoded,validate=True)
    except Exception as e: raise ValueError("PlainProof is not canonical base64") from e
    if base64.b64encode(raw).decode("ascii")!=encoded: raise ValueError("PlainProof base64 is noncanonical")
    return raw

def _gzip_proof(plain):
    # Kryptex's captured KRig request uses gzip-compressed native PlainProof bytes.
    # mtime=0 and a fixed OS byte make this gzip member deterministic. Its
    # decompressed bytes must equal canonical native PlainProof bytes.
    packed=bytearray(gzip.compress(plain,compresslevel=6,mtime=0))
    packed[9]=255
    return bytes(packed)

def build_prl_submit_params(job,candidate,telemetry=None):
    started=time.perf_counter()
    try:
        if candidate.job_id!=job.job_id or candidate.job_fingerprint!=job.fingerprint or candidate.generation!=job.generation: raise ValueError("candidate belongs to a different PRL job")
        if not candidate.backend_valid: raise ValueError("invalid backend candidate")
        if isinstance(candidate.nonce,bool) or not isinstance(candidate.nonce,int) or not 0<=candidate.nonce<1<<64: raise ValueError("nonce outside uint64")
        plain=_plain_proof_bytes(candidate.proof)
        params={"job_id":job.job_id,"plain_proof":base64.b64encode(_gzip_proof(plain)).decode("ascii")}
        return params
    finally:
        if telemetry is not None: telemetry.record_stage("submission_encoding",time.perf_counter()-started)

def canonical_submit_message(request_id,params):
    return json.dumps({"id":request_id,"method":"mining.submit","params":params},sort_keys=True,separators=(",",":"))
