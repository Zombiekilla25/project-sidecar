"""PearlHash fields derived from official PlainProof roots and PRL cert version."""
from __future__ import annotations
import struct
import blake3

def proof_context(job,proof,pm=None):
    if isinstance(proof,str):
        if pm is None: import pearl_mining as pm
        proof=pm.PlainProof.from_base64(proof)
    if proof.moe is not None: raise ValueError("MoE proof encoding is not qualified by this frontend")
    a_rows=list(proof.a.row_indices); b_rows=list(proof.bt.row_indices)
    if not a_rows or not b_rows or any(a>=b for a,b in zip(a_rows,a_rows[1:])) or any(a>=b for a,b in zip(b_rows,b_rows[1:])):
        raise ValueError("PlainProof row indices must be nonempty and strictly increasing")
    if pm is None: import pearl_mining as pm
    rp=pm.PeriodicPattern.from_list([i-a_rows[0] for i in a_rows])
    cp=pm.PeriodicPattern.from_list([i-b_rows[0] for i in b_rows])
    config=pm.MiningConfiguration(proof.k,proof.noise_rank,pm.MMAType.Int7xInt7ToInt32,rp,cp)
    key=blake3.blake3(job.header+bytes(config.to_bytes())).digest()
    ar=bytes(proof.a.root); br=bytes(proof.bt.root)
    if len(ar)!=32 or len(br)!=32: raise ValueError("PlainProof roots must be 32 bytes")
    if job.cert_version==3:
        salt_a=blake3.blake3(b"pearl/cert-v3/noise-seed/A").digest()
        salt_b=blake3.blake3(b"pearl/cert-v3/noise-seed/B").digest()
        ar=blake3.blake3(ar+struct.pack("<I",proof.m)+bytes(28),key=salt_a).digest()
        br=blake3.blake3(br+struct.pack("<I",proof.n)+bytes(28),key=salt_b).digest()
    b_seed=blake3.blake3(key+br).digest()
    sigma=blake3.blake3(b_seed+ar).digest()
    return config,key,sigma,b_seed,len(a_rows)*len(b_rows)*proof.k
