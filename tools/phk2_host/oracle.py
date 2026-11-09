"""Adapter over the frozen PHK2 CPU golden model and 13 retained cases."""
from __future__ import annotations
import hashlib,json,struct,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import golden_model
from runtime import Descriptor,fixture_path,sha
FIXTURE=fixture_path(); CASES=FIXTURE.parent/'retained-cases'
try:
    from blake3 import blake3
except ImportError as e:
    raise RuntimeError('install requirements.txt to use the keyed BLAKE3 CPU oracle') from e
K=4096; R=256; PROFILE_A=b'A_tensor'+bytes(24); PROFILE_B=b'B_tensor'+bytes(24)
def random_hash(index,seed,key,prepend):
    words=[0]*8; words[prepend]=1+index
    return blake3(struct.pack('<8i',*words)+seed,key=key).digest()
def uniform(rows,key,seed):
    count=rows*R; raw=b''.join(random_hash(i,seed,key,0) for i in range((count+31)//32))[:count]
    return bytes(((b&0x3f)-32)&255 for b in raw)
def sparse_indices(required,key,seed):
    out=bytearray(required*2); pos=0
    for draw in range((required+7)//8):
        digest=random_hash(draw,seed,key,1)
        for lane in range(8):
            if pos>=required: break
            word=struct.unpack_from('<I',digest,lane*4)[0]; first=word&(R-1); second=first^(1+(((R-1)*word)>>32))
            out[2*pos]=first; out[2*pos+1]=second; pos+=1
    if pos!=required: raise AssertionError('sparse permutation mismatch')
    return bytes(out)
def recipe_from_seeds(seed_a,seed_b):
    return b''.join((uniform(64,seed_a,PROFILE_A),uniform(80,seed_b,PROFILE_B),sparse_indices(K,seed_a,PROFILE_A),sparse_indices(K,seed_b,PROFILE_B)))
def case_for(desc):
    index=json.loads((CASES/'manifest.json').read_text())
    for item in index['items']:
        b=(CASES/item['descriptor_file']).resolve().read_bytes()
        if b==desc.encode(): return item
    raise ValueError('descriptor is not one of the 13 retained authoritative production cases')
def predict(desc:Descriptor,range_start:int=0,count:int=1):
    if range_start!=0 or count!=1: raise ValueError('qualified CPU fixture covers one 4x5 tile result at range start (0,0); other ranges need their own retained CPU qualification')
    case=case_for(desc); seed_a=bytes.fromhex(case['noise_seed_A']); seed_b=bytes.fromhex(case['noise_seed_B'])
    ports,vectors=golden_model.expand_capture(recipe_from_seeds(seed_a,seed_b),int(case['seed64'],16))
    transcripts,digests=golden_model.cpu_known_answers(vectors,seed_a)
    expected_t=(CASES/case['expected_transcripts_file']).read_bytes(); expected_d=(CASES/case['expected_digests_file']).read_bytes()
    checks={'operand_exact':[sha(x)==y for x,y in zip(ports,case['expected_operand_port_sha256'])], 'transcript_exact':b''.join(transcripts)==expected_t,'digest_exact':b''.join(digests)==expected_d}
    checks['exact']=all(checks['operand_exact']) and checks['transcript_exact'] and checks['digest_exact']
    return {'expected_operands':ports,'expected_compact_result':digests,'canonical_result':transcripts,'checks':checks,'capture':case['capture']}
def fixture_oracle():
    desc=Descriptor.decode((FIXTURE/'descriptor.bin').read_bytes())
    return predict(desc,0,1)
