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
    try: case=case_for(desc)
    except ValueError: case=None
    seed_a,seed_b=desc.noise_seed_A,desc.noise_seed_B
    if count==64:
        from batch64_oracle import predict_batch64
        batch=predict_batch64(desc,seed_a,seed_b,range_start,count)
        checks={'model_generated':True,'batch64_operand_hashes_exact':None,'batch64_captured_cpu_overlap_exact':None}
        if case and case['capture']=='real-v3-slice-1017db2f_2097152-20261013T222702Z':
            expected=json.loads((FIXTURE/'batch64/operand_sha256.json').read_text())
            checks['batch64_operand_hashes_exact']=batch['operand_sha256']==expected['per_item_sha256']
            expected_t=(FIXTURE/'expected_transcripts.bin').read_bytes(); expected_d=(FIXTURE/'expected_digests.bin').read_bytes()
            overlap=[row*8+col for row in range(4) for col in range(5)]
            checks['batch64_captured_cpu_overlap_exact']=all(batch['transcripts'][slot]==expected_t[i*64:(i+1)*64] and batch['digests'][slot]==expected_d[i*32:(i+1)*32] for i,slot in enumerate(overlap))
            checks['exact']=checks['batch64_operand_hashes_exact'] and checks['batch64_captured_cpu_overlap_exact']
        return {'expected_operands':batch['operands'],'expected_compact_result':batch['digests'],'canonical_result':batch['transcripts'],'checks':checks,'capture':case['capture'] if case else 'CPU_MODEL_PREDICTION'}
    if range_start!=0 or count!=1: raise ValueError('supported ranges are one origin tile (count 1) or the origin 8x8 batch64 window')
    ports,vectors=golden_model.expand_capture(recipe_from_seeds(seed_a,seed_b),desc.setup_seed64)
    transcripts,digests=golden_model.cpu_known_answers(vectors,seed_a)
    if case:
        expected_t=(CASES/case['expected_transcripts_file']).read_bytes(); expected_d=(CASES/case['expected_digests_file']).read_bytes()
        checks={'operand_exact':[sha(x)==y for x,y in zip(ports,case['expected_operand_port_sha256'])], 'transcript_exact':b''.join(transcripts)==expected_t,'digest_exact':b''.join(digests)==expected_d}
        checks['exact']=all(checks['operand_exact']) and checks['transcript_exact'] and checks['digest_exact']
    else: checks={'model_generated':True,'retained_capture_crosscheck':False}
    return {'expected_operands':ports,'expected_compact_result':digests,'canonical_result':transcripts,'checks':checks,'capture':case['capture'] if case else 'CPU_MODEL_PREDICTION'}

def fixture_oracle():
    desc=Descriptor.decode((FIXTURE/'descriptor.bin').read_bytes())
    return predict(desc,0,1)
