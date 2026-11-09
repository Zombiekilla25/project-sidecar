"""CPU golden prediction for an 8x8 tile-coordinate range on one production grid."""
from __future__ import annotations
import struct
from oracle import K,R,PROFILE_A,PROFILE_B,recipe_from_seeds,uniform,sparse_indices
import golden_model
from runtime import sha
N=131072

def _signed(b): return b if b<128 else b-256

def _compress(words,key):
    mask=0xffffffff; iv=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a]
    perm=[2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]
    def rr(v,n): return ((v>>n)|(v<<(32-n)))&mask
    m=list(words); v=list(struct.unpack('<8I',key))+iv+[0,0,64,27]
    def g(a,b,c,d,x,y):
        v[a]=(v[a]+v[b]+x)&mask; v[d]=rr(v[d]^v[a],16); v[c]=(v[c]+v[d])&mask; v[b]=rr(v[b]^v[c],12)
        v[a]=(v[a]+v[b]+y)&mask; v[d]=rr(v[d]^v[a],8); v[c]=(v[c]+v[d])&mask; v[b]=rr(v[b]^v[c],7)
    sched=[(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]
    for _ in range(7):
        for i,(a,b,c,d) in enumerate(sched): g(a,b,c,d,m[2*i],m[2*i+1])
        m=[m[i] for i in perm]
    return struct.pack('<8I',*(v[i]^v[i+8] for i in range(8)))

def _engine(av,bv,key):
    acc=[0]*256; words=[]
    for k in range(K):
        aa=av[k]; bb=bv[k]
        for i in range(16):
            x=_signed(aa[i]); base=i*16
            for j in range(16): acc[base+j]+=x*_signed(bb[j])
        if k%R==R-1:
            v=0
            for x in acc: v^=x&0xffffffff
            words.append(v)
    return struct.pack('<16I',*words),_compress(words,key)

def predict_batch64(desc,seed_a,seed_b,start=0,count=64):
    if start!=0 or count!=64: raise ValueError('production golden range currently qualifies the origin 8x8 tile-coordinate window (64 items)')
    rows=128; recipe=b''.join((uniform(rows,seed_a,PROFILE_A),uniform(rows,seed_b,PROFILE_B),sparse_indices(K,seed_a,PROFILE_A),sparse_indices(K,seed_b,PROFILE_B)))
    off=0; eal=recipe[off:off+rows*R];off+=rows*R; ebr=recipe[off:off+rows*R];off+=rows*R; ear=recipe[off:off+K*2];off+=K*2; ebl=recipe[off:off+K*2]
    A=bytearray(rows*K); B=bytearray(rows*K)
    for row in range(rows):
        rb=row*K; eb=row*R
        for kbase in range(0,K,4):
            vals=golden_model.philox4(rb+kbase,int(desc.setup_seed64))
            for lane,raw in enumerate(vals):
                k=kbase+lane; plus,minus=ear[2*k],ear[2*k+1]
                val=raw+_signed(eal[eb+plus])-_signed(eal[eb+minus])
                if not -128<=val<=127: raise ValueError('A int8 overflow')
                A[rb+k]=val&255
    for k in range(K):
        kbase=k*N
        for colbase in range(0,rows,4):
            vals=golden_model.philox4(kbase+colbase,(int(desc.setup_seed64)+1)&0xffffffffffffffff)
            for lane,raw in enumerate(vals):
                col=colbase+lane; eb=col*R; plus,minus=ebl[2*k],ebl[2*k+1]
                val=raw+_signed(ebr[eb+plus])-_signed(ebr[eb+minus])
                if not -128<=val<=127: raise ValueError('B int8 overflow')
                B[eb//R*K+k]=val&255
    ag=[]; bg=[]
    for group in range(8):
        off=group*16
        ag.append(tuple(bytes(A[(off+j)*K+k] for j in range(16)) for k in range(K)))
        bg.append(tuple(bytes(B[(off+j)*K+k] for j in range(16)) for k in range(K)))
    operands=[]; transcripts=[]; digests=[]; item_hashes=[]
    for slot in range(64):
        row,col=divmod(slot,8); av,bv=ag[row],bg[col]
        operand=b''.join(av[k]+bv[k] for k in range(K)); transcript,digest=_engine(av,bv,seed_a)
        operands.append(operand); item_hashes.append(sha(operand)); transcripts.append(transcript); digests.append(digest)
    return {'operands':operands,'operand_sha256':item_hashes,'transcripts':transcripts,'digests':digests}
