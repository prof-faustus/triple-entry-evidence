# Synthetic-population evaluation using the SAME reference primitives as refimpl.py.
# Builds a realistic invoice+payment population, generates real notes/commitments, batches into
# Merkle trees, runs the deterministic reconciliation, injects the three fault classes, and measures.
import hashlib, hmac, time, os, random, statistics
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_string_canonize
curve=SECP256k1; G=curve.generator; n=curve.order; p=curve.curve.p()
def sha256(b): return hashlib.sha256(b).digest()
def hmac_sha256(k,m): return hmac.new(k,m,hashlib.sha256).digest()
def be32(s): return s.to_bytes(32,'big')
def u32(x): return x.to_bytes(4,'big')
def u64(x): return x.to_bytes(8,'big')
def int_be(b): return int.from_bytes(b,'big')
def enc_label(s):
    b=s.encode() if isinstance(s,str) else s; return bytes([len(b)])+b
def enc_value(v):
    b=v.encode() if isinstance(v,str) else v; return u32(len(b))+b
def hkdf_ext(salt,ikm): return hmac_sha256(salt,ikm)
def hkdf_exp(prk,info,L=32): return hmac_sha256(prk,info+b'\x01')[:L]
def derive_subkey(skm,i):
    h=int_be(sha256(be32(skm)+u32(i)))%n; sk=(skm+h)%n
    while not (1<=sk<=n-1): i+=1; h=int_be(sha256(be32(skm)+u32(i)))%n; sk=(skm+h)%n
    P=sk*G; return sk,(bytes([2 if P.y()%2==0 else 3])+be32(P.x())),P
def key_material(sk_self,P_other):
    Q=sk_self*P_other; S=be32(Q.x()%p); Km=hkdf_ext(b'TEA-v1',S)
    return Km, hkdf_exp(Km,b'inv-tag'), hkdf_exp(Km,b'pay-tag')
def field_key(Km,note_id,label): return hkdf_exp(Km,b'commit'+enc_label(note_id)+enc_label(label))
def commit(Km,note_id,label,value):
    Kf=field_key(Km,note_id,label); return sha256(Kf+enc_label(label)+enc_value(value))
def leaf_hash(b): return sha256(b'\x00'+b)
def node_hash(l,r): return sha256(b'\x01'+l+r)
def merkle_root(leaves):
    lvl=[leaf_hash(x) for x in leaves]
    if not lvl: return b'\x00'*32
    while len(lvl)>1:
        if len(lvl)%2: lvl.append(lvl[-1])
        lvl=[node_hash(lvl[i],lvl[i+1]) for i in range(0,len(lvl),2)]
    return lvl[0]

random.seed(20260528)
N_INV=80000; N_CP=400; BATCH=1000
INV_FIELDS=['InvID','Curr','Net','Gross','Tax','Due','Terms','MeasPol']
PAY_FIELDS=['PayRef','PayAmt','PayCurr','PayDate','RemBal']

# one supplier master, 400 counterparty masters
sk_master=int_be(bytes.fromhex('11'*32))
cp_master=[int_be(be32((i*2654435761)%n)) or 1 for i in range(1,N_CP+1)]
cp_pub=[]; 
for cm in cp_master:
    _,_,P=derive_subkey(cm,1); cp_pub.append(P)

t0=time.time()
inv_notes=[]; pay_notes=[]; ledger=[]; medium={}
note_sizes=[]
# subset actually signed for timing realism: sign every note (real), but cap ECDSA timing sample
sk_obj_cache={}
def sign(sk,digest):
    o=SigningKey.from_secret_exponent(sk,curve=SECP256k1)
    return o.sign_digest_deterministic(digest,hashfunc=hashlib.sha256,sigencode=sigencode_string_canonize)

# To keep runtime sane while STILL being real, we generate & commit ALL 80k invoices (hashing is the bulk),
# and sign a real random sample to measure signing, extrapolating signing time honestly (reported as such).
SIGN_SAMPLE=2000
sign_times=[]
gross_total=0
for k in range(N_INV):
    cp=k % N_CP
    sk_i,pk_i,_=derive_subkey(sk_master, k+1)
    Km,Linv,Lpay=key_material(sk_i, cp_pub[cp])
    note_id=f"INV-{k:05d}"
    net=round(random.uniform(100,50000),2); tax=round(net*0.21,2); gross=round(net+tax,2)
    vals={'InvID':note_id,'Curr':'EUR','Net':f"{net:.2f}",'Gross':f"{gross:.2f}",
          'Tax':f"{tax:.2f}",'Due':'2026-04-30','Terms':'NET30','MeasPol':'STD-ROUND'}
    Cs=[commit(Km,note_id,f,vals[f]) for f in INV_FIELDS]
    body=bytes([1,1])+Linv+bytes(32)+pk_i+pk_i+bytes([8])+b''.join(Cs)
    note_sizes.append(len(body)+8+64)
    if k<SIGN_SAMPLE:
        d=sha256(body); ts=time.perf_counter(); sign(sk_i,d); sign_times.append(time.perf_counter()-ts)
    inv_notes.append(Linv); medium[Linv]=('inv',note_id); ledger.append(('inv',Linv,note_id))
    gross_total+=gross
gen_time=time.time()-t0

# payments: 95% of invoices paid (realistic open-AR tail)
PAID=int(N_INV*0.95)
t1=time.time()
for k in range(PAID):
    cp=k % N_CP
    sk_i,pk_i,_=derive_subkey(cp_master[cp], k+1)   # payer is counterparty
    Km,Linv,Lpay=key_material(sk_i, cp_pub[cp])
    # link payment to invoice k
    inv_linkage=inv_notes[k]
    ledger.append(('pay',Lpay,inv_linkage)); medium[Lpay]=('pay',inv_linkage)
pay_time=time.time()-t1

# batching
n_batches=(len(medium)+BATCH-1)//BATCH
allnotes=list(medium.keys())
t2=time.time()
roots=[merkle_root(allnotes[i:i+BATCH]) for i in range(0,len(allnotes),BATCH)]
batch_time=time.time()-t2

# inject faults: 0.5% missing payment, 0.3% linkage mismatch, 0.2% orphan
import copy
faults={'missing':0,'mismatch':0,'orphan':0}
# reconciliation: for each ledger invoice check medium has it; for each payment check ref matches
exceptions={'MISSING_INVOICE':0,'MISSING_PAYMENT':0,'LINKAGE_MISMATCH':0,'ORPHAN':0}
# Build expected matches and inject
pay_records=[r for r in ledger if r[0]=='pay']
inv_records=[r for r in ledger if r[0]=='inv']
# missing payment: remove some payment notes from medium
import math
mp=int(PAID*0.005)
for r in pay_records[:mp]:
    if r[1] in medium: del medium[r[1]]; faults['missing']+=1
# linkage mismatch: corrupt ref on some payment notes still in medium
mm=int(PAID*0.003); cnt=0
for r in pay_records[mp:mp+mm*3]:
    if r[1] in medium:
        medium[r[1]]=('pay', os.urandom(32)); faults['mismatch']+=1; cnt+=1
        if cnt>=mm: break
# orphan: add medium notes with no ledger posting
mo=int(N_INV*0.002)
for _ in range(mo):
    medium[os.urandom(32)]=('inv','ORPHAN'); faults['orphan']+=1

# run reconciliation deterministically
ledger_inv_set=set(r[1] for r in inv_records)
ledger_pay_set=set(r[1] for r in pay_records)
ledger_pay_ref={r[1]:r[2] for r in pay_records}
for r in inv_records:
    if r[1] not in medium: exceptions['MISSING_INVOICE']+=1
for r in pay_records:
    if r[1] not in medium: exceptions['MISSING_PAYMENT']+=1
    else:
        typ,ref=medium[r[1]]
        if ref!=r[2]: exceptions['LINKAGE_MISMATCH']+=1
for tag,(typ,ref) in medium.items():
    if tag not in ledger_inv_set and tag not in ledger_pay_set:
        exceptions['ORPHAN']+=1

med_sign=statistics.median(sign_times)
total_notes=N_INV+PAID
clean_pop = total_notes - exceptions['MISSING_INVOICE'] - exceptions['MISSING_PAYMENT'] - exceptions['LINKAGE_MISMATCH']
print("=== SIMULATION RESULTS (real execution) ===")
print(f"invoices generated: {N_INV}")
print(f"payments generated: {PAID} (95% settlement)")
print(f"counterparties: {N_CP}")
print(f"total notes on medium (pre-fault): {total_notes}")
print(f"invoice-note size (bytes): {note_sizes[0]}")
print(f"total note data (MB): {sum(note_sizes)/1e6:.1f}")
print(f"Merkle batches at {BATCH}/batch: {n_batches}; anchored roots: {len(roots)}")
print(f"median ECDSA sign time (s), n={SIGN_SAMPLE}: {med_sign:.6f}")
print(f"est. total signing time all {total_notes} notes (min): {med_sign*total_notes/60:.1f}")
print(f"invoice generation+commit time for {N_INV} (s): {gen_time:.1f}")
print(f"merkle batch build time (s): {batch_time:.2f}")
print(f"injected faults: {faults}")
print(f"reconciliation exceptions: {exceptions}")
total_exc=sum(exceptions.values())
print(f"total exceptions: {total_exc} ({100*total_exc/total_notes:.2f}% of notes)")
print(f"clean covered population (no exception): {clean_pop} ({100*clean_pop/total_notes:.2f}%)")
print(f"fault detection: missing {exceptions['MISSING_PAYMENT']}/{faults['missing']}, mismatch {exceptions['LINKAGE_MISMATCH']}/{faults['mismatch']}, orphan {exceptions['ORPHAN']}/{faults['orphan']}")
