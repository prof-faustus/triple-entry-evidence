# Full-population (80k) behavioural simulation: REAL hashing/commitment/Merkle/reconciliation at full scale.
# Per-note ECDH+ECDSA crypto cost is taken from the measured Table 11 medians (cited as such), not re-run 80k
# times, because the population study measures STORAGE, BATCHING, and RECONCILIATION behaviour, while the
# per-operation cryptographic cost is already measured separately. All hashing/commitment/Merkle/reconciliation
# numbers below are produced by real execution over the full 80,000-invoice population.
import hashlib, os, random, time
def sha256(b): return hashlib.sha256(b).digest()
def u32(x): return x.to_bytes(4,'big')
def enc_label(s):
    b=s.encode() if isinstance(s,str) else s; return bytes([len(b)])+b
def enc_value(v):
    b=v.encode() if isinstance(v,str) else v; return u32(len(b))+b
def hkdf_exp(prk,info): return hashlib.sha256(prk+info+b'\x01').digest()  # single-block, real shape
def field_key(Km,note_id,label): return hkdf_exp(Km,b'commit'+enc_label(note_id)+enc_label(label))
def commit(Km,note_id,label,value):
    Kf=field_key(Km,note_id,label); return sha256(Kf+enc_label(label)+enc_value(value))
def leaf_hash(b): return sha256(b'\x00'+b)
def node_hash(l,r): return sha256(b'\x01'+l+r)
def merkle_root(leaves):
    lvl=[leaf_hash(x) for x in leaves]
    if not lvl: return b''
    while len(lvl)>1:
        if len(lvl)%2: lvl.append(lvl[-1])
        lvl=[node_hash(lvl[i],lvl[i+1]) for i in range(0,len(lvl),2)]
    return lvl[0]

random.seed(20260528)
N_INV=80000; N_CP=400; BATCH=1000
INV_FIELDS=['InvID','Curr','Net','Gross','Tax','Due','Terms','MeasPol']
t0=time.time()
inv_tags=[]; note_sizes=[]; gross_total=0.0
for k in range(N_INV):
    Km=sha256(b'note-master'+u32(k))           # stand-in per-note key material (real 32-byte key)
    note_id=f"INV-{k:05d}"
    net=round(random.uniform(100,50000),2); tax=round(net*0.21,2); gross=round(net+tax,2); gross_total+=gross
    vals={'InvID':note_id,'Curr':'EUR','Net':f"{net:.2f}",'Gross':f"{gross:.2f}",'Tax':f"{tax:.2f}",
          'Due':'2026-04-30','Terms':'NET30','MeasPol':'STD-ROUND'}
    Cs=[commit(Km,note_id,f,vals[f]) for f in INV_FIELDS]
    linkage=sha256(b'inv-tag'+u32(k))
    body_len=2+32+32+33+33+1+32*8     # 389
    note_sizes.append(body_len+8+64)  # +timestamp+sig
    inv_tags.append(linkage)
commit_time=time.time()-t0

PAID=int(N_INV*0.95)
pay_tags=[sha256(b'pay-tag'+u32(k)) for k in range(PAID)]
medium={}; 
for t in inv_tags: medium[t]=('inv',None)
pay_ref={}
for k in range(PAID):
    medium[pay_tags[k]]=('pay',inv_tags[k]); pay_ref[pay_tags[k]]=inv_tags[k]

allnotes=list(medium.keys())
t2=time.time()
roots=[merkle_root(allnotes[i:i+BATCH]) for i in range(0,len(allnotes),BATCH)]
batch_time=time.time()-t2

# inject faults
faults={'missing':0,'mismatch':0,'orphan':0}
mp=int(PAID*0.005)
for k in range(mp):
    if pay_tags[k] in medium: del medium[pay_tags[k]]; faults['missing']+=1
mm=int(PAID*0.003)
for k in range(mp, mp+mm):
    if pay_tags[k] in medium: medium[pay_tags[k]]=('pay',os.urandom(32)); faults['mismatch']+=1
mo=int(N_INV*0.002)
for _ in range(mo): medium[os.urandom(32)]=('inv','ORPHAN'); faults['orphan']+=1

# reconciliation (deterministic)
inv_set=set(inv_tags); pay_set=set(pay_tags)
exc={'MISSING_INVOICE':0,'MISSING_PAYMENT':0,'LINKAGE_MISMATCH':0,'ORPHAN':0}
t3=time.time()
for t in inv_tags:
    if t not in medium: exc['MISSING_INVOICE']+=1
for k in range(PAID):
    t=pay_tags[k]
    if t not in medium: exc['MISSING_PAYMENT']+=1
    else:
        typ,ref=medium[t]
        if ref!=inv_tags[k]: exc['LINKAGE_MISMATCH']+=1
for tag,(typ,ref) in medium.items():
    if tag not in inv_set and tag not in pay_set: exc['ORPHAN']+=1
recon_time=time.time()-t3

# Table 11 measured medians (microseconds) for crypto cost extrapolation, cited as measured:
SIGN_US=2738.9; ECDH_US=2050.9   # verify-note and linkage-material medians
total_notes=N_INV+PAID
total_exc=sum(exc.values())
clean=total_notes-exc['MISSING_INVOICE']-exc['MISSING_PAYMENT']-exc['LINKAGE_MISMATCH']
print("=== FULL-POPULATION SIMULATION (real execution: commitments, Merkle, reconciliation) ===")
print(f"invoices: {N_INV} | payments: {PAID} (95%) | counterparties: {N_CP}")
print(f"total notes on medium: {total_notes}")
print(f"invoice note size: {note_sizes[0]} bytes")
print(f"total note data: {sum(note_sizes)/1e6:.1f} MB (pre-batch)")
print(f"commitment generation (8 fields x {N_INV} invoices) wall time: {commit_time:.1f} s")
print(f"Merkle batches ({BATCH}/batch): {len(roots)} roots; build wall time: {batch_time:.2f} s")
print(f"reconciliation wall time over {total_notes} notes: {recon_time:.2f} s")
print(f"injected faults: {faults}")
print(f"reconciliation exceptions: {exc}")
print(f"detection: missing {exc['MISSING_PAYMENT']}/{faults['missing']}; mismatch {exc['LINKAGE_MISMATCH']}/{faults['mismatch']}; orphan {exc['ORPHAN']}/{faults['orphan']}")
print(f"total exceptions: {total_exc} ({100*total_exc/total_notes:.2f}% of notes)")
print(f"clean covered population (full-population recalculation, no confirmation needed): {clean} ({100*clean/total_notes:.2f}%)")
print(f"--- crypto cost extrapolated from Table 11 measured medians (labelled as such) ---")
print(f"signing+verify all notes: ~{SIGN_US*total_notes/1e6/60:.1f} min; linkage material: ~{ECDH_US*total_notes/1e6/60:.1f} min")
print(f"anchor writes reduced from {total_notes} to {len(roots)} via batching (x{total_notes//len(roots)} amortisation)")
