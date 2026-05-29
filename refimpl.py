# Reference implementation of the artefact, used to COMPUTE the deterministic vectors that
# Appendix C must contain. Mirrors Appendix C exactly: secp256k1, SHA-256, HKDF-SHA256, ECDSA low-S RFC6979.
import hashlib, hmac
from ecdsa import SECP256k1, ellipticcurve, numbertheory
from ecdsa.util import sigencode_string_canonize
curve = SECP256k1
G = curve.generator
n = curve.order
p = curve.curve.p()

def sha256(b): return hashlib.sha256(b).digest()
def hmac_sha256(k,m): return hmac.new(k,m,hashlib.sha256).digest()
def be32(s): return s.to_bytes(32,'big')
def int_be(b): return int.from_bytes(b,'big')
def u32(nn): return nn.to_bytes(4,'big')
def ascii_b(s): return s.encode('ascii')
def encode_label(s):
    b=s.encode('ascii') if isinstance(s,str) else s
    assert len(b)<=255
    return bytes([len(b)])+b
def encode_value(v):
    b=v.encode('ascii') if isinstance(v,str) else v
    return u32(len(b))+b
def encode_scalar(s): return be32(s)
def point_compress(P):
    x=P.x(); y=P.y()
    return bytes([0x02 if y%2==0 else 0x03])+be32(x)

def hkdf_extract(salt,ikm): return hmac_sha256(salt,ikm)
def hkdf_expand(prk,info,L=32):
    assert L<=32
    return hmac_sha256(prk, info+b'\x01')[:L]

def derive_subkey(sk_master,i):
    h=int_be(sha256(encode_scalar(sk_master)+u32(i)))%n
    sk_i=(sk_master+h)%n
    assert 1<=sk_i<=n-1
    P=sk_i*G
    return sk_i, point_compress(P), P

def derive_key_material(sk_self,pk_other_point):
    Q=sk_self*pk_other_point
    S=encode_scalar(Q.x()%p)
    Kmaster=hkdf_extract(ascii_b('TEA-v1'),S)
    Linv=hkdf_expand(Kmaster,ascii_b('inv-tag'),32)
    Lpay=hkdf_expand(Kmaster,ascii_b('pay-tag'),32)
    return S,Kmaster,Linv,Lpay

def field_key(Kmaster,note_id,label):
    info=ascii_b('commit')+encode_label(note_id)+encode_label(label)
    return hkdf_expand(Kmaster,info,32)
def commit(Kmaster,note_id,label,value):
    Kf=field_key(Kmaster,note_id,label)
    msg=Kf+encode_label(label)+encode_value(value)
    return Kf, sha256(msg)

# ---- worked example inputs ----
skA=int_be(bytes.fromhex('11'*32))
skB=int_be(bytes.fromhex('22'*32))
skA1,pkA1,PA1=derive_subkey(skA,1)
skB1,pkB1,PB1=derive_subkey(skB,1)
S_A,Km_A,Linv,Lpay=derive_key_material(skA1,PB1)
S_B,Km_B,_,_=derive_key_material(skB1,PA1)
assert S_A==S_B and Km_A==Km_B, "ECDH agreement failed"
S=S_A; Km=Km_A
note_id='INV-0001'
# CANONICAL DECISION (fix the fork): Tax commits the AMOUNT 2100.00; Due = 2026-04-30; MeasPol token = STD-ROUND
fields=[('InvID','INV-0001'),('Curr','EUR'),('Net','10000.00'),('Gross','12100.00'),
        ('Tax','2100.00'),('Due','2026-04-30'),('Terms','NET30'),('MeasPol','STD-ROUND')]
Kfs=[]; Cs=[]
for label,val in fields:
    Kf,C=commit(Km,note_id,label,val); Kfs.append((label,Kf)); Cs.append((label,C))
# body
body=bytes([0x01,0x01])+Linv+bytes(32)+pkA1+pkB1+bytes([8])+b''.join(C for _,C in Cs)
bodyhash=sha256(body)
# ECDSA low-S deterministic
from ecdsa import SigningKey
sk_obj=SigningKey.from_secret_exponent(skA1,curve=SECP256k1)
sig=sk_obj.sign_digest_deterministic(bodyhash,hashfunc=hashlib.sha256,sigencode=sigencode_string_canonize)
r=int_be(sig[:32]); s=int_be(sig[32:])

def hx(b): return b.hex()
print("sk_master_A   ", '11'*32)
print("sk_master_B   ", '22'*32)
print("sk_A_1        ", be32(skA1).hex())
print("pk_A_1        ", pkA1.hex())
print("sk_B_1        ", be32(skB1).hex())
print("pk_B_1        ", pkB1.hex())
print("S             ", S.hex())
print("K_master      ", Km.hex())
print("L_inv         ", Linv.hex())
print("L_pay         ", Lpay.hex())
for (label,Kf) in Kfs: print(f"K_field[{label:8}] ", Kf.hex())
for (label,C) in Cs:  print(f"C_field[{label:8}] ", C.hex())
print("body (hex)    ", body.hex())
print("body_len      ", len(body))
print("body_hash     ", bodyhash.hex())
print("r             ", be32(r).hex())
print("s             ", be32(s).hex())
print("low_S_ok      ", s <= n//2)
