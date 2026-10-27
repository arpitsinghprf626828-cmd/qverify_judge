"""Trusted key registry. The ROOT key (ML-DSA-65) signs the registry, so editing it is detected."""
import json, base64, hashlib, datetime as dt
from pathlib import Path
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as S
from . import keystore

KD = Path("keys"); REG = KD / "registry.json"
OWNERS = {"PLATFORM": "Q-Verify Verification Service (demo)", "NBA": "National Board of Accreditation (MOCK)",
          "STATE_NOC": "State Higher Education Dept (MOCK)", "FIRE": "Fire Services Dept (MOCK)",
          "BUILDING": "Public Works Dept (MOCK)"}
b64 = lambda b: base64.b64encode(b).decode(); unb64 = lambda s: base64.b64decode(s)
def canonical(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def key_id(pk): return hashlib.sha256(pk).hexdigest()[:16]

def ensure_pki():
    """Creates demo keys + root-signed registry on first run (idempotent)."""
    KD.mkdir(exist_ok=True)
    if REG.exists(): return
    rpk, rsk = ML_DSA_65.keygen(); (KD / "root_pk.bin").write_bytes(rpk); keystore.write_secret(KD / "root.sk", rsk)
    today = dt.date.today(); keys = []
    for iid, owner in OWNERS.items():
        pk, sk = ML_DSA_44.keygen(); keystore.write_secret(KD / f"{iid}.sk", sk)
        e = {"issuer_id": iid, "owner": owner, "alg": "ML-DSA-44", "key_id": key_id(pk), "public_key_b64": b64(pk),
             "valid_from": str(today - dt.timedelta(days=30)), "valid_to": str(today + dt.timedelta(days=365)), "status": "active"}
        if iid == "PLATFORM":
            ed = Ed25519PrivateKey.generate()
            keystore.write_secret(KD / "ed.sk", ed.private_bytes(S.Encoding.Raw, S.PrivateFormat.Raw, S.NoEncryption()))
            e["ed25519_pk_b64"] = b64(ed.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw))
        keys.append(e)
    _save(keys)

def _save(keys):
    sig = ML_DSA_65.sign(keystore.read_secret(KD / "root.sk"), canonical(keys))
    REG.write_text(json.dumps({"keys": keys, "root_signature_b64": b64(sig)}, indent=2))

def load():
    """-> (dict key_id -> entry, integrity_ok). integrity_ok False means the registry file was edited."""
    ensure_pki(); d = json.loads(REG.read_text())
    try: ok = bool(ML_DSA_65.verify((KD / "root_pk.bin").read_bytes(), canonical(d["keys"]), unb64(d["root_signature_b64"])))
    except Exception: ok = False
    return {k["key_id"]: k for k in d["keys"]}, ok

def entries(): return list(load()[0].values())
def by_issuer(iid): return next(e for e in entries() if e["issuer_id"] == iid)
def secret(iid): ensure_pki(); return keystore.read_secret(KD / f"{iid}.sk")
def set_status(iid, status):
    ks = entries()
    for k in ks:
        if k["issuer_id"] == iid: k["status"] = status
    _save(ks)
def revoke(iid): set_status(iid, "revoked")
def reinstate(iid): set_status(iid, "active")

def trust_check(kid, when=None):
    """-> (trusted: bool, reason: str)"""
    reg, ok = load(); e = reg.get(kid); when = str(when or dt.date.today())[:10]
    if not ok: return False, "registry_tampered"
    if not e: return False, "unknown_key"
    if e["status"] != "active": return False, "revoked"
    if not (e["valid_from"] <= when <= e["valid_to"]): return False, "key_expired"
    return True, "ok"
