"""Signed verification reports: ML-DSA-44 (FIPS 204) + optional Ed25519 hybrid. Keys come from the registry.
NOTE: dilithium-py is a pure-Python educational implementation; production should use a hardened library (liboqs/HSM)."""
import json, time, io, hashlib, datetime as dt
from dilithium_py.ml_dsa import ML_DSA_44 as MLDSA
from dilithium_py.ml_dsa import ML_DSA_65, ML_DSA_87
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import qrcode
from . import registry as R, keystore

def sign_report(report, hybrid=True):
    R.ensure_pki(); e = R.by_issuer("PLATFORM")
    meta = {"alg": "ML-DSA-44" + ("+Ed25519" if hybrid else ""), "key_id": e["key_id"],
            "signed_at": dt.datetime.now().isoformat(timespec="seconds")}
    payload = R.canonical({"report": report, **meta})
    env = {"report": report, **meta, "report_sha256": hashlib.sha256(payload).hexdigest(),
           "sig_mldsa": R.b64(MLDSA.sign(R.secret("PLATFORM"), payload))}
    if hybrid: env["sig_ed25519"] = R.b64(Ed25519PrivateKey.from_private_bytes(keystore.read_secret(R.KD / "ed.sk")).sign(payload))
    return env

def verify_envelope(env):
    """-> {valid, mldsa, ed25519?, key_trusted, reason}"""
    reg, _ = R.load(); e = reg.get(env.get("key_id"))
    trusted, why = R.trust_check(env.get("key_id"), (env.get("signed_at") or "")[:10] or None)
    res = {"key_trusted": trusted, "reason": why if not trusted else "ok"}
    if not e: res.update(mldsa=False, valid=False); return res
    payload = R.canonical({"report": env.get("report"), **{x: env.get(x) for x in ("alg", "key_id", "signed_at")}})
    try: res["mldsa"] = bool(MLDSA.verify(R.unb64(e["public_key_b64"]), payload, R.unb64(env["sig_mldsa"])))
    except Exception: res["mldsa"] = False
    if "sig_ed25519" in env:
        try: Ed25519PublicKey.from_public_bytes(R.unb64(e["ed25519_pk_b64"])).verify(R.unb64(env["sig_ed25519"]), payload); res["ed25519"] = True
        except (InvalidSignature, Exception): res["ed25519"] = False
    res["valid"] = trusted and res["mldsa"] and res.get("ed25519", True)
    if res["mldsa"] is False and trusted: res["reason"] = "bad_signature"
    return res

def qr_png(env):
    buf = io.BytesIO(); qrcode.make(f"QVERIFY|{env['alg']}|{env['key_id']}|{env['report_sha256']}").save(buf, format="PNG"); return buf.getvalue()

def benchmark(n=10):
    R.ensure_pki(); msg = b"x" * 2000; out = []
    def t(fn):
        s = time.perf_counter()
        for _ in range(n): r = fn()
        return round((time.perf_counter() - s) / n * 1000, 2), r
    ed = Ed25519PrivateKey.generate(); epk = ed.public_key()
    ts, sg = t(lambda: ed.sign(msg)); tv, _ = t(lambda: epk.verify(sg, msg))
    out.append({"Algorithm": "Ed25519 (classical)", "Public key (B)": 32, "Signature (B)": len(sg), "Sign (ms)": ts, "Verify (ms)": tv, "Quantum-safe": "No"})
    for name, M in (("ML-DSA-44", MLDSA), ("ML-DSA-65", ML_DSA_65), ("ML-DSA-87", ML_DSA_87)):
        pk, sk = M.keygen(); ts, sg = t(lambda: M.sign(sk, msg)); tv, _ = t(lambda: M.verify(pk, msg, sg))
        out.append({"Algorithm": f"{name} (FIPS 204)", "Public key (B)": len(pk), "Signature (B)": len(sg), "Sign (ms)": ts, "Verify (ms)": tv, "Quantum-safe": "Yes"})
    return out
