"""Issuer-signed credentials. The issuer signs the certificate's key fields with ML-DSA; the signed envelope travels INSIDE
the document (PDF metadata). The platform verifies it OFFLINE against the trusted key registry - no issuer API needed.
A forged date in the document text no longer matches the signed record; an edited credential fails signature verification."""
import json, base64, datetime as dt
from dilithium_py.ml_dsa import ML_DSA_44 as MLDSA
from . import registry as R

def issue(issuer_id, payload, sign_payload=None, issued_at=None):
    """sign_payload: signs DIFFERENT values than the ones shipped (used only by the demo to simulate tampering)."""
    e = R.by_issuer(issuer_id); issued_at = issued_at or dt.datetime.now().isoformat(timespec="seconds")
    meta = {"issuer_id": issuer_id, "key_id": e["key_id"], "alg": "ML-DSA-44", "issued_at": issued_at}
    msg = R.canonical({"payload": sign_payload or payload, **meta})
    return {"payload": payload, **meta, "sig": R.b64(MLDSA.sign(R.secret(issuer_id), msg))}

def verify(env, as_of=None):
    """-> {ok, reason, payload, issuer, key_id}. reason: ok | unknown_key | revoked | key_expired | registry_tampered | bad_signature | malformed"""
    try:
        reg, _ = R.load(); e = reg.get(env["key_id"])
        base = {"payload": env["payload"], "key_id": env["key_id"], "issuer": (e or {}).get("owner", "unknown issuer")}
        trusted, why = R.trust_check(env["key_id"], env["issued_at"][:10])
        if not trusted: return {**base, "ok": False, "reason": why}
        msg = R.canonical({"payload": env["payload"], **{k: env[k] for k in ("issuer_id", "key_id", "alg", "issued_at")}})
        good = bool(MLDSA.verify(R.unb64(e["public_key_b64"]), msg, R.unb64(env["sig"])))
        return {**base, "ok": good, "reason": "ok" if good else "bad_signature"}
    except Exception:
        return {"ok": False, "reason": "malformed", "payload": {}, "key_id": None, "issuer": "unknown"}

def encode(env): return base64.b64encode(json.dumps(env, sort_keys=True).encode()).decode()
def decode(s): return json.loads(base64.b64decode(s))
