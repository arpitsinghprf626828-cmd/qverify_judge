import copy
from pqc import registry, signing, credentials, vault
from pqc.audit import AuditLog
def test_sign_verify_tamper():
    env = signing.sign_report({"a": 1, "findings": [{"id": "F01", "severity": "High"}]}); assert signing.verify_envelope(env)["valid"]
    t = copy.deepcopy(env); t["report"]["findings"][0]["severity"] = "Low"; assert not signing.verify_envelope(t)["valid"]
def test_credential_tamper_and_revocation():
    env = credentials.issue("NBA", {"valid_until": "2030-01-01"}); assert credentials.verify(env)["ok"]
    t = copy.deepcopy(env); t["payload"]["valid_until"] = "2040-01-01"; assert credentials.verify(t)["reason"] == "bad_signature"
    registry.revoke("NBA")
    try: assert credentials.verify(env)["reason"] == "revoked"
    finally: registry.reinstate("NBA")
    assert credentials.verify(env)["ok"]
def test_registry_tamper_detected():
    import json; d = json.loads(registry.REG.read_text()); orig = registry.REG.read_text(); d["keys"][1]["status"] = "revoked"; registry.REG.write_text(json.dumps(d))
    try: assert registry.load()[1] is False
    finally: registry.REG.write_text(orig)
def test_vault_roundtrip_and_aad():
    blob = vault.seal(b"secret", "CASE1"); assert vault.open_sealed(blob, "CASE1") == b"secret"
    try: vault.open_sealed(blob, "CASE2"); assert False
    except Exception: pass
def test_audit_chain_and_checkpoint(tmp_path):
    a = AuditLog(tmp_path / "a.jsonl", tmp_path / "c.jsonl")
    for i in range(5): a.add("t", "x", str(i))
    a.checkpoint(); assert a.verify_chain()[0] and all(c["ok"] for c in a.verify_checkpoints())
    lines = (tmp_path / "a.jsonl").read_text().splitlines(); lines[2] = lines[2].replace('"x"', '"y"'); (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n"); assert not a.verify_chain()[0]

def test_keys_encrypted_at_rest(monkeypatch, tmp_path):
    from pqc import keystore
    monkeypatch.setenv("QV_KEY_PASSPHRASE", "unit-test-pass")
    p = tmp_path / "x.sk"; keystore.write_secret(p, b"secret-key-bytes")
    assert keystore.is_encrypted(p) and b"secret-key-bytes" not in p.read_bytes() and keystore.read_secret(p) == b"secret-key-bytes"
    monkeypatch.setenv("QV_KEY_PASSPHRASE", "wrong")
    try: keystore.read_secret(p); assert False
    except Exception: pass

def test_login_lockout(tmp_path, monkeypatch):
    import auth; monkeypatch.setattr(auth, "FAILS", tmp_path / "f.json")
    for _ in range(5): assert auth.login("admin1", "wrong") is None
    assert auth.locked_for("admin1") > 0 and auth.login("admin1", "Admin@123") is None
