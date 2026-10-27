"""Hash-chained audit log + ML-DSA-signed Merkle checkpoints (rewriting the whole file still fails the checkpoint check)."""
import json, hashlib, datetime as dt
from pathlib import Path
from . import signing

def _h(b): return hashlib.sha256(b).hexdigest()
def merkle_root(hashes):
    level = [bytes.fromhex(h) for h in hashes] or [b"\x00" * 32]
    while len(level) > 1:
        if len(level) % 2: level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()

class AuditLog:
    def __init__(self, path="audit.jsonl", cp="audit_checkpoints.jsonl"):
        self.path, self.cp = Path(path), Path(cp); self.path.touch(exist_ok=True); self.cp.touch(exist_ok=True)
    def entries(self): return [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]
    def add(self, actor, action, detail=""):
        es = self.entries(); prev = es[-1]["hash"] if es else "0" * 64
        e = {"ts": dt.datetime.now().isoformat(timespec="seconds"), "actor": actor, "action": action, "detail": detail, "prev": prev}
        e["hash"] = _h(json.dumps(e, sort_keys=True).encode())
        with open(self.path, "a") as f: f.write(json.dumps(e) + "\n")
    def verify_chain(self):
        prev = "0" * 64
        for i, e in enumerate(self.entries()):
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["prev"] != prev or _h(json.dumps(body, sort_keys=True).encode()) != e["hash"]: return False, i
            prev = e["hash"]
        return True, None
    def checkpoint(self):
        hs = [e["hash"] for e in self.entries()]
        env = signing.sign_report({"type": "audit_checkpoint", "merkle_root": merkle_root(hs), "entries": len(hs)}, hybrid=False)
        with open(self.cp, "a") as f: f.write(json.dumps(env) + "\n")
        return env
    def verify_checkpoints(self):
        """-> list of {entries, ok, reason}"""
        hs = [e["hash"] for e in self.entries()]; out = []
        for l in self.cp.read_text().splitlines():
            if not l.strip(): continue
            env = json.loads(l); r = env["report"]; v = signing.verify_envelope(env)
            same = len(hs) >= r["entries"] and merkle_root(hs[:r["entries"]]) == r["merkle_root"]
            out.append({"entries": r["entries"], "ok": bool(v["valid"] and same),
                        "reason": "ok" if v["valid"] and same else ("history_rewritten" if v["valid"] else v["reason"])})
        return out
