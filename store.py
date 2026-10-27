"""Case database (SQLite), alerts and a simulated e-mail outbox."""
import json, sqlite3, datetime as dt
from pathlib import Path
class CaseStore:
    def __init__(self, path="cases.db"):
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.execute("create table if not exists cases(id integer primary key autoincrement, ts text, user text, inst_id text, inst_name text, category text, status text, score int, high int, n int, findings text, docs text)")
        self.con.commit()
    def add(self, user, form, result):
        F = result["findings"]; high = sum(f["severity"] == "High" for f in F)
        docs = [{"name": p["name"], "status": (p.get("issuer") or {}).get("status", "n/a"), "pqc": bool((p.get("issuer") or {}).get("pqc"))} for p in result["parsed"]]
        cur = self.con.execute("insert into cases(ts,user,inst_id,inst_name,category,status,score,high,n,findings,docs) values (?,?,?,?,?,?,?,?,?,?,?)",
            (dt.datetime.now().isoformat(timespec="seconds"), user, form["institution_id"], form["institution_name"], form["category"], "Clean" if not F else "Needs review", result["score"], high, len(F),
             json.dumps([{k: f[k] for k in ("rule", "severity", "document", "message")} for f in F]), json.dumps(docs)))
        self.con.commit(); return cur.lastrowid
    def rows(self):
        cols = ["id", "ts", "user", "inst_id", "inst_name", "category", "status", "score", "high", "n"]
        return [dict(zip(cols, r)) for r in self.con.execute(f"select {','.join(cols)} from cases order by id desc")]
    def set_status(self, cid, status): self.con.execute("update cases set status=? where id=?", (status, cid)); self.con.commit()
    def alerts(self):
        out = []
        for cid, name, st, fj, dj in self.con.execute("select id, inst_name, status, findings, docs from cases order by id desc"):
            if st in ("Resolved", "Clean"): continue
            for f in json.loads(fj):
                if f["rule"] == "R04": out.append({"case": cid, "institution": name, "type": "Expiring soon", "detail": f"{f['document']}: {f['message']}"})
                if f["severity"] == "High" and f["rule"] in ("R11", "R14", "R17"): out.append({"case": cid, "institution": name, "type": "Suspected anomaly", "detail": f"{f['document']}: {f['message']}"})
            for dd in json.loads(dj):
                if dd["status"] in ("Source unavailable", "Verification pending", "Manual review required"): out.append({"case": cid, "institution": name, "type": "Pending verification", "detail": f"{dd['name']}: {dd['status']}"})
        return out
def send_alert(text, to="reviewer@aicte.demo (SIMULATED)"):
    Path("outbox").mkdir(exist_ok=True); p = Path("outbox/alerts.log")
    with open(p, "a") as f: f.write(f"[{dt.datetime.now().isoformat(timespec='seconds')}] To: {to}\n{text}\n---\n")
    return p
