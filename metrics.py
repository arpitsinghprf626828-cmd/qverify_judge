"""Measures extraction accuracy and per-rule precision/recall/F1 on the labelled synthetic batch. Run: python metrics.py"""
import json, time
from pathlib import Path
import engine

def run(root="samples/batch", write=True):
    reg = json.load(open("registry.json")); truth = json.load(open(Path(root) / "ground_truth.json")); cfg = engine.load_rules()
    tp, fp, fn = {}, {}, {}; fld_ok = fld_n = 0; times = []; per_app = []
    for app, gt in truth.items():
        docs = [(p.name, p.read_bytes()) for p in sorted((Path(root) / app).glob("*.pdf"))]; form = json.load(open(Path(root) / app / "form.json"))
        t0 = time.perf_counter(); res = engine.validate(docs, form, reg, cfg=cfg); times.append(time.perf_counter() - t0)
        got = {(f["rule"], f["document"]) for f in res["findings"] if f["rule"] not in ("R19", "R04")}; exp = {tuple(x) for x in gt["expected"]}
        for r, _ in got & exp: tp[r] = tp.get(r, 0) + 1
        for r, _ in got - exp: fp[r] = fp.get(r, 0) + 1
        for r, _ in exp - got: fn[r] = fn.get(r, 0) + 1
        for p in res["parsed"]:
            for k, v in gt["fields"].get(p["name"], {}).items():
                fld_n += 1; fld_ok += int(p["fields"].get(k, {}).get("value") == v)
        per_app.append({"app": app, "faults": gt["faults"], "expected": len(exp), "found": len(got), "missed": sorted(exp - got), "extra": sorted(got - exp)})
    rows = []
    for r in sorted(set(tp) | set(fp) | set(fn)):
        a, b, c = tp.get(r, 0), fp.get(r, 0), fn.get(r, 0); p = a / (a + b) if a + b else 1.0; rc = a / (a + c) if a + c else 1.0
        rows.append({"Rule": r, "TP": a, "FP": b, "FN": c, "Precision": round(p, 3), "Recall": round(rc, 3), "F1": round(2 * p * rc / (p + rc), 3) if p + rc else 0.0})
    A, B, C = sum(tp.values()), sum(fp.values()), sum(fn.values()); mp = A / (A + B) if A + B else 1.0; mr = A / (A + C) if A + C else 1.0
    out = {"applications": len(truth), "extraction_accuracy": round(fld_ok / fld_n, 4) if fld_n else None, "fields_checked": fld_n, "per_rule": rows,
           "micro_precision": round(mp, 3), "micro_recall": round(mr, 3), "avg_seconds_per_case": round(sum(times) / len(times), 2), "per_app": per_app}
    if write: Path("models").mkdir(exist_ok=True); Path("models/eval.json").write_text(json.dumps(out, indent=2))
    return out

if __name__ == "__main__":
    o = run(); print(f"Applications: {o['applications']}  Extraction accuracy: {o['extraction_accuracy']} ({o['fields_checked']} fields)  Avg {o['avg_seconds_per_case']}s/case")
    print(f"Micro precision {o['micro_precision']}  recall {o['micro_recall']}"); [print(r) for r in o["per_rule"]]
    for a in o["per_app"]:
        if a["missed"] or a["extra"]: print("CHECK", a["app"], a["faults"], "missed", a["missed"], "extra", a["extra"])
