"""Explainable ML (scikit-learn), trained on SYNTHETIC data and retrained automatically on first run.
1) Document classifier: TF-IDF + logistic regression, with confidence and the top terms behind each prediction.
2) Metadata anomaly detector: IsolationForest over forensic features. ADVISORY only; always shown as an indicator for human review."""
import json, random
from pathlib import Path
import numpy as np, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
MD = Path("models"); CLF = MD / "doc_clf.joblib"; ANO = MD / "anomaly.joblib"; MET = MD / "metrics.json"
TITLES = {"affidavit": ["AFFIDAVIT AND UNDERTAKING", "AFFIDAVIT", "UNDERTAKING BY THE INSTITUTION", "NOTARISED DECLARATION AFFIDAVIT", "SWORN AFFIDAVIT"],
          "noc": ["STATE NO OBJECTION CERTIFICATE (NOC)", "NO OBJECTION CERTIFICATE", "CERTIFICATE OF NO OBJECTION", "STATE GOVERNMENT NOC", "NOC FOR EXTENSION OF APPROVAL"],
          "accreditation": ["NBA ACCREDITATION CERTIFICATE", "ACCREDITATION CERTIFICATE", "NATIONAL BOARD OF ACCREDITATION", "PROGRAMME ACCREDITATION", "NAAC ACCREDITATION"],
          "fire_safety": ["FIRE SAFETY CERTIFICATE", "FIRE NOC", "FIRE SAFETY COMPLIANCE", "FIRE DEPARTMENT CLEARANCE", "FIRE PREVENTION CERTIFICATE"],
          "building": ["BUILDING STABILITY CERTIFICATE", "STRUCTURAL SAFETY CERTIFICATE", "STRUCTURAL STABILITY REPORT", "BUILDING SAFETY CERTIFICATE", "ENGINEER STABILITY CERTIFICATE"]}
BODY = ["Institution Name: {n}", "Institution ID: AICTE-1-{i}", "Reference No: REF/{i}/{y}", "Issue Date: {y}-0{m}-1{m}", "Valid Until: {y2}-0{m}-2{m}", "(SYNTHETIC DEMO DOCUMENT - NOT REAL)"]
NAMES = ["Narmada Institute", "Vindhya College", "Malwa Technical Campus", "Satpura Engineering College", "Holkar Institute"]
def _typo(s, rng): 
    return "".join(c if rng.random() > 0.01 else rng.choice("0Ol1") for c in s)
def synth(t, rng):
    body = [b.format(n=rng.choice(NAMES), i=rng.randint(10000, 99999), y=rng.randint(2022, 2027), y2=rng.randint(2027, 2032), m=rng.randint(1, 9)) for b in BODY]
    if t == "affidavit": body.append(f"Approved Intake: {rng.choice([60, 120, 240, 360, 420])}")
    rng.shuffle(body[1:]); return _typo(rng.choice(TITLES[t]) + "\n" + "\n".join(body), rng)

def train_classifier():
    MD.mkdir(exist_ok=True); rng = random.Random(7); X, y = [], []
    for t in TITLES:
        for _ in range(160): X.append(synth(t, rng)); y.append(t)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=1, stratify=y)
    m = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2), LogisticRegression(max_iter=1000, C=8)).fit(Xtr, ytr)
    acc = float(m.score(Xte, yte)); joblib.dump(m, CLF); return m, acc

def _feat(x):
    x = np.asarray(x, dtype=float).copy(); x[..., 0] = np.log1p(np.abs(x[..., 0])); return x

def train_anomaly():
    rng = np.random.default_rng(3); n = 1500
    X = np.c_[rng.exponential(2.0, n).round(), rng.random(n) < 0.04, rng.random(n) < 0.02, rng.random(n) < 0.02,
              rng.uniform(0.1, 0.7, n), rng.integers(4, 8, n)]
    m = IsolationForest(n_estimators=200, contamination=0.01, random_state=0).fit(_feat(X)); joblib.dump(m, ANO); return m

def ensure_models():
    out = {}
    try: out["clf"] = joblib.load(CLF)
    except Exception: out["clf"], acc = train_classifier(); MET.write_text(json.dumps({"classifier_holdout_accuracy": round(acc, 4), "train_samples": 600, "data": "synthetic"}))
    try: out["ano"] = joblib.load(ANO)
    except Exception: out["ano"] = train_anomaly()
    return out
_M = {}
def _m():
    if not _M: _M.update(ensure_models())
    return _M

def classify(text):
    """-> {type, confidence, top_terms}"""
    if len(text.strip()) < 15: return {"type": "unknown", "confidence": 0.0, "top_terms": []}
    pipe = _m()["clf"]; vec, lr = pipe.steps[0][1], pipe.steps[1][1]
    x = vec.transform([text]); pr = lr.predict_proba(x)[0]; k = int(pr.argmax())
    contrib = x.toarray()[0] * lr.coef_[k]; top = np.argsort(contrib)[::-1][:3]; names = vec.get_feature_names_out()
    return {"type": str(lr.classes_[k]), "confidence": float(pr[k]), "top_terms": [str(names[i]) for i in top if contrib[i] > 0]}

def anomaly(feats):
    """feats: [gap_days, extra_eof, mixed_font_spans, suspicious_producer, text_len/1000, n_fields] -> (is_anomaly, score; lower = more anomalous)"""
    m = _m()["ano"]; f = _feat([feats]); s = float(m.decision_function(f)[0]); return bool(m.predict(f)[0] == -1), s
