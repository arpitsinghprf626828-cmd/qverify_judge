"""Validation engine: OCR cascade, ML classification, configurable rules (rules.json), PQC credential verification,
forensics, photo checks, explainable scoring."""
import hashlib, io, json, re, datetime as dt
from pathlib import Path
from pypdf import PdfReader
from rapidfuzz import fuzz
from dateutil import parser as dp
from PIL import Image
import ocr, ml, forensics as fx
from pqc import credentials

RULES_PATH = Path("rules.json")
def load_rules(): return json.load(open(RULES_PATH))
def save_rules(cfg): RULES_PATH.write_text(json.dumps(cfg, indent=2))
RULES_VERSION = load_rules()["rules_version"]

KEYWORDS = {"affidavit": "affidavit", "noc": "no objection", "accreditation": "accreditation", "fire_safety": "fire safety", "building": "building stability"}
FIELDS = {"institution_id": r"Institution ID:\s*(\S+)", "institution_name": r"Institution Name:\s*(.+)", "ref_no": r"Reference No:\s*(\S+)",
          "issue_date": r"Issue Date:\s*([0-9A-Za-z/\-\. ,]{6,20})", "valid_until": r"Valid Until:\s*([0-9A-Za-z/\-\. ,]{6,20})", "intake": r"Approved Intake:\s*(\d+)"}
DATE_FIELDS = ("issue_date", "valid_until")
SUSPICIOUS_SOFTWARE = ["photoshop", "gimp", "illustrator", "canva"]
WEIGHT = {"High": 5, "Medium": 3, "Low": 1}

def sha256(b): return hashlib.sha256(b).hexdigest()
def norm(s): return re.sub(r"[^a-z0-9]", "", (s or "").lower())
def d(s): return dt.date.fromisoformat(s) if s else None
def to_iso(s):
    """Finds a date inside noisy text (OCR) and returns ISO. ISO input is never reinterpreted (dayfirst would swap month/day)."""
    m = re.search(r"\d{4}-\d{2}-\d{2}", s)
    if m: return m.group(0)
    m = re.search(r"\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}", s)       # 05/03/2026, 5 March 2026
    try: return dp.parse(m.group(0), dayfirst=True).date().isoformat() if m else None            # Indian documents write day first
    except Exception: return None

def _pdf_date(s):
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})", str(s or "")); return dt.date(int(m[1]), int(m[2]), int(m[3])) if m else None

def parse_document(name, data, S):
    p = {"name": name, "sha256": sha256(data), "doc_type": "unknown", "kind": "unknown", "fields": {}, "readable": False, "meta": {},
         "method": "none", "ocr_conf": None, "ml": None, "forensics": {"eof_count": 0, "mixed": []}, "qr": None, "image": None, "anomaly": None}
    pages, p["method"], p["ocr_conf"] = ocr.extract_pages(data, name, S.get("ocr_lang", "eng"))
    full = "\n".join(pages); p["readable"] = len(full.strip()) > 20; p["text_len"] = len(full)
    is_pdf = name.lower().endswith(".pdf"); is_img = name.lower().endswith(ocr.IMG_EXT)
    if is_pdf:
        try:
            md = PdfReader(io.BytesIO(data)).metadata or {}
            p["meta"] = {"producer": str(md.get("/Producer", "")), "created": _pdf_date(md.get("/CreationDate")),
                         "modified": _pdf_date(md.get("/ModDate")), "cred": str(md.get("/QVerifyCred", ""))}
            p["forensics"] = fx.pdf_forensics(data); p["qr"] = fx.decode_qr(fx.render_page(data, 0))
        except Exception: pass
    if p["readable"]:
        head = full[:200].lower(); p["ml"] = ml.classify(full)
        kw = next((t for t, k in KEYWORDS.items() if k in head), None)
        if kw: p["doc_type"] = kw
        elif p["ml"]["confidence"] >= S.get("ml_min_confidence", 0.6): p["doc_type"] = p["ml"]["type"]
    if is_img:
        try:
            img = Image.open(io.BytesIO(data)); p["image"] = {"phash": fx.phash(img), "blur": round(fx.blur_score(img), 1), "size": img.size, "gps": fx.exif_gps(data)}
        except Exception: pass
        if p["doc_type"] == "unknown" or not p["readable"]: p["kind"] = "photo"; p["doc_type"] = "infra_photo"
    if p["kind"] == "unknown" and p["doc_type"] != "unknown": p["kind"] = "certificate"
    for k, rx in FIELDS.items():
        for i, txt in enumerate(pages):
            m = re.search(rx, txt)
            if m:
                v = m.group(1).strip(); v = (to_iso(v) or v) if k in DATE_FIELDS else v.strip(" .,;:")
                conf = 0.99 if p["method"] == "text" else round((p["ocr_conf"] or 0) / 100, 2)
                p["fields"][k] = {"value": v, "page": i + 1, "snippet": m.group(0).strip(), "confidence": conf}; break
    return p

def verify_issuer(p, registry, as_of):
    """PQC path first: issuer-signed ML-DSA credential embedded in the PDF is verified OFFLINE against the trusted key registry and
    compared with the document text. Fallback: MOCK issuer lookup by reference number. Status labels follow the problem statement."""
    f = p["fields"]; ref = f.get("ref_no", {}).get("value"); stamp = dt.datetime.now().isoformat(timespec="seconds"); cred_s = p["meta"].get("cred")
    if cred_s:
        try: env = credentials.decode(cred_s)
        except Exception: env = {}
        v = credentials.verify(env)
        base = {"reference": ref, "checked_at": stamp, "pqc": True, "key_id": v.get("key_id"), "source": f"{v.get('issuer')} [SIMULATED] - ML-DSA signed credential, verified offline"}
        if not v["ok"]:
            st = "Mismatch detected" if v["reason"] in ("bad_signature", "malformed") else "Manual review required"
            return {**base, "status": st, "detail": f"PQC credential rejected: {v['reason']}"}
        pl = v["payload"]; diff = [k for k in ("institution_id", "ref_no", "valid_until", "issue_date") if str(pl.get(k)) != str(f.get(k, {}).get("value"))]
        if diff: return {**base, "status": "Mismatch detected", "detail": "Document differs from issuer-signed record in: " + "; ".join(f"{k} (document {f.get(k, {}).get('value')} vs signed {pl.get(k)})" for k in diff)}
        if pl.get("valid_until") and d(pl["valid_until"]) < as_of: return {**base, "status": "Expired", "detail": f"Signature valid; issuer-signed record expired on {pl['valid_until']}"}
        return {**base, "status": "Verified", "detail": "ML-DSA signature valid and document matches issuer-signed record (no issuer API needed)"}
    if not ref: return None
    rec = registry["issuers"].get(ref)
    base = {"reference": ref, "checked_at": stamp, "pqc": False, "source": (rec or {}).get("issuer", "No matching issuer record") + " [SIMULATED]"}
    if rec is None: return {**base, "status": "Manual review required", "detail": "Reference not found in issuer registry; no PQC credential"}
    if not rec["online"]: return {**base, "status": "Source unavailable", "detail": "Issuer service did not respond; routed to manual confirmation"}
    dv = f.get("valid_until", {}).get("value")
    if rec["institution_id"] != f.get("institution_id", {}).get("value"): return {**base, "status": "Mismatch detected", "detail": "Institution ID differs from issuer record"}
    if dv != rec["valid_until"]: return {**base, "status": "Mismatch detected", "detail": f"Document says valid until {dv}, issuer record says {rec['valid_until']}"}
    if d(rec["valid_until"]) < as_of: return {**base, "status": "Expired", "detail": f"Issuer record expired on {rec['valid_until']}"}
    return {**base, "status": "Verified", "detail": "Details match issuer record"}

def validate(docs, form, registry, as_of=None, hash_store=None, cfg=None):
    as_of = as_of or dt.date.today(); cfg = cfg or load_rules(); RU, S = cfg["rules"], cfg["settings"]
    parsed = [parse_document(n, b, S) for n, b in docs]; F = []
    def add(rule, doc, msg, ev="", sev=None, page=None, needle=None):
        if not RU[rule]["enabled"]: return
        F.append({"id": f"F{len(F)+1:02d}", "rule": rule, "rule_text": RU[rule]["text"], "handbook_ref": RU[rule]["handbook_ref"],
                  "severity": sev or RU[rule]["severity"], "document": doc, "message": msg, "evidence": ev, "page": page, "needle": needle})
    have = {p["doc_type"] for p in parsed}
    for req in cfg["category_checklists"].get(form["category"], []):
        if req not in have: add("R01", "-", f"Missing required document: {req.replace('_', ' ')}", "Not found among uploaded files")
    seen = {}
    for p in parsed:
        if p["sha256"] in seen: add("R09", p["name"], f"{p['name']} is byte-identical to {seen[p['sha256']]}", f"SHA-256 {p['sha256'][:16]}...")
        else: seen[p["sha256"]] = p["name"]
    rec = registry["institutions"].get(form["institution_id"])
    if rec:
        if form["claimed_intake"] != rec["approved_intake"]: add("R08", "form", f"Form claims intake {form['claimed_intake']} but AICTE record approves {rec['approved_intake']}", "AICTE record (mock)")
        if not rec["ter_paid"]: add("R12", "AICTE record", "TER payment not recorded as paid", "AICTE record (mock)")
        if rec["open_deficiency"]: add("R12", "AICTE record", "Open compliance/deficiency status", "AICTE record (mock)")
    for p in parsed:
        n, f = p["name"], p["fields"]
        if p["kind"] == "photo":
            im = p["image"]
            if not im: add("R02", n, "Image could not be read", "Corrupt or unsupported image"); continue
            if hash_store is not None:
                for inst, doc, dist in hash_store.find(im["phash"], form["institution_id"], S["phash_threshold"]):
                    add("R14", n, f"Photo is visually identical to {doc} submitted by {inst} (Hamming distance {dist})", f"perceptual hash {im['phash']}")
                hash_store.add(form["institution_id"], n, im["phash"])
            if im["gps"] and form.get("campus_lat") is not None:
                km = fx.haversine_km(im["gps"], (form["campus_lat"], form["campus_lon"]))
                if km > S["gps_max_km"]: add("R15", n, f"Photo GPS is {km:.0f} km from the declared campus - request additional evidence", f"EXIF GPS {im['gps'][0]:.4f}, {im['gps'][1]:.4f}")
            if im["blur"] < S["blur_min"] or min(im["size"]) < S["min_photo_side"]:
                add("R16", n, "Photo too blurry or too small to serve as evidence", f"sharpness {im['blur']} (min {S['blur_min']}), size {im['size']}")
            continue
        if not p["readable"] or p["doc_type"] == "unknown":
            add("R02", n, "Could not read or classify document - manual review", f"method={p['method']}"); continue
        if p["method"] != "text" and (p["ocr_conf"] or 0) < S["ocr_min_conf"]:
            add("R02", n, f"Low OCR confidence ({p['ocr_conf']:.0f}) - manual review", "Tesseract average word confidence")
        ev = lambda k: f"p.{f[k]['page']}: \"{f[k]['snippet']}\"" if k in f else ""
        nd = lambda k: dict(page=f[k]["page"], needle=f[k]["snippet"]) if k in f else {}
        if f.get("institution_id", {}).get("value") != form["institution_id"]: add("R05", n, "Institution ID mismatch with form", ev("institution_id"), **nd("institution_id"))
        sc = fuzz.token_set_ratio(norm(f.get("institution_name", {}).get("value")), norm(form["institution_name"]))
        if sc < S["name_match_threshold"]: add("R06", n, f"Institution name mismatch with form (similarity {sc:.0f})", ev("institution_name"), **nd("institution_name"))
        if "intake" in f and int(f["intake"]["value"]) != form["claimed_intake"]: add("R07", n, f"Document intake {f['intake']['value']} vs form {form['claimed_intake']}", ev("intake"), **nd("intake"))
        vu, iss = d(f.get("valid_until", {}).get("value")), d(f.get("issue_date", {}).get("value"))
        if vu and vu < as_of: add("R03", n, f"Expired on {vu}", ev("valid_until"), **nd("valid_until"))
        elif vu and (vu - as_of).days <= S["warn_days"]: add("R04", n, f"Expires on {vu}", ev("valid_until"), **nd("valid_until"))
        if iss and ((vu and iss > vu) or iss > as_of): add("R13", n, "Irregular dates", ev("issue_date"), **nd("issue_date"))
        m = p["meta"]; gap = (m["modified"] - m["created"]).days if m.get("created") and m.get("modified") else 0
        susp = any(s in m.get("producer", "").lower() for s in SUSPICIOUS_SOFTWARE)
        if gap > 1: add("R10", n, f"File modified {gap} days after creation (suspicious - review required)", f"created {m['created']}, modified {m['modified']}")
        if susp: add("R10", n, f"Produced by image-editing software: {m['producer']} (suspicious - review required)", f"Producer: {m['producer']}")
        fo = p["forensics"]
        for x in fo["mixed"]: add("R18", n, f"Data field rendered in a different font from the rest of the page (suspicious - review required)", f"p.{x['page']}: \"{x['text']}\" in font {x['font']}", page=x["page"], needle=x["text"])
        if fo["eof_count"] > 1: add("R18", n, f"File was saved incrementally {fo['eof_count']} times (suspicious - review required)", f"{fo['eof_count']} end-of-file markers")
        if p["qr"] and f.get("ref_no") and p["qr"].split("|")[-1] != f["ref_no"]["value"]:
            add("R17", n, "QR code reference differs from printed reference number", f"QR says {p['qr'].split('|')[-1]}, text says {f['ref_no']['value']}")
        p["issuer"] = verify_issuer(p, registry, as_of)
        if p["issuer"] and p["issuer"]["status"] != "Verified":
            add("R11", n, f"Issuer check: {p['issuer']['status']}", p["issuer"]["detail"], sev=RU["R11"]["severity"] if p["issuer"]["status"] in ("Mismatch detected", "Expired") else "Medium")
        feats = [gap, max(fo["eof_count"] - 1, 0), len(fo["mixed"]), int(susp), p["text_len"] / 1000, len(f)]
        isan, sc2 = ml.anomaly(feats); p["anomaly"] = {"flag": isan, "score": round(sc2, 3)}
        if isan: add("R19", n, f"ML anomaly detector: unusual file characteristics (score {sc2:.2f}) - advisory", "IsolationForest over metadata/forensic features (synthetic training data)")
    breakdown = [(x["id"], x["rule"], WEIGHT[x["severity"]]) for x in F]
    return {"parsed": parsed, "findings": F, "score": sum(b[2] for b in breakdown), "breakdown": breakdown, "as_of": str(as_of)}

def build_report(form, result):
    return {"application": form, "as_of": result["as_of"], "rules_version": load_rules()["rules_version"], "priority_score": result["score"],
            "documents": [{"name": p["name"], "type": p["doc_type"], "sha256": p["sha256"], "extraction": p["method"], "issuer_status": (p.get("issuer") or {}).get("status", "n/a"),
                           "pqc_verified": bool((p.get("issuer") or {}).get("pqc"))} for p in result["parsed"]],
            "findings": [{k: x[k] for k in ("id", "rule", "severity", "document", "message")} for x in result["findings"]],
            "notice": "Decision-support output only. Findings are indicators requiring human review; final decisions rest with authorised AICTE officials."}
