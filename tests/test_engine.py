import json, io
from pathlib import Path
import engine, forensics as fx
REG = json.load(open("registry.json"))
def run(s, store=None):
    docs = [(p.name, p.read_bytes()) for p in sorted(Path("samples", s).iterdir()) if p.suffix in (".pdf", ".jpg")]
    return engine.validate(docs, json.load(open(f"samples/{s}/form.json")), REG, hash_store=store)
def test_clean_has_no_findings(): assert run("clean")["findings"] == []
def test_problem_rules_fire():
    rules = {f["rule"] for f in run("problem", fx.HashStore())["findings"]}
    assert {"R01", "R03", "R07", "R08", "R09", "R10", "R11", "R12", "R14", "R15", "R16", "R17", "R18"} <= rules
def test_forged_noc_caught_by_pqc():
    noc = next(p for p in run("problem")["parsed"] if p["name"] == "noc.pdf")
    assert noc["issuer"]["status"] == "Mismatch detected" and noc["issuer"]["pqc"]
def test_tampered_credential_rejected():
    fire = next(p for p in run("problem")["parsed"] if p["name"] == "fire_safety.pdf"); assert "bad_signature" in fire["issuer"]["detail"]
def test_iso_dates_not_swapped(): assert engine.to_iso("2028-03-12") == "2028-03-12" and engine.to_iso("05/03/2026") == "2026-03-05"
def test_rule_can_be_disabled():
    cfg = engine.load_rules(); cfg["rules"]["R12"]["enabled"] = False
    docs = [(p.name, p.read_bytes()) for p in sorted(Path("samples/problem").glob("*.pdf"))]
    r = engine.validate(docs, json.load(open("samples/problem/form.json")), REG, cfg=cfg); assert "R12" not in {f["rule"] for f in r["findings"]}
def test_scanned_image_uses_ocr():
    import ocr
    if not ocr.tesseract_available(): return
    img = fx.render_page(Path("samples/clean/noc.pdf").read_bytes(), 0, dpi=250); b = io.BytesIO(); img.save(b, "PNG")
    p = engine.parse_document("scan.png", b.getvalue(), engine.load_rules()["settings"]); assert p["method"] == "ocr" and p["doc_type"] == "noc" and p["fields"]["ref_no"]["value"] == "NOC/MP/2025/0451"
