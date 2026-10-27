"""PDF forensics, QR decoding, image checks (perceptual hash, EXIF GPS, blur) and the cross-institution hash store."""
import io, math, sqlite3
import numpy as np, imagehash, piexif, cv2, pymupdf
from PIL import Image

def render_page(raw, page=0, dpi=130):
    doc = pymupdf.open(stream=raw, filetype="pdf"); pix = doc[min(page, len(doc) - 1)].get_pixmap(dpi=dpi)
    return Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")

def pdf_forensics(raw):
    """-> {eof_count, pages, mixed: [{page, text, font}]}. Indicators only - never proof."""
    out = {"eof_count": raw.count(b"%%EOF"), "pages": 0, "mixed": []}
    try:
        doc = pymupdf.open(stream=raw, filetype="pdf"); out["pages"] = len(doc); spans = []
        for pn, pg in enumerate(doc):
            for b in pg.get_text("dict")["blocks"]:
                for l in b.get("lines", []):
                    for s in l["spans"]:
                        if s["text"].strip(): spans.append((pn + 1, s["font"], s["text"].strip()))
        if spans:
            weight = {}
            for _, f, t in spans: weight[f] = weight.get(f, 0) + len(t)
            major = max(weight, key=weight.get)
            out["mixed"] = [{"page": p, "text": t, "font": f} for p, f, t in spans if f != major and any(ch.isdigit() for ch in t)][:5]
    except Exception: pass
    return out

def decode_qr(img):
    try:
        val, _, _ = cv2.QRCodeDetector().detectAndDecode(np.array(img.convert("RGB"))[:, :, ::-1]); return val or None
    except Exception: return None

def phash(img): return str(imagehash.phash(img))
def hamming(a, b): return imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b)

def blur_score(img, max_side=800):
    g = img.convert("L"); g.thumbnail((max_side, max_side)); a = np.asarray(g, dtype=np.float64)
    lap = -4 * a[1:-1, 1:-1] + a[:-2, 1:-1] + a[2:, 1:-1] + a[1:-1, :-2] + a[1:-1, 2:]
    return float(lap.var())

def exif_gps(raw):
    try:
        g = piexif.load(raw).get("GPS", {})
        if not g: return None
        f = lambda v: v[0][0] / v[0][1] + v[1][0] / v[1][1] / 60 + v[2][0] / v[2][1] / 3600
        lat = f(g[piexif.GPSIFD.GPSLatitude]) * (1 if g[piexif.GPSIFD.GPSLatitudeRef] in (b"N", "N") else -1)
        lon = f(g[piexif.GPSIFD.GPSLongitude]) * (1 if g[piexif.GPSIFD.GPSLongitudeRef] in (b"E", "E") else -1)
        return lat, lon
    except Exception: return None

def haversine_km(a, b):
    R = 6371.0; p1, p2 = math.radians(a[0]), math.radians(b[0]); dp = p2 - p1; dl = math.radians(b[1] - a[1])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R * math.asin(math.sqrt(h))

def gps_exif_bytes(lat, lon):
    def r(x):
        x = abs(x); d = int(x); m = int((x - d) * 60); s = round(((x - d) * 60 - m) * 60 * 100)
        return ((d, 1), (m, 1), (s, 100))
    return {"GPS": {piexif.GPSIFD.GPSLatitudeRef: "N" if lat >= 0 else "S", piexif.GPSIFD.GPSLatitude: r(lat),
                    piexif.GPSIFD.GPSLongitudeRef: "E" if lon >= 0 else "W", piexif.GPSIFD.GPSLongitude: r(lon)}}

class HashStore:
    """SQLite store of perceptual hashes of every photo ever submitted, to detect reuse across institutions."""
    def __init__(self, path="hashes.db"):
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.execute("create table if not exists h(inst text, doc text, ph text, unique(inst, doc, ph))"); self.con.commit()
    def add(self, inst, doc, ph): self.con.execute("insert or ignore into h values (?,?,?)", (inst, doc, ph)); self.con.commit()
    def find(self, ph, exclude_inst, thr=8):
        return [(i, d, hamming(ph, p)) for i, d, p in self.con.execute("select inst, doc, ph from h where inst != ?", (exclude_inst,)) if hamming(ph, p) <= thr]

def highlight_png(raw, page, needle, dpi=90):
    """Renders a PDF page with the evidence text highlighted -> PNG bytes (or None)."""
    try:
        doc = pymupdf.open(stream=raw, filetype="pdf"); pg = doc[max(page - 1, 0)]
        for r in pg.search_for(needle): pg.add_highlight_annot(r)
        return pg.get_pixmap(dpi=dpi).tobytes("png")
    except Exception: return None
