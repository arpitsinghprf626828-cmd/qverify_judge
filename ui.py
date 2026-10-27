"""Design system for Q-Verify: "Quantum Seal".
Ivory paper surfaces, deep-ink sidebar/hero, emerald for verified, violet for post-quantum, amber wax-seal accent.
Serif display headings (Fraunces) + Inter body; falls back to system fonts when offline."""
import streamlit as st

P = {"paper": "#f6f3ec", "card": "#ffffff", "line": "#e7e1d3", "ink": "#16213e", "muted": "#5f6b85",
     "emerald": "#0b7a6b", "violet": "#5b3fd6", "amber": "#b7791f", "red": "#b42318", "seal": "#d99a1e"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=Inter:wght@400;500;600;700&display=swap');
:root { --paper:#f6f3ec; --card:#fff; --line:#e7e1d3; --ink:#16213e; --muted:#5f6b85; --em:#0b7a6b; --vi:#5b3fd6; --am:#b7791f; --rd:#b42318; --seal:#d99a1e; }
html, body, [class*="css"], .stMarkdown, .stTextInput, .stSelectbox { font-family:'Inter',system-ui,sans-serif; }
.stApp { background: var(--paper); color: var(--ink); }
.block-container { padding-top: 1.4rem; max-width: 1280px; }
h1,h2,h3 { font-family:'Fraunces',Georgia,serif !important; color: var(--ink) !important; letter-spacing:-0.01em; }
h4,h5 { color: var(--ink) !important; }
p, li, label, .stCaption, span { color: inherit; }

/* sidebar */
section[data-testid="stSidebar"] { background: linear-gradient(180deg,#16213e 0%,#1d2b52 100%); }
section[data-testid="stSidebar"] * { color:#e9edf7 !important; }
section[data-testid="stSidebar"] .stButton>button { background:#ffffff14; border:1px solid #ffffff33; color:#fff !important; }
section[data-testid="stSidebar"] .stButton>button:hover { background:#ffffff26; }

/* hero */
.hero { position:relative; overflow:hidden; padding:28px 32px; border-radius:22px; margin-bottom:20px;
  background: radial-gradient(900px 300px at 85% -20%, #5b3fd655, transparent), linear-gradient(135deg,#16213e 0%,#1f2f5c 60%,#0b5c63 100%);
  box-shadow:0 10px 30px #16213e22; display:flex; gap:22px; align-items:center; }
.hero .seal { flex:0 0 auto; }
.hero h1 { color:#fff !important; font-size:2.15rem; margin:0 0 4px 0; }
.hero p { color:#cdd7ee; margin:0; font-size:1.02rem; }
.hero b { color:#ffd77a; }
.tag { display:inline-block; padding:3px 11px; border-radius:999px; font-size:.72rem; font-weight:600; margin:10px 6px 0 0;
  border:1px solid #ffffff3d; color:#e8eefc; background:#ffffff14; }
.tag.v { border-color:#b9a8ff88; color:#d9d0ff; background:#5b3fd633; }

/* cards & kpis */
.card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:16px 18px; height:100%; min-height:210px; box-shadow:0 1px 2px #16213e0d; transition:transform .15s, box-shadow .15s; }
.card:hover { transform:translateY(-2px); box-shadow:0 8px 22px #16213e14; }
.card h4 { margin:0 0 6px 0; font-size:1rem; } .card p { color:var(--muted); font-size:.88rem; margin:0; line-height:1.45; }
.card .ic { width:36px; height:36px; border-radius:10px; display:flex; align-items:center; justify-content:center; font-size:1.15rem; background:#5b3fd612; margin-bottom:10px; }
.kpi { background:var(--card); border:1px solid var(--line); border-left:4px solid var(--seal); border-radius:14px; padding:14px 16px; box-shadow:0 1px 2px #16213e0d; }
.kpi .v { font-family:'Fraunces',Georgia,serif; font-size:2rem; font-weight:700; line-height:1.1; }
.kpi .l { color:var(--muted); font-size:.74rem; text-transform:uppercase; letter-spacing:.07em; margin-top:2px; }

/* pills */
.pill { display:inline-block; padding:2px 10px; border-radius:999px; font-size:.74rem; font-weight:700; border:1px solid transparent; }
.pill.ok { background:#0b7a6b18; color:#0b7a6b; border-color:#0b7a6b44; }
.pill.bad { background:#b4231814; color:#b42318; border-color:#b4231844; }
.pill.warn { background:#b7791f18; color:#9a6212; border-color:#b7791f44; }
.pill.pq { background:#5b3fd614; color:#5b3fd6; border-color:#5b3fd644; }
.pill.info { background:#16213e0d; color:#3b4768; border-color:#16213e22; }

/* tabs */
.stTabs [data-baseweb="tab-list"] { gap:6px; flex-wrap:wrap; border-bottom:none; }
.stTabs [data-baseweb="tab"] { background:#fff; border:1px solid var(--line); border-radius:12px; padding:8px 14px; color:var(--muted); height:auto; }
.stTabs [aria-selected="true"] { background:var(--ink); color:#fff !important; border-color:var(--ink); }
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] { display:none; }

/* inputs & buttons */
.stButton>button { border-radius:12px; border:1px solid var(--line); font-weight:600; }
.stButton>button[kind="primary"], .stFormSubmitButton>button[kind="primary"], .stFormSubmitButton>button { background:linear-gradient(135deg,#0b7a6b,#0b5c63); border:0; color:#fff; }
.stButton>button[kind="primary"]:hover { filter:brightness(1.08); }
div[data-testid="stExpander"] { background:#fff; border:1px solid var(--line); border-radius:14px; }
div[data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:12px; overflow:hidden; }

/* steps, sig, seal, gauge */
.step { display:flex; gap:14px; align-items:flex-start; padding:6px 0; }
.step .n { min-width:32px; height:32px; border-radius:50%; background:var(--ink); color:#ffd77a; font-weight:700; display:flex; align-items:center; justify-content:center; font-family:'Fraunces',serif; }
.step small { color:var(--muted); }
.sig { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:.76rem; color:var(--muted); word-break:break-all; background:#fff; border:1px dashed var(--line); border-radius:10px; padding:10px; }
.sealbox { display:flex; gap:16px; align-items:center; background:#fff; border:1px solid var(--line); border-radius:16px; padding:14px 18px; }
.sealbox h4 { margin:0; } .sealbox p { margin:2px 0 0 0; color:var(--muted); font-size:.85rem; }
.gauge { background:#fff; border:1px solid var(--line); border-radius:16px; padding:16px 18px; }
.gauge .bar { height:12px; border-radius:999px; background:#ece6d8; overflow:hidden; margin:10px 0 6px 0; }
.gauge .bar > div { height:100%; border-radius:999px; }
.gauge .n { font-family:'Fraunces',serif; font-size:2.3rem; font-weight:700; line-height:1; }
</style>"""

SEAL_SVG = """<svg width="{s}" height="{s}" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
<defs><radialGradient id="g{k}" cx="35%" cy="30%"><stop offset="0" stop-color="#ffe29a"/><stop offset="1" stop-color="{c}"/></radialGradient></defs>
<path d="M50 4 L58 12 L69 8 L74 19 L86 20 L86 32 L96 38 L91 49 L96 60 L86 66 L86 78 L74 79 L69 90 L58 86 L50 94 L42 86 L31 90 L26 79 L14 78 L14 66 L4 60 L9 49 L4 38 L14 32 L14 20 L26 19 L31 8 L42 12 Z" fill="url(#g{k})" stroke="#fff3" stroke-width="1.5"/>
<circle cx="50" cy="49" r="28" fill="none" stroke="#16213e" stroke-opacity=".35" stroke-width="2"/>
{mark}</svg>"""
MARK_OK = '<path d="M35 50 L46 61 L67 38" fill="none" stroke="#16213e" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>'
MARK_BAD = '<path d="M38 38 L62 62 M62 38 L38 62" fill="none" stroke="#fff" stroke-width="7" stroke-linecap="round"/>'
MARK_Q = '<text x="50" y="62" text-anchor="middle" font-size="38" font-family="Georgia,serif" font-weight="700" fill="#16213e">Q</text>'

def seal_svg(kind="q", size=64):
    c = {"ok": "#d99a1e", "bad": "#b42318", "q": "#d99a1e"}[kind]
    m = {"ok": MARK_OK, "bad": MARK_BAD, "q": MARK_Q}[kind]
    return SEAL_SVG.format(s=size, c=c, mark=m, k=kind)

def inject(): st.markdown(CSS, unsafe_allow_html=True)

def hero(title, sub, tags):
    t = "".join(f'<span class="tag {"v" if i % 2 else ""}">{x}</span>' for i, x in enumerate(tags))
    st.markdown(f'<div class="hero"><div class="seal">{seal_svg("q", 78)}</div><div><h1>{title}</h1><p>{sub}</p>{t}</div></div>', unsafe_allow_html=True)

def kpi(col, value, label, color="#16213e"):
    col.markdown(f'<div class="kpi"><div class="v" style="color:{color}">{value}</div><div class="l">{label}</div></div>', unsafe_allow_html=True)

def card(col, title, body, icon=""):
    col.markdown(f'<div class="card"><div class="ic">{icon}</div><h4>{title}</h4><p>{body}</p></div>', unsafe_allow_html=True)

def pill(text, kind="info"): return f'<span class="pill {kind}">{text}</span>'

STATUS_KIND = {"Verified": "ok", "Mismatch detected": "bad", "Expired": "bad", "Source unavailable": "warn",
               "Manual review required": "warn", "Verification pending": "warn", "n/a": "info"}
def status_pill(s): return pill(s, STATUS_KIND.get(s, "info"))

def seal_banner(ok, title, body):
    st.markdown(f'<div class="sealbox">{seal_svg("ok" if ok else "bad", 64)}<div><h4>{title}</h4><p>{body}</p></div></div>', unsafe_allow_html=True)

def readiness(findings):
    """Applicant-facing 'submission readiness' 0-100 (explainable): start at 100, subtract severity points."""
    pts = {"High": 18, "Medium": 8, "Low": 2}
    score = max(0, 100 - sum(pts[f["severity"]] for f in findings))
    color = P["emerald"] if score >= 85 else P["amber"] if score >= 60 else P["red"]
    label = "Ready to submit" if score >= 85 else "Fix a few issues first" if score >= 60 else "Needs significant corrections"
    st.markdown(f'<div class="gauge"><div class="l" style="color:#5f6b85;font-size:.74rem;text-transform:uppercase;letter-spacing:.07em">Submission readiness</div>'
                f'<div class="n" style="color:{color}">{score}<span style="font-size:1rem;color:#5f6b85"> / 100</span></div>'
                f'<div class="bar"><div style="width:{score}%;background:{color}"></div></div><b style="color:{color}">{label}</b>'
                f'<div style="color:#5f6b85;font-size:.8rem;margin-top:4px">100 minus 18 per High, 8 per Medium, 2 per Low finding. An indicator for the applicant, not a decision.</div></div>', unsafe_allow_html=True)
    return score
