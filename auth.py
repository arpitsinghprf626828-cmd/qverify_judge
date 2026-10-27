"""Login + role-based access control. Passwords are stored as salted scrypt hashes (users.json is created on first run)."""
import json, os, hashlib, hmac, secrets, time
from pathlib import Path
USERS = Path("users.json")
PERMS = {"applicant": {"upload", "view_vault"},
         "reviewer": {"upload", "view_all", "decide", "sign", "view_trust", "view_vault", "run_batch"},
         "auditor": {"view_all", "view_audit", "view_trust"},
         "judge": {"upload", "view_all", "decide", "sign", "view_trust", "view_vault", "run_batch", "view_audit"},
         "admin": {"upload", "view_all", "decide", "sign", "view_trust", "view_vault", "run_batch", "view_audit", "manage_keys", "edit_rules"}}
DEMO = {"applicant1": ("applicant", "Applicant@123"), "reviewer1": ("reviewer", "Reviewer@123"),
        "auditor1": ("auditor", "Auditor@123"), "admin1": ("admin", "Admin@123")}
def _h(pw, salt): return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()
def ensure_users():
    """Creates users.json on first run. Passwords: env QV_PW_<USERNAME> if set; otherwise the demo password when QV_DEMO != 0,
    otherwise a random one that is printed ONCE to the server log (deployment mode never ships known passwords)."""
    if USERS.exists(): return
    demo = os.environ.get("QV_DEMO", "1") != "0"; out = {}
    for u, (role, dpw) in DEMO.items():
        pw = os.environ.get(f"QV_PW_{u.upper()}") or (dpw if demo else secrets.token_urlsafe(12))
        if not demo and not os.environ.get(f"QV_PW_{u.upper()}"): print(f"[Q-Verify] initial password for {u} ({role}): {pw}", flush=True)
        salt = os.urandom(16); out[u] = {"role": role, "salt": salt.hex(), "hash": _h(pw, salt)}
    USERS.write_text(json.dumps(out, indent=2))
def ensure_judge():
    """Optional public-evaluation account. QV_JUDGE_PASSWORD set -> user judge1 (role judge) exists with that password; unset -> removed.
    The judge role can run everything except key revocation and rule editing, so one evaluator cannot change results for the next."""
    ensure_users(); pw = os.environ.get("QV_JUDGE_PASSWORD"); d = json.loads(USERS.read_text()); u = d.get("judge1")
    if not pw:
        if u: d.pop("judge1"); USERS.write_text(json.dumps(d, indent=2))
        return
    if u and hmac.compare_digest(_h(pw, bytes.fromhex(u["salt"])), u["hash"]): return
    salt = os.urandom(16); d["judge1"] = {"role": "judge", "salt": salt.hex(), "hash": _h(pw, salt)}; USERS.write_text(json.dumps(d, indent=2))
FAILS = Path("failed_logins.json"); MAX_FAILS, WINDOW = 5, 600
def _fails():
    try: return json.loads(FAILS.read_text())
    except Exception: return {}
def locked_for(username):
    """Seconds left on a lockout (5 failures within 10 minutes), else 0."""
    ts = [t for t in _fails().get(username, []) if time.time() - t < WINDOW]
    return int(WINDOW - (time.time() - min(ts))) if len(ts) >= MAX_FAILS else 0
def _record(username, ok):
    f = _fails()
    f[username] = [] if ok else [t for t in f.get(username, []) if time.time() - t < WINDOW] + [time.time()]
    FAILS.write_text(json.dumps(f))
def login(username, password):
    if locked_for(username): return None
    u = _login(username, password); _record(username, bool(u)); return u
def _login(username, password):
    ensure_judge(); u = json.loads(USERS.read_text()).get(username)
    if u and hmac.compare_digest(_h(password, bytes.fromhex(u["salt"])), u["hash"]): return {"name": username, "role": u["role"]}
    return None
def can(user, perm): return bool(user) and perm in PERMS[user["role"]]
def need(user, perm, audit=None):
    """Enforce in the code path that performs the action (UI hiding alone is not security)."""
    if not can(user, perm):
        if audit: audit.add((user or {}).get("name", "anonymous"), "denied", perm)
        raise PermissionError(perm)
