"""CyberShield - Cyber Crime Case Management System for police cyber cells.

Single-file edition (whole project is this one file).
Install: pip install fastapi uvicorn pyjwt
Run:     uvicorn cybershield:app --reload   then open http://127.0.0.1:8000
Features: JWT auth + RBAC, auto IOC extraction, linked-case (gang) detection,
explainable risk score, SHA-256 evidence integrity, chain of custody,
hash-chained tamper-evident audit log, built-in dashboard at "/".
"""
import base64
import binascii
import hashlib
import hmac
import math
import os
import re
import secrets
import sqlite3
import time
import types
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlparse

import jwt
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field



# ======== DATABASE ========

DB_PATH = os.getenv("CYBERSHIELD_DB", "data/cybershield.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','investigator','officer','viewer'))
);
CREATE TABLE IF NOT EXISTS cases(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_no TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  victim_name TEXT NOT NULL,
  loss_amount REAL NOT NULL DEFAULT 0,
  severity TEXT NOT NULL DEFAULT 'low',
  risk_score INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'open',
  created_by INTEGER NOT NULL REFERENCES users(id),
  assigned_to INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL,
  due_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id),
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(case_id, type, value)
);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value);
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER NOT NULL REFERENCES cases(id),
  filename TEXT NOT NULL,
  stored_as TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  collected_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS custody(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  evidence_id INTEGER NOT NULL REFERENCES evidence(id),
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_db():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    conn = connect()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# ======== AUDIT LEDGER ========

GENESIS = "0" * 64


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _digest(prev: str, ts: str, actor: str, action: str, detail: str) -> str:
    return hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{detail}".encode()).hexdigest()


def log(db, actor: str, action: str, detail: str = "") -> None:
    last = db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else GENESIS
    ts = now()
    db.execute(
        "INSERT INTO audit(ts,actor,action,detail,prev_hash,hash) VALUES(?,?,?,?,?,?)",
        (ts, actor, action, detail, prev, _digest(prev, ts, actor, action, detail)),
    )


def verify(db) -> dict:
    prev = GENESIS
    count = 0
    for r in db.execute("SELECT * FROM audit ORDER BY id"):
        expected = _digest(prev, r["ts"], r["actor"], r["action"], r["detail"])
        if r["prev_hash"] != prev or r["hash"] != expected:
            return {"valid": False, "entries": count, "broken_at": r["id"]}
        prev = r["hash"]
        count += 1
    return {"valid": True, "entries": count, "broken_at": None}

audit = types.SimpleNamespace(log=log, verify=verify, now=now)


# ======== IOC EXTRACTION + RISK SCORE ========

URL = re.compile(r"https?://[^\s<>\"']+", re.I)
UPI = re.compile(r"\b[\w.\-]{2,}@(?:ybl|ibl|axl|apl|okhdfcbank|oksbi|okaxis|okicici|paytm|upi)\b", re.I)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
PHONE = re.compile(r"(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{4}[\-\s]?\d{5}(?!\d)")


def extract_iocs(text: str) -> list[tuple[str, str]]:
    """Return a de-duplicated list of (type, value) found in free text."""
    found: dict[tuple[str, str], None] = {}
    work = text

    def take(kind: str, pattern: re.Pattern, normalise=lambda v: v):
        nonlocal work
        for m in pattern.finditer(work):
            found[(kind, normalise(m.group(0)))] = None
        work = pattern.sub(" ", work)  # stop later patterns re-matching the same text

    take("url", URL, lambda v: v.rstrip(".,;)"))
    for kind, value in list(found):
        host = urlparse(value).hostname
        if host and not IPV4.fullmatch(host):
            found[("domain", host.lower())] = None
    take("upi", UPI, str.lower)
    take("email", EMAIL, str.lower)
    take("sha256", SHA256, str.lower)
    take("md5", MD5, str.lower)
    take("ipv4", IPV4)
    take("phone", PHONE, lambda v: re.sub(r"\D", "", v)[-10:])
    return list(found)


CATEGORY_WEIGHT = {
    "ransomware": 40, "data_breach": 35, "hacking": 30, "sextortion": 30,
    "upi_fraud": 25, "identity_theft": 25, "phishing": 20, "cyberbullying": 15, "other": 10,
}
SLA_HOURS = {"critical": 24, "high": 72, "medium": 168, "low": 336}


def risk_score(category: str, loss_amount: float, ioc_count: int, related_cases: int) -> int:
    """0-100 score: category weight + financial loss + evidence richness + campaign links."""
    score = CATEGORY_WEIGHT.get(category, 10)
    score += min(30, int(math.log10(loss_amount + 1) * 6))
    score += min(15, ioc_count * 3)
    score += min(15, related_cases * 5)
    return min(100, score)


def severity(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


# ======== SECURITY ========

SECRET = os.getenv("CYBERSHIELD_SECRET") or secrets.token_hex(32)
TOKEN_MINUTES = 60
MAX_FAILS, LOCK_SECONDS = 5, 300
_fails: dict[str, tuple[int, float]] = {}
bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, dk_hex = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 200_000)
    return hmac.compare_digest(dk.hex(), dk_hex)


def check_lock(username: str) -> None:
    count, until = _fails.get(username, (0, 0.0))
    if count >= MAX_FAILS and time.time() < until:
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")


def record_fail(username: str) -> None:
    count, _ = _fails.get(username, (0, 0.0))
    _fails[username] = (count + 1, time.time() + LOCK_SECONDS)


def clear_fails(username: str) -> None:
    _fails.pop(username, None)


def make_token(user_id: int, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)
    return jwt.encode({"sub": str(user_id), "role": role, "exp": exp}, SECRET, algorithm="HS256")


def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer), db=Depends(get_db)):
    if not creds:
        raise HTTPException(401, "Missing bearer token")
    try:
        payload = jwt.decode(creds.credentials, SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid or expired token")
    user = db.execute("SELECT id,username,role FROM users WHERE id=?", (int(payload["sub"]),)).fetchone()
    if not user:
        raise HTTPException(401, "Unknown user")
    return user


def require(*roles: str):
    def dep(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, f"Role '{user['role']}' is not allowed to do this")
        return user
    return dep


# ======== API ========

EVIDENCE_DIR = Path(os.getenv("CYBERSHIELD_EVIDENCE_DIR", "data/evidence"))
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024

Category = Literal["phishing", "ransomware", "upi_fraud", "identity_theft", "sextortion",
                   "hacking", "data_breach", "cyberbullying", "other"]
Role = Literal["admin", "investigator", "officer", "viewer"]
TRANSITIONS = {
    "open": {"investigating", "closed"},
    "investigating": {"resolved", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = connect()
    if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        password = os.getenv("CYBERSHIELD_ADMIN_PASSWORD")
        if not password:
            password = secrets.token_urlsafe(12)
            print(f"[CyberShield] First run. Admin login -> admin / {password}")
        db.execute("INSERT INTO users(username,pw_hash,role) VALUES('admin',?,'admin')",
                   (hash_password(password),))
        audit.log(db, "system", "bootstrap", "admin account created")
        db.commit()
    db.close()
    yield


app = FastAPI(title="CyberShield", version="1.0.0",
              description="Cyber-crime case management with tamper-evident evidence handling.",
              lifespan=lifespan)


# ---------- schemas ----------
class Login(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=10, max_length=128)
    role: Role


class CaseIn(BaseModel):
    title: str = Field(min_length=5, max_length=140)
    category: Category
    description: str = Field(min_length=10, max_length=5000)
    victim_name: str = Field(min_length=2, max_length=80)
    loss_amount: float = Field(0, ge=0, le=1e11)


class StatusIn(BaseModel):
    status: Literal["open", "investigating", "resolved", "closed"]


class AssignIn(BaseModel):
    username: str


class IocIn(BaseModel):
    type: Literal["url", "domain", "upi", "email", "sha256", "md5", "ipv4", "phone"]
    value: str = Field(min_length=3, max_length=300)


class EvidenceIn(BaseModel):
    filename: str = Field(min_length=1, max_length=120)
    content_b64: str
    note: str = Field("", max_length=300)


class TransferIn(BaseModel):
    to_user: str
    note: str = Field("", max_length=300)


# ---------- helpers ----------
def get_case_or_404(db, case_id: int):
    row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Case not found")
    return row


def related_cases(db, case_id: int) -> list[dict]:
    rows = db.execute(
        """SELECT c.id, c.case_no, c.title, c.category, GROUP_CONCAT(DISTINCT i.value) AS shared
           FROM iocs i JOIN iocs j ON i.value=j.value AND j.case_id!=i.case_id
           JOIN cases c ON c.id=j.case_id WHERE i.case_id=? GROUP BY c.id""", (case_id,)).fetchall()
    return [dict(r) for r in rows]


def refresh_risk(db, case_id: int) -> None:
    c = get_case_or_404(db, case_id)
    n_ioc = db.execute("SELECT COUNT(*) FROM iocs WHERE case_id=?", (case_id,)).fetchone()[0]
    score = risk_score(c["category"], c["loss_amount"], n_ioc, len(related_cases(db, case_id)))
    sev = severity(score)
    due = datetime.fromisoformat(c["created_at"]) + timedelta(hours=SLA_HOURS[sev])
    db.execute("UPDATE cases SET risk_score=?, severity=?, due_at=? WHERE id=?",
               (score, sev, due.isoformat(timespec="seconds"), case_id))


def add_iocs(db, case_id: int, items) -> int:
    added = 0
    for kind, value in items:
        cur = db.execute("INSERT OR IGNORE INTO iocs(case_id,type,value,created_at) VALUES(?,?,?,?)",
                         (case_id, kind, value, audit.now()))
        added += cur.rowcount
    return added


def add_custody(db, evidence_id: int, action: str, actor: str, note: str = "") -> None:
    db.execute("INSERT INTO custody(evidence_id,action,actor,note,ts) VALUES(?,?,?,?,?)",
               (evidence_id, action, actor, note, audit.now()))


# ---------- auth & users ----------
@app.post("/auth/login")
def login(body: Login, db=Depends(get_db)):
    check_lock(body.username)
    u = db.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    if not u or not verify_password(body.password, u["pw_hash"]):
        record_fail(body.username)
        audit.log(db, body.username, "login_failed")
        db.commit()
        raise HTTPException(401, "Wrong username or password")
    clear_fails(body.username)
    audit.log(db, u["username"], "login")
    return {"access_token": make_token(u["id"], u["role"]), "role": u["role"], "username": u["username"]}


@app.post("/users", status_code=201)
def create_user(body: UserIn, admin=Depends(require("admin")), db=Depends(get_db)):
    if db.execute("SELECT 1 FROM users WHERE username=?", (body.username,)).fetchone():
        raise HTTPException(409, "Username already exists")
    db.execute("INSERT INTO users(username,pw_hash,role) VALUES(?,?,?)",
               (body.username, hash_password(body.password), body.role))
    audit.log(db, admin["username"], "user_created", f"{body.username} ({body.role})")
    return {"username": body.username, "role": body.role}


# ---------- cases ----------
@app.post("/cases", status_code=201)
def create_case(body: CaseIn, user=Depends(require("admin", "officer", "investigator")), db=Depends(get_db)):
    ts = audit.now()
    cur = db.execute(
        """INSERT INTO cases(title,category,description,victim_name,loss_amount,created_by,created_at,due_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (body.title, body.category, body.description, body.victim_name, body.loss_amount,
         user["id"], ts, ts))
    cid = cur.lastrowid
    db.execute("UPDATE cases SET case_no=? WHERE id=?", (f"CS-{ts[:4]}-{cid:05d}", cid))
    found = extract_iocs(body.description)
    add_iocs(db, cid, found)
    refresh_risk(db, cid)
    # a new IOC link also raises the risk of the older, related cases
    for r in related_cases(db, cid):
        refresh_risk(db, r["id"])
    audit.log(db, user["username"], "case_created", f"case {cid}, {len(found)} IOCs auto-extracted")
    return case_detail(cid, user, db)


@app.get("/cases")
def list_cases(status: Optional[str] = None, severity: Optional[str] = None,
               user=Depends(current_user), db=Depends(get_db)):
    sql, args = "SELECT c.*, u.username AS assignee FROM cases c LEFT JOIN users u ON u.id=c.assigned_to WHERE 1=1", []
    if status:
        sql += " AND c.status=?"; args.append(status)
    if severity:
        sql += " AND c.severity=?"; args.append(severity)
    sql += " ORDER BY c.risk_score DESC, c.id DESC LIMIT 200"
    return [dict(r) for r in db.execute(sql, args)]


@app.get("/cases/{case_id}")
def case_detail(case_id: int, user=Depends(current_user), db=Depends(get_db)):
    c = get_case_or_404(db, case_id)
    assignee = db.execute("SELECT username FROM users WHERE id=?", (c["assigned_to"],)).fetchone()
    return {
        **dict(c),
        "assignee": assignee["username"] if assignee else None,
        "iocs": [dict(r) for r in db.execute("SELECT type,value FROM iocs WHERE case_id=?", (case_id,))],
        "evidence": [dict(r) for r in db.execute(
            "SELECT id,filename,sha256,size,created_at FROM evidence WHERE case_id=?", (case_id,))],
        "related": related_cases(db, case_id),
    }


@app.patch("/cases/{case_id}/status")
def set_status(case_id: int, body: StatusIn, user=Depends(require("admin", "investigator")), db=Depends(get_db)):
    c = get_case_or_404(db, case_id)
    if body.status not in TRANSITIONS[c["status"]]:
        raise HTTPException(409, f"Cannot move from '{c['status']}' to '{body.status}'")
    db.execute("UPDATE cases SET status=? WHERE id=?", (body.status, case_id))
    audit.log(db, user["username"], "status_changed", f"case {case_id}: {c['status']} -> {body.status}")
    return {"id": case_id, "status": body.status}


@app.post("/cases/{case_id}/assign")
def assign(case_id: int, body: AssignIn, user=Depends(require("admin")), db=Depends(get_db)):
    get_case_or_404(db, case_id)
    target = db.execute("SELECT id,role FROM users WHERE username=?", (body.username,)).fetchone()
    if not target or target["role"] not in ("investigator", "admin"):
        raise HTTPException(400, "Assignee must be an existing investigator")
    db.execute("UPDATE cases SET assigned_to=? WHERE id=?", (target["id"], case_id))
    audit.log(db, user["username"], "case_assigned", f"case {case_id} -> {body.username}")
    return {"id": case_id, "assignee": body.username}


@app.post("/cases/{case_id}/iocs", status_code=201)
def add_ioc(case_id: int, body: IocIn, user=Depends(require("admin", "investigator")), db=Depends(get_db)):
    get_case_or_404(db, case_id)
    added = add_iocs(db, case_id, [(body.type, body.value.strip().lower())])
    refresh_risk(db, case_id)
    for r in related_cases(db, case_id):
        refresh_risk(db, r["id"])
    audit.log(db, user["username"], "ioc_added", f"case {case_id}: {body.type}")
    return {"added": bool(added)}


@app.get("/cases/{case_id}/related")
def related(case_id: int, user=Depends(current_user), db=Depends(get_db)):
    get_case_or_404(db, case_id)
    return related_cases(db, case_id)


# ---------- evidence & chain of custody ----------
@app.post("/cases/{case_id}/evidence", status_code=201)
def upload_evidence(case_id: int, body: EvidenceIn, user=Depends(require("admin", "investigator")),
                    db=Depends(get_db)):
    get_case_or_404(db, case_id)
    try:
        data = base64.b64decode(body.content_b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, "content_b64 is not valid base64")
    if not data or len(data) > MAX_EVIDENCE_BYTES:
        raise HTTPException(413, "Evidence must be between 1 byte and 5 MB")
    safe_name = Path(body.filename).name or "evidence.bin"
    stored = f"{uuid.uuid4().hex}_{safe_name}"
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / stored).write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    cur = db.execute(
        "INSERT INTO evidence(case_id,filename,stored_as,sha256,size,collected_by,created_at) VALUES(?,?,?,?,?,?,?)",
        (case_id, safe_name, stored, sha, len(data), user["id"], audit.now()))
    add_custody(db, cur.lastrowid, "collected", user["username"], body.note)
    audit.log(db, user["username"], "evidence_added", f"case {case_id}, sha256 {sha[:16]}")
    return {"id": cur.lastrowid, "sha256": sha, "size": len(data)}


@app.get("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: int, user=Depends(current_user), db=Depends(get_db)):
    e = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not e:
        raise HTTPException(404, "Evidence not found")
    path = EVIDENCE_DIR / e["stored_as"]
    intact = path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == e["sha256"]
    add_custody(db, evidence_id, "verified_intact" if intact else "INTEGRITY_FAILURE", user["username"])
    audit.log(db, user["username"], "evidence_verified", f"evidence {evidence_id}: {'ok' if intact else 'TAMPERED'}")
    return {"evidence_id": evidence_id, "intact": intact, "expected_sha256": e["sha256"]}


@app.post("/evidence/{evidence_id}/transfer")
def transfer_evidence(evidence_id: int, body: TransferIn, user=Depends(require("admin", "investigator")),
                      db=Depends(get_db)):
    if not db.execute("SELECT 1 FROM evidence WHERE id=?", (evidence_id,)).fetchone():
        raise HTTPException(404, "Evidence not found")
    if not db.execute("SELECT 1 FROM users WHERE username=?", (body.to_user,)).fetchone():
        raise HTTPException(400, "Recipient does not exist")
    add_custody(db, evidence_id, f"transferred_to:{body.to_user}", user["username"], body.note)
    audit.log(db, user["username"], "evidence_transferred", f"evidence {evidence_id} -> {body.to_user}")
    return {"ok": True}


@app.get("/evidence/{evidence_id}/custody")
def custody(evidence_id: int, user=Depends(current_user), db=Depends(get_db)):
    return [dict(r) for r in db.execute(
        "SELECT action,actor,note,ts FROM custody WHERE evidence_id=? ORDER BY id", (evidence_id,))]


# ---------- analytics & audit ----------
@app.get("/stats")
def stats(user=Depends(current_user), db=Depends(get_db)):
    def group(col):
        return {r[0]: r[1] for r in db.execute(f"SELECT {col}, COUNT(*) FROM cases GROUP BY {col}")}
    overdue = db.execute("SELECT COUNT(*) FROM cases WHERE status IN ('open','investigating') AND due_at < ?",
                         (audit.now(),)).fetchone()[0]
    campaigns = [dict(r) for r in db.execute(
        """SELECT type, value, COUNT(DISTINCT case_id) AS cases FROM iocs
           GROUP BY type, value HAVING cases > 1 ORDER BY cases DESC LIMIT 5""")]
    return {
        "total": db.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
        "by_status": group("status"), "by_severity": group("severity"), "by_category": group("category"),
        "overdue": overdue,
        "total_loss": db.execute("SELECT COALESCE(SUM(loss_amount),0) FROM cases").fetchone()[0],
        "campaigns": campaigns,
    }


@app.get("/audit/verify")
def audit_verify(user=Depends(current_user), db=Depends(get_db)):
    return audit.verify(db)


@app.get("/audit")
def audit_list(user=Depends(require("admin")), db=Depends(get_db)):
    return [dict(r) for r in db.execute("SELECT id,ts,actor,action,detail FROM audit ORDER BY id DESC LIMIT 100")]


@app.get("/", include_in_schema=False)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


# ======== DASHBOARD ========

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberShield - Cyber Cell Case Desk</title>
<style>
:root{--paper:#eef1f5;--card:#fff;--ink:#14233b;--steel:#5b6b82;--line:#d5dce6;--tag:#f2b705;
--critical:#b3261e;--high:#d9730d;--medium:#9a7400;--low:#2e7d5b;--ok:#2e7d5b;--bad:#b3261e;
--head:"Iowan Old Style","Palatino Linotype",Georgia,serif;--body:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
@media (prefers-color-scheme:dark){:root{--paper:#0f1724;--card:#17243a;--ink:#e8edf5;--steel:#9fb0c8;--line:#2a3b57;--medium:#e0b200}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 var(--body)}
header{background:#14233b;color:#fff;padding:14px 20px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
header h1{font:700 22px var(--head);margin:0;letter-spacing:.2px}header small{color:#aebbd0}
.ledger{margin-left:auto;display:flex;align-items:center;gap:8px;border:2px dashed var(--tag);padding:5px 12px;border-radius:4px;font-size:13px;color:#fff;background:transparent;cursor:pointer}
.ledger i{width:10px;height:10px;border-radius:50%;background:#888;display:inline-block}
.ledger.ok i{background:#4cd08b}.ledger.bad i{background:#ff6b5e}
main{max-width:1100px;margin:0 auto;padding:18px;display:grid;gap:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px}
h2{font:700 18px var(--head);margin:0 0 10px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{border-left:4px solid var(--tag);padding:4px 12px}.stat b{font:700 26px var(--head);display:block}.stat span{color:var(--steel);font-size:13px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:top}
th{color:var(--steel);font-weight:600}tbody tr{cursor:pointer}tbody tr:hover{background:rgba(242,183,5,.12)}
.wrap{overflow-x:auto}
.chip{display:inline-block;padding:1px 8px;border-radius:3px;color:#fff;font-size:12px;font-weight:600}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}
input,select,textarea,button{font:inherit;color:inherit}
input,select,textarea{width:100%;padding:8px;border:1px solid var(--line);border-radius:4px;background:var(--paper)}
label{display:block;font-size:13px;color:var(--steel);margin:8px 0 2px}
button.primary{background:var(--ink);color:var(--paper);border:0;padding:9px 16px;border-radius:4px;cursor:pointer;margin-top:10px}
button.small{background:transparent;border:1px solid var(--line);padding:4px 10px;border-radius:4px;cursor:pointer;margin:2px}
:focus-visible{outline:3px solid var(--tag);outline-offset:2px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:700px){.grid2{grid-template-columns:1fr}}
code{font-size:12px;word-break:break-all;background:var(--paper);padding:1px 4px;border-radius:3px}
.msg{color:var(--bad);min-height:20px;font-size:13px}.hidden{display:none}
</style>
</head>
<body>
<header>
  <h1>CyberShield</h1><small>Cyber Cell Case Desk</small>
  <button id="ledger" class="ledger hidden" title="Re-check audit ledger"><i></i><span>Ledger: checking...</span></button>
</header>
<main>
  <section id="login" class="card" style="max-width:380px;margin:40px auto">
    <h2>Officer sign-in</h2>
    <label for="u">Username</label><input id="u" autocomplete="username">
    <label for="p">Password</label><input id="p" type="password" autocomplete="current-password">
    <div class="msg" id="loginMsg"></div>
    <button class="primary" id="loginBtn">Sign in</button>
  </section>

  <div id="app" class="hidden" style="display:none;gap:18px;grid-template-columns:1fr">
    <section class="card"><h2>Station overview</h2><div class="stats" id="stats"></div></section>
    <section class="card" id="campaignBox"><h2>Repeat indicators across cases</h2><div id="campaigns"></div></section>
    <section class="card"><h2>Open complaints, highest risk first</h2>
      <div class="wrap"><table><thead><tr><th>Case</th><th>Title</th><th>Category</th><th>Risk</th><th>Status</th><th>Due</th></tr></thead><tbody id="rows"></tbody></table></div>
    </section>
    <section class="card hidden" id="detail"></section>
    <section class="card"><h2>Register a complaint</h2>
      <div class="grid2">
        <div><label for="t">Title</label><input id="t"></div>
        <div><label for="cat">Category</label><select id="cat"></select></div>
        <div><label for="vn">Victim name</label><input id="vn"></div>
        <div><label for="loss">Amount lost (INR)</label><input id="loss" type="number" min="0" value="0"></div>
      </div>
      <label for="d">What happened? Paste links, UPI IDs, phone numbers, emails - they are picked up automatically.</label>
      <textarea id="d" rows="4"></textarea>
      <div class="msg" id="caseMsg"></div>
      <button class="primary" id="addCase">Register complaint</button>
    </section>
  </div>
</main>
<script>
let token=null, role=null;
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const CATS=["phishing","ransomware","upi_fraud","identity_theft","sextortion","hacking","data_breach","cyberbullying","other"];
$("cat").innerHTML=CATS.map(c=>`<option value="${c}">${c.replace("_"," ")}</option>`).join("");

async function api(path,opts={}){
  const r=await fetch(path,{...opts,headers:{"Content-Type":"application/json",...(token?{Authorization:"Bearer "+token}:{})}});
  const j=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(typeof j.detail==="string"?j.detail:"Request failed ("+r.status+")");
  return j;
}
$("loginBtn").onclick=async()=>{
  try{
    const j=await api("/auth/login",{method:"POST",body:JSON.stringify({username:$("u").value,password:$("p").value})});
    token=j.access_token;role=j.role;$("login").style.display="none";$("app").style.display="grid";$("ledger").classList.remove("hidden");
    refresh();checkLedger();
  }catch(e){$("loginMsg").textContent=e.message}
};
async function checkLedger(){
  const b=$("ledger");
  try{const j=await api("/audit/verify");b.className="ledger "+(j.valid?"ok":"bad");
    b.lastElementChild.textContent=j.valid?`Audit ledger intact (${j.entries} entries)`:`Ledger broken at entry ${j.broken_at}`;}
  catch(e){b.lastElementChild.textContent="Ledger check failed"}
}
$("ledger").onclick=checkLedger;

async function refresh(){
  const [s,cases]=await Promise.all([api("/stats"),api("/cases")]);
  const sev=s.by_severity;
  $("stats").innerHTML=[["Total cases",s.total],["Critical",sev.critical||0],["High",sev.high||0],["Overdue",s.overdue],
    ["Money lost","Rs "+Math.round(s.total_loss).toLocaleString("en-IN")]].map(([k,v])=>`<div class="stat"><b>${esc(v)}</b><span>${k}</span></div>`).join("");
  $("campaignBox").style.display=s.campaigns.length?"":"none";
  $("campaigns").innerHTML=s.campaigns.map(c=>`<div><code>${esc(c.value)}</code> (${esc(c.type)}) appears in <b>${c.cases}</b> cases - possible single gang.</div>`).join("");
  $("rows").innerHTML=cases.map(c=>`<tr data-id="${c.id}" tabindex="0"><td>${esc(c.case_no)}</td><td>${esc(c.title)}</td><td>${esc(c.category.replace("_"," "))}</td>
    <td><span class="chip ${c.severity}">${esc(c.severity)} ${c.risk_score}</span></td><td>${esc(c.status)}</td><td>${esc(c.due_at.slice(0,10))}</td></tr>`).join("")
    ||`<tr><td colspan="6">No complaints yet. Register the first one below.</td></tr>`;
  document.querySelectorAll("#rows tr[data-id]").forEach(tr=>{tr.onclick=()=>showCase(tr.dataset.id);tr.onkeydown=e=>{if(e.key==="Enter")showCase(tr.dataset.id)}});
}
async function showCase(id){
  const c=await api("/cases/"+id), d=$("detail");d.classList.remove("hidden");
  const canWork=role==="admin"||role==="investigator";
  d.innerHTML=`<h2>${esc(c.case_no)} - ${esc(c.title)}</h2>
   <p><span class="chip ${c.severity}">${esc(c.severity)} ${c.risk_score}</span> status: <b>${esc(c.status)}</b> | victim: ${esc(c.victim_name)} | assigned: ${esc(c.assignee||"nobody yet")}</p>
   <p>${esc(c.description)}</p>
   <p><b>Indicators found:</b> ${c.iocs.map(i=>`<code>${esc(i.type)}: ${esc(i.value)}</code>`).join(" ")||"none"}</p>
   <p><b>Linked cases:</b> ${c.related.map(r=>`${esc(r.case_no)} (shares <code>${esc(r.shared)}</code>)`).join("; ")||"none"}</p>
   <p><b>Evidence:</b> ${c.evidence.map(e=>`${esc(e.filename)} <code>${esc(e.sha256.slice(0,16))}...</code> <button class="small" data-ev="${e.id}">Verify integrity</button>`).join("<br>")||"none"}</p>
   ${canWork?`<div>${["investigating","resolved","closed"].map(s=>`<button class="small" data-st="${s}">Mark ${s}</button>`).join("")}</div>`:""}
   <div class="msg" id="detMsg"></div>`;
  d.querySelectorAll("[data-st]").forEach(b=>b.onclick=async()=>{try{await api(`/cases/${id}/status`,{method:"PATCH",body:JSON.stringify({status:b.dataset.st})});refresh();showCase(id);checkLedger()}catch(e){$("detMsg").textContent=e.message}});
  d.querySelectorAll("[data-ev]").forEach(b=>b.onclick=async()=>{const r=await api(`/evidence/${b.dataset.ev}/verify`);$("detMsg").style.color=r.intact?"var(--ok)":"var(--bad)";$("detMsg").textContent=r.intact?"Evidence matches its original fingerprint.":"WARNING: file no longer matches the recorded fingerprint.";checkLedger()});
  d.scrollIntoView({behavior:"smooth"});
}
$("addCase").onclick=async()=>{
  try{
    await api("/cases",{method:"POST",body:JSON.stringify({title:$("t").value,category:$("cat").value,description:$("d").value,victim_name:$("vn").value,loss_amount:+$("loss").value||0})});
    ["t","d","vn"].forEach(i=>$(i).value="");$("loss").value=0;$("caseMsg").textContent="";refresh();checkLedger();
  }catch(e){$("caseMsg").textContent=e.message}
};
</script>
</body>
</html>
"""
