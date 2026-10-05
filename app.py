"""MediVault: secure healthcare data management and analytics platform.

Run:  python app.py        then open http://127.0.0.1:5000
"""
import datetime as dt
import hashlib
import io
import json
import os
import re
import secrets
import threading
import time
import uuid
import webbrowser
from collections import Counter
from functools import wraps

from flask import (Flask, abort, g, jsonify, redirect, render_template, request, send_file,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import config
import seed
from services import Services, iam
from services.audit import utcnow

app = Flask(__name__)
app.config.update(
    SECRET_KEY=config.SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=config.MAX_UPLOAD_MB * 1024 * 1024 + 8192,
    PERMANENT_SESSION_LIFETIME=dt.timedelta(minutes=config.SESSION_MINUTES),
)
svc = Services()
seed.seed_all(svc)
_DUMMY_HASH = generate_password_hash("not-a-real-password")


# --------------------------------------------------------------------------- helpers
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def me():
    """Signed-in user. The role is re-read from the database so role changes apply immediately."""
    u = session.get("user")
    if not u:
        return None
    if "me" not in g:
        row = svc.db.one("SELECT username, full_name, role FROM users WHERE username = ?", (u["username"],))
        g.me = dict(row) if row else None
    if g.me is None:
        session.clear()
    return g.me


def log(event, resource="", outcome="Success", detail=""):
    u = me() or {"username": "anonymous", "role": "-"}
    svc.audit.log(event, u["username"], u["role"], request.remote_addr or "", resource, outcome, detail)


def api_auth(*actions):
    """Require a signed-in user holding at least one of the given permissions."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = me()
            if not user:
                return jsonify(error="Please sign in again."), 401
            if actions and not any(iam.can(user["role"], a) for a in actions):
                log("iam:AccessDenied", actions[0], "Denied",
                    f"Role {user['role']} is not allowed to perform {actions[0]}")
                return jsonify(error=f"Your role ({user['role']}) is not allowed to do this."), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def mask_id(value):
    digits = re.sub(r"\D", "", value or "")
    return "XXXX-XXXX-" + digits[-4:] if len(digits) >= 4 else "XXXX"


def page_int(value, default=1):
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not sent or not expected or not secrets.compare_digest(sent.encode(), expected.encode()):
            if request.path.startswith("/api/"):
                return jsonify(error="Your session expired. Reload the page and try again."), 400
            abort(400)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
    if request.path.startswith("/api/") or request.path in ("/login", "/dashboard"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def start_session(row, method):
    session.clear()
    session.permanent = True
    session["user"] = {"username": row["username"], "full_name": row["full_name"], "role": row["role"]}
    csrf_token()
    svc.db.execute("UPDATE users SET last_login = ? WHERE id = ?", (utcnow(), row["id"]))
    svc.audit.log("signin:ConsoleLogin", row["username"], row["role"], request.remote_addr or "", "",
                  "Success", f"Signed in with {method}")


def login_context(error=None, notice=None):
    users = [{"username": u[0], "name": u[1], "role": iam.ROLES[u[2]]["label"]} for u in seed.USERS]
    return dict(users=users, demo_password=config.DEMO_PASSWORD if config.MODE == "demo" else None,
                error=error, notice=notice, mode=config.MODE)


@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    ctx = login_context("That page does not exist.")
    ctx.update(users=[], demo_password=None)
    return render_template("login.html", **ctx), 404


@app.errorhandler(413)
def too_large(_):
    return jsonify(error=f"File is larger than {config.MAX_UPLOAD_MB} MB."), 413


# --------------------------------------------------------------------------- pages
@app.get("/")
def landing():
    return render_template("landing.html", mode=config.MODE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if me():
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()[:64]
        password = request.form.get("password", "")
        ip = request.remote_addr or ""
        row = svc.db.one("SELECT * FROM users WHERE username = ?", (username,))
        if svc.audit.recent_failed_logins(username) >= 5:
            svc.audit.log("signin:ConsoleLogin", username, "-", ip, "", "Failure", "Locked: too many attempts")
            error = "Too many failed attempts. Wait 10 minutes and try again."
        elif row and check_password_hash(row["pw_hash"], password):
            start_session(row, "password")
            return redirect(url_for("dashboard"))
        else:
            check_password_hash(_DUMMY_HASH, password)  # keep timing similar
            svc.audit.log("signin:ConsoleLogin", username or "unknown", "-", ip, "", "Failure", "Bad credentials")
            error = "Username or password is incorrect."
    return render_template("login.html", **login_context(error))


# --------------------------------------------------------------------------- create an account
_reg_hits = {}
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")


def password_problem(password, username):
    if len(password) < 8:
        return "Use at least 8 characters for the password."
    if len(password) > 128:
        return "That password is too long (128 characters at most)."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "The password needs at least one letter and one number."
    if password.lower() == username.lower():
        return "The password must be different from the username."
    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if me():
        return redirect(url_for("dashboard"))
    form = {"full_name": "", "username": ""}
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        now = time.time()
        hits = [t for t in _reg_hits.get(ip, []) if now - t < 3600]
        full_name = " ".join(request.form.get("full_name", "").split())[:80]
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        form = {"full_name": full_name, "username": username}
        if len(hits) >= 5:
            error = "Too many accounts were created from this device. Try again in an hour."
        elif len(full_name) < 2:
            error = "Enter your full name."
        elif not USERNAME_RE.match(username):
            error = "Choose a username of 3 to 32 characters: lowercase letters, numbers, dot, dash or underscore."
        elif password != confirm:
            error = "The two passwords do not match."
        else:
            error = password_problem(password, username)
        if not error and svc.db.one("SELECT id FROM users WHERE username = ?", (username,)):
            error = "That username is taken. Try another one."
        if not error:
            _reg_hits[ip] = hits + [now]
            svc.db.execute("INSERT INTO users (username, full_name, role, pw_hash, mfa_enabled) VALUES (?,?,?,?,?)",
                           (username, full_name, "guest", generate_password_hash(password), 0))
            svc.audit.log("iam:CreateUser", username, "guest", ip, username, "Success",
                          "New user created their own account")
            start_session(svc.db.one("SELECT * FROM users WHERE username = ?", (username,)), "new account")
            return redirect(url_for("dashboard"))
    return render_template("register.html", error=error, form=form)


@app.post("/logout")
def logout():
    if me():
        log("signin:ConsoleLogout", detail="Signed out")
    session.clear()
    return redirect(url_for("landing"))


@app.get("/dashboard")
def dashboard():
    if not me():
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=me(), role_label=iam.ROLES[me()["role"]]["label"],
                           mode=config.MODE)


@app.get("/healthz")
def healthz():
    return jsonify(status="ok", mode=config.MODE)


# --------------------------------------------------------------------------- public demo
_rate = {}


@app.post("/api/demo/encrypt")
def demo_encrypt():
    ip = request.remote_addr or "?"
    now = time.time()
    hits = [t for t in _rate.get(ip, []) if now - t < 60]
    if len(hits) >= 40:
        return jsonify(error="Slow down a little and try again in a minute."), 429
    _rate[ip] = hits + [now]
    text = (request.get_json(silent=True) or {}).get("text", "")
    if not isinstance(text, str) or not text.strip():
        return jsonify(error="Type something to encrypt."), 400
    text = text[:120]
    env = json.loads(svc.vault.encrypt(text.encode(), {"demo": "landing-page"}))
    return jsonify(key_id=env["kid"], encrypted_data_key=env["edk"], nonce=env["n"], ciphertext=env["ct"],
                   plaintext_bytes=len(text.encode()))


# --------------------------------------------------------------------------- session info
@app.get("/api/me")
@api_auth()
def api_me():
    u = me()
    return jsonify(user=u, role_label=iam.ROLES[u["role"]]["label"], permissions=iam.permissions(u["role"]),
                   view_level=iam.patient_view_level(u["role"]), mode=config.MODE)


# --------------------------------------------------------------------------- overview + analytics
@app.get("/api/overview")
@api_auth()
def api_overview():
    u = me()
    if not iam.permissions(u["role"]):
        return jsonify(limited=True, name=u["full_name"])
    today = dt.date.today()
    since = (today - dt.timedelta(days=30)).isoformat()
    day_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = {
        "patients": svc.db.one("SELECT COUNT(*) AS n FROM patients")["n"],
        "admissions_30d": svc.db.one("SELECT COUNT(*) AS n FROM admissions WHERE admit_date >= ?", (since,))["n"],
        "documents": svc.db.one("SELECT COUNT(*) AS n FROM documents")["n"],
        "compliance_score": None, "events_24h": None, "denied_24h": None, "noncompliant": None,
    }
    if iam.can(u["role"], "compliance:Read"):
        results, score = svc.compliance.evaluate()
        out["compliance_score"] = score
        out["noncompliant"] = [r["id"] for r in results if r["status"] == "NON_COMPLIANT"]
    if iam.can(u["role"], "audit:Read"):
        out["events_24h"] = svc.db.one("SELECT COUNT(*) AS n FROM audit_log WHERE event_time >= ?", (day_ago,))["n"]
        out["denied_24h"] = svc.db.one(
            "SELECT COUNT(*) AS n FROM audit_log WHERE event_time >= ? AND outcome = 'Denied'", (day_ago,))["n"]
    try:
        key = svc.kms.describe()
    except Exception as exc:  # AWS errors should not break the overview
        key = {"key_id": config.KMS_KEY_ID, "alias": "", "spec": "", "origin": "AWS_KMS", "created": "",
               "error": str(exc)[:120]}
    out["system"] = {
        "mode": config.MODE, "kms": key, "storage": svc.storage.describe(),
        "database": "Amazon Aurora MySQL" if svc.db.engine == "mysql" else "SQLite (stands in for Aurora)",
    }
    return jsonify(out)


AGE_BANDS = [("0-14", 0, 14), ("15-29", 15, 29), ("30-44", 30, 44), ("45-59", 45, 59),
             ("60-74", 60, 74), ("75+", 75, 200)]
MIN_CELL = 5  # groups smaller than this are suppressed so nobody can be singled out


@app.get("/api/analytics")
@api_auth("analytics:Read")
def api_analytics():
    rows = svc.db.query(
        "SELECT a.department, a.diagnosis, a.admit_date, a.discharge_date, a.readmission, p.age, p.gender "
        "FROM admissions a JOIN patients p ON p.id = a.patient_id")
    today = dt.date.today()
    months = []
    y, m = today.year, today.month
    for _ in range(12):
        months.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    months.reverse()
    by_month = Counter(r["admit_date"][:7] for r in rows)
    diag = Counter(r["diagnosis"] for r in rows).most_common(8)
    dept = Counter(r["department"] for r in rows).most_common()
    stays = {}
    for r in rows:
        if r["discharge_date"]:
            days = (dt.date.fromisoformat(r["discharge_date"]) - dt.date.fromisoformat(r["admit_date"])).days
            stays.setdefault(r["department"], []).append(days)
    ages = [r["age"] for r in svc.db.query("SELECT age FROM patients")]
    bands = []
    for label, lo, hi in AGE_BANDS:
        n = sum(1 for a in ages if lo <= a <= hi)
        bands.append({"label": label, "value": None if n < MIN_CELL else n, "suppressed": n < MIN_CELL})
    genders = Counter(r["gender"] for r in svc.db.query("SELECT gender FROM patients"))
    total = len(rows)
    return jsonify(
        months=[{"label": dt.date(int(k[:4]), int(k[5:]), 1).strftime("%b %y"), "value": by_month.get(k, 0)}
                for k in months],
        diagnoses=[{"label": k, "value": v} for k, v in diag if v >= MIN_CELL],
        departments=[{"label": k, "value": v} for k, v in dept if v >= MIN_CELL],
        los=[{"label": k, "value": round(sum(v) / len(v), 1)} for k, v in sorted(stays.items()) if len(v) >= MIN_CELL],
        age_bands=bands,
        genders=[{"label": k, "value": v} for k, v in genders.items() if v >= MIN_CELL],
        readmission_rate=round(100 * sum(r["readmission"] for r in rows) / total, 1) if total else 0,
        admissions=total, min_cell=MIN_CELL)


# --------------------------------------------------------------------------- patients (Aurora + KMS)
def _phi(row):
    return svc.vault.decrypt_json(row["phi_enc"], {"mrn": row["mrn"], "table": "patients"})


@app.get("/api/patients")
@api_auth("patients:ReadFull", "patients:ReadPartial", "patients:ListDeidentified")
def api_patients():
    level = iam.patient_view_level(me()["role"])
    q = request.args.get("q", "").strip()[:40]
    page, size = page_int(request.args.get("page")), 15
    where, params = "", []
    if q:
        where, params = "WHERE mrn LIKE ? OR city LIKE ? OR gender LIKE ?", [f"%{q}%"] * 3
    total = svc.db.one(f"SELECT COUNT(*) AS n FROM patients {where}", params)["n"]
    rows = svc.db.query(
        f"SELECT mrn, phi_enc, age, gender, blood_group, city, created_at FROM patients {where} "
        "ORDER BY id DESC LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    decrypted, patients = 0, []
    for r in rows:
        name = None
        if level in ("full", "partial"):
            try:
                name = _phi(r)["name"]
                decrypted += 1
            except Exception:
                name = "Unreadable"
        patients.append({"mrn": r["mrn"], "name": name, "age": r["age"], "gender": r["gender"],
                         "blood_group": r["blood_group"], "city": r["city"], "created_at": r["created_at"][:10]})
    log("rds-data:ExecuteStatement", "patients", detail=f"Listed {len(rows)} patients ({level} view)")
    if decrypted:
        log("kms:Decrypt", "patients", detail=f"Unwrapped {decrypted} data keys")
    return jsonify(level=level, total=total, page=page, pages=max(1, -(-total // size)), patients=patients)


@app.get("/api/patients/<mrn>")
@api_auth("patients:ReadFull", "patients:ReadPartial")
def api_patient(mrn):
    level = iam.patient_view_level(me()["role"])
    row = svc.db.one("SELECT * FROM patients WHERE mrn = ?", (mrn,))
    if not row:
        return jsonify(error="Patient not found."), 404
    try:
        phi = _phi(row)
    except Exception:
        log("kms:Decrypt", mrn, "Failure", "Data key could not be unwrapped")
        return jsonify(error="This record could not be decrypted."), 500
    detail = {"name": phi["name"], "national_id": phi["national_id"] if level == "full" else mask_id(phi["national_id"])}
    if level == "full":
        detail.update(phone=phi["phone"], address=phi["address"], notes=phi["notes"])
    adms = svc.db.query(
        "SELECT department, diagnosis, admit_date, discharge_date, outcome FROM admissions "
        "WHERE patient_id = (SELECT id FROM patients WHERE mrn = ?) ORDER BY admit_date DESC", (mrn,))
    docs = svc.db.query("SELECT COUNT(*) AS n FROM documents WHERE mrn = ?", (mrn,))[0]["n"]
    log("rds-data:ExecuteStatement", mrn, detail="Opened patient record")
    log("kms:Decrypt", mrn, detail=f"Unwrapped data key ({level} view)")
    return jsonify(level=level, mrn=mrn, age=row["age"], gender=row["gender"], blood_group=row["blood_group"],
                   city=row["city"], created_at=row["created_at"][:10], key_id=_key_id(row["phi_enc"]),
                   documents=docs, admissions=adms, **detail)


def _key_id(token):
    try:
        return svc.vault.key_id_of(token)
    except Exception:
        return ""


@app.post("/api/patients")
@api_auth("patients:Create")
def api_patient_create():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()
    gender = str(d.get("gender", ""))
    blood = str(d.get("blood_group", ""))
    try:
        age = int(d.get("age"))
    except (TypeError, ValueError):
        age = -1
    errors = []
    if not 2 <= len(name) <= 80:
        errors.append("Enter the patient's full name (2 to 80 characters).")
    if not 0 <= age <= 120:
        errors.append("Enter an age between 0 and 120.")
    if gender not in ("Female", "Male", "Other"):
        errors.append("Choose a gender.")
    if blood and blood not in seed.BLOOD:
        errors.append("Choose a valid blood group.")
    if errors:
        return jsonify(error=" ".join(errors)), 400
    phi = {
        "name": name,
        "national_id": re.sub(r"[^\d-]", "", str(d.get("national_id", "")))[:20],
        "phone": re.sub(r"[^\d+ -]", "", str(d.get("phone", "")))[:20],
        "address": str(d.get("address", ""))[:200],
        "notes": str(d.get("notes", ""))[:1000],
    }
    for _ in range(10):
        mrn = f"MV-{secrets.randbelow(900000) + 100000}"
        if not svc.db.one("SELECT id FROM patients WHERE mrn = ?", (mrn,)):
            break
    token = svc.vault.encrypt_json(phi, {"mrn": mrn, "table": "patients"})
    svc.db.execute(
        "INSERT INTO patients (mrn, phi_enc, age, gender, blood_group, city, created_at, created_by) VALUES (?,?,?,?,?,?,?,?)",
        (mrn, token, age, gender, blood or None, str(d.get("city", ""))[:64], utcnow(), me()["username"]))
    log("kms:GenerateDataKey", mrn, detail="New data key for patient record")
    log("rds-data:ExecuteStatement", mrn, detail="Inserted encrypted patient record")
    return jsonify(mrn=mrn), 201


# --------------------------------------------------------------------------- documents (S3 + KMS)
ALLOWED_EXT = {"pdf", "png", "jpg", "jpeg", "txt", "csv"}


@app.get("/api/documents")
@api_auth("documents:Upload", "documents:Download")
def api_documents():
    mrn = request.args.get("mrn", "").strip()[:32]
    if mrn:
        rows = svc.db.query("SELECT * FROM documents WHERE mrn = ? ORDER BY id DESC LIMIT 100", (mrn,))
    else:
        rows = svc.db.query("SELECT * FROM documents ORDER BY id DESC LIMIT 100")
    can_dl = iam.can(me()["role"], "documents:Download")
    return jsonify(can_download=can_dl, documents=[{
        "id": r["id"], "mrn": r["mrn"], "filename": r["filename"], "size_bytes": r["size_bytes"],
        "key_id": r["key_id"], "uploaded_by": r["uploaded_by"], "uploaded_at": r["uploaded_at"],
        "s3_key": r["s3_key"]} for r in rows])


@app.post("/api/documents")
@api_auth("documents:Upload")
def api_document_upload():
    mrn = request.form.get("mrn", "").strip()
    f = request.files.get("file")
    if not svc.db.one("SELECT id FROM patients WHERE mrn = ?", (mrn,)):
        return jsonify(error="Enter a valid patient MRN, for example MV-100000."), 400
    if not f or not f.filename:
        return jsonify(error="Choose a file to upload."), 400
    filename = secure_filename(f.filename)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        return jsonify(error="Allowed file types: " + ", ".join(sorted(ALLOWED_EXT)) + "."), 400
    data = f.read()
    if not data:
        return jsonify(error="That file is empty."), 400
    key = f"patients/{mrn}/{uuid.uuid4().hex[:8]}-{filename}"
    token = svc.vault.encrypt(data, {"mrn": mrn, "s3_key": key})
    svc.storage.put(key, token.encode(), svc.kms.key_id)
    svc.db.execute(
        "INSERT INTO documents (mrn, filename, s3_key, size_bytes, content_type, key_id, sha256, uploaded_by, uploaded_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (mrn, filename, key, len(data), f.mimetype, svc.vault.key_id_of(token), hashlib.sha256(data).hexdigest(),
         me()["username"], utcnow()))
    log("kms:GenerateDataKey", mrn, detail="New data key for uploaded file")
    log("s3:PutObject", key, detail=f"Stored {len(data)} bytes encrypted")
    return jsonify(ok=True, s3_key=key), 201


@app.get("/api/documents/<int:doc_id>/download")
@api_auth("documents:Download")
def api_document_download(doc_id):
    doc = svc.db.one("SELECT * FROM documents WHERE id = ?", (doc_id,))
    if not doc:
        abort(404)
    try:
        token = svc.storage.get(doc["s3_key"]).decode()
        data = svc.vault.decrypt(token, {"mrn": doc["mrn"], "s3_key": doc["s3_key"]})
    except Exception:
        log("kms:Decrypt", doc["s3_key"], "Failure", "Could not decrypt object")
        return jsonify(error="This file could not be decrypted."), 500
    if hashlib.sha256(data).hexdigest() != doc["sha256"]:
        log("s3:GetObject", doc["s3_key"], "Failure", "Checksum mismatch")
        return jsonify(error="File failed its integrity check."), 500
    log("s3:GetObject", doc["s3_key"], detail="Downloaded file")
    log("kms:Decrypt", doc["s3_key"], detail="Unwrapped data key for file")
    return send_file(io.BytesIO(data), as_attachment=True, download_name=doc["filename"],
                     mimetype="application/octet-stream")


# --------------------------------------------------------------------------- IAM
@app.get("/api/iam")
@api_auth("iam:Read")
def api_iam():
    roles = []
    for rid, spec in iam.ROLES.items():
        roles.append({"id": rid, "label": spec["label"], "summary": spec["summary"], "allow": spec["allow"],
                      "deny": spec["deny"], "policy": iam.aws_policy(rid, svc.kms.key_id)})
    users = svc.db.query("SELECT username, full_name, role, mfa_enabled, last_login FROM users ORDER BY id")
    return jsonify(roles=roles, actions=iam.ACTIONS, users=users, can_manage=iam.can(me()["role"], "iam:Manage"),
                   assignable=[{"id": k, "label": v["label"]} for k, v in iam.ROLES.items()])


@app.post("/api/iam/users/<path:username>/role")
@api_auth("iam:Manage")
def api_set_role(username):
    role = str((request.get_json(silent=True) or {}).get("role", ""))
    if role not in iam.ROLES:
        return jsonify(error="Choose a valid role."), 400
    target = svc.db.one("SELECT * FROM users WHERE username = ?", (username,))
    if not target:
        return jsonify(error="User not found."), 404
    if target["username"] == me()["username"]:
        return jsonify(error="You cannot change your own role."), 400
    svc.db.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
    log("iam:UpdateUser", username, detail=f"Role changed from {target['role']} to {role}")
    return jsonify(ok=True, username=username, role=role)


# --------------------------------------------------------------------------- Config (compliance)
def _compliance_payload():
    results, score = svc.compliance.evaluate()
    for r in results:
        r["setting_on"] = None if not r["state"] or config.MODE == "aws" else svc.db.get_state(r["state"]) == "1"
    return {"rules": results, "score": score, "last_evaluated": svc.compliance.last_evaluated,
            "demo_controls": config.MODE == "demo", "can_manage": iam.can(me()["role"], "compliance:Manage")}


@app.get("/api/compliance")
@api_auth("compliance:Read")
def api_compliance():
    return jsonify(_compliance_payload())


@app.post("/api/compliance/evaluate")
@api_auth("compliance:Manage")
def api_compliance_evaluate():
    svc.compliance.start_evaluation()
    log("config:StartConfigRulesEvaluation", "all rules", detail="Re-evaluated all rules")
    return jsonify(_compliance_payload())


@app.post("/api/compliance/toggle")
@api_auth("compliance:Manage")
def api_compliance_toggle():
    if config.MODE != "demo":
        return jsonify(error="Settings can only be toggled in demo mode."), 400
    key = (request.get_json(silent=True) or {}).get("state", "")
    try:
        new = svc.compliance.toggle(key)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    log("config:PutConfigRule", key, detail=f"Setting changed to {'on' if new == '1' else 'off'} (demo drift)")
    svc.compliance.last_evaluated = utcnow()
    return jsonify(_compliance_payload())


@app.post("/api/compliance/remediate")
@api_auth("compliance:Manage")
def api_compliance_remediate():
    if config.MODE != "demo":
        return jsonify(error="Fixes are applied in your AWS account, not from this page."), 400
    rule = (request.get_json(silent=True) or {}).get("rule", "")
    try:
        svc.compliance.remediate(rule)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    log("config:StartRemediationExecution", rule, detail="Applied fix")
    svc.compliance.last_evaluated = utcnow()
    return jsonify(_compliance_payload())


# --------------------------------------------------------------------------- CloudTrail (audit)
@app.get("/api/audit")
@api_auth("audit:Read")
def api_audit():
    rows = svc.audit.search(request.args.get("q", "").strip()[:60], request.args.get("outcome", ""),
                            min(page_int(request.args.get("limit"), 100), 300))
    return jsonify(events=rows, cloudtrail=svc.audit.cloudtrail_available())


@app.get("/api/audit/cloudtrail")
@api_auth("audit:Read")
def api_cloudtrail():
    if not svc.audit.cloudtrail_available():
        return jsonify(available=False, events=[])
    try:
        return jsonify(available=True, events=svc.audit.lookup_cloudtrail(50))
    except Exception as exc:
        return jsonify(error=f"CloudTrail lookup failed: {str(exc)[:160]}"), 502


# --------------------------------------------------------------------------- run
def _open_browser(port):
    time.sleep(1.2)
    webbrowser.open(f"http://127.0.0.1:{port}")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    if os.environ.get("MEDIVAULT_NO_BROWSER") != "1":
        threading.Thread(target=_open_browser, args=(port,), daemon=True).start()
    print(f"\n  MediVault ({config.MODE} mode) running at http://127.0.0.1:{port}\n  Press Ctrl+C to stop.\n")
    app.run(host="127.0.0.1", port=port, debug=False)
