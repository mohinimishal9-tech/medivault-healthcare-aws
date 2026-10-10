"""MediVault on Streamlit: secure healthcare data management and analytics on AWS.

Run locally:   streamlit run streamlit_app.py
Streamlit Cloud: set the main file path to streamlit_app.py

All security logic (KMS envelope encryption, IAM roles, audit trail, Config rules)
is reused from the services/ folder, so it behaves exactly like the Flask version.
"""
import datetime as dt
import hashlib
import json
import re
import time
import uuid
from collections import Counter

import pandas as pd
import streamlit as st
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import config
import seed
from services import Services, iam
from services.audit import utcnow

st.set_page_config(page_title="MediVault", page_icon="🔐", layout="wide")


# --------------------------------------------------------------------------- shared setup
@st.cache_resource(show_spinner="Preparing the secure platform...")
def get_services():
    svc = Services()
    seed.seed_all(svc)  # safe to call from several sessions at once
    return svc


@st.cache_resource
def reg_hits():
    return []


svc = get_services()
DUMMY_HASH = generate_password_hash("not-a-real-password")

CSS = """
<style>
#MainMenu {visibility: hidden;} footer {visibility: hidden;}
.block-container {padding-top: 2rem; max-width: 1180px;}
h1, h2, h3 {letter-spacing: -0.01em;}
.hero h1 {font-size: 3rem; line-height: 1.08; font-weight: 800; color: #123B34; margin: 0 0 .8rem 0;}
.hero p {font-size: 1.1rem; color: #55655F; max-width: 40rem;}
.cipher {background: #123B34; color: #E9F1ED; border-radius: 14px; padding: 1.2rem 1.4rem;}
.cipher small {color: #9CB9AF; display: block; margin-top: .8rem;}
.cipher code {color: #E3A93B; background: transparent; word-break: break-all; font-size: .8rem;}
.pill {display: inline-block; padding: .1rem .6rem; border-radius: 99px; font-size: .8rem; font-weight: 600;}
.pill.ok {background: #D9EFE3; color: #14553B;} .pill.bad {background: #F6DCD8; color: #7A2119;}
.pill.warn {background: #F4E6C6; color: #6B4510;} .pill.mute {background: #E7ECE9; color: #44524C;}
.step {padding: .6rem 0 .6rem 0; border-top: 1px solid #D6DFD9;}
.step b {color: #123B34;}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# --------------------------------------------------------------------------- helpers
def current_user():
    name = st.session_state.get("username")
    if not name:
        return None
    row = svc.db.one("SELECT username, full_name, role FROM users WHERE username = ?", (name,))
    if not row:
        st.session_state.pop("username", None)
        return None
    return row


def log(user, event, resource="", outcome="Success", detail=""):
    who = user["username"] if user else "anonymous"
    role = user["role"] if user else "-"
    svc.audit.log(event, who, role, "streamlit", resource, outcome, detail)


def allowed(user, action):
    return iam.can(user["role"], action)


def need(user, *actions):
    """True if the role holds one of the actions. Otherwise logs a denial and shows a message."""
    if any(allowed(user, a) for a in actions):
        return True
    log(user, "iam:AccessDenied", actions[0], "Denied", f"Role {user['role']} is not allowed to perform {actions[0]}")
    st.error(f"Your role ({iam.ROLES[user['role']]['label']}) is not allowed to open this page.")
    return False


def pill(text, kind):
    return f'<span class="pill {kind}">{text}</span>'


def mask_id(value):
    digits = re.sub(r"\D", "", value or "")
    return "XXXX-XXXX-" + digits[-4:] if len(digits) >= 4 else "XXXX"


def fmt_time(value):
    return (value or "").replace("T", " ").replace("Z", "")


def sign_in(row, method):
    st.session_state["username"] = row["username"]
    svc.db.execute("UPDATE users SET last_login = ? WHERE id = ?", (utcnow(), row["id"]))
    svc.audit.log("signin:ConsoleLogin", row["username"], row["role"], "streamlit", "", "Success",
                  f"Signed in with {method}")


# --------------------------------------------------------------------------- public pages
def page_home():
    left, right = st.columns([1.1, 1])
    with left:
        st.markdown(
            '<div class="hero"><h1>Patient records, locked before they reach the database.</h1>'
            "<p>MediVault encrypts each sensitive field with its own AWS KMS data key, lets IAM decide who "
            "can decrypt it, and records every access in an audit trail.</p></div>",
            unsafe_allow_html=True)
        st.write("")
        st.info("Use the **Sign in** or **Create account** tab above to open the dashboard.")
    with right:
        st.markdown("##### Try the encryption")
        text = st.text_input("Type a patient detail", value="Asha Verma, 41, hypertension", max_chars=120,
                             key="demo_input")
        if text.strip():
            if st.session_state.get("demo_text") != text:
                env = json.loads(svc.vault.encrypt(text.encode(), {"demo": "landing-page"}))
                st.session_state["demo_text"] = text
                st.session_state["demo_env"] = env
            env = st.session_state["demo_env"]
            st.markdown(
                f'<div class="cipher"><b>What Aurora stores</b><br><code>{env["ct"]}</code>'
                f'<small>Encrypted data key (only KMS can open it)</small><code>{env["edk"][:64]}...</code>'
                f'<small>KMS key</small><code>{env["kid"]}</code>'
                f'<small>Each change asks KMS for a new data key, so the same text never gives the same ciphertext.</small></div>',
                unsafe_allow_html=True)

    st.divider()
    st.subheader("What happens to one patient record")
    steps = [
        ("A signed-in user submits the record", "The app checks the user's IAM role before anything is written."),
        ("KMS issues a one-time data key", "A new 256-bit key is generated under the customer managed key. Only its encrypted copy is kept."),
        ("Sensitive fields are encrypted", "Name, ID number, phone, address and notes are sealed with AES-256-GCM. Age, gender and diagnosis stay readable for analytics."),
        ("Aurora and S3 store only ciphertext", "Structured data goes to Aurora. Scans and lab reports go to S3 with SSE-KMS."),
        ("CloudTrail and Config keep watching", "Every decrypt is logged, and Config rules flag any setting that drifts out of policy."),
    ]
    for i, (title, body) in enumerate(steps, 1):
        st.markdown(f'<div class="step"><b>{i}. {title}</b><br>{body}</div>', unsafe_allow_html=True)

    st.divider()
    st.subheader("Six AWS services, one job each")
    services = [
        ("Amazon Aurora", "Stores patient and admission records in an encrypted cluster inside private subnets."),
        ("Amazon S3", "Holds lab reports and scans. Versioned, encrypted, and blocked from public access."),
        ("AWS KMS", "Owns the master key and rotates it every year. Each decrypt needs a permitted role."),
        ("AWS IAM", "Gives each role the least access it needs. Administrators cannot decrypt patient data."),
        ("AWS Config", "Checks seven security rules continuously and flags anything out of compliance."),
        ("AWS CloudTrail", "Records who called which API, from where, and whether it was allowed."),
    ]
    cols = st.columns(2)
    for i, (name, body) in enumerate(services):
        with cols[i % 2]:
            st.markdown(f"**{name}**  \n{body}")

    st.divider()
    st.subheader("Who sees what")
    st.table(pd.DataFrame([
        ["Doctor", "Full", "Yes", "Upload and download", "Yes", "No"],
        ["Nurse", "Name, masked ID", "No", "Upload only", "No", "No"],
        ["Data analyst", "De-identified rows", "No", "No", "Yes", "No"],
        ["Compliance auditor", "No", "No", "No", "No", "Read only"],
        ["Administrator", "De-identified rows", "No", "No", "Yes", "Manage"],
    ], columns=["Role", "Patient identity", "Clinical notes", "Files in S3", "Analytics", "Audit and compliance"]).set_index("Role"))
    st.caption("MediVault is a class project. All patient data shown is synthetic.")


def page_login():
    st.subheader("Sign in")
    with st.form("login_form"):
        username = st.text_input("Username").strip().lower()
        password = st.text_input("Password", type="password")
        go = st.form_submit_button("Sign in")
    if go:
        row = svc.db.one("SELECT * FROM users WHERE username = ?", (username,))
        if svc.audit.recent_failed_logins(username) >= 5:
            svc.audit.log("signin:ConsoleLogin", username, "-", "streamlit", "", "Failure", "Locked: too many attempts")
            st.error("Too many failed attempts. Wait 10 minutes and try again.")
        elif row and check_password_hash(row["pw_hash"], password):
            sign_in(row, "password")
            st.rerun()
        else:
            check_password_hash(DUMMY_HASH, password)
            svc.audit.log("signin:ConsoleLogin", username or "unknown", "-", "streamlit", "", "Failure", "Bad credentials")
            st.error("Username or password is incorrect.")
    if config.MODE == "demo":
        with st.expander("Demo accounts"):
            st.write(f"Password for all: `{config.DEMO_PASSWORD}`")
            st.table(pd.DataFrame(
                [[u[0], u[1], iam.ROLES[u[2]]["label"]] for u in seed.USERS],
                columns=["Username", "Name", "Role"]).set_index("Username"))


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


def page_register():
    st.subheader("Create an account")
    st.caption("New accounts start with no access to patient data. An administrator assigns your role afterwards.")
    with st.form("register_form"):
        full_name = " ".join(st.text_input("Full name", max_chars=80).split())
        username = st.text_input("Username", max_chars=32, help="3 to 32 characters: lowercase letters, numbers, dot, dash or underscore.").strip().lower()
        password = st.text_input("Password", type="password", help="At least 8 characters, with a letter and a number.")
        confirm = st.text_input("Confirm password", type="password")
        go = st.form_submit_button("Create account")
    if not go:
        return
    now = time.time()
    hits = reg_hits()
    hits[:] = [t for t in hits if now - t < 3600]
    error = None
    if len(hits) >= 30:
        error = "Too many accounts were created recently. Try again in an hour."
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
    if error:
        st.error(error)
        return
    hits.append(now)
    svc.db.execute("INSERT INTO users (username, full_name, role, pw_hash, mfa_enabled) VALUES (?,?,?,?,?)",
                   (username, full_name, "guest", generate_password_hash(password), 0))
    svc.audit.log("iam:CreateUser", username, "guest", "streamlit", username, "Success", "New user created their own account")
    sign_in(svc.db.one("SELECT * FROM users WHERE username = ?", (username,)), "new account")
    st.rerun()


# --------------------------------------------------------------------------- dashboard pages
def page_overview(user):
    if not iam.permissions(user["role"]):
        st.info(f"Welcome, {user['full_name']}. Your account is new and has no access to patient data yet. "
                "Ask an administrator to assign your role, then reload this page.")
        return
    today = dt.date.today()
    since = (today - dt.timedelta(days=30)).isoformat()
    day_ago = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    metrics = [("Patients", svc.db.one("SELECT COUNT(*) AS n FROM patients")["n"]),
               ("Admissions, last 30 days", svc.db.one("SELECT COUNT(*) AS n FROM admissions WHERE admit_date >= ?", (since,))["n"]),
               ("Encrypted files", svc.db.one("SELECT COUNT(*) AS n FROM documents")["n"])]
    if allowed(user, "compliance:Read"):
        metrics.append(("Config compliance", f"{svc.compliance.evaluate()[1]}%"))
    if allowed(user, "audit:Read"):
        metrics.append(("Events, 24 hours", svc.db.one("SELECT COUNT(*) AS n FROM audit_log WHERE event_time >= ?", (day_ago,))["n"]))
        metrics.append(("Denied, 24 hours", svc.db.one("SELECT COUNT(*) AS n FROM audit_log WHERE event_time >= ? AND outcome = 'Denied'", (day_ago,))["n"]))
    for col, (label, value) in zip(st.columns(len(metrics)), metrics):
        col.metric(label, value)
    left, right = st.columns([1.6, 1])
    with left:
        if allowed(user, "analytics:Read"):
            st.markdown("##### Admissions per month")
            data = compute_analytics()
            st.line_chart(pd.DataFrame(data["months"]).set_index("label")["value"])
        else:
            st.caption("Your role does not include analytics.")
    with right:
        st.markdown("##### Security services")
        try:
            key = svc.kms.describe()
            st.write(f"**Database:** {'Amazon Aurora MySQL' if svc.db.engine == 'mysql' else 'SQLite (stands in for Aurora)'}")
            st.write(f"**Encryption key:** {key.get('alias') or 'KMS key'}")
            st.code(key["key_id"], language=None)
            st.write(f"**Key type:** {key['spec']}")
            st.write(f"**File storage:** {svc.storage.describe()['bucket']}")
        except Exception as exc:
            st.warning(f"Could not read key details: {str(exc)[:100]}")


AGE_BANDS = [("0-14", 0, 14), ("15-29", 15, 29), ("30-44", 30, 44), ("45-59", 45, 59), ("60-74", 60, 74), ("75+", 75, 200)]
MIN_CELL = 5


def compute_analytics():
    rows = svc.db.query(
        "SELECT a.department, a.diagnosis, a.admit_date, a.discharge_date, a.readmission, p.age, p.gender "
        "FROM admissions a JOIN patients p ON p.id = a.patient_id")
    today = dt.date.today()
    months, y, m = [], today.year, today.month
    for _ in range(12):
        months.append(f"{y:04d}-{m:02d}")
        m -= 1
        if m == 0:
            y, m = y - 1, 12
    months.reverse()
    by_month = Counter(r["admit_date"][:7] for r in rows)
    stays = {}
    for r in rows:
        if r["discharge_date"]:
            days = (dt.date.fromisoformat(r["discharge_date"]) - dt.date.fromisoformat(r["admit_date"])).days
            stays.setdefault(r["department"], []).append(days)
    ages = [r["age"] for r in svc.db.query("SELECT age FROM patients")]
    genders = Counter(r["gender"] for r in svc.db.query("SELECT gender FROM patients"))
    total = len(rows)
    bands = []
    for label, lo, hi in AGE_BANDS:
        n = sum(1 for a in ages if lo <= a <= hi)
        bands.append({"label": label, "value": 0 if n < MIN_CELL else n, "hidden": n < MIN_CELL})
    return {
        "months": [{"label": dt.date(int(k[:4]), int(k[5:]), 1).strftime("%b %y"), "value": by_month.get(k, 0)} for k in months],
        "diagnoses": [{"label": k, "value": v} for k, v in Counter(r["diagnosis"] for r in rows).most_common(8) if v >= MIN_CELL],
        "departments": [{"label": k, "value": v} for k, v in Counter(r["department"] for r in rows).most_common() if v >= MIN_CELL],
        "los": [{"label": k, "value": round(sum(v) / len(v), 1)} for k, v in sorted(stays.items()) if len(v) >= MIN_CELL],
        "age_bands": bands,
        "genders": [{"label": k, "value": v} for k, v in genders.items() if v >= MIN_CELL],
        "readmission_rate": round(100 * sum(r["readmission"] for r in rows) / total, 1) if total else 0,
        "admissions": total,
    }


def bar(items, label="label"):
    if not items:
        st.caption("Not enough data to show without exposing individuals.")
        return
    st.bar_chart(pd.DataFrame(items).set_index(label)["value"])


def page_analytics(user):
    if not need(user, "analytics:Read"):
        return
    a = compute_analytics()
    st.info(f"Analytics use de-identified data only. Groups smaller than {MIN_CELL} people are hidden so nobody can be singled out.")
    c1, c2 = st.columns(2)
    c1.metric("Admissions", a["admissions"])
    c2.metric("Readmission rate", f"{a['readmission_rate']}%")
    left, right = st.columns(2)
    with left:
        st.markdown("##### Admissions per month")
        st.line_chart(pd.DataFrame(a["months"]).set_index("label")["value"])
        st.markdown("##### Most common diagnoses")
        bar(a["diagnoses"])
        st.markdown("##### Patients by age group")
        bar(a["age_bands"])
        if any(b["hidden"] for b in a["age_bands"]):
            st.caption("Groups shown as zero were hidden because they had fewer than 5 people.")
    with right:
        st.markdown("##### Admissions by department")
        bar(a["departments"])
        st.markdown("##### Average stay by department (days)")
        bar(a["los"])
        st.markdown("##### Patients by gender")
        bar(a["genders"])


def phi_of(row):
    return svc.vault.decrypt_json(row["phi_enc"], {"mrn": row["mrn"], "table": "patients"})


def page_patients(user):
    if not need(user, "patients:ReadFull", "patients:ReadPartial", "patients:ListDeidentified"):
        return
    level = iam.patient_view_level(user["role"])
    st.info({"full": "Full access: names, IDs and notes are decrypted when you open a record. Each open is logged.",
             "partial": "Partial access: you can see names and masked ID numbers. Notes and contact details stay hidden.",
             "deidentified": "De-identified view: names and IDs are not decrypted for your role."}[level])
    c1, c2 = st.columns([3, 1])
    q = c1.text_input("Search by MRN, city or gender").strip()[:40]
    page = int(c2.number_input("Page", min_value=1, value=1, step=1))
    size = 15
    where, params = "", []
    if q:
        where, params = "WHERE mrn LIKE ? OR city LIKE ? OR gender LIKE ?", [f"%{q}%"] * 3
    total = svc.db.one(f"SELECT COUNT(*) AS n FROM patients {where}", params)["n"]
    pages = max(1, -(-total // size))
    rows = svc.db.query(
        f"SELECT mrn, phi_enc, age, gender, blood_group, city, created_at FROM patients {where} "
        "ORDER BY id DESC LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
    table, decrypted = [], 0
    for r in rows:
        item = {"MRN": r["mrn"]}
        if level in ("full", "partial"):
            try:
                item["Name"] = phi_of(r)["name"]
                decrypted += 1
            except Exception:
                item["Name"] = "Unreadable"
        item.update({"Age": r["age"], "Gender": r["gender"], "Blood": r["blood_group"] or "",
                     "City": r["city"] or "", "Registered": r["created_at"][:10]})
        table.append(item)
    sig = (q, page, user["username"])
    if st.session_state.get("pt_sig") != sig:
        st.session_state["pt_sig"] = sig
        log(user, "rds-data:ExecuteStatement", "patients", detail=f"Listed {len(rows)} patients ({level} view)")
        if decrypted:
            log(user, "kms:Decrypt", "patients", detail=f"Unwrapped {decrypted} data keys")
    st.caption(f"Page {min(page, pages)} of {pages} · {total} patients")
    if table:
        st.dataframe(pd.DataFrame(table), hide_index=True)
    else:
        st.write("No patients match your search.")

    if level in ("full", "partial") and rows:
        st.markdown("##### Open a record")
        mrn = st.selectbox("Patient MRN", [""] + [r["mrn"] for r in rows], key="open_mrn")
        if mrn:
            show_patient(user, mrn, level)

    if allowed(user, "patients:Create"):
        with st.expander("Register a new patient"):
            register_patient(user)


def show_patient(user, mrn, level):
    row = svc.db.one("SELECT * FROM patients WHERE mrn = ?", (mrn,))
    if not row:
        st.error("Patient not found.")
        return
    try:
        phi = phi_of(row)
    except Exception:
        log(user, "kms:Decrypt", mrn, "Failure", "Data key could not be unwrapped")
        st.error("This record could not be decrypted.")
        return
    sig = ("open", mrn, user["username"])
    if st.session_state.get("open_sig") != sig:
        st.session_state["open_sig"] = sig
        log(user, "rds-data:ExecuteStatement", mrn, detail="Opened patient record")
        log(user, "kms:Decrypt", mrn, detail=f"Unwrapped data key ({level} view)")
    st.markdown(f"### {phi['name']}")
    facts = {"MRN": mrn, "National ID": phi["national_id"] if level == "full" else mask_id(phi["national_id"]),
             "Age / gender": f"{row['age']}, {row['gender']}", "Blood group": row["blood_group"] or "Unknown",
             "City": row["city"] or ""}
    if level == "full":
        facts.update({"Phone": phi["phone"], "Address": phi["address"], "Notes": phi["notes"]})
    facts["Files in S3"] = svc.db.one("SELECT COUNT(*) AS n FROM documents WHERE mrn = ?", (mrn,))["n"]
    facts["Data key"] = svc.vault.key_id_of(row["phi_enc"])
    st.table(pd.DataFrame({"Value": [str(v) for v in facts.values()]}, index=list(facts.keys())))
    adms = svc.db.query(
        "SELECT department, diagnosis, admit_date, discharge_date, outcome FROM admissions "
        "WHERE patient_id = ? ORDER BY admit_date DESC", (row["id"],))
    st.markdown("**Admissions**")
    st.dataframe(pd.DataFrame(adms).rename(columns=str.title), hide_index=True)


def register_patient(user):
    with st.form("new_patient", clear_on_submit=True):
        name = st.text_input("Full name", max_chars=80)
        c1, c2, c3 = st.columns(3)
        age = c1.number_input("Age", min_value=0, max_value=120, value=30, step=1)
        gender = c2.selectbox("Gender", ["Female", "Male", "Other"])
        blood = c3.selectbox("Blood group", [""] + seed.BLOOD, format_func=lambda v: v or "Unknown")
        c4, c5 = st.columns(2)
        city = c4.text_input("City", max_chars=64)
        national_id = c5.text_input("National ID number", max_chars=20)
        phone = st.text_input("Phone", max_chars=20)
        address = st.text_input("Address", max_chars=200)
        notes = st.text_area("Clinical notes", max_chars=1000)
        go = st.form_submit_button("Encrypt and save")
    if not go:
        return
    name = " ".join(name.split())
    if not 2 <= len(name) <= 80:
        st.error("Enter the patient's full name (2 to 80 characters).")
        return
    phi = {"name": name, "national_id": re.sub(r"[^\d-]", "", national_id)[:20],
           "phone": re.sub(r"[^\d+ -]", "", phone)[:20], "address": address[:200], "notes": notes[:1000]}
    for _ in range(10):
        mrn = f"MV-{100000 + uuid.uuid4().int % 900000}"
        if not svc.db.one("SELECT id FROM patients WHERE mrn = ?", (mrn,)):
            break
    token = svc.vault.encrypt_json(phi, {"mrn": mrn, "table": "patients"})
    svc.db.execute(
        "INSERT INTO patients (mrn, phi_enc, age, gender, blood_group, city, created_at, created_by) VALUES (?,?,?,?,?,?,?,?)",
        (mrn, token, int(age), gender, blood or None, city[:64], utcnow(), user["username"]))
    log(user, "kms:GenerateDataKey", mrn, detail="New data key for patient record")
    log(user, "rds-data:ExecuteStatement", mrn, detail="Inserted encrypted patient record")
    st.session_state["pt_sig"] = None
    st.success(f"Saved and encrypted as {mrn}")


ALLOWED_EXT = {"pdf", "png", "jpg", "jpeg", "txt", "csv"}


def page_files(user):
    if not need(user, "documents:Upload", "documents:Download"):
        return
    if allowed(user, "documents:Upload"):
        st.markdown("##### Upload a file")
        st.caption("PDF, PNG, JPG, TXT or CSV up to 5 MB. Each file is encrypted with its own data key before it reaches S3.")
        with st.form("upload_form", clear_on_submit=True):
            mrn = st.text_input("Patient MRN", placeholder="MV-100000").strip()
            up = st.file_uploader("File")
            go = st.form_submit_button("Encrypt and upload")
        if go:
            upload_file(user, mrn, up)
    st.markdown("##### Stored files")
    filt = st.text_input("Filter by patient MRN", key="doc_filter").strip()[:32]
    if filt:
        docs = svc.db.query("SELECT * FROM documents WHERE mrn = ? ORDER BY id DESC LIMIT 100", (filt,))
    else:
        docs = svc.db.query("SELECT * FROM documents ORDER BY id DESC LIMIT 100")
    if not docs:
        st.write("No files yet.")
        return
    st.dataframe(pd.DataFrame([{"File": d["filename"], "Patient": d["mrn"], "Size (KB)": max(1, round(d["size_bytes"] / 1024)),
                                "Uploaded": fmt_time(d["uploaded_at"]), "By": d["uploaded_by"], "S3 key": d["s3_key"]} for d in docs]),
                 hide_index=True)
    if not allowed(user, "documents:Download"):
        st.caption("Your role can upload files but not download them.")
        return
    labels = {d["id"]: f"{d['filename']} ({d['mrn']})" for d in docs}
    pick = st.selectbox("Choose a file to download", list(labels), format_func=lambda i: labels[i])
    if st.button("Decrypt and prepare download"):
        doc = next(d for d in docs if d["id"] == pick)
        try:
            token = svc.storage.get(doc["s3_key"]).decode()
            data = svc.vault.decrypt(token, {"mrn": doc["mrn"], "s3_key": doc["s3_key"]})
        except Exception:
            log(user, "kms:Decrypt", doc["s3_key"], "Failure", "Could not decrypt object")
            st.error("This file could not be decrypted.")
            return
        if hashlib.sha256(data).hexdigest() != doc["sha256"]:
            log(user, "s3:GetObject", doc["s3_key"], "Failure", "Checksum mismatch")
            st.error("File failed its integrity check.")
            return
        log(user, "s3:GetObject", doc["s3_key"], detail="Downloaded file")
        log(user, "kms:Decrypt", doc["s3_key"], detail="Unwrapped data key for file")
        st.session_state["dl"] = (pick, doc["filename"], data)
    dl = st.session_state.get("dl")
    if dl and dl[0] == pick:
        st.download_button(f"Download {dl[1]}", data=dl[2], file_name=dl[1])


def upload_file(user, mrn, up):
    if not svc.db.one("SELECT id FROM patients WHERE mrn = ?", (mrn,)):
        st.error("Enter a valid patient MRN, for example MV-100000.")
        return
    if up is None:
        st.error("Choose a file to upload.")
        return
    filename = secure_filename(up.name)
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXT:
        st.error("Allowed file types: " + ", ".join(sorted(ALLOWED_EXT)) + ".")
        return
    data = up.getvalue()
    if not data:
        st.error("That file is empty.")
        return
    if len(data) > config.MAX_UPLOAD_MB * 1024 * 1024:
        st.error(f"File is larger than {config.MAX_UPLOAD_MB} MB.")
        return
    key = f"patients/{mrn}/{uuid.uuid4().hex[:8]}-{filename}"
    token = svc.vault.encrypt(data, {"mrn": mrn, "s3_key": key})
    svc.storage.put(key, token.encode(), svc.kms.key_id)
    svc.db.execute(
        "INSERT INTO documents (mrn, filename, s3_key, size_bytes, content_type, key_id, sha256, uploaded_by, uploaded_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (mrn, filename, key, len(data), up.type or "", svc.vault.key_id_of(token), hashlib.sha256(data).hexdigest(),
         user["username"], utcnow()))
    log(user, "kms:GenerateDataKey", mrn, detail="New data key for uploaded file")
    log(user, "s3:PutObject", key, detail=f"Stored {len(data)} bytes encrypted")
    st.success("File encrypted and stored.")


def page_access(user):
    if not need(user, "iam:Read"):
        return
    roles = list(iam.ROLES.items())
    st.markdown("##### Permissions by role")
    st.caption("Allow means the role holds the permission. Deny is an explicit deny and beats any allow.")
    matrix = {}
    for action, desc in iam.ACTIONS.items():
        matrix[f"{desc} ({action})"] = [("Deny" if action in spec["deny"] else "Allow" if action in spec["allow"] else "-")
                                        for _, spec in roles]
    st.dataframe(pd.DataFrame(matrix, index=[spec["label"] for _, spec in roles]).T)
    st.markdown("##### IAM policies")
    st.caption("The policy each role would carry in AWS.")
    for rid, spec in roles:
        with st.expander(spec["label"]):
            st.write(spec["summary"])
            st.json(iam.aws_policy(rid, svc.kms.key_id))
    st.markdown("##### Users")
    users = svc.db.query("SELECT username, full_name, role, mfa_enabled, last_login FROM users ORDER BY id")
    st.dataframe(pd.DataFrame([{"Username": u["username"], "Name": u["full_name"], "Role": iam.ROLES.get(u["role"], {}).get("label", u["role"]),
                                "MFA": "On" if u["mfa_enabled"] else "Off", "Last sign-in": fmt_time(u["last_login"]) or "Never"}
                               for u in users]), hide_index=True)
    if allowed(user, "iam:Manage"):
        st.markdown("##### Assign a role")
        others = [u["username"] for u in users if u["username"] != user["username"]]
        with st.form("assign_role"):
            target = st.selectbox("User", others)
            role_id = st.selectbox("Role", list(iam.ROLES), format_func=lambda r: iam.ROLES[r]["label"])
            go = st.form_submit_button("Save role")
        if go and target:
            old = svc.db.one("SELECT role FROM users WHERE username = ?", (target,))
            svc.db.execute("UPDATE users SET role = ? WHERE username = ?", (role_id, target))
            log(user, "iam:UpdateUser", target, detail=f"Role changed from {old['role'] if old else '?'} to {role_id}")
            st.success(f"{target} is now {iam.ROLES[role_id]['label']}. It applies on their next page load.")
        st.caption("You cannot change your own role.")


def page_compliance(user):
    if not need(user, "compliance:Read"):
        return
    results, score = svc.compliance.evaluate()
    manage = allowed(user, "compliance:Manage")
    top, mid = st.columns([1, 3])
    top.metric("Compliance score", f"{score}%")
    with mid:
        st.write("All rules pass." if score == 100 else "Some rules need attention.")
        st.caption(f"Last evaluated: {fmt_time(svc.compliance.last_evaluated) or 'on startup'}")
        if manage and st.button("Re-evaluate all rules"):
            svc.compliance.start_evaluation()
            log(user, "config:StartConfigRulesEvaluation", "all rules", detail="Re-evaluated all rules")
            st.rerun()
    if manage and config.MODE == "demo":
        st.info("Demo controls: turn a setting off to simulate a misconfiguration, watch the rule fail, then apply the fix. Every change is logged.")
    st.markdown("##### AWS Config rules")
    for r in results:
        bad = r["status"] == "NON_COMPLIANT"
        kind = "ok" if r["status"] == "COMPLIANT" else "bad" if bad else "mute"
        with st.container(border=True):
            a, b = st.columns([4, 1])
            a.markdown(f"**{r['title']}**  \n{r['service']} · `{r['id']}`  \n{r['detail']}" + (f". {r['fix']}" if bad else ""))
            b.markdown(pill(r["status"].replace("_", " ").lower(), kind), unsafe_allow_html=True)
            if manage and config.MODE == "demo":
                c1, c2, _ = st.columns([1.3, 1, 3])
                if r["state"]:
                    on = svc.db.get_state(r["state"]) == "1"
                    if c1.button("Simulate drift: turn off" if on else "Turn on", key=f"tg_{r['id']}"):
                        svc.compliance.toggle(r["state"])
                        log(user, "config:PutConfigRule", r["state"], detail=f"Setting changed to {'off' if on else 'on'} (demo drift)")
                        svc.compliance.last_evaluated = utcnow()
                        st.rerun()
                if bad and c2.button("Apply fix", key=f"fx_{r['id']}"):
                    svc.compliance.remediate(r["id"])
                    log(user, "config:StartRemediationExecution", r["id"], detail="Applied fix")
                    svc.compliance.last_evaluated = utcnow()
                    st.rerun()


def page_audit(user):
    if not need(user, "audit:Read"):
        return
    c1, c2, c3 = st.columns([3, 1.2, 1])
    q = c1.text_input("Search user, event or resource").strip()[:60]
    outcome = c2.selectbox("Outcome", ["", "Success", "Denied", "Failure"], format_func=lambda v: v or "All outcomes")
    limit = int(c3.number_input("Rows", min_value=10, max_value=300, value=100, step=10))
    events = svc.audit.search(q, outcome, limit)
    if not events:
        st.write("No events match.")
        return
    st.dataframe(pd.DataFrame([{"Time (UTC)": fmt_time(e["event_time"]), "Event": e["event_name"], "Source": e["event_source"],
                                "User": e["username"], "Role": e["role"], "Resource": e["resource"], "Outcome": e["outcome"],
                                "Details": e["detail"] or ""} for e in events]), hide_index=True)


PAGES = [
    ("Overview", [], page_overview),
    ("Analytics", ["analytics:Read"], page_analytics),
    ("Patients", ["patients:ReadFull", "patients:ReadPartial", "patients:ListDeidentified"], page_patients),
    ("Files in S3", ["documents:Upload", "documents:Download"], page_files),
    ("Access (IAM)", ["iam:Read"], page_access),
    ("Compliance (Config)", ["compliance:Read"], page_compliance),
    ("Audit trail (CloudTrail)", ["audit:Read"], page_audit),
]


# --------------------------------------------------------------------------- main
def main():
    user = current_user()
    if not user:
        st.markdown("# 🔐 MediVault")
        tab_home, tab_in, tab_new = st.tabs(["Home", "Sign in", "Create account"])
        with tab_home:
            page_home()
        with tab_in:
            page_login()
        with tab_new:
            page_register()
        return
    with st.sidebar:
        st.markdown("## 🔐 MediVault")
        st.write(f"**{user['full_name']}**")
        st.caption(iam.ROLES[user["role"]]["label"])
        visible = [p for p in PAGES if not p[1] or any(allowed(user, a) for a in p[1])]
        choice = st.radio("Go to", [p[0] for p in visible], label_visibility="collapsed")
        st.divider()
        if st.button("Sign out"):
            svc.audit.log("signin:ConsoleLogout", user["username"], user["role"], "streamlit", "", "Success", "Signed out")
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()
    st.title(choice)
    dict((p[0], p[2]) for p in visible)[choice](user)


main()
