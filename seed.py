"""Creates demo users and a synthetic hospital dataset. Safe to run repeatedly."""
import datetime as dt
import random

from werkzeug.security import generate_password_hash

import config

USERS = [
    ("admin.kapoor", "Meera Kapoor", "admin", 1),
    ("dr.mehta", "Dr. Rohan Mehta", "doctor", 1),
    ("nurse.das", "Anita Das", "nurse", 1),
    ("analyst.nair", "Kabir Nair", "analyst", 0),   # no MFA -> one Config finding to fix in the demo
    ("auditor.iqbal", "Sana Iqbal", "auditor", 1),
]

FIRST = ["Asha", "Rahul", "Priya", "Vikram", "Neha", "Arjun", "Sunita", "Manoj", "Deepa", "Imran",
         "Kavya", "Sanjay", "Lakshmi", "Rohit", "Pooja", "Anil", "Meena", "Suresh", "Divya", "Farhan",
         "Ritu", "Harish", "Swati", "Naveen", "Jyoti", "Amit", "Nandini", "Ravi", "Shreya", "Tarun"]
LAST = ["Verma", "Sharma", "Patel", "Reddy", "Nayak", "Das", "Khan", "Singh", "Mishra", "Panda",
        "Iyer", "Joshi", "Behera", "Rao", "Mohanty", "Gupta", "Sahoo", "Pillai", "Mukherjee", "Roy"]
CITIES = ["Bhubaneswar", "Cuttack", "Visakhapatnam", "Kolkata", "Hyderabad", "Pune", "Chennai", "Jaipur"]
BLOOD = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]
BLOOD_W = [22, 3, 30, 3, 28, 3, 8, 1]

DEPARTMENTS = {
    "Cardiology": ["Hypertension", "Coronary artery disease", "Arrhythmia", "Heart failure"],
    "Neurology": ["Migraine", "Epilepsy", "Stroke", "Neuropathy"],
    "Orthopedics": ["Fracture", "Osteoarthritis", "Ligament injury"],
    "Pediatrics": ["Pneumonia", "Gastroenteritis", "Asthma", "Viral fever"],
    "Oncology": ["Breast cancer", "Lymphoma", "Colorectal cancer"],
    "General medicine": ["Type 2 diabetes", "Dengue", "Typhoid", "Anemia"],
    "Emergency": ["Trauma", "Poisoning", "Acute abdomen", "Burns"],
    "Obstetrics": ["Normal delivery", "C-section", "Gestational diabetes"],
}
DEPT_WEIGHT = [14, 9, 11, 13, 6, 22, 15, 10]
NOTES = [
    "Responding well to treatment. Follow-up in two weeks.",
    "Allergic to penicillin. Use alternatives.",
    "Family history of cardiac disease. Lifestyle counselling given.",
    "Discharged with medication plan and diet advice.",
    "Requires physiotherapy three times a week.",
    "Referred for specialist review. Reports pending.",
]


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_users(svc):
    if svc.db.one("SELECT id FROM users LIMIT 1"):
        return
    pw = generate_password_hash(config.DEMO_PASSWORD)
    for username, name, role, mfa in USERS:
        svc.db.execute(
            "INSERT INTO users (username, full_name, role, pw_hash, mfa_enabled) VALUES (?,?,?,?,?)",
            (username, name, role, pw, mfa))
    svc.compliance.ensure_defaults()


def seed_patients(svc, count=220):
    if svc.db.one("SELECT id FROM patients LIMIT 1"):
        return
    rng = random.Random(42)
    today = dt.date.today()
    depts = list(DEPARTMENTS)
    for i in range(count):
        mrn = f"MV-{100000 + i * 7 + rng.randint(0, 6)}"
        dept = rng.choices(depts, DEPT_WEIGHT)[0]
        if dept == "Pediatrics":
            age = rng.randint(1, 14)
        elif dept == "Obstetrics":
            age = rng.randint(20, 38)
        else:
            age = min(88, max(18, int(rng.gauss(50, 18))))
        gender = "Female" if dept == "Obstetrics" else rng.choice(["Female", "Male"])
        phi = {
            "name": f"{rng.choice(FIRST)} {rng.choice(LAST)}",
            "national_id": "".join(str(rng.randint(0, 9)) for _ in range(12)),
            "phone": "+91 9" + "".join(str(rng.randint(0, 9)) for _ in range(9)),
            "address": f"{rng.randint(1, 240)}, Sector {rng.randint(1, 20)}, {rng.choice(CITIES)}",
            "notes": rng.choice(NOTES),
        }
        created = today - dt.timedelta(days=rng.randint(0, 360))
        token = svc.vault.encrypt_json(phi, {"mrn": mrn, "table": "patients"})
        pid = svc.db.execute(
            "INSERT INTO patients (mrn, phi_enc, age, gender, blood_group, city, created_at, created_by)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (mrn, token, age, gender, rng.choices(BLOOD, BLOOD_W)[0], rng.choice(CITIES),
             _iso(dt.datetime.combine(created, dt.time(9, 30))), "dr.mehta"))
        for _ in range(rng.choices([1, 2, 3], [60, 30, 10])[0]):
            adm_dept = dept if rng.random() < 0.8 else rng.choice(depts)
            admit = today - dt.timedelta(days=rng.randint(0, 360))
            stay = rng.randint(1, 12)
            discharge = admit + dt.timedelta(days=stay)
            ongoing = discharge >= today
            svc.db.execute(
                "INSERT INTO admissions (patient_id, department, diagnosis, admit_date, discharge_date,"
                " outcome, readmission) VALUES (?,?,?,?,?,?,?)",
                (pid, adm_dept, rng.choice(DEPARTMENTS[adm_dept]), admit.isoformat(),
                 None if ongoing else discharge.isoformat(),
                 "Under observation" if ongoing else rng.choices(["Recovered", "Referred"], [88, 12])[0],
                 1 if rng.random() < 0.08 else 0))


def seed_audit_history(svc):
    if svc.db.one("SELECT id FROM audit_log LIMIT 1"):
        return
    rng = random.Random(7)
    now = dt.datetime.now(dt.timezone.utc)
    people = [("dr.mehta", "doctor"), ("nurse.das", "nurse"), ("analyst.nair", "analyst"),
              ("admin.kapoor", "admin"), ("auditor.iqbal", "auditor")]
    events = []
    for _ in range(260):
        when = now - dt.timedelta(minutes=rng.randint(5, 60 * 24 * 6))
        user, role = rng.choice(people)
        events.append((when, user, role, "signin:ConsoleLogin", "-", "Success", "Signed in"))
        if role in ("doctor", "nurse"):
            mrn = f"MV-{100000 + rng.randint(0, 220) * 7}"
            events.append((when + dt.timedelta(seconds=20), user, role, "rds-data:ExecuteStatement",
                           "patients", "Success", "Looked up patient records"))
            events.append((when + dt.timedelta(seconds=21), user, role, "kms:Decrypt",
                           mrn, "Success", "Unwrapped data key for 1 record"))
            if role == "doctor" and rng.random() < 0.4:
                events.append((when + dt.timedelta(seconds=60), user, role, "s3:GetObject",
                               f"patients/{mrn}/report.pdf", "Success", "Downloaded report"))
    for _ in range(9):
        when = now - dt.timedelta(minutes=rng.randint(30, 60 * 24 * 5))
        user, role = rng.choice([("analyst.nair", "analyst"), ("admin.kapoor", "admin"),
                                 ("nurse.das", "nurse"), ("auditor.iqbal", "auditor")])
        denied = rng.choice(["kms:Decrypt", "s3:GetObject", "patients:ReadFull"])
        events.append((when, user, role, "iam:AccessDenied", denied, "Denied",
                       f"Role {role} is not allowed to perform {denied}"))
    events.append((now - dt.timedelta(hours=30), "unknown", "-", "signin:ConsoleLogin", "-", "Failure",
                   "Bad password"))
    events.sort(key=lambda e: e[0])
    for when, user, role, name, resource, outcome, detail in events:
        svc.audit.log(name, user, role, "10.0.%d.%d" % (rng.randint(0, 5), rng.randint(2, 250)),
                      resource, outcome, detail, when=_iso(when))


def seed_all(svc):
    seed_users(svc)
    seed_patients(svc)
    seed_audit_history(svc)
    svc.compliance.ensure_defaults()
