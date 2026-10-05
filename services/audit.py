"""CloudTrail-style audit trail. Every access decision is recorded here.

In AWS mode the same actions also appear in real CloudTrail; lookup_cloudtrail()
reads those events so the dashboard can show both side by side.
"""
import datetime as dt

import config

SOURCES = {
    "kms": "kms.amazonaws.com", "s3": "s3.amazonaws.com", "rds-data": "rds-data.amazonaws.com",
    "iam": "iam.amazonaws.com", "config": "config.amazonaws.com", "signin": "signin.amazonaws.com",
    "app": "medivault.app",
}


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class AuditService:
    def __init__(self, db):
        self.db = db

    def log(self, event_name, username="anonymous", role="-", source_ip="", resource="",
            outcome="Success", detail="", when=None):
        prefix = event_name.split(":")[0].lower() if ":" in event_name else "app"
        source = SOURCES.get(prefix, SOURCES["app"])
        self.db.execute(
            "INSERT INTO audit_log (event_time, event_name, event_source, username, role, source_ip,"
            " resource, outcome, detail) VALUES (?,?,?,?,?,?,?,?,?)",
            (when or utcnow(), event_name, source, username, role, source_ip, resource, outcome, detail),
        )

    def search(self, q="", outcome="", limit=100):
        sql = "SELECT * FROM audit_log WHERE 1=1"
        params = []
        if q:
            like = f"%{q}%"
            sql += " AND (event_name LIKE ? OR username LIKE ? OR resource LIKE ? OR detail LIKE ?)"
            params += [like, like, like, like]
        if outcome in ("Success", "Denied", "Failure"):
            sql += " AND outcome = ?"
            params.append(outcome)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(int(limit))
        return self.db.query(sql, params)

    def recent_failed_logins(self, username, minutes=10):
        rows = self.db.query(
            "SELECT event_time FROM audit_log WHERE event_name = 'signin:ConsoleLogin' AND outcome = 'Failure'"
            " AND username = ? ORDER BY id DESC LIMIT 10", (username,))
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=minutes)
        count = 0
        for r in rows:
            t = dt.datetime.strptime(r["event_time"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
            if t >= cutoff:
                count += 1
        return count

    @staticmethod
    def cloudtrail_available():
        return config.MODE == "aws"

    @staticmethod
    def lookup_cloudtrail(limit=50):
        import boto3
        client = boto3.client("cloudtrail", region_name=config.AWS_REGION)
        events = client.lookup_events(MaxResults=min(int(limit), 50)).get("Events", [])
        return [{
            "event_time": e["EventTime"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_name": e.get("EventName", ""),
            "event_source": e.get("EventSource", ""),
            "username": e.get("Username", ""),
            "resource": ", ".join(r.get("ResourceName", "") for r in e.get("Resources", [])),
        } for e in events]
