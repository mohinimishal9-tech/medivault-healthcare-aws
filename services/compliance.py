"""AWS Config rule results.

Demo mode evaluates seven rules against the platform's own settings, so toggling a
setting on the Compliance page really flips a rule. AWS mode reads the real
compliance results from AWS Config.
"""
import config

RULES = [
    {"id": "cmk-backing-key-rotation-enabled", "service": "AWS KMS", "state": "kms_rotation",
     "title": "Customer managed key rotates every year",
     "fix": "Turn on automatic key rotation for the KMS key."},
    {"id": "s3-bucket-server-side-encryption-enabled", "service": "Amazon S3", "state": "s3_sse",
     "title": "S3 bucket encrypts every object",
     "fix": "Enable default SSE-KMS encryption on the bucket."},
    {"id": "s3-bucket-public-read-prohibited", "service": "Amazon S3", "state": "s3_block_public",
     "title": "S3 bucket blocks public access",
     "fix": "Turn on S3 Block Public Access."},
    {"id": "s3-bucket-versioning-enabled", "service": "Amazon S3", "state": "s3_versioning",
     "title": "S3 bucket keeps object versions",
     "fix": "Enable versioning on the bucket."},
    {"id": "rds-storage-encrypted", "service": "Amazon Aurora", "state": "rds_encrypted",
     "title": "Aurora cluster storage is encrypted",
     "fix": "Encryption cannot be added later: restore a snapshot copy into an encrypted cluster."},
    {"id": "cloud-trail-enabled", "service": "AWS CloudTrail", "state": "cloudtrail_logging",
     "title": "CloudTrail is logging API activity",
     "fix": "Start logging on the trail."},
    {"id": "iam-user-mfa-enabled", "service": "AWS IAM", "state": None,
     "title": "Every user has multi-factor authentication",
     "fix": "Require MFA for the listed users."},
]
DEFAULT_STATE = {r["state"]: "1" for r in RULES if r["state"]}
TOGGLEABLE = set(DEFAULT_STATE)


class ComplianceService:
    def __init__(self, db):
        self.db = db
        self.last_evaluated = None

    def ensure_defaults(self):
        for key, value in DEFAULT_STATE.items():
            if not self.db.one("SELECT k FROM config_state WHERE k = ?", (key,)):
                self.db.set_state(key, value)

    # -- demo evaluation -----------------------------------------------------
    def _evaluate_local(self):
        results = []
        for rule in RULES:
            if rule["id"] == "iam-user-mfa-enabled":
                bad = [u["username"] for u in self.db.query("SELECT username FROM users WHERE mfa_enabled = 0")]
                ok, detail = not bad, ("All users have MFA" if not bad else "No MFA: " + ", ".join(bad))
            elif rule["id"] == "s3-bucket-server-side-encryption-enabled":
                ok = self.db.get_state("s3_sse") == "1"
                total = self.db.one("SELECT COUNT(*) AS n FROM documents")["n"]
                detail = f"Default encryption on; {total} stored objects" if ok else "Default encryption is off"
            else:
                ok = self.db.get_state(rule["state"]) == "1"
                detail = "Setting is on" if ok else "Setting is off"
            results.append({**rule, "status": "COMPLIANT" if ok else "NON_COMPLIANT", "detail": detail})
        return results

    # -- aws evaluation ------------------------------------------------------
    def _evaluate_aws(self):
        import boto3
        client = boto3.client("config", region_name=config.AWS_REGION)
        found = {}
        for page in client.get_paginator("describe_compliance_by_config_rule").paginate():
            for item in page.get("ComplianceByConfigRules", []):
                name = item["ConfigRuleName"]
                if name.startswith(config.CONFIG_RULE_PREFIX):
                    found[name[len(config.CONFIG_RULE_PREFIX):]] = (name, item["Compliance"]["ComplianceType"])
        results = []
        for rule in RULES:
            name, status = found.get(rule["id"], (None, "INSUFFICIENT_DATA"))
            detail = "Evaluated by AWS Config"
            if status == "NON_COMPLIANT" and name:
                try:
                    d = client.get_compliance_details_by_config_rule(
                        ConfigRuleName=name, ComplianceTypes=["NON_COMPLIANT"], Limit=5)
                    ids = [r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
                           for r in d.get("EvaluationResults", [])]
                    detail = "Non-compliant: " + ", ".join(ids)
                except Exception:  # keep the dashboard alive if details are unavailable
                    pass
            results.append({**rule, "status": status, "detail": detail})
        return results

    def evaluate(self):
        results = self._evaluate_aws() if config.MODE == "aws" else self._evaluate_local()
        scored = [r for r in results if r["status"] in ("COMPLIANT", "NON_COMPLIANT")]
        good = sum(1 for r in scored if r["status"] == "COMPLIANT")
        score = round(100 * good / len(scored)) if scored else 0
        return results, score

    def start_evaluation(self):
        import datetime as dt
        self.last_evaluated = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if config.MODE == "aws":
            import boto3
            client = boto3.client("config", region_name=config.AWS_REGION)
            client.start_config_rules_evaluation(
                ConfigRuleNames=[config.CONFIG_RULE_PREFIX + r["id"] for r in RULES][:25])

    # -- demo-only drift and fix --------------------------------------------
    def toggle(self, state_key):
        if state_key not in TOGGLEABLE:
            raise ValueError("Unknown setting")
        new = "0" if self.db.get_state(state_key) == "1" else "1"
        self.db.set_state(state_key, new)
        return new

    def remediate(self, rule_id):
        rule = next((r for r in RULES if r["id"] == rule_id), None)
        if not rule:
            raise ValueError("Unknown rule")
        if rule_id == "iam-user-mfa-enabled":
            self.db.execute("UPDATE users SET mfa_enabled = 1 WHERE mfa_enabled = 0")
        else:
            self.db.set_state(rule["state"], "1")
