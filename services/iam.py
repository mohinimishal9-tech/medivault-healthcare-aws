"""Role-based access control that mirrors the IAM policies in infra/template.yaml.

Least privilege is the point: the administrator can run the platform but cannot
decrypt patient data, and the auditor can read logs but never patient records.
"""
import copy

import config

ACTIONS = {
    "patients:ReadFull": "See patient names, ID numbers, contact details and notes",
    "patients:ReadPartial": "See patient names and masked ID numbers (no notes)",
    "patients:ListDeidentified": "See patient rows with identity fields removed",
    "patients:Create": "Register new patients",
    "documents:Upload": "Upload reports and scans to S3",
    "documents:Download": "Download and decrypt reports and scans",
    "analytics:Read": "View de-identified analytics",
    "audit:Read": "Read the CloudTrail-style audit log",
    "compliance:Read": "View AWS Config rule results",
    "compliance:Manage": "Re-evaluate rules and apply fixes",
    "iam:Read": "View roles, policies and users",
    "iam:Manage": "Assign roles to users",
    "kms:GenerateDataKey": "Ask KMS for a data key to encrypt new data",
    "kms:Decrypt": "Ask KMS to unwrap a data key to read encrypted data",
}

ROLES = {
    "admin": {
        "label": "Platform administrator",
        "summary": "Runs the platform and its controls. Explicitly denied from decrypting patient data.",
        "allow": ["iam:Read", "iam:Manage", "compliance:Read", "compliance:Manage", "audit:Read",
                  "analytics:Read", "patients:ListDeidentified"],
        "deny": ["kms:Decrypt", "s3:GetObject"],
    },
    "doctor": {
        "label": "Doctor",
        "summary": "Full clinical access to the patients under care.",
        "allow": ["patients:ReadFull", "patients:Create", "documents:Upload", "documents:Download",
                  "analytics:Read", "kms:Decrypt", "kms:GenerateDataKey"],
        "deny": [],
    },
    "nurse": {
        "label": "Nurse",
        "summary": "Registers patients and uploads reports. Sees names but not notes or full ID numbers.",
        "allow": ["patients:ReadPartial", "patients:Create", "documents:Upload",
                  "kms:Decrypt", "kms:GenerateDataKey"],
        "deny": [],
    },
    "analyst": {
        "label": "Data analyst",
        "summary": "Works only with de-identified data and aggregate analytics.",
        "allow": ["analytics:Read", "patients:ListDeidentified"],
        "deny": [],
    },
    "guest": {
        "label": "New user",
        "summary": "Just created an account. No access to data until an administrator assigns a role.",
        "allow": [],
        "deny": ["kms:Decrypt", "s3:GetObject"],
    },
    "auditor": {
        "label": "Compliance auditor",
        "summary": "Reads the audit trail and compliance results. Never touches patient data.",
        "allow": ["audit:Read", "compliance:Read", "iam:Read"],
        "deny": [],
    },
}

# Real IAM statements for each role. Tokens are filled in by aws_policy().
AWS_STATEMENTS = {
    "admin": [
        {"Sid": "RunThePlatform", "Effect": "Allow",
         "Action": ["config:Describe*", "config:StartConfigRulesEvaluation",
                    "cloudtrail:LookupEvents", "iam:Get*", "iam:List*"], "Resource": "*"},
        {"Sid": "NeverReadPatientData", "Effect": "Deny",
         "Action": ["kms:Decrypt", "s3:GetObject", "rds-db:connect"],
         "Resource": ["{KEY_ARN}", "{BUCKET_ARN}/*", "{DB_ARN}"]},
    ],
    "doctor": [
        {"Sid": "UseTheKey", "Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
         "Resource": "{KEY_ARN}"},
        {"Sid": "ReadWriteReports", "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": "{BUCKET_ARN}/patients/*"},
        {"Sid": "ConnectToAurora", "Effect": "Allow", "Action": "rds-db:connect", "Resource": "{DB_ARN}"},
    ],
    "nurse": [
        {"Sid": "UseTheKey", "Effect": "Allow", "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
         "Resource": "{KEY_ARN}"},
        {"Sid": "UploadReportsOnly", "Effect": "Allow", "Action": "s3:PutObject",
         "Resource": "{BUCKET_ARN}/patients/*"},
        {"Sid": "ConnectToAurora", "Effect": "Allow", "Action": "rds-db:connect", "Resource": "{DB_ARN}"},
    ],
    "analyst": [
        {"Sid": "ReadDeidentifiedViews", "Effect": "Allow", "Action": "rds-db:connect", "Resource": "{DB_ARN}"},
    ],
    "guest": [
        {"Sid": "NoDataAccessUntilAssigned", "Effect": "Deny",
         "Action": ["kms:Decrypt", "s3:GetObject", "rds-db:connect"],
         "Resource": ["{KEY_ARN}", "{BUCKET_ARN}/*", "{DB_ARN}"]},
    ],
    "auditor": [
        {"Sid": "ReadTrailAndConfig", "Effect": "Allow",
         "Action": ["cloudtrail:LookupEvents", "config:Describe*", "config:GetComplianceDetailsByConfigRule",
                    "iam:Get*", "iam:List*"], "Resource": "*"},
    ],
}


def can(role: str, action: str) -> bool:
    spec = ROLES.get(role)
    return bool(spec) and action in spec["allow"] and action not in spec["deny"]


def permissions(role: str):
    spec = ROLES.get(role)
    return list(spec["allow"]) if spec else []


def patient_view_level(role: str):
    if can(role, "patients:ReadFull"):
        return "full"
    if can(role, "patients:ReadPartial"):
        return "partial"
    if can(role, "patients:ListDeidentified"):
        return "deidentified"
    return None


def aws_policy(role: str, key_id: str = ""):
    region = config.AWS_REGION
    tokens = {
        "{KEY_ARN}": f"arn:aws:kms:{region}:<account-id>:key/{key_id or '<key-id>'}",
        "{BUCKET_ARN}": f"arn:aws:s3:::{config.S3_BUCKET}",
        "{DB_ARN}": f"arn:aws:rds-db:{region}:<account-id>:dbuser:<cluster-resource-id>/medivault_{role}",
    }

    def fill(value):
        if isinstance(value, str):
            for token, real in tokens.items():
                value = value.replace(token, real)
            return value
        if isinstance(value, list):
            return [fill(v) for v in value]
        return value

    statements = []
    for st in copy.deepcopy(AWS_STATEMENTS[role]):
        statements.append({k: fill(v) for k, v in st.items()})
    return {"Version": "2012-10-17", "Statement": statements}
