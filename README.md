# MediVault: secure healthcare data management and analytics on AWS

A working class project with a landing page, a role-based dashboard, and the AWS
architecture behind it: **Aurora, S3, KMS, IAM, AWS Config and CloudTrail**.

## Run it (2 minutes, no AWS account needed)

1. Install Python 3.10 or newer (python.org). On Windows tick "Add Python to PATH".
2. Unzip this folder.
3. Windows: double-click `run.bat`. Mac/Linux: run `./run.sh`.
4. Your browser opens at http://127.0.0.1:5000

Manual way: `pip install -r requirements.txt` then `python app.py`.

The first start creates `data/` with a demo database of 220 synthetic patients, a local KMS key,
and a local S3 folder. Delete `data/` to reset everything.

## Demo accounts (password for all: `Demo@2026`)

| Username | Role | What to try |
|---|---|---|
| dr.mehta | Doctor | Open a patient, see full details, upload and download a file |
| nurse.das | Nurse | Register a patient, see masked ID, notes hidden, upload only |
| analyst.nair | Data analyst | De-identified patient rows and analytics only |
| auditor.iqbal | Compliance auditor | Audit trail and Config results, no patient data |
| admin.kapoor | Administrator | Compliance controls, IAM view. Denied from decrypting data |

## Create a new account

The sign-in page has a **Create a new account** link. Anyone can register with a name, username and
password. New accounts get the "New user" role, which cannot see any patient data. Sign in as
`admin.kapoor`, open **Access (IAM)**, and pick a role for the new user in the Users table.

## Five-minute demo script for your presentation

1. Landing page: type a patient detail into the encryption box. Point out that the same text gives a new ciphertext every time (new KMS data key).
2. Sign in as the **doctor**. Open a patient. Upload a report, then download it.
3. Sign out. Sign in as the **admin** and try Patients: names are hidden. Open Audit trail: your attempts appear, and `iam:AccessDenied` shows the denials.
4. As admin open **Compliance**. One rule fails (an analyst has no MFA). Click **Apply fix**: score goes to 100%.
5. Click **Simulate drift: turn off** on key rotation. The rule fails. This is what AWS Config catches in real life.
6. Open **Access (IAM)** and show the policies. The admin role has an explicit Deny on `kms:Decrypt`.

## How each AWS service is used

| Service | In demo mode | In AWS mode |
|---|---|---|
| KMS | `services/kms.py` LocalKMS issues data keys with an EncryptionContext | Real `GenerateDataKey` / `Decrypt` on your customer managed key |
| S3 | Files saved under `data/s3/` as ciphertext | `put_object` with SSE-KMS plus client-side envelope encryption |
| Aurora | SQLite file with the same schema | Aurora MySQL through PyMySQL (credentials from Secrets Manager) |
| IAM | App-level roles in `services/iam.py` | Role policies in `infra/template.yaml`, MFA required to assume |
| Config | Seven rules evaluated against platform settings | Real managed rules, results read with `describe_compliance_by_config_rule` |
| CloudTrail | Audit table written on every action | Real trail in the template, events read with `lookup_events` |

Encryption design: **envelope encryption**. For each record, KMS creates a fresh 256-bit data key.
The record's sensitive fields are encrypted with AES-256-GCM using that key, and only the
KMS-encrypted copy of the key is stored. The EncryptionContext (patient MRN) is bound to the
ciphertext, so a record copied onto another patient will not decrypt.

## Security features in the code

- Field-level encryption of name, ID number, phone, address and notes
- Role-based access control with explicit deny, enforced on every API route
- Per-role data views: full, partial (masked ID), de-identified
- Small-group suppression in analytics (groups under 5 are hidden)
- Audit log of sign-ins, decrypts, uploads, downloads and denied requests
- Self-service sign-up with password rules and rate limit; new users get a no-access role until an administrator assigns one
- Password hashing, account lockout after 5 failed sign-ins, 30-minute sessions
- CSRF tokens, HttpOnly session cookies, strict Content-Security-Policy
- File type allow-list, 5 MB limit, SHA-256 integrity check on download

## Honest limits (mention these in your report)

- Demo mode simulates AWS locally. It shows the design, not real AWS isolation.
- The MFA flag in demo mode is a stored setting, not a one-time-code check. Real MFA is enforced by IAM in AWS mode.
- Demo credentials are printed on the sign-in page on purpose. Never do that in production.
- This is a learning project, not a certified HIPAA system. All data is synthetic.

## Running against real AWS (optional)

See `docs/AWS_DEPLOYMENT.md`. Short version: deploy `infra/template.yaml`, then set
`MEDIVAULT_MODE=aws` and the values from the stack outputs. The template and the AWS-mode code
were written carefully but could not be run against a live account while building this zip,
so expect to fix small issues the first time you deploy.

## Project layout

```
app.py            Flask routes, auth, CSRF, security headers
config.py         Settings (environment variables)
seed.py           Demo users and synthetic hospital data
services/         kms, crypto (envelope), storage (S3), db (Aurora), iam, audit, compliance
templates/        landing, login, dashboard
static/           CSS and JavaScript (charts are plain SVG, no libraries)
infra/template.yaml   CloudFormation for the real AWS resources
docs/             Architecture and deployment guides
```
