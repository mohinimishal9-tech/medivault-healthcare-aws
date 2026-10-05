# Architecture

```
 Browser ──HTTPS──> Flask app (IAM role check on every route)
                        │
        ┌───────────────┼─────────────────────────────┐
        │               │                             │
   Aurora MySQL      S3 bucket                     AWS KMS
   (encrypted        (SSE-KMS, versioned,          (customer managed key,
    storage, ciphertext  blocked from public)       yearly rotation)
    in PHI column)        │                             │
        └───────────────┴──────────── all API calls ──┴──> CloudTrail ──> log bucket
                                                         └> AWS Config rules (7)
```

## Data flow: register a patient
1. Nurse or doctor submits the form. The API checks `patients:Create`.
2. App calls KMS `GenerateDataKey` with EncryptionContext `{mrn, table}`.
3. Name, ID, phone, address and notes are encrypted with AES-256-GCM using the data key.
4. The ciphertext and the encrypted data key are written to the `phi_enc` column in Aurora. Age, gender, city and blood group stay readable for analytics.
5. Audit rows are written: `kms:GenerateDataKey`, `rds-data:ExecuteStatement`.

## Data flow: open a patient
1. API checks the role: full, partial or denied.
2. App reads the row, then calls KMS `Decrypt` to unwrap the data key (CloudTrail records it).
3. Fields are decrypted. Partial roles get a masked ID and no notes.

## Data flow: upload a report
The file is encrypted with its own data key (context `{mrn, s3_key}`), stored in S3 with SSE-KMS,
and its SHA-256 is saved in Aurora. Download re-checks the hash after decryption.

## IAM design
| Role | Decrypt | Read S3 | Notes |
|---|---|---|---|
| Doctor | yes | yes | Full clinical access |
| Nurse | yes | no | Partial view, upload only |
| Analyst | no | no | De-identified rows and analytics |
| Auditor | no | no | CloudTrail and Config read-only |
| Admin | **denied** | **denied** | Separation of duties: runs the platform, cannot read data |

All human roles require MFA to assume (`aws:MultiFactorAuthPresent`).

## AWS Config rules
cmk-backing-key-rotation-enabled, s3-bucket-server-side-encryption-enabled,
s3-bucket-public-read-prohibited, s3-bucket-versioning-enabled, rds-storage-encrypted,
cloud-trail-enabled, iam-user-mfa-enabled.

## Threats addressed
| Threat | Control |
|---|---|
| Database dump stolen | PHI is ciphertext; keys live only in KMS |
| Curious administrator | Explicit deny on decrypt, plus audit log |
| Record swapped between patients | EncryptionContext bound to MRN |
| Public bucket by mistake | Block Public Access, Config rule, TLS-only bucket policy |
| Unnoticed misconfiguration | AWS Config rules and dashboard score |
| Denied or suspicious access | CloudTrail and app audit trail, lockout after 5 failures |
