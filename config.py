"""Central configuration. Everything can be overridden with environment variables.

MEDIVAULT_MODE=demo  (default)  -> runs fully offline. KMS, S3, IAM, Config and
                                   CloudTrail are simulated locally with the same
                                   interfaces the real AWS services use.
MEDIVAULT_MODE=aws              -> uses real AWS (needs boto3, credentials, and the
                                   resources created by infra/template.yaml).
"""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = Path(os.environ.get("MEDIVAULT_DATA", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

MODE = os.environ.get("MEDIVAULT_MODE", "demo").lower()
if MODE not in ("demo", "aws"):
    raise SystemExit("MEDIVAULT_MODE must be 'demo' or 'aws'")

# --- AWS settings (aws mode) -------------------------------------------------
AWS_REGION = os.environ.get("AWS_REGION", "ap-south-1")
KMS_KEY_ID = os.environ.get("MEDIVAULT_KMS_KEY_ID", "")
S3_BUCKET = os.environ.get("MEDIVAULT_S3_BUCKET", "medivault-phi-demo")
CONFIG_RULE_PREFIX = os.environ.get("MEDIVAULT_CONFIG_PREFIX", "medivault-")

# --- Database ----------------------------------------------------------------
# SQLite is used unless DB_HOST is set, in which case Aurora MySQL is used.
DB_HOST = os.environ.get("MEDIVAULT_DB_HOST", "")
DB_PORT = int(os.environ.get("MEDIVAULT_DB_PORT", "3306"))
DB_NAME = os.environ.get("MEDIVAULT_DB_NAME", "medivault")
DB_USER = os.environ.get("MEDIVAULT_DB_USER", "admin")
DB_PASSWORD = os.environ.get("MEDIVAULT_DB_PASSWORD", "")
DB_SECRET_ARN = os.environ.get("MEDIVAULT_DB_SECRET_ARN", "")  # Secrets Manager
DB_ENGINE = "mysql" if DB_HOST else "sqlite"
SQLITE_PATH = DATA_DIR / "medivault.db"

# --- App ---------------------------------------------------------------------
DEMO_PASSWORD = os.environ.get("MEDIVAULT_DEMO_PASSWORD", "Demo@2026")
SESSION_MINUTES = int(os.environ.get("MEDIVAULT_SESSION_MINUTES", "30"))
MAX_UPLOAD_MB = 5


def _secret_key() -> str:
    env = os.environ.get("MEDIVAULT_SECRET_KEY")
    if env:
        return env
    path = DATA_DIR / "secret_key"
    if not path.exists():
        path.write_text(secrets.token_hex(32))
    return path.read_text().strip()


SECRET_KEY = _secret_key()
