"""Builds the service objects the app uses, in demo or aws mode."""
import config
from .audit import AuditService
from .compliance import ComplianceService
from .crypto import Vault
from .db import Database
from .kms import AwsKMS, LocalKMS
from .storage import AwsS3, LocalS3


class Services:
    def __init__(self):
        self.db = Database()
        self.db.init_schema()
        if config.MODE == "aws":
            if not config.KMS_KEY_ID:
                raise SystemExit("Set MEDIVAULT_KMS_KEY_ID for aws mode (see docs/AWS_DEPLOYMENT.md)")
            self.kms = AwsKMS(config.KMS_KEY_ID, config.AWS_REGION)
            self.storage = AwsS3(config.S3_BUCKET, config.AWS_REGION)
        else:
            self.kms = LocalKMS(config.DATA_DIR)
            self.storage = LocalS3(config.DATA_DIR, config.S3_BUCKET)
        self.vault = Vault(self.kms)
        self.audit = AuditService(self.db)
        self.compliance = ComplianceService(self.db)
