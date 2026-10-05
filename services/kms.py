"""Key management. LocalKMS mimics AWS KMS; AwsKMS calls the real service.

Both expose the same two operations used for envelope encryption:
  generate_data_key(context) -> (plaintext_key, encrypted_key_blob)
  decrypt_data_key(blob, context) -> plaintext_key

`context` is the KMS EncryptionContext: extra authenticated data that must be
supplied again to decrypt, so a blob copied to another record will not open.
"""
import base64
import datetime as dt
import json
import os
import uuid

from cryptography.fernet import Fernet


class LocalKMS:
    origin = "LOCAL_SIMULATION"

    def __init__(self, data_dir):
        folder = data_dir / "kms"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "cmk.json"
        if not path.exists():
            path.write_text(json.dumps({
                "key_id": str(uuid.uuid4()),
                "alias": "alias/medivault-phi",
                "material": Fernet.generate_key().decode(),
                "created": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        meta = json.loads(path.read_text())
        self.key_id = meta["key_id"]
        self.alias = meta["alias"]
        self.created = meta["created"]
        self._fernet = Fernet(meta["material"].encode())

    def generate_data_key(self, context):
        plaintext = os.urandom(32)
        payload = json.dumps(
            {"k": base64.b64encode(plaintext).decode(), "ctx": context}, sort_keys=True
        ).encode()
        return plaintext, self._fernet.encrypt(payload)

    def decrypt_data_key(self, blob, context):
        data = json.loads(self._fernet.decrypt(blob))
        if data["ctx"] != context:
            raise PermissionError("EncryptionContext does not match")
        return base64.b64decode(data["k"])

    def describe(self):
        return {"key_id": self.key_id, "alias": self.alias, "spec": "SYMMETRIC_DEFAULT (AES-256)",
                "origin": self.origin, "created": self.created}


class AwsKMS:
    origin = "AWS_KMS"

    def __init__(self, key_id, region):
        import boto3
        self.client = boto3.client("kms", region_name=region)
        self.key_id = key_id

    def generate_data_key(self, context):
        r = self.client.generate_data_key(KeyId=self.key_id, KeySpec="AES_256",
                                          EncryptionContext=context)
        return r["Plaintext"], r["CiphertextBlob"]

    def decrypt_data_key(self, blob, context):
        r = self.client.decrypt(CiphertextBlob=blob, KeyId=self.key_id, EncryptionContext=context)
        return r["Plaintext"]

    def describe(self):
        meta = self.client.describe_key(KeyId=self.key_id)["KeyMetadata"]
        return {"key_id": meta["KeyId"], "alias": "", "spec": meta.get("KeySpec", ""),
                "origin": self.origin, "created": meta["CreationDate"].strftime("%Y-%m-%dT%H:%M:%SZ")}
