"""Envelope encryption on top of KMS.

1. Ask KMS for a fresh 256-bit data key (plaintext + encrypted copy).
2. Encrypt the data locally with AES-256-GCM, binding the EncryptionContext as AAD.
3. Store the ciphertext together with the *encrypted* data key. The plaintext key is dropped.
To decrypt, KMS must unwrap the data key first, which is where IAM and CloudTrail step in.
"""
import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _aad(context: dict) -> bytes:
    return json.dumps(context, sort_keys=True).encode()


class Vault:
    def __init__(self, kms):
        self.kms = kms

    def encrypt(self, plaintext: bytes, context: dict) -> str:
        data_key, wrapped = self.kms.generate_data_key(context)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, _aad(context))
        return json.dumps({
            "v": 1, "kid": self.kms.key_id, "edk": _b64(wrapped),
            "n": _b64(nonce), "ct": _b64(ciphertext),
        })

    def decrypt(self, token: str, context: dict) -> bytes:
        env = json.loads(token)
        data_key = self.kms.decrypt_data_key(base64.b64decode(env["edk"]), context)
        return AESGCM(data_key).decrypt(
            base64.b64decode(env["n"]), base64.b64decode(env["ct"]), _aad(context)
        )

    def encrypt_json(self, obj: dict, context: dict) -> str:
        return self.encrypt(json.dumps(obj).encode(), context)

    def decrypt_json(self, token: str, context: dict) -> dict:
        return json.loads(self.decrypt(token, context))

    @staticmethod
    def key_id_of(token: str) -> str:
        return json.loads(token)["kid"]
