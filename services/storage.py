"""Object storage. LocalS3 writes to ./data/s3/<bucket>/; AwsS3 uses boto3 with SSE-KMS."""
from pathlib import Path


class LocalS3:
    def __init__(self, data_dir, bucket):
        self.bucket = bucket
        self.root = (data_dir / "s3" / bucket).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if self.root not in path.parents:
            raise ValueError("invalid object key")
        return path

    def put(self, key: str, body: bytes, kms_key_id: str):
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def describe(self):
        return {"bucket": self.bucket, "encryption": "AES-256-GCM envelope (simulated SSE-KMS)",
                "location": str(self.root)}


class AwsS3:
    def __init__(self, bucket, region):
        import boto3
        self.bucket = bucket
        self.client = boto3.client("s3", region_name=region)

    def put(self, key: str, body: bytes, kms_key_id: str):
        self.client.put_object(Bucket=self.bucket, Key=key, Body=body,
                               ServerSideEncryption="aws:kms", SSEKMSKeyId=kms_key_id)

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def describe(self):
        return {"bucket": self.bucket, "encryption": "SSE-KMS + client-side envelope", "location": "Amazon S3"}
