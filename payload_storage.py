"""
S3-совместимый клиент для хранения зашифрованных payload'ов.
Работает с Railway Bucket (по сути MinIO под капотом).
"""
from __future__ import annotations

import os
from typing import Optional

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError


BUCKET_ENDPOINT   = os.getenv("BUCKET_ENDPOINT", "").rstrip("/")
BUCKET_ACCESS_KEY = os.getenv("BUCKET_ACCESS_KEY", "")
BUCKET_SECRET_KEY = os.getenv("BUCKET_SECRET_KEY", "")
# Имя бакета: BUCKET_NAME основной, RAILWAY_BUCKET_NAME — как фоллбэк
# (Railway автоматически инжектит RAILWAY_BUCKET_NAME при добавлении Bucket в проект).
BUCKET_NAME       = os.getenv("BUCKET_NAME") or os.getenv("RAILWAY_BUCKET_NAME") or "glitchdlc-payloads"
BUCKET_REGION     = os.getenv("BUCKET_REGION", "us-east-1")
# Стиль адресации: "path" (https://endpoint/bucket/key) или "virtual" (https://bucket.endpoint/key).
# Railway Bucket (R2/S3-совместимый под капотом) хочет virtual-hosted style.
BUCKET_ADDRESSING = os.getenv("BUCKET_ADDRESSING", "path").lower()

# presigned URL живёт совсем недолго — лоудер должен скачать сразу.
PRESIGN_TTL_SECONDS = 90


def is_configured() -> bool:
    return bool(BUCKET_ENDPOINT and BUCKET_ACCESS_KEY and BUCKET_SECRET_KEY)


def _client():
    if not is_configured():
        raise RuntimeError(
            "Bucket не сконфигурирован. Заполни BUCKET_ENDPOINT / BUCKET_ACCESS_KEY / BUCKET_SECRET_KEY."
        )
    return boto3.client(
        "s3",
        endpoint_url=BUCKET_ENDPOINT,
        aws_access_key_id=BUCKET_ACCESS_KEY,
        aws_secret_access_key=BUCKET_SECRET_KEY,
        region_name=BUCKET_REGION,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "virtual" if BUCKET_ADDRESSING == "virtual" else "path"},
        ),
    )


def ensure_bucket() -> None:
    """Создаёт bucket если его нет (идемпотентно)."""
    if not is_configured():
        # Чтобы в логах было ясно почему payload не работает
        raise RuntimeError(
            "Bucket env vars not set: BUCKET_ENDPOINT / BUCKET_ACCESS_KEY / "
            "BUCKET_SECRET_KEY / BUCKET_NAME"
        )
    s3 = _client()
    try:
        s3.head_bucket(Bucket=BUCKET_NAME)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            try:
                s3.create_bucket(Bucket=BUCKET_NAME)
            except ClientError as ce:
                # Если уже создан конкурентно — игнор.
                if ce.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                    raise
        else:
            raise


def upload_payload(key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
    """Заливает зашифрованный payload в бакет."""
    s3 = _client()
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=key,
        Body=data,
        ContentType=content_type,
        # Никаких ACL public-read — только presigned!
    )


def delete_payload(key: str) -> None:
    if not is_configured():
        return
    try:
        _client().delete_object(Bucket=BUCKET_NAME, Key=key)
    except ClientError:
        pass


def presigned_get(key: str, ttl: int = PRESIGN_TTL_SECONDS) -> str:
    """Генерирует одноразовую ссылку на скачивание (TTL короткий)."""
    return _client().generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": BUCKET_NAME, "Key": key},
        ExpiresIn=ttl,
    )


def object_exists(key: str) -> bool:
    if not is_configured():
        return False
    try:
        _client().head_object(Bucket=BUCKET_NAME, Key=key)
        return True
    except ClientError:
        return False
