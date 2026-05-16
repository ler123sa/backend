"""
Payload encryption / DEK wrapping для GlitchDLC.

Двухуровневая схема:
    1. Payload (jar после grunt+proguard+remap) шифруется один раз случайным DEK
       (Data Encryption Key) — AES-256-GCM, кладётся в Bucket.
    2. На каждый запрос юзера сервер оборачивает DEK в KEK (Key Encryption Key),
       который выводится HKDF из:
          PAYLOAD_MASTER_SECRET + payload_version + user_hwid + launch_token
       и отдаёт лоудеру { url, dek_wrapped, dek_nonce, payload_nonce, payload_tag }.

Что это даёт:
    - На сервере dek хранится только зашифрованным (через master secret).
    - Без валидной сессии (launch_token) и совпадающего HWID dek не разворачивается.
    - Ключи разные для каждого запуска — повторное использование снифа бесполезно.
    - Сам payload в Bucket один и тот же (один раз закодировали), что снимает нагрузку.
"""
from __future__ import annotations

import hmac
import os
import secrets
import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PAYLOAD_MASTER_SECRET = os.getenv(
    "PAYLOAD_MASTER_SECRET",
    "INSECURE_DEV_FALLBACK_change_me_in_production_environment_xxxxxxxxxxxxxx",
).encode()

# AES-GCM настройки
DEK_LEN   = 32   # 256-bit
NONCE_LEN = 12   # 96-bit (стандарт для AES-GCM)


@dataclass
class EncryptedPayload:
    """Результат шифрования jar — то, что заливается в Bucket."""
    ciphertext: bytes        # AES-GCM(plaintext) — содержит auth tag в конце
    nonce: bytes             # 12 байт
    dek: bytes               # 32 байта — НЕ хранится открыто, шифруется master'ом перед DB

    @property
    def size(self) -> int:
        return len(self.ciphertext)


@dataclass
class WrappedDEK:
    """DEK, обёрнутый под HWID+launch_token конкретного запроса (legacy)."""
    wrapped: bytes           # AES-GCM(dek) под KEK
    nonce: bytes             # 12 байт


def encrypt_payload(plaintext: bytes) -> EncryptedPayload:
    """Шифрует jar свежим DEK. Вызывается админом при загрузке payload'а."""
    dek   = secrets.token_bytes(DEK_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct    = AESGCM(dek).encrypt(nonce, plaintext, associated_data=b"glitchdlc-payload-v1")
    return EncryptedPayload(ciphertext=ct, nonce=nonce, dek=dek)


def wrap_dek_for_master(dek: bytes) -> bytes:
    """
    Оборачивает DEK под master-секретом для безопасного хранения в DB.
    Формат: nonce(12) || ciphertext_with_tag.
    """
    kek   = _derive_master_kek()
    nonce = secrets.token_bytes(NONCE_LEN)
    ct    = AESGCM(kek).encrypt(nonce, dek, associated_data=b"glitchdlc-dek-master")
    return nonce + ct


def unwrap_dek_from_master(stored: bytes) -> bytes:
    """Обратная операция к wrap_dek_for_master."""
    if len(stored) < NONCE_LEN + 16:
        raise ValueError("stored dek too short")
    nonce, ct = stored[:NONCE_LEN], stored[NONCE_LEN:]
    kek = _derive_master_kek()
    return AESGCM(kek).decrypt(nonce, ct, associated_data=b"glitchdlc-dek-master")


def wrap_dek_for_session(
    dek: bytes,
    *,
    payload_version: str,
    hwid: str,
    launch_token: str,
) -> WrappedDEK:
    """
    Оборачивает DEK под ключ сессии (KEK = HKDF(master, hwid, launch_token, version)).
    Лоудер сможет развернуть только если у него есть точно те же hwid + launch_token.
    """
    kek   = _derive_session_kek(payload_version, hwid, launch_token)
    nonce = secrets.token_bytes(NONCE_LEN)
    ct    = AESGCM(kek).encrypt(nonce, dek, associated_data=b"glitchdlc-dek-session")
    return WrappedDEK(wrapped=ct, nonce=nonce)


def integrity_signature(*parts: str) -> str:
    """
    HMAC-SHA256 над набором полей — чтобы лоудер мог проверить, что ответ
    /api/launcher/payload не подменили MITM'ом (даже несмотря на TLS).
    Возвращает hex.
    """
    h = hmac.new(PAYLOAD_MASTER_SECRET, digestmod=sha256)
    for p in parts:
        h.update(struct.pack(">I", len(p)))
        h.update(p.encode("utf-8"))
    return h.hexdigest()


# ─── Internal ─────────────────────────────────────────────────────────────────
def _derive_master_kek() -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"glitchdlc-master-v1",
        info=b"dek-wrap",
    ).derive(PAYLOAD_MASTER_SECRET)


def _derive_session_kek(payload_version: str, hwid: str, launch_token: str) -> bytes:
    info = (
        b"glitchdlc-session-v1|"
        + payload_version.encode()
        + b"|"
        + hwid.encode()
        + b"|"
        + launch_token.encode()
    )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"glitchdlc-session-salt-v1",
        info=info,
    ).derive(PAYLOAD_MASTER_SECRET)
