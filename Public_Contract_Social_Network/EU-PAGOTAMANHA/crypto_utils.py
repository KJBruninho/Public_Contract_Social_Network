from __future__ import annotations

import base64
import hashlib
import hmac
import os
from datetime import datetime
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CipherName = Literal["AES-256-CBC", "AES-256-CTR"]
HmacName = Literal["HMAC-SHA256", "HMAC-SHA512"]


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def generate_rsa_keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def derive_key(password: str, salt: bytes, length: int = 32, iterations: int = 250_000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(private_pem: str, password: str) -> dict[str, str]:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(private_pem.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return {
        "encrypted_private_key": b64e(enc),
        "private_key_salt": b64e(salt),
        "private_key_iv": b64e(iv),
        "private_key_algorithm": "AES-256-CBC",
    }


def decrypt_private_key(encrypted_private_key: str, password: str, salt_b64: str, iv_b64: str) -> str:
    key = derive_key(password, b64d(salt_b64))
    cipher = Cipher(algorithms.AES(key), modes.CBC(b64d(iv_b64)))
    padded = cipher.decryptor().update(b64d(encrypted_private_key)) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode("utf-8")


def load_private_key(private_pem: str):
    return serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)


def load_public_key(public_pem: str):
    return serialization.load_pem_public_key(public_pem.encode("utf-8"))


def sign_payload(private_pem: str, payload: bytes) -> str:
    private_key = load_private_key(private_pem)
    sig = private_key.sign(
        payload,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return b64e(sig)


def verify_signature(public_pem: str, payload: bytes, signature_b64: str | None) -> bool:
    if not signature_b64:
        return False
    try:
        public_key = load_public_key(public_pem)
        public_key.verify(
            b64d(signature_b64),
            payload,
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def canonical_contract_payload(contract: dict) -> bytes:
    # Assina exatamente os campos que definem o compromisso.
    created = contract.get("data_criacao") or ""
    if isinstance(created, datetime):
        created = created.strftime("%Y-%m-%d %H:%M:%S")
    parts = [
        str(contract.get("id_proponente") or ""),
        str(contract.get("id_aceitante") or ""),
        str(contract.get("texto_contrato") or ""),
        str(created),
    ]
    return "\n".join(parts).encode("utf-8")


def encrypt_contract_text(text: str, password: str, cipher_name: CipherName = "AES-256-CBC", hmac_name: HmacName = "HMAC-SHA256") -> dict[str, str]:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    raw = text.encode("utf-8")
    if cipher_name == "AES-256-CTR":
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        ciphertext = cipher.encryptor().update(raw) + cipher.encryptor().finalize()
    else:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(raw) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        ciphertext = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    digest = hashlib.sha512 if hmac_name == "HMAC-SHA512" else hashlib.sha256
    mac = hmac.new(key, ciphertext, digest).digest()
    return {
        "encrypted_text": b64e(ciphertext),
        "encryption_iv": b64e(iv),
        "encryption_salt": b64e(salt),
        "encryption_algorithm": cipher_name,
        "hmac_algorithm": hmac_name,
        "hmac_value": b64e(mac),
    }
