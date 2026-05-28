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

ALLOWED_ENCRYPTION_COMBINATIONS = {
    "AES-256-CBC:HMAC-SHA256": ("AES-256-CBC", "HMAC-SHA256"),
    "AES-256-CBC:HMAC-SHA512": ("AES-256-CBC", "HMAC-SHA512"),
    "AES-256-CTR:HMAC-SHA256": ("AES-256-CTR", "HMAC-SHA256"),
    "AES-256-CTR:HMAC-SHA512": ("AES-256-CTR", "HMAC-SHA512"),
}


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
    """Deriva uma chave AES-256 a partir de password + salt.

    O salt é guardado na BD em base64. Isto impede que duas passwords iguais
    originem a mesma chave derivada.
    """
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def get_hmac_digest(hmac_name: HmacName):
    if hmac_name == "HMAC-SHA512":
        return hashlib.sha512
    if hmac_name == "HMAC-SHA256":
        return hashlib.sha256
    raise ValueError("Unsupported HMAC algorithm")


def make_hmac_payload(cipher_name: str, iv: bytes, ciphertext: bytes) -> bytes:
    """Dados autenticados pelo HMAC.

    Inclui o nome da cifra e o IV para detetar alteração do modo de cifra,
    alteração do IV ou alteração do criptograma.
    """
    return cipher_name.encode("utf-8") + b"\0" + iv + b"\0" + ciphertext


def encrypt_private_key(private_pem: str, password: str) -> dict[str, str]:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(private_pem.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    enc = encryptor.update(padded) + encryptor.finalize()
    return {
        "encrypted_private_key": b64e(enc),
        "private_key_salt": b64e(salt),
        "private_key_iv": b64e(iv),
        "private_key_algorithm": "AES-256-CBC",
    }


def decrypt_private_key(encrypted_private_key: str, password: str, salt_b64: str, iv_b64: str) -> str:
    key = derive_key(password, b64d(salt_b64))
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b64d(iv_b64))).decryptor()
    padded = decryptor.update(b64d(encrypted_private_key)) + decryptor.finalize()
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


def parse_encryption_profile(profile: str) -> tuple[CipherName, HmacName] | None:
    """Converte a escolha do formulário numa combinação válida.

    Valores aceites:
    - none
    - AES-256-CBC:HMAC-SHA256
    - AES-256-CBC:HMAC-SHA512
    - AES-256-CTR:HMAC-SHA256
    - AES-256-CTR:HMAC-SHA512
    """
    if not profile or profile == "none":
        return None
    combo = ALLOWED_ENCRYPTION_COMBINATIONS.get(profile)
    if not combo:
        raise ValueError("Unsupported encryption profile")
    return combo  # type: ignore[return-value]


def encrypt_contract_text(
    text: str,
    password: str,
    cipher_name: CipherName = "AES-256-CBC",
    hmac_name: HmacName = "HMAC-SHA256",
) -> dict[str, str]:
    """Cifra o texto do contrato com AES-256 e autentica com HMAC.

    Opções suportadas:
    - AES-256-CBC + HMAC-SHA256
    - AES-256-CBC + HMAC-SHA512
    - AES-256-CTR + HMAC-SHA256
    - AES-256-CTR + HMAC-SHA512
    """
    if cipher_name not in ("AES-256-CBC", "AES-256-CTR"):
        raise ValueError("Unsupported cipher")
    if hmac_name not in ("HMAC-SHA256", "HMAC-SHA512"):
        raise ValueError("Unsupported HMAC")

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    raw = text.encode("utf-8")

    if cipher_name == "AES-256-CTR":
        encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        ciphertext = encryptor.update(raw) + encryptor.finalize()
    else:
        padder = padding.PKCS7(128).padder()
        padded = padder.update(raw) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

    mac_payload = make_hmac_payload(cipher_name, iv, ciphertext)
    mac = hmac.new(key, mac_payload, get_hmac_digest(hmac_name)).digest()

    return {
        "encrypted_text": b64e(ciphertext),
        "encryption_iv": b64e(iv),
        "encryption_salt": b64e(salt),
        "encryption_algorithm": cipher_name,
        "hmac_algorithm": hmac_name,
        "hmac_value": b64e(mac),
    }


def verify_contract_hmac(
    encrypted_text_b64: str,
    password: str,
    salt_b64: str,
    iv_b64: str,
    cipher_name: CipherName,
    hmac_name: HmacName,
    hmac_value_b64: str,
) -> bool:
    """Verifica a integridade do criptograma com HMAC."""
    try:
        salt = b64d(salt_b64)
        iv = b64d(iv_b64)
        ciphertext = b64d(encrypted_text_b64)
        key = derive_key(password, salt)
        expected = hmac.new(key, make_hmac_payload(cipher_name, iv, ciphertext), get_hmac_digest(hmac_name)).digest()
        return hmac.compare_digest(expected, b64d(hmac_value_b64))
    except Exception:
        return False


def decrypt_contract_text(
    encrypted_text_b64: str,
    password: str,
    salt_b64: str,
    iv_b64: str,
    cipher_name: CipherName,
    hmac_name: HmacName,
    hmac_value_b64: str,
) -> str:
    """Verifica HMAC e decifra o texto do contrato."""
    if not verify_contract_hmac(encrypted_text_b64, password, salt_b64, iv_b64, cipher_name, hmac_name, hmac_value_b64):
        raise ValueError("Invalid HMAC")

    key = derive_key(password, b64d(salt_b64))
    iv = b64d(iv_b64)
    ciphertext = b64d(encrypted_text_b64)

    if cipher_name == "AES-256-CTR":
        decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        raw = decryptor.update(ciphertext) + decryptor.finalize()
        return raw.decode("utf-8")

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    raw = unpadder.update(padded) + unpadder.finalize()
    return raw.decode("utf-8")
