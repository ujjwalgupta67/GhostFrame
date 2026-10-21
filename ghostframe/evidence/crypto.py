from __future__ import annotations

import base64
import binascii
import json
import os
import struct
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .canonical import CanonicalizationError, canonical_json_bytes
from .errors import EvidenceAuthenticationError, EvidenceResourceLimitError, MalformedEvidenceError, UnsupportedEvidenceError
from .models import CANONICALIZATION_VERSION, EVIDENCE_SCHEMA_VERSION, EvidenceRecord


GFE_MAGIC = b"GFE\x00\x01\r\n\x1a"
GFE_FORMAT_VERSION = "ghostframe-gfe/1.0"
ENCRYPTION_ALGORITHM = "AES-256-GCM"
KDF_ALGORITHM = "scrypt"
HEADER_STRUCT = struct.Struct(">8sIQ")
MAX_HEADER_SIZE = 4096
MAX_PLAINTEXT_SIZE = 16 * 1024 * 1024
MAX_CIPHERTEXT_SIZE = MAX_PLAINTEXT_SIZE + 16
MAX_GFE_SIZE = HEADER_STRUCT.size + MAX_HEADER_SIZE + MAX_CIPHERTEXT_SIZE
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
DEFAULT_SCRYPT_N = 2**15
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
MIN_SCRYPT_N = 2**14
MAX_SCRYPT_N = 2**17
MAX_SCRYPT_R = 16
MAX_SCRYPT_P = 4
MIN_PASSPHRASE_LENGTH = 12


def _passphrase_bytes(passphrase: str) -> bytes:
    if not isinstance(passphrase, str):
        raise TypeError("Passphrase must be text.")
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(f"Passphrase must contain at least {MIN_PASSPHRASE_LENGTH} characters.")
    return passphrase.encode("utf-8")


def _validate_kdf(n: int, r: int, p: int, length: int) -> None:
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in (n, r, p, length)):
        raise MalformedEvidenceError("Invalid encrypted-evidence KDF parameters.")
    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1):
        raise EvidenceResourceLimitError("Encrypted-evidence Scrypt cost is outside the supported bounds.")
    if r < 1 or r > MAX_SCRYPT_R or p < 1 or p > MAX_SCRYPT_P or length != KEY_SIZE:
        raise EvidenceResourceLimitError("Encrypted-evidence Scrypt parameters are outside the supported bounds.")
    if 128 * n * r > 256 * 1024 * 1024:
        raise EvidenceResourceLimitError("Encrypted-evidence Scrypt memory request exceeds the safety limit.")


def _derive_key(passphrase: str, salt: bytes, *, n: int, r: int, p: int, length: int = KEY_SIZE) -> bytes:
    _validate_kdf(n, r, p, length)
    if len(salt) != SALT_SIZE:
        raise MalformedEvidenceError("Invalid encrypted-evidence salt length.")
    return Scrypt(salt=salt, length=length, n=n, r=r, p=p).derive(_passphrase_bytes(passphrase))


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_b64(value: Any, expected_size: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise MalformedEvidenceError(f"Invalid encrypted-evidence {label}.")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MalformedEvidenceError(f"Invalid encrypted-evidence {label}.") from exc
    if len(decoded) != expected_size:
        raise MalformedEvidenceError(f"Invalid encrypted-evidence {label} length.")
    return decoded


def _header(salt: bytes, nonce: bytes, *, n: int, r: int, p: int) -> dict[str, Any]:
    return {
        "canonicalization_version": CANONICALIZATION_VERSION,
        "container_version": GFE_FORMAT_VERSION,
        "encryption": {"algorithm": ENCRYPTION_ALGORITHM, "nonce": _b64(nonce)},
        "evidence_schema_version": EVIDENCE_SCHEMA_VERSION,
        "kdf": {"algorithm": KDF_ALGORITHM, "length": KEY_SIZE, "n": n, "p": p, "r": r, "salt": _b64(salt)},
    }


def _encrypt_evidence_with_material(
    record: EvidenceRecord,
    passphrase: str,
    *,
    salt: bytes,
    nonce: bytes,
    n: int = DEFAULT_SCRYPT_N,
    r: int = DEFAULT_SCRYPT_R,
    p: int = DEFAULT_SCRYPT_P,
) -> bytes:
    """Internal deterministic-material entry point used only by format tests."""

    if len(nonce) != NONCE_SIZE:
        raise ValueError("AES-GCM nonce must be 12 bytes.")
    plaintext = canonical_json_bytes(record.to_dict())
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise EvidenceResourceLimitError("Canonical evidence exceeds the encrypted-evidence size limit.")
    header_bytes = canonical_json_bytes(_header(salt, nonce, n=n, r=r, p=p))
    if len(header_bytes) > MAX_HEADER_SIZE:
        raise EvidenceResourceLimitError("Encrypted-evidence header exceeds the safety limit.")
    ciphertext_size = len(plaintext) + 16
    prefix = HEADER_STRUCT.pack(GFE_MAGIC, len(header_bytes), ciphertext_size)
    aad = prefix + header_bytes
    key = _derive_key(passphrase, salt, n=n, r=r, p=p)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return aad + ciphertext


def encrypt_evidence(record: EvidenceRecord, passphrase: str) -> bytes:
    """Encrypt one evidence record using fresh OS-generated salt and nonce."""

    return _encrypt_evidence_with_material(record, passphrase, salt=os.urandom(SALT_SIZE), nonce=os.urandom(NONCE_SIZE))


def _decode_json_object(raw: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in values:
            if key in output:
                raise MalformedEvidenceError("Duplicate key in encrypted evidence.")
            output[key] = value
        return output

    def reject_number(value: str) -> Any:
        raise MalformedEvidenceError("Floating-point values are not supported in encrypted evidence.")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=reject_number, parse_constant=reject_number)
    except MalformedEvidenceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedEvidenceError("Encrypted evidence contains malformed JSON.") from exc
    if not isinstance(value, dict):
        raise MalformedEvidenceError("Encrypted evidence root must be an object.")
    return value


def _parse_container(container: bytes) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    if not isinstance(container, bytes):
        raise TypeError("Encrypted evidence must be bytes.")
    if len(container) > MAX_GFE_SIZE:
        raise EvidenceResourceLimitError("Encrypted-evidence container exceeds the safety limit.")
    if len(container) < HEADER_STRUCT.size:
        raise MalformedEvidenceError("Encrypted-evidence container is truncated.")
    magic, header_size, ciphertext_size = HEADER_STRUCT.unpack_from(container)
    if magic != GFE_MAGIC:
        raise UnsupportedEvidenceError("Unsupported encrypted-evidence magic or container version.")
    if header_size < 2 or header_size > MAX_HEADER_SIZE:
        raise EvidenceResourceLimitError("Encrypted-evidence header size is outside the supported bounds.")
    if ciphertext_size < 16 or ciphertext_size > MAX_CIPHERTEXT_SIZE:
        raise EvidenceResourceLimitError("Encrypted-evidence ciphertext size is outside the supported bounds.")
    expected_size = HEADER_STRUCT.size + header_size + ciphertext_size
    if len(container) != expected_size:
        raise MalformedEvidenceError("Encrypted-evidence container is truncated or has trailing data.")
    header_bytes = container[HEADER_STRUCT.size:HEADER_STRUCT.size + header_size]
    header = _decode_json_object(header_bytes)
    try:
        if canonical_json_bytes(header) != header_bytes:
            raise MalformedEvidenceError("Encrypted-evidence header is not canonical.")
    except CanonicalizationError as exc:
        raise MalformedEvidenceError("Encrypted-evidence header is invalid.") from exc
    expected_header = {"canonicalization_version", "container_version", "encryption", "evidence_schema_version", "kdf"}
    if set(header) != expected_header:
        raise MalformedEvidenceError("Encrypted-evidence header fields are invalid.")
    if header["container_version"] != GFE_FORMAT_VERSION:
        raise UnsupportedEvidenceError("Unsupported encrypted-evidence container version.")
    if header["evidence_schema_version"] != EVIDENCE_SCHEMA_VERSION or header["canonicalization_version"] != CANONICALIZATION_VERSION:
        raise UnsupportedEvidenceError("Encrypted evidence requires an unsupported evidence format.")
    encryption = header["encryption"]
    kdf = header["kdf"]
    if not isinstance(encryption, Mapping) or set(encryption) != {"algorithm", "nonce"}:
        raise MalformedEvidenceError("Encrypted-evidence algorithm header is invalid.")
    if encryption["algorithm"] != ENCRYPTION_ALGORITHM:
        raise UnsupportedEvidenceError("Unsupported encrypted-evidence encryption algorithm.")
    if not isinstance(kdf, Mapping) or set(kdf) != {"algorithm", "length", "n", "p", "r", "salt"}:
        raise MalformedEvidenceError("Encrypted-evidence KDF header is invalid.")
    if kdf["algorithm"] != KDF_ALGORITHM:
        raise UnsupportedEvidenceError("Unsupported encrypted-evidence KDF algorithm.")
    _validate_kdf(kdf["n"], kdf["r"], kdf["p"], kdf["length"])
    nonce = _decode_b64(encryption["nonce"], NONCE_SIZE, "nonce")
    salt = _decode_b64(kdf["salt"], SALT_SIZE, "salt")
    ciphertext = container[HEADER_STRUCT.size + header_size:]
    return header, header_bytes, salt, nonce


def decrypt_evidence_bytes(container: bytes, passphrase: str) -> bytes:
    header, header_bytes, salt, nonce = _parse_container(container)
    _, header_size, ciphertext_size = HEADER_STRUCT.unpack_from(container)
    prefix = container[:HEADER_STRUCT.size]
    ciphertext = container[HEADER_STRUCT.size + header_size:]
    if len(ciphertext) != ciphertext_size:
        raise MalformedEvidenceError("Encrypted-evidence ciphertext length is invalid.")
    kdf = header["kdf"]
    key = _derive_key(passphrase, salt, n=kdf["n"], r=kdf["r"], p=kdf["p"], length=kdf["length"])
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, prefix + header_bytes)
    except InvalidTag as exc:
        raise EvidenceAuthenticationError("Evidence authentication failed.") from exc
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise EvidenceResourceLimitError("Decrypted evidence exceeds the safety limit.")
    return plaintext


def decrypt_evidence(container: bytes, passphrase: str) -> EvidenceRecord:
    plaintext = decrypt_evidence_bytes(container, passphrase)
    value = _decode_json_object(plaintext)
    try:
        if canonical_json_bytes(value) != plaintext:
            raise MalformedEvidenceError("Decrypted evidence is not canonical.")
        return EvidenceRecord.from_dict(value)
    except MalformedEvidenceError:
        raise
    except (CanonicalizationError, ValueError, TypeError, KeyError) as exc:
        raise MalformedEvidenceError("Decrypted evidence record is malformed.") from exc
