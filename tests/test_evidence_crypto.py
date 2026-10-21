from __future__ import annotations

import hashlib
import json
import random

import pytest

from ghostframe.evidence import (
    EvidenceAuthenticationError,
    EvidenceError,
    EvidenceResourceLimitError,
    MalformedEvidenceError,
    UnsupportedEvidenceError,
    canonical_json_bytes,
    decrypt_evidence,
    decrypt_evidence_bytes,
    encrypt_evidence,
)
from ghostframe.evidence.crypto import (
    DEFAULT_SCRYPT_N,
    GFE_FORMAT_VERSION,
    HEADER_STRUCT,
    _encrypt_evidence_with_material,
)
from tests.evidence_support import PASSPHRASE, completed_record


SALT = bytes(range(16))
NONCE = bytes(range(12))


def deterministic_gfe(record=None) -> bytes:
    return _encrypt_evidence_with_material(record or completed_record(), PASSPHRASE, salt=SALT, nonce=NONCE)


def rewrite_header(container: bytes, mutate) -> bytes:
    magic, header_size, ciphertext_size = HEADER_STRUCT.unpack_from(container)
    header = json.loads(container[HEADER_STRUCT.size:HEADER_STRUCT.size + header_size])
    mutate(header)
    encoded = canonical_json_bytes(header)
    ciphertext = container[HEADER_STRUCT.size + header_size:]
    return HEADER_STRUCT.pack(magic, len(encoded), ciphertext_size) + encoded + ciphertext


def test_gfe_round_trip_randomness_unicode_and_exact_plaintext():
    record = completed_record(author="Synthetic José")
    first = encrypt_evidence(record, PASSPHRASE)
    second = encrypt_evidence(record, PASSPHRASE)
    assert first != second
    assert decrypt_evidence(first, PASSPHRASE).to_dict() == record.to_dict()
    assert decrypt_evidence_bytes(first, PASSPHRASE) == canonical_json_bytes(record.to_dict())


def test_gfe_round_trip_minimal_incomplete_evidence():
    complete = completed_record()
    minimal = complete.__class__(
        operation_id=complete.operation_id,
        created_at=complete.created_at,
        source_file=complete.source_file,
        initial_inspection={},
    )
    encrypted = encrypt_evidence(minimal, PASSPHRASE)
    assert decrypt_evidence(encrypted, PASSPHRASE).to_dict() == minimal.to_dict()


def test_gfe_fixed_material_known_answer_and_structure():
    container = deterministic_gfe()
    assert hashlib.sha256(container).hexdigest() == "1b01dad4b70c8fe5e8fb60f62ab59b4da277f69d51ba7a59e3f35ddcdbea1f9e"
    magic, header_size, ciphertext_size = HEADER_STRUCT.unpack_from(container)
    assert header_size <= 4096 and ciphertext_size >= 16
    assert len(container) == HEADER_STRUCT.size + header_size + ciphertext_size
    assert decrypt_evidence(container, PASSPHRASE).is_complete


def test_wrong_passphrase_and_ciphertext_or_tag_tampering_fail_uniformly():
    container = deterministic_gfe()
    with pytest.raises(EvidenceAuthenticationError, match="authentication failed"):
        decrypt_evidence(container, "different synthetic passphrase")
    for index in (-1, -17):
        changed = bytearray(container); changed[index] ^= 1
        with pytest.raises(EvidenceAuthenticationError, match="authentication failed"):
            decrypt_evidence(bytes(changed), PASSPHRASE)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda header: header["encryption"].update(nonce="AQEBAQEBAQEBAQEB"),
        lambda header: header["kdf"].update(salt="AQEBAQEBAQEBAQEBAQEBAQ=="),
        lambda header: header["kdf"].update(p=2),
    ],
)
def test_authenticated_header_nonce_and_salt_tampering(mutation):
    changed = rewrite_header(deterministic_gfe(), mutation)
    with pytest.raises(EvidenceAuthenticationError):
        decrypt_evidence(changed, PASSPHRASE)


def test_unsupported_version_algorithm_and_kdf_fail_closed():
    with pytest.raises(UnsupportedEvidenceError, match="container version"):
        decrypt_evidence(rewrite_header(deterministic_gfe(), lambda h: h.update(container_version="ghostframe-gfe/9.0")), PASSPHRASE)
    with pytest.raises(UnsupportedEvidenceError, match="encryption algorithm"):
        decrypt_evidence(rewrite_header(deterministic_gfe(), lambda h: h["encryption"].update(algorithm="AES-ECB")), PASSPHRASE)
    with pytest.raises(UnsupportedEvidenceError, match="KDF algorithm"):
        decrypt_evidence(rewrite_header(deterministic_gfe(), lambda h: h["kdf"].update(algorithm="unknown")), PASSPHRASE)


def test_excessive_kdf_parameters_rejected_before_derivation(monkeypatch):
    changed = rewrite_header(deterministic_gfe(), lambda h: h["kdf"].update(n=2**30))
    called = False

    def forbidden(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("KDF allocation should not occur")

    monkeypatch.setattr("ghostframe.evidence.crypto.Scrypt", forbidden)
    with pytest.raises(EvidenceResourceLimitError, match="outside"):
        decrypt_evidence(changed, PASSPHRASE)
    assert not called


@pytest.mark.parametrize("container", [b"", b"GFE", deterministic_gfe()[:-1], deterministic_gfe() + b"trailing"])
def test_truncated_and_trailing_gfe_rejected(container):
    with pytest.raises(EvidenceError):
        decrypt_evidence(container, PASSPHRASE)


def test_short_passphrase_rejected_without_output():
    with pytest.raises(ValueError, match="at least"):
        encrypt_evidence(completed_record(), "short")


def test_malformed_input_fuzz_style_is_controlled():
    generator = random.Random(20260926)
    for size in range(0, 513, 17):
        payload = generator.randbytes(size)
        try:
            decrypt_evidence(payload, PASSPHRASE)
        except EvidenceError:
            pass
        else:
            pytest.fail("Arbitrary malformed input unexpectedly decrypted")


def test_default_scrypt_cost_is_fixed_not_adaptive():
    assert DEFAULT_SCRYPT_N == 2**15
    assert GFE_FORMAT_VERSION == "ghostframe-gfe/1.0"
