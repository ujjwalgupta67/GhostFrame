from __future__ import annotations

import json

import pytest

from ghostframe.evidence import VerificationState, decrypt_evidence, parse_evidence_package
from ghostframe.evidence.ui import (
    EVIDENCE_PERSISTED_KEY,
    EVIDENCE_REQUEST_KEY,
    EVIDENCE_RESULT_KEY,
    EvidenceUIError,
    clear_evidence_session,
    evidence_download_names,
    generate_evidence_once,
    persist_evidence_result,
    verify_package_for_ui,
)
from tests.evidence_support import PASSPHRASE
from tests.test_evidence_lifecycle import _docx, _jpeg


def test_passphrase_validation_is_exact_and_not_trimmed():
    source, name = _jpeg()
    for password, confirmation, message in (
        ("", "", "Enter"),
        ("correct synthetic passphrase", "different", "does not match"),
        (" short ", " short ", "at least 12"),
    ):
        with pytest.raises(EvidenceUIError, match=message):
            generate_evidence_once(
                {}, source_data=source, source_name=name, passphrase=password,
                confirmation=confirmation, use_exiftool=False,
            )


def test_generation_reuses_exact_artifacts_and_never_retains_passphrase():
    source, name = _jpeg()
    state = {}
    calls = 0

    from ghostframe.evidence import run_evidence_lifecycle

    def counted_runner(*args, **kwargs):
        nonlocal calls
        calls += 1
        return run_evidence_lifecycle(*args, **kwargs)

    first = generate_evidence_once(
        state, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False, runner=counted_runner,
    )
    second = generate_evidence_once(
        state, source_data=source, source_name=name, passphrase="",
        confirmation="mismatch", use_exiftool=False, runner=counted_runner,
    )
    assert first is second and calls == 1
    assert parse_evidence_package(first.evidence_package).encrypted_evidence == first.encrypted_evidence
    assert all("passphrase" not in key for key in state)
    assert PASSPHRASE not in repr(state)


def test_reset_clears_generation_verification_and_persistence_state():
    state = {
        EVIDENCE_RESULT_KEY: object(),
        EVIDENCE_REQUEST_KEY: "request",
        EVIDENCE_PERSISTED_KEY: object(),
        "gf_verify_result": object(),
        "gf_result": "ordinary scan remains",
    }
    clear_evidence_session(state)
    assert state == {"gf_result": "ordinary scan remains"}


def test_download_names_use_only_public_commitment():
    names = evidence_download_names("b" * 64)
    assert names.package == "ghostframe-bbbbbbbbbbbbbbbb.gfp"
    assert names.encrypted_evidence == "ghostframe-bbbbbbbbbbbbbbbb.gfe"
    assert "source" not in names.package


def test_explicit_ui_persistence_reuses_exact_generated_bytes(tmp_path):
    source, name = _jpeg()
    result = generate_evidence_once(
        {}, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False,
    )
    persisted = persist_evidence_result(
        result,
        root=tmp_path,
        include_encrypted_evidence=True,
    )
    assert persisted.package_path.read_bytes() == result.evidence_package
    assert persisted.encrypted_evidence_path.read_bytes() == result.encrypted_evidence
    assert name not in persisted.package_path.name
    assert PASSPHRASE not in persisted.package_path.name


def test_public_metadata_and_filenames_do_not_leak_synthetic_sensitive_values():
    source, name = _docx()
    state = {}
    result = generate_evidence_once(
        state, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False,
    )
    parsed = parse_evidence_package(result.evidence_package)
    names = evidence_download_names(result.public_operation_commitment)
    public = json.dumps(parsed.manifest, sort_keys=True) + json.dumps(parsed.receipts, sort_keys=True)
    public += names.package + names.encrypted_evidence
    prohibited = [
        "Synthetic Author", "Synthetic Reviewer", "Synthetic note",
        "synthetic.docx", "user@example.invalid", "12.3456,78.9012",
    ]
    private_evidence = json.dumps(decrypt_evidence(result.encrypted_evidence, PASSPHRASE).to_dict(), sort_keys=True)
    assert all(value in private_evidence for value in prohibited[:3] + prohibited[4:])
    assert not any(value in public for value in prohibited)


def test_independent_verification_correct_wrong_absent_and_mismatched_files():
    source, name = _jpeg()
    generated = generate_evidence_once(
        {}, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False,
    )
    absent = verify_package_for_ui(package=generated.evidence_package, passphrase=PASSPHRASE)
    assert absent.package_structure.state == VerificationState.VERIFIED
    assert absent.source_file.state == VerificationState.NOT_PROVIDED
    assert absent.sanitized_file.state == VerificationState.NOT_PROVIDED
    assert absent.inspection_blockchain_anchor.state == VerificationState.NOT_APPLICABLE
    assert absent.verification_blockchain_anchor.state == VerificationState.NOT_APPLICABLE

    matching = verify_package_for_ui(
        package=generated.evidence_package,
        passphrase=PASSPHRASE,
        source_file=source,
        sanitized_file=generated.sanitization_outcome.data,
    )
    assert matching.source_file.state == VerificationState.VERIFIED
    assert matching.sanitized_file.state == VerificationState.VERIFIED

    mismatch = verify_package_for_ui(
        package=generated.evidence_package,
        passphrase=PASSPHRASE,
        source_file=b"wrong source",
        sanitized_file=b"wrong sanitized",
    )
    assert mismatch.source_file.state == VerificationState.FAILED
    assert mismatch.sanitized_file.state == VerificationState.FAILED

    wrong_passphrase = verify_package_for_ui(
        package=generated.evidence_package,
        passphrase="different synthetic passphrase",
    )
    assert wrong_passphrase.encrypted_evidence_authenticity.state == VerificationState.FAILED


def test_malformed_tampered_and_oversized_packages_fail_structurally():
    malformed = verify_package_for_ui(package=b"not a package", passphrase=PASSPHRASE)
    assert malformed.package_structure.state == VerificationState.FAILED

    source, name = _jpeg()
    generated = generate_evidence_once(
        {}, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False,
    )
    tampered = bytearray(generated.evidence_package)
    tampered[len(tampered) // 2] ^= 1
    assert verify_package_for_ui(package=bytes(tampered), passphrase=PASSPHRASE).package_structure.state == VerificationState.FAILED

    from ghostframe.evidence.package import MAX_PACKAGE_COMPRESSED_SIZE

    oversized = verify_package_for_ui(package=b"x" * (MAX_PACKAGE_COMPRESSED_SIZE + 1), passphrase=PASSPHRASE)
    assert oversized.package_structure.state == VerificationState.FAILED


def test_ui_error_messages_do_not_include_backend_secrets():
    source, name = _jpeg()

    def fail(*args, **kwargs):
        raise RuntimeError(f"secret={PASSPHRASE} path=/private/synthetic")

    with pytest.raises(EvidenceUIError) as caught:
        generate_evidence_once(
            {}, source_data=source, source_name=name, passphrase=PASSPHRASE,
            confirmation=PASSPHRASE, use_exiftool=False, runner=fail,
        )
    assert PASSPHRASE not in str(caught.value)
    assert "/private/" not in str(caught.value)
