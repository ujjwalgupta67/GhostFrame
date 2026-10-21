from __future__ import annotations

import os
import stat

import pytest

from ghostframe.evidence import EvidenceCollisionError, EvidencePersistenceError, EvidenceStore, evidence_artifact_names


COMMITMENT = "a" * 64
PACKAGE = b"synthetic encrypted package"
ENCRYPTED = b"synthetic encrypted evidence"


def test_store_is_disabled_until_persist_is_explicitly_called(tmp_path):
    store = EvidenceStore(tmp_path)
    assert not store.destination.exists()


def test_explicit_persistence_writes_only_selected_encrypted_artifacts(tmp_path):
    store = EvidenceStore(tmp_path)
    result = store.persist(operation_commitment=COMMITMENT, evidence_package=PACKAGE)
    assert result.package_path.read_bytes() == PACKAGE
    assert result.encrypted_evidence_path is None
    assert sorted(path.suffix for path in store.destination.iterdir()) == [".gfp"]
    assert not any(path.suffix in {".json", ".txt"} for path in store.destination.iterdir())

    second_root = tmp_path / "second"
    second_root.mkdir()
    second = EvidenceStore(second_root).persist(
        operation_commitment=COMMITMENT,
        evidence_package=PACKAGE,
        encrypted_evidence=ENCRYPTED,
        include_encrypted_evidence=True,
    )
    assert second.package_path.read_bytes() == PACKAGE
    assert second.encrypted_evidence_path.read_bytes() == ENCRYPTED


def test_collision_never_overwrites_existing_artifact(tmp_path):
    store = EvidenceStore(tmp_path)
    first = store.persist(operation_commitment=COMMITMENT, evidence_package=PACKAGE)
    with pytest.raises(EvidenceCollisionError):
        store.persist(operation_commitment=COMMITMENT, evidence_package=b"replacement")
    assert first.package_path.read_bytes() == PACKAGE


@pytest.mark.parametrize("value", ["../escape", "A" * 64, "a" * 63, "a" * 65, "a/b" + "a" * 61])
def test_commitment_derived_names_reject_traversal_and_invalid_values(value):
    with pytest.raises(ValueError):
        evidence_artifact_names(value)


def test_atomic_commit_failure_cleans_temporary_and_partial_files(tmp_path):
    calls = 0

    def fail_second_link(source, target):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic atomic failure")
        os.link(source, target)

    store = EvidenceStore(tmp_path, linker=fail_second_link)
    with pytest.raises(EvidencePersistenceError):
        store.persist(
            operation_commitment=COMMITMENT,
            evidence_package=PACKAGE,
            encrypted_evidence=ENCRYPTED,
            include_encrypted_evidence=True,
        )
    assert store.destination.exists()
    assert list(store.destination.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are not portable")
def test_posix_directory_and_file_permissions_are_restrictive(tmp_path):
    store = EvidenceStore(tmp_path)
    result = store.persist(operation_commitment=COMMITMENT, evidence_package=PACKAGE)
    assert stat.S_IMODE(store.destination.stat().st_mode) == 0o700
    assert stat.S_IMODE(result.package_path.stat().st_mode) == 0o600


def test_symlinked_destination_cannot_escape_project_root(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (tmp_path / ".ghostframe").symlink_to(outside, target_is_directory=True)
    store = EvidenceStore(tmp_path)
    with pytest.raises(EvidencePersistenceError, match="escapes"):
        store.persist(operation_commitment=COMMITMENT, evidence_package=PACKAGE)
    assert not (outside / "evidence").exists()
