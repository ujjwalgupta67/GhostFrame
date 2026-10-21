from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


COMMITMENT_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidencePersistenceError(RuntimeError):
    """Controlled failure while saving encrypted evidence."""


class EvidenceCollisionError(EvidencePersistenceError):
    """A persisted artifact already uses this operation commitment."""


@dataclass(frozen=True)
class PersistedEvidence:
    package_path: Path
    encrypted_evidence_path: Path | None = None


def evidence_artifact_names(operation_commitment: str) -> tuple[str, str]:
    if not isinstance(operation_commitment, str) or not COMMITMENT_RE.fullmatch(operation_commitment):
        raise ValueError("A valid operation commitment is required for evidence filenames.")
    safe_id = operation_commitment[:16]
    return f"ghostframe-{safe_id}.gfp", f"ghostframe-{safe_id}.gfe"


class EvidenceStore:
    """Explicit, collision-safe storage for encrypted evidence artifacts only."""

    def __init__(self, root: str | Path | None = None, *, linker: Callable[[str, str], None] = os.link) -> None:
        self.root = Path.cwd() if root is None else Path(root)
        self._linker = linker

    @property
    def destination(self) -> Path:
        return self.root / ".ghostframe" / "evidence"

    def _prepare_destination(self) -> Path:
        try:
            root = self.root.resolve(strict=True)
            container = root / ".ghostframe"
            if container.exists() or container.is_symlink():
                if not container.resolve(strict=True).is_relative_to(root):
                    raise EvidencePersistenceError("Evidence destination escapes the selected project directory.")
            else:
                container.mkdir(mode=0o700)
            destination = container / "evidence"
            if destination.exists() or destination.is_symlink():
                if not destination.resolve(strict=True).is_relative_to(root):
                    raise EvidencePersistenceError("Evidence destination escapes the selected project directory.")
            else:
                destination.mkdir(mode=0o700)
            resolved = destination.resolve(strict=True)
            if not resolved.is_relative_to(root):
                raise EvidencePersistenceError("Evidence destination escapes the selected project directory.")
            if os.name == "posix":
                os.chmod(destination.parent, 0o700)
                os.chmod(destination, 0o700)
            return destination
        except EvidencePersistenceError:
            raise
        except OSError:
            raise EvidencePersistenceError("Could not prepare the local evidence directory safely.") from None

    def _atomic_write_new(self, destination: Path, filename: str, data: bytes) -> Path:
        if not isinstance(data, bytes):
            raise TypeError("Persisted evidence must be bytes.")
        target = destination / filename
        if target.parent != destination or target.exists():
            raise EvidenceCollisionError("An evidence artifact already exists for this operation.")
        descriptor, temporary_name = tempfile.mkstemp(prefix=".ghostframe-write-", suffix=".tmp", dir=destination)
        temporary = Path(temporary_name)
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                self._linker(os.fspath(temporary), os.fspath(target))
            except FileExistsError:
                raise EvidenceCollisionError("An evidence artifact already exists for this operation.") from None
            except OSError:
                raise EvidencePersistenceError("Evidence could not be committed atomically.") from None
            if os.name == "posix":
                try:
                    directory_fd = os.open(destination, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError:
                    pass
            return target
        except EvidencePersistenceError:
            raise
        except OSError:
            raise EvidencePersistenceError("Evidence could not be written safely.") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def persist(
        self,
        *,
        operation_commitment: str,
        evidence_package: bytes,
        encrypted_evidence: bytes | None = None,
        include_encrypted_evidence: bool = False,
    ) -> PersistedEvidence:
        package_name, encrypted_name = evidence_artifact_names(operation_commitment)
        if include_encrypted_evidence and encrypted_evidence is None:
            raise ValueError("Encrypted evidence bytes are required when standalone persistence is enabled.")
        destination = self._prepare_destination()
        targets = [destination / package_name]
        if include_encrypted_evidence:
            targets.append(destination / encrypted_name)
        if any(target.exists() for target in targets):
            raise EvidenceCollisionError("An evidence artifact already exists for this operation.")
        created: list[Path] = []
        try:
            package_path = self._atomic_write_new(destination, package_name, evidence_package)
            created.append(package_path)
            encrypted_path = None
            if include_encrypted_evidence:
                encrypted_path = self._atomic_write_new(destination, encrypted_name, encrypted_evidence)
                created.append(encrypted_path)
            return PersistedEvidence(package_path, encrypted_path)
        except Exception:
            for path in created:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
