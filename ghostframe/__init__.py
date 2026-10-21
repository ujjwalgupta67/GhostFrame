"""GhostFrame local metadata inspection and sanitization package."""

from .version import __version__

from .core import (
    MAX_FILE_SIZE,
    Finding,
    InspectionResult,
    SanitizationOutcome,
    UnsafeFileError,
    UnsupportedFileError,
    inspect_file,
    sanitize_file,
    sanitize_with_verification,
)

__all__ = [
    "MAX_FILE_SIZE",
    "Finding",
    "InspectionResult",
    "SanitizationOutcome",
    "UnsafeFileError",
    "UnsupportedFileError",
    "inspect_file",
    "sanitize_file",
    "sanitize_with_verification",
]
