class EvidenceError(ValueError):
    """Base class for controlled evidence-format failures."""


class MalformedEvidenceError(EvidenceError):
    """Evidence bytes do not follow the declared format."""


class UnsupportedEvidenceError(EvidenceError):
    """Evidence uses a version or algorithm this release cannot process."""


class EvidenceResourceLimitError(EvidenceError):
    """Evidence exceeds a bounded processing limit."""


class EvidenceAuthenticationError(EvidenceError):
    """Encrypted evidence could not be authenticated."""


class MalformedPackageError(EvidenceError):
    """An evidence package is structurally invalid."""


class VerificationMismatchError(EvidenceError):
    """Supplied evidence does not match its declared commitment."""
