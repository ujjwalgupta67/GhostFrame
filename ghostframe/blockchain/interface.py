from __future__ import annotations

from abc import ABC, abstractmethod

from .models import (
    AnchorHealth,
    AnchorReceipt,
    AnchorRecord,
    AnchorRequest,
    AnchorVerification,
    InspectionAnchorRequest,
    VerificationAnchorRequest,
)


class BlockchainAnchor(ABC):
    """Typed privacy boundary for commitment-only blockchain adapters."""

    @abstractmethod
    def health(self) -> AnchorHealth: ...

    @abstractmethod
    def anchor_inspection(self, request: InspectionAnchorRequest) -> AnchorReceipt: ...

    @abstractmethod
    def anchor_verification(self, request: VerificationAnchorRequest) -> AnchorReceipt: ...

    @abstractmethod
    def get_anchor(self, operation_commitment: str) -> AnchorRecord | None: ...

    @abstractmethod
    def verify_anchor(self, request: AnchorRequest, receipt: AnchorReceipt | None = None) -> AnchorVerification: ...

