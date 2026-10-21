from __future__ import annotations

from .interface import BlockchainAnchor
from .models import (
    AnchorHealth,
    AnchorReceipt,
    AnchorRequest,
    AnchorState,
    AnchorVerification,
    FailureCategory,
    InspectionAnchorRequest,
    VerificationAnchorRequest,
    AnchorStage,
)


class DisabledAnchor(BlockchainAnchor):
    """Offline default. This module deliberately imports no Web3 package."""

    def health(self) -> AnchorHealth:
        return AnchorHealth(AnchorState.DISABLED, "Blockchain anchoring is disabled.")

    def _receipt(self, request: AnchorRequest, stage: AnchorStage) -> AnchorReceipt:
        return AnchorReceipt(
            state=AnchorState.DISABLED,
            stage=stage,
            operation_commitment=request.operation_commitment,
            failure_category=FailureCategory.DISABLED,
            detail="Blockchain anchoring is disabled; no transaction was requested.",
        )

    def anchor_inspection(self, request: InspectionAnchorRequest) -> AnchorReceipt:
        return self._receipt(request, AnchorStage.INSPECTION)

    def anchor_verification(self, request: VerificationAnchorRequest) -> AnchorReceipt:
        return self._receipt(request, AnchorStage.VERIFICATION)

    def get_anchor(self, operation_commitment: str):
        return None

    def verify_anchor(self, request: AnchorRequest, receipt: AnchorReceipt | None = None) -> AnchorVerification:
        stage = AnchorStage.INSPECTION if isinstance(request, InspectionAnchorRequest) else AnchorStage.VERIFICATION
        return AnchorVerification(AnchorState.DISABLED, "Blockchain anchoring is disabled.", stage, request.operation_commitment, receipt=receipt)

