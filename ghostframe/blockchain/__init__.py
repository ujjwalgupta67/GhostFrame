"""Optional commitment-only blockchain foundation.

Normal GhostFrame operation does not import Web3 or require an RPC endpoint.
"""

from .disabled import DisabledAnchor
from .evm import EvmAnchor
from .interface import BlockchainAnchor
from .memory import InMemoryAnchor
from .models import (
    AnchorHealth,
    AnchorReceipt,
    AnchorRecord,
    AnchorStage,
    AnchorState,
    AnchorVerification,
    BlockchainConfig,
    FailureCategory,
    InspectionAnchorRequest,
    VerificationAnchorRequest,
)

__all__ = [
    "AnchorHealth", "AnchorReceipt", "AnchorRecord", "AnchorStage", "AnchorState",
    "AnchorVerification", "BlockchainAnchor", "BlockchainConfig", "DisabledAnchor", "EvmAnchor",
    "FailureCategory", "InMemoryAnchor", "InspectionAnchorRequest", "VerificationAnchorRequest",
]
