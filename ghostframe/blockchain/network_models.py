from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .models import AnchorStage, AnchorState


class NetworkAgreement(str, Enum):
    ALL_AGREE = "ALL_AGREE"
    PARTIAL_AGREEMENT = "PARTIAL_AGREEMENT"
    CATCHING_UP = "CATCHING_UP"
    DISAGREEMENT = "DISAGREEMENT"
    WRONG_NETWORK = "WRONG_NETWORK"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class NodeEndpoint:
    node_id: str
    label: str
    rpc_url: str


@dataclass(frozen=True)
class NodeObservation:
    node_id: str
    label: str
    rpc_url: str
    available: bool
    chain_id: int | None = None
    genesis_hash: str | None = None
    block_height: int | None = None
    current_block_hash: str | None = None
    peer_count: int | None = None
    syncing: bool | None = None
    latency_ms: float | None = None
    observed_at: str | None = None
    common_block_hash: str | None = None
    error: str | None = None
    error_category: str | None = None


@dataclass(frozen=True)
class NetworkObservation:
    nodes: tuple[NodeObservation, ...]
    agreement: NetworkAgreement
    common_height: int | None
    detail: str


@dataclass(frozen=True)
class NodeAnchorVerification:
    node_id: str
    label: str
    stage: AnchorStage
    state: AnchorState
    detail: str


@dataclass(frozen=True)
class MultiNodeAnchorVerification:
    stage: AnchorStage
    results: tuple[NodeAnchorVerification, ...]
    verified_nodes: int
    required_nodes: int
    state: AnchorState
    detail: str
