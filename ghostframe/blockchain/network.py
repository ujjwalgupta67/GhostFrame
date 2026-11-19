from __future__ import annotations

import ipaddress
import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from .network_models import NetworkAgreement, NetworkObservation, NodeEndpoint, NodeObservation


BESU_FOUR_NODE_ENDPOINTS = (
    NodeEndpoint("node1", "Node 1 processing", "http://127.0.0.1:8545"),
    NodeEndpoint("node2", "Node 2 client", "http://127.0.0.1:8546"),
    NodeEndpoint("node3", "Node 3 auditor", "http://127.0.0.1:8547"),
    NodeEndpoint("node4", "Node 4 validator", "http://127.0.0.1:8548"),
)


def _validate_endpoint(endpoint: NodeEndpoint) -> None:
    parsed = urlparse(endpoint.rpc_url)
    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host) if host not in {None, "localhost"} else None
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Node RPC endpoint must be an explicit loopback HTTP URL.") from exc
    if (
        parsed.scheme not in {"http", "https"} or host is None or port is None
        or parsed.username or parsed.password or parsed.query or parsed.fragment
        or parsed.path not in {"", "/"}
        or (host != "localhost" and (address is None or not address.is_loopback))
    ):
        raise ValueError("Node RPC endpoint must be an explicit loopback HTTP URL.")


def rpc(endpoint: NodeEndpoint, method: str, params: list[Any] | None = None, *, timeout: float = 3.0) -> Any:
    _validate_endpoint(endpoint)
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}).encode()
    request = urllib.request.Request(endpoint.rpc_url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.loads(response.read())
    if "error" in value:
        raise RuntimeError("Node RPC returned an error.")
    return value["result"]


def _observe(endpoint: NodeEndpoint, timeout: float) -> NodeObservation:
    started = time.monotonic()
    observed_at = datetime.now(timezone.utc).isoformat()
    try:
        chain_id = int(rpc(endpoint, "eth_chainId", timeout=timeout), 16)
        height = int(rpc(endpoint, "eth_blockNumber", timeout=timeout), 16)
        current = rpc(endpoint, "eth_getBlockByNumber", [hex(height), False], timeout=timeout)
        genesis = rpc(endpoint, "eth_getBlockByNumber", ["0x0", False], timeout=timeout)
        peers = int(rpc(endpoint, "net_peerCount", timeout=timeout), 16)
        syncing_value = rpc(endpoint, "eth_syncing", timeout=timeout)
        return NodeObservation(
            endpoint.node_id, endpoint.label, endpoint.rpc_url, True,
            chain_id=chain_id, genesis_hash=str(genesis["hash"]).lower(),
            block_height=height, current_block_hash=str(current["hash"]).lower(),
            peer_count=peers, syncing=syncing_value is not False,
            latency_ms=(time.monotonic() - started) * 1000, observed_at=observed_at,
        )
    except Exception:
        return NodeObservation(
            endpoint.node_id, endpoint.label, endpoint.rpc_url, False,
            latency_ms=(time.monotonic() - started) * 1000, observed_at=observed_at,
            error="RPC unavailable or response could not be validated.",
            error_category="RPC_UNAVAILABLE",
        )


def observe_network(
    endpoints: tuple[NodeEndpoint, ...] = BESU_FOUR_NODE_ENDPOINTS,
    *, expected_chain_id: int = 4242, expected_genesis_hash: str | None = None,
    timeout: float = 3.0,
) -> NetworkObservation:
    with ThreadPoolExecutor(max_workers=len(endpoints)) as pool:
        futures = {pool.submit(_observe, endpoint, timeout): endpoint for endpoint in endpoints}
        by_id: dict[str, NodeObservation] = {}
        for future in as_completed(futures):
            observation = future.result()
            by_id[observation.node_id] = observation
    nodes = tuple(by_id[endpoint.node_id] for endpoint in endpoints)
    live = [node for node in nodes if node.available]
    if not live:
        return NetworkObservation(nodes, NetworkAgreement.UNAVAILABLE, None, "All four Besu RPC endpoints are unavailable.")
    correct = [
        node for node in live
        if node.chain_id == expected_chain_id
        and (expected_genesis_hash is None or node.genesis_hash == expected_genesis_hash.lower())
    ]
    if len(correct) != len(live):
        return NetworkObservation(nodes, NetworkAgreement.WRONG_NETWORK, None, "At least one reachable node has the wrong chain identity.")
    common_height = min(node.block_height for node in correct if node.block_height is not None)
    updated: list[NodeObservation] = []
    hashes: set[str] = set()
    for node in nodes:
        if not node.available:
            updated.append(node)
            continue
        endpoint = next(item for item in endpoints if item.node_id == node.node_id)
        try:
            block = rpc(endpoint, "eth_getBlockByNumber", [hex(common_height), False], timeout=timeout)
            block_hash = str(block["hash"]).lower()
            hashes.add(block_hash)
            updated.append(replace(node, common_block_hash=block_hash))
        except Exception:
            updated.append(replace(
                node, available=False, error="Common block could not be checked.",
                error_category="BLOCK_UNAVAILABLE",
            ))
    available = [node for node in updated if node.available]
    if len(hashes) > 1:
        agreement = NetworkAgreement.DISAGREEMENT
        detail = "Reachable nodes disagree on the block hash at the common height."
    elif any(node.syncing for node in available) or len({node.block_height for node in available}) > 1:
        agreement = NetworkAgreement.CATCHING_UP
        detail = "Reachable nodes share history but at least one node is catching up."
    elif len(available) == len(endpoints):
        agreement = NetworkAgreement.ALL_AGREE
        detail = "All four nodes share the same chain and common block history."
    else:
        agreement = NetworkAgreement.PARTIAL_AGREEMENT
        detail = f"{len(available)} of {len(endpoints)} nodes agree; unavailable nodes were not verified."
    return NetworkObservation(tuple(updated), agreement, common_height, detail)
