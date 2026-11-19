from __future__ import annotations

from types import SimpleNamespace

from ghostframe.blockchain import besu, multinode, network
from ghostframe.blockchain.models import AnchorReceipt, AnchorStage, AnchorState, InspectionAnchorRequest
from ghostframe.blockchain.network_models import NetworkAgreement, NodeEndpoint


def h(char: str) -> str:
    return "0x" + char * 64


ENDPOINTS = tuple(
    NodeEndpoint(f"node{number}", f"Node {number}", f"http://127.0.0.1:{8600 + number}")
    for number in range(1, 5)
)


def test_network_observation_reports_all_agree_and_partial(monkeypatch):
    unavailable: set[str] = set()

    def fake_rpc(endpoint, method, params=None, *, timeout=3.0):
        if endpoint.node_id in unavailable:
            raise OSError("offline")
        return {
            "eth_chainId": hex(4242),
            "eth_blockNumber": hex(12),
            "net_peerCount": hex(3),
            "eth_syncing": False,
        }.get(method, {"hash": h("a")})

    monkeypatch.setattr(network, "rpc", fake_rpc)
    all_live = network.observe_network(ENDPOINTS, expected_chain_id=4242, expected_genesis_hash=h("a"))
    assert all_live.agreement == NetworkAgreement.ALL_AGREE
    assert all_live.common_height == 12
    assert all(node.available for node in all_live.nodes)

    unavailable.add("node4")
    partial = network.observe_network(ENDPOINTS, expected_chain_id=4242, expected_genesis_hash=h("a"))
    assert partial.agreement == NetworkAgreement.PARTIAL_AGREEMENT
    assert sum(node.available for node in partial.nodes) == 3


def test_network_observation_detects_wrong_chain_and_disagreement(monkeypatch):
    def wrong_chain(endpoint, method, params=None, *, timeout=3.0):
        if method == "eth_chainId":
            return hex(1 if endpoint.node_id == "node4" else 4242)
        if method in {"eth_blockNumber", "net_peerCount"}:
            return hex(8 if method == "eth_blockNumber" else 3)
        if method == "eth_syncing":
            return False
        return {"hash": h("a")}

    monkeypatch.setattr(network, "rpc", wrong_chain)
    assert network.observe_network(ENDPOINTS).agreement == NetworkAgreement.WRONG_NETWORK

    def divergent(endpoint, method, params=None, *, timeout=3.0):
        if method == "eth_chainId":
            return hex(4242)
        if method in {"eth_blockNumber", "net_peerCount"}:
            return hex(8 if method == "eth_blockNumber" else 3)
        if method == "eth_syncing":
            return False
        return {"hash": h("b" if params and endpoint.node_id == "node4" else "a")}

    monkeypatch.setattr(network, "rpc", divergent)
    assert network.observe_network(ENDPOINTS).agreement == NetworkAgreement.DISAGREEMENT


def test_multinode_anchor_policy_requires_all_nodes_by_default(monkeypatch):
    class FakeAnchor:
        def __init__(self, config, *, web3):
            self.web3 = web3

        def verify_anchor(self, request, receipt):
            state = AnchorState.FAILED if self.web3.endswith("8604") else AnchorState.CONFIRMED
            return SimpleNamespace(state=state, detail=f"{self.web3} {state.value}")

    monkeypatch.setattr(multinode, "EvmAnchor", FakeAnchor)
    monkeypatch.setattr(besu, "besu_web3", lambda rpc_url: rpc_url)
    request = InspectionAnchorRequest(h("1"), h("2"), h("3"), h("4"))
    receipt = AnchorReceipt(AnchorState.CONFIRMED, AnchorStage.INSPECTION, h("1"))
    common = dict(
        endpoints=ENDPOINTS,
        expected_chain_id=4242,
        contract_address="0x" + "5" * 40,
        expected_code_hash=h("6"),
        expected_contract_version="ghostframe-anchor/1.0",
    )
    strict = multinode.verify_anchor_across_nodes(request, receipt, **common)
    quorum = multinode.verify_anchor_across_nodes(request, receipt, required_nodes=3, **common)
    assert strict.state == AnchorState.FAILED and strict.verified_nodes == 3
    assert quorum.state == AnchorState.CONFIRMED and quorum.verified_nodes == 3

