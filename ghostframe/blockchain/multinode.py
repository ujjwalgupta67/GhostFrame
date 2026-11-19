from __future__ import annotations

from .evm import EvmAnchor
from .models import AnchorReceipt, AnchorRequest, AnchorStage, AnchorState, BlockchainConfig, InspectionAnchorRequest
from .network_models import MultiNodeAnchorVerification, NodeAnchorVerification, NodeEndpoint


def verify_anchor_across_nodes(
    request: AnchorRequest, receipt: AnchorReceipt,
    endpoints: tuple[NodeEndpoint, ...], *, expected_chain_id: int,
    contract_address: str, expected_code_hash: str,
    expected_contract_version: str, required_nodes: int | None = None,
    receipt_timeout_seconds: int = 5, expected_genesis_hash: str | None = None,
) -> MultiNodeAnchorVerification:
    stage = AnchorStage.INSPECTION if isinstance(request, InspectionAnchorRequest) else AnchorStage.VERIFICATION
    required = len(endpoints) if required_nodes is None else required_nodes
    results: list[NodeAnchorVerification] = []
    for endpoint in endpoints:
        try:
            # Besu QBFT block headers have a longer extraData field than
            # Ethereum mainnet.  Use the same PoA-aware Web3 client as the
            # main Besu adapter so canonical-block verification works on
            # every node.
            from .besu import besu_web3

            web3 = besu_web3(endpoint.rpc_url)
            if expected_genesis_hash is not None:
                genesis_hash = "0x" + bytes(web3.eth.get_block(0)["hash"]).hex()
                if genesis_hash.lower() != expected_genesis_hash.lower():
                    raise ValueError("Node genesis hash does not match the deployment manifest.")
            config = BlockchainConfig(
                enabled=True, rpc_url=endpoint.rpc_url, expected_chain_id=expected_chain_id,
                contract_address=contract_address, expected_code_hash=expected_code_hash,
                expected_contract_version=expected_contract_version,
                receipt_timeout_seconds=receipt_timeout_seconds,
            )
            result = EvmAnchor(config, web3=web3).verify_anchor(request, receipt)
            results.append(NodeAnchorVerification(endpoint.node_id, endpoint.label, stage, result.state, result.detail))
        except Exception:
            results.append(NodeAnchorVerification(endpoint.node_id, endpoint.label, stage, AnchorState.FAILED, "Node verification was unavailable."))
    verified = sum(item.state == AnchorState.CONFIRMED for item in results)
    pending = any(item.state == AnchorState.PENDING for item in results)
    if verified >= required:
        state = AnchorState.CONFIRMED
        detail = f"Anchor verified through {verified} of {len(endpoints)} configured nodes."
    elif pending:
        state = AnchorState.PENDING
        detail = f"Only {verified} of {required} required nodes verified; at least one result is pending."
    else:
        state = AnchorState.FAILED
        detail = f"Only {verified} of {required} required nodes verified."
    return MultiNodeAnchorVerification(stage, tuple(results), verified, required, state, detail)


def verify_package_across_nodes(
    package: bytes, passphrase: str, endpoints: tuple[NodeEndpoint, ...],
    *, expected_chain_id: int, contract_address: str, expected_code_hash: str,
    expected_contract_version: str, required_nodes: int | None = None,
    expected_genesis_hash: str | None = None,
) -> tuple[MultiNodeAnchorVerification, MultiNodeAnchorVerification]:
    """Authenticate a GFP 2.0 package, then verify both receipts at every node."""

    from ghostframe.evidence.anchoring import (
        inspection_anchor_request, lifecycle_commitment, verification_anchor_request,
    )
    from ghostframe.evidence.crypto import decrypt_evidence
    from ghostframe.evidence.package import parse_evidence_package

    parsed = parse_evidence_package(package)
    if parsed.inspection_receipt is None or parsed.verification_receipt is None:
        raise ValueError("Four-node verification requires a GFP 2.0 package.")
    record = decrypt_evidence(parsed.encrypted_evidence, passphrase)
    inspection = inspection_anchor_request(record)
    final_commitment = lifecycle_commitment(
        operation_commitment=record.public_operation_commitment,
        inspection_commitment=record.inspection_commitment(),
        evidence_verification_commitment=record.verification_commitment(),
        audit_head=parsed.audit_chain.head_hash or "",
    )
    verification = verification_anchor_request(record, final_lifecycle_commitment=final_commitment)
    common = dict(
        endpoints=endpoints, expected_chain_id=expected_chain_id,
        contract_address=contract_address, expected_code_hash=expected_code_hash,
        expected_contract_version=expected_contract_version, required_nodes=required_nodes,
        expected_genesis_hash=expected_genesis_hash,
    )
    return (
        verify_anchor_across_nodes(inspection, parsed.inspection_receipt, **common),
        verify_anchor_across_nodes(verification, parsed.verification_receipt, **common),
    )
