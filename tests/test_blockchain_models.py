from __future__ import annotations

import dataclasses
import json

import pytest

from ghostframe.blockchain.models import (
    AnchorReceipt,
    AnchorStage,
    AnchorState,
    BlockchainConfig,
    InspectionAnchorRequest,
    VerificationAnchorRequest,
)


def h(char: str) -> str:
    return "0x" + char * 64


def test_commitment_models_accept_only_fixed_nonzero_bytes32_values():
    request = InspectionAnchorRequest(h("1"), h("2"), h("3"), h("4"))
    assert list(request.to_dict()) == ["operation_commitment", "source_file_hash", "inspection_commitment", "schema_commitment"]
    for bad in ("", "1" * 64, "0x" + "0" * 64, "0x" + "A" * 64, "0x1234"):
        with pytest.raises(ValueError):
            InspectionAnchorRequest(bad, h("2"), h("3"), h("4"))


def test_receipt_is_canonical_public_only_serialization():
    receipt = AnchorReceipt(AnchorState.CONFIRMED, AnchorStage.INSPECTION, h("1"), confirmations=1)
    raw = receipt.to_json_bytes()
    assert raw == json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    assert set(receipt.to_dict()) == {
        "receipt_version", "state", "stage", "chain_id", "contract_address", "contract_code_hash",
        "contract_version", "transaction_hash", "block_number", "block_hash", "log_index",
        "confirmations", "submitter_address", "operation_commitment", "failure_category", "detail",
    }
    assert AnchorReceipt.from_dict(receipt.to_dict()) == receipt
    with pytest.raises(ValueError):
        AnchorReceipt.from_dict({**receipt.to_dict(), "passphrase": "synthetic-secret"})


def test_config_is_disabled_by_default_and_restricts_phase5_to_loopback():
    assert BlockchainConfig().enabled is False
    common = dict(
        enabled=True, expected_chain_id=31337, contract_address="0x" + "11" * 20,
        expected_code_hash=h("2"),
    )
    assert BlockchainConfig(rpc_url="http://127.0.0.1:8545", **common).enabled
    for url in (
        "https://rpc.example.test", "file:///tmp/socket", "http://user:secret@127.0.0.1:8545",
        "http://127.0.0.1:8545/path", "http://127.0.0.1:8545/?token=secret",
    ):
        with pytest.raises(ValueError):
            BlockchainConfig(rpc_url=url, **common)


def test_privacy_boundary_models_have_no_sensitive_application_fields():
    forbidden = {
        "gps", "username", "author", "email", "exif", "comment", "filename", "document",
        "evidence", "passphrase", "encryption_key", "private_key", "metadata", "blob",
    }
    field_names = set()
    for model in (InspectionAnchorRequest, VerificationAnchorRequest, AnchorReceipt, BlockchainConfig):
        field_names.update(field.name.lower() for field in dataclasses.fields(model))
    assert "rpc_url" in field_names
    assert not any(term in name for term in forbidden for name in field_names)


def test_synthetic_sensitive_values_cannot_enter_requests_or_receipts():
    sensitive = ["author@example.test", "51.5007,-0.1246", "synthetic-user", "private-file.pdf", "synthetic comment"]
    request = VerificationAnchorRequest(h("1"), h("5"), h("6"), h("7"))
    receipt = AnchorReceipt(AnchorState.CONFIRMED, AnchorStage.VERIFICATION, h("1"), confirmations=1)
    public = json.dumps({"request": request.to_dict(), "receipt": receipt.to_dict()}, sort_keys=True)
    assert all(value not in public for value in sensitive)
