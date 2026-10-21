from __future__ import annotations

import json

import pytest
from streamlit.testing.v1 import AppTest

from ghostframe.blockchain.memory import InMemoryAnchor
from ghostframe.blockchain.models import AnchorState
from ghostframe.blockchain.ui import (
    LocalBlockchainUIError,
    LocalEVMSettings,
    check_local_evm_health,
    create_local_evm_adapter,
    validate_local_rpc_url,
)
from ghostframe.evidence import VerificationState, parse_evidence_package
from ghostframe.evidence.ui import generate_evidence_once, verify_package_for_ui
from tests.evidence_support import PASSPHRASE
from tests.test_evidence_lifecycle import FIXTURES, _png


SAFE_URLS = (
    "http://127.0.0.1:8545",
    "http://localhost:8545",
    "http://[::1]:8545",
    "https://127.0.0.1:9545",
)
UNSAFE_URLS = (
    "https://example.com:8545",
    "http://8.8.8.8:8545",
    "http://169.254.169.254:80",
    "http://192.168.1.10:8545",
    "ftp://127.0.0.1:8545",
    "http://user:secret@127.0.0.1:8545",
    "http://127.0.0.1:8545/path",
)


@pytest.mark.parametrize("value", SAFE_URLS)
def test_local_rpc_policy_accepts_only_explicit_loopback_http_endpoints(value):
    assert validate_local_rpc_url(value) == value


@pytest.mark.parametrize("value", UNSAFE_URLS)
def test_local_rpc_policy_rejects_unsafe_targets_without_requesting_them(value):
    with pytest.raises(LocalBlockchainUIError):
        validate_local_rpc_url(value)


def _settings() -> LocalEVMSettings:
    return LocalEVMSettings(
        "http://127.0.0.1:8545", 31337, "0x" + "11" * 20,
        "0x" + "22" * 32, "ghostframe-anchor/1.0", 1,
    )


def test_health_uses_adapter_boundary_and_never_requires_web3_for_test_double():
    adapter = InMemoryAnchor()
    health = check_local_evm_health(_settings(), factory=lambda config: adapter)
    assert health.state == AnchorState.CONFIRMED
    assert create_local_evm_adapter(_settings(), factory=lambda config: adapter) is adapter


def test_blockchain_generation_is_explicit_cached_and_never_resubmits_on_rerun():
    source, name = _png()
    state = {}
    adapter = InMemoryAnchor()
    first = generate_evidence_once(
        state, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False, blockchain_anchor=adapter,
        blockchain_fingerprint=_settings().fingerprint(),
    )
    transaction_count = adapter._sequence
    second = generate_evidence_once(
        state, source_data=source, source_name=name, passphrase="",
        confirmation="", use_exiftool=False, blockchain_anchor=adapter,
        blockchain_fingerprint=_settings().fingerprint(),
    )
    assert first is second
    assert adapter._sequence == transaction_count == 2
    assert parse_evidence_package(first.evidence_package).package_version == "ghostframe-gfp/2.0"


def test_v2_offline_then_current_recheck_preserves_package_bytes():
    source, name = _png()
    adapter = InMemoryAnchor()
    generated = generate_evidence_once(
        {}, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False, blockchain_anchor=adapter,
        blockchain_fingerprint=_settings().fingerprint(),
    )
    original = generated.evidence_package
    offline = verify_package_for_ui(package=original, passphrase=PASSPHRASE)
    assert offline.locally_verified
    assert offline.recorded_inspection_anchor_state == "CONFIRMED"
    assert offline.inspection_blockchain_anchor.state == VerificationState.NOT_CHECKED
    online = verify_package_for_ui(package=original, passphrase=PASSPHRASE, blockchain_anchor=adapter)
    assert online.inspection_blockchain_anchor.state == VerificationState.VERIFIED
    assert online.verification_blockchain_anchor.state == VerificationState.VERIFIED
    assert generated.evidence_package == original
    assert adapter._sequence == 2


@pytest.mark.parametrize("fixture", FIXTURES, ids=["jpeg", "png", "pdf", "docx"])
def test_ui_controller_all_formats_keep_sensitive_values_out_of_public_receipts(fixture):
    source, name = fixture()
    adapter = InMemoryAnchor()
    generated = generate_evidence_once(
        {}, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False, blockchain_anchor=adapter,
        blockchain_fingerprint=_settings().fingerprint(),
    )
    parsed = parse_evidence_package(generated.evidence_package)
    public = json.dumps(parsed.manifest, sort_keys=True) + json.dumps(parsed.receipts, sort_keys=True)
    assert name not in public
    for sensitive in ("Synthetic Author", "Synthetic Reviewer", "user@example.invalid", "12.3456,78.9012"):
        assert sensitive not in public
    assert generated.inspection_anchor.state == AnchorState.CONFIRMED
    assert generated.verification_anchor.state == AnchorState.CONFIRMED


def test_streamlit_modes_and_local_development_labels_are_explicit():
    app = AppTest.from_file("app.py", default_timeout=20).run()
    workflow = next(item for item in app.radio if item.label == "Workflow")
    assert workflow.value == "Local Privacy Mode"
    assert "Local Blockchain-Anchored Evidence Mode" in workflow.options
    workflow.set_value("Local Blockchain-Anchored Evidence Mode")
    next(button for button in app.button if button.label == "Learn using a synthetic example").click()
    app.run()
    assert not app.exception
    assert any("LOCAL EVM / DEVELOPMENT MODE" in item.value for item in app.warning)
    assert any(item.label == "Test local blockchain connection" for item in app.button)
    assert not any("private key" in item.label.lower() or "mnemonic" in item.label.lower() for item in app.text_input)


def test_ui_controller_real_local_evm_generation_and_restart_reverification():
    pytest.importorskip("web3")
    pytest.importorskip("eth_tester")
    from web3 import EthereumTesterProvider, Web3
    from ghostframe.blockchain.evm import EvmAnchor

    adapter = EvmAnchor.deploy(Web3(EthereumTesterProvider()))
    source, name = _png()
    first_session = {}
    generated = generate_evidence_once(
        first_session, source_data=source, source_name=name, passphrase=PASSPHRASE,
        confirmation=PASSPHRASE, use_exiftool=False, blockchain_anchor=adapter,
        blockchain_fingerprint="local-evm-test",
    )
    downloaded = bytes(generated.evidence_package)
    first_session.clear()  # Simulated Streamlit restart.
    offline = verify_package_for_ui(package=downloaded, passphrase=PASSPHRASE)
    assert offline.locally_verified
    assert offline.inspection_blockchain_anchor.state == VerificationState.NOT_CHECKED
    current = verify_package_for_ui(package=downloaded, passphrase=PASSPHRASE, blockchain_anchor=adapter)
    assert current.inspection_blockchain_anchor.state == VerificationState.VERIFIED
    assert current.verification_blockchain_anchor.state == VerificationState.VERIFIED
    assert downloaded == generated.evidence_package
