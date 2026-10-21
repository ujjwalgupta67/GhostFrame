from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from .interface import BlockchainAnchor
from .models import AnchorHealth, BlockchainConfig, CONTRACT_INTERFACE_VERSION


class LocalBlockchainUIError(ValueError):
    """Concise, public-safe local-development configuration error."""


@dataclass(frozen=True)
class LocalEVMSettings:
    rpc_url: str
    chain_id: int
    contract_address: str
    contract_code_hash: str
    contract_version: str = CONTRACT_INTERFACE_VERSION
    confirmations: int = 1

    def fingerprint(self) -> str:
        return ":".join((
            self.rpc_url, str(self.chain_id), self.contract_address.lower(),
            self.contract_code_hash.lower(), self.contract_version,
            str(self.confirmations),
        ))


def validate_local_rpc_url(value: str) -> str:
    """Allow HTTP(S) loopback RPC endpoints only; never makes a request."""

    try:
        parsed = urlparse(value)
        host = parsed.hostname
        address = ipaddress.ip_address(host) if host not in {None, "localhost"} else None
    except ValueError as exc:
        raise LocalBlockchainUIError("Use a valid loopback HTTP(S) RPC URL.") from exc
    if parsed.scheme not in {"http", "https"} or host is None:
        raise LocalBlockchainUIError("Local EVM RPC must use HTTP or HTTPS.")
    if parsed.username or parsed.password:
        raise LocalBlockchainUIError("RPC credentials are not accepted or stored by this local-development UI.")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise LocalBlockchainUIError("Local EVM RPC URLs cannot contain paths, queries, or fragments.")
    if host != "localhost" and (address is None or not address.is_loopback):
        raise LocalBlockchainUIError("Phase 7 accepts loopback RPC endpoints only.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise LocalBlockchainUIError("Use a valid local EVM RPC port.") from exc
    if port is None:
        raise LocalBlockchainUIError("Specify the local EVM RPC port explicitly.")
    return value


def create_local_evm_adapter(
    settings: LocalEVMSettings,
    *,
    factory: Callable[[BlockchainConfig], BlockchainAnchor] | None = None,
) -> BlockchainAnchor:
    validate_local_rpc_url(settings.rpc_url)
    try:
        config = BlockchainConfig(
            enabled=True,
            rpc_url=settings.rpc_url,
            expected_chain_id=settings.chain_id,
            contract_address=settings.contract_address,
            expected_code_hash=settings.contract_code_hash,
            expected_contract_version=settings.contract_version,
            confirmations_required=settings.confirmations,
        )
        if factory is not None:
            return factory(config)
        from .evm import EvmAnchor

        return EvmAnchor(config)
    except (TypeError, ValueError) as exc:
        raise LocalBlockchainUIError("Local EVM configuration is incomplete or invalid.") from exc
    except RuntimeError as exc:
        raise LocalBlockchainUIError("Install requirements-blockchain.txt to use local blockchain mode.") from exc


def check_local_evm_health(settings: LocalEVMSettings, *, factory=None) -> AnchorHealth:
    return create_local_evm_adapter(settings, factory=factory).health()


def local_development_account(adapter: BlockchainAnchor) -> str | None:
    """Return only the public unlocked development address, when exposed."""

    try:
        accounts = adapter.web3.eth.accounts  # type: ignore[attr-defined]
        return str(accounts[0]) if accounts else None
    except Exception:
        return None
