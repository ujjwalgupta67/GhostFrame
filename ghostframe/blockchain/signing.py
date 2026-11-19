from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class TransactionSigner(Protocol):
    """Server-side transaction signer. Implementations never expose key bytes."""

    @property
    def address(self) -> str: ...

    def submit(self, web3: Any, transaction_builder: Any) -> Any: ...


@dataclass(frozen=True)
class LocalDevelopmentSigner:
    """Sign a transaction locally for an isolated loopback development chain."""

    _private_key: str = field(repr=False)
    chain_id: int
    gas_price_wei: int = 0

    def __post_init__(self) -> None:
        if self.chain_id <= 0:
            raise ValueError("Signer chain ID must be positive.")
        if self.gas_price_wei < 0:
            raise ValueError("Gas price cannot be negative.")
        try:
            from eth_account import Account

            Account.from_key(self._private_key)
        except Exception as exc:
            raise ValueError("Local development signer configuration is invalid.") from exc

    @property
    def address(self) -> str:
        from eth_account import Account

        return str(Account.from_key(self._private_key).address)

    @classmethod
    def from_environment(
        cls, variable: str, *, chain_id: int, gas_price_wei: int = 0,
    ) -> "LocalDevelopmentSigner":
        import os

        private_key = os.environ.get(variable)
        if not private_key:
            raise RuntimeError(
                f"Set {variable} in the server environment before using four-node signing."
            )
        return cls(private_key, chain_id, gas_price_wei)

    def submit(self, web3: Any, transaction_builder: Any) -> Any:
        """Build once, sign once, and submit once; callers recover by transaction hash."""

        if int(web3.eth.chain_id) != self.chain_id:
            raise RuntimeError("Local signer refused a transaction for the wrong chain.")
        nonce = int(web3.eth.get_transaction_count(self.address, "pending"))
        base = {
            "from": self.address,
            "nonce": nonce,
            "chainId": self.chain_id,
            "gasPrice": self.gas_price_wei,
        }
        estimate = int(transaction_builder.estimate_gas(base))
        transaction = transaction_builder.build_transaction({
            **base,
            "gas": max(21_000, int(estimate * 1.25) + 5_000),
        })
        signed = web3.eth.account.sign_transaction(transaction, self._private_key)
        return web3.eth.send_raw_transaction(signed.raw_transaction)
