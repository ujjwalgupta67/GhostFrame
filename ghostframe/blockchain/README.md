# GhostFrame optional blockchain anchoring

This package is an optional, isolated commitment registry. The backend evidence
lifecycle can use it through explicit dependency injection; the Streamlit
interface remains unconnected to a chain. Normal GhostFrame remains fully
offline, requires only `requirements.txt`, and creates immutable v1 packages.

## Architecture and privacy boundary

`BlockchainAnchor` accepts only typed, non-zero `bytes32` commitments. The
disabled adapter is the production-safe default, `InMemoryAnchor` is a
deterministic state-machine test double, and `EvmAnchor` talks to the pinned
`GhostFrameAnchor` contract on a configured loopback EVM.

The contract stores an inspection submitter and block timestamp plus:

- operation commitment, source-file SHA-256, inspection commitment, and schema commitment;
- later, sanitized-file SHA-256, verification commitment, and final lifecycle commitment.

It never receives filenames, metadata, GPS, author/email values, document
content, evidence plaintext or ciphertext, passphrases, encryption keys, or
private keys. File hashes can still permit known-file correlation when another
party already has identical bytes.

## Contract and ownership model

`GhostFrameAnchor.sol` is compiled with pinned Solidity 0.8.30, optimizer 200,
and compiler metadata disabled. It has no payable function, fallback, receive,
external calls, administrator, proxy, token, NFT, withdrawal, or upgrade path.

An operation's inspection anchor can be registered once. Its verification
anchor requires that inspection, can be registered once, and must be submitted
by the same address. Timestamps come only from `block.timestamp`. Existing
values have no mutation function.

The committed artifact contains only the ABI, creation/runtime bytecode,
compiler and interface versions, and source/runtime hashes. Compilation is a
development action and never runs during application startup.

## Identity and confirmation semantics

Before interaction, the EVM adapter checks the configured RPC chain ID,
contract address, exact SHA-256 of deployed runtime bytecode, and
`CONTRACT_VERSION`. A receipt is `CONFIRMED` only after all of these checks plus:

- successful transaction status;
- the expected event exactly once with matching arguments;
- matching stored state;
- the configured confirmation count.

Until enough blocks exist, the receipt is `PENDING`. A transaction hash alone
is never treated as proof. Serialized receipts bind the chain, contract,
runtime identity, interface version, operation, stage, transaction, block,
event index, submitter, and confirmation count. These objects are serialized
only in `ghostframe-gfp/2.0` with `ghostframe-receipts/2.0`. The historical
confirmation count is kept separate from a verifier's current independently
queried state. `.gfp` v1 is unchanged.

## Local development

Install the optional development dependencies separately:

```sh
python -m pip install -r requirements-blockchain.txt
```

Automated tests use `eth-tester` with `py-evm`, require no network or real
currency, and use ephemeral funded accounts. For manual Anvil use, start Anvil
on its default loopback endpoint and deploy with an unlocked development
account:

```sh
anvil
python scripts/deploy_local_anchor.py --rpc http://127.0.0.1:8545
```

The deployment command prints only public deployment information. It does not
accept or persist a private key. Do not reuse Anvil development accounts or
mnemonics outside local testing.

In Streamlit, select **Local Blockchain-Anchored Evidence Mode** and enter the
deployment command's public values. Phase 7 UI configuration is deliberately
stricter than a general network client: only `localhost`, `127.0.0.1`, or `::1`
with an explicit HTTP(S) port is accepted. Public hosts, LAN addresses,
link-local metadata endpoints, embedded credentials, URL paths, queries, and
fragments are rejected without being contacted.

The connection test delegates chain, contract-code, and interface checks to
`EvmAnchor.health()`. An unlocked account address may be shown as a **LOCAL
DEVELOPMENT ACCOUNT**; GhostFrame does not manage its key. There is no automatic
RPC discovery, transaction submission, retry, public explorer link, or public
network configuration.

For existing GFP 2.0 packages, offline verification shows historical receipt
states and reports current state as `NOT_CHECKED`. The explicit **Re-check
blockchain status** action rebuilds expected requests from authenticated
evidence and verifies them against independently entered local configuration.
It does not mutate or regenerate any artifact and does not resubmit a
transaction.

To rebuild the committed artifact, explicitly install the pinned compiler and
compile:

```sh
python scripts/compile_anchor_contract.py --install-solc
```

Ordinary execution never downloads a compiler. A rebuild without the explicit
flag refuses to download anything.

## Configuration and failure isolation

`BlockchainConfig` is disabled by default. The EVM adapter accepts only loopback
HTTP(S) RPC URLs without embedded credentials, paths, queries, or fragments.
Enabled configuration requires an expected chain ID, contract address, runtime
code hash, interface version, confirmation count, and receipt timeout. No real
key belongs in configuration or the repository.

RPC unavailability/timeouts, wrong chain/address/code/version, rejected or
reverted transactions, missing/malformed receipts, unexpected or mismatched
events, state mismatches, and insufficient confirmations become structured
states. They do not modify GhostFrame files or evidence.

Verification reflects the configured RPC's view of the expected chain. A
malicious or compromised RPC can lie; this is not independent consensus
verification.

## Front-running and limitations

The first inspection submitter owns the corresponding verification transition.
An observer who learns an operation commitment before confirmation could try to
register it first. GhostFrame operation commitments are derived from random
UUIDv4 operation identifiers, so guessing an unseen commitment is intended to
be impractical, but exposure before submission still creates a residual
front-running risk. Commit-reveal or authenticated submitter binding may be
considered before any public-chain deployment.

Local timestamps are miner/sequencer-controlled within EVM rules and are not a
trusted wall-clock oracle. A v2 receipt records an adapter result; only current
verification through independently supplied configuration checks the present
RPC view. None of this proves authorship, identity, ownership, or metadata truth.
