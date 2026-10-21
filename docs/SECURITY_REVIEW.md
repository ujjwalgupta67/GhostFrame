# GhostFrame 2.2.0 Final Security Review

## Review result

The release-candidate source was reviewed for upload parsing, XML/ZIP/PDF/image handling, evidence cryptography, GFP parsing, persistence, Streamlit boundaries, subprocess execution, local RPC handling, release packaging and the smart contract. No confirmed application-code vulnerability remained after review. Scanner observations were classified as follows:

| Observation | Classification | Rationale |
|---|---|---|
| Base dependency advisories in the Phase 7 pins | FIXED | Streamlit, Pillow and cryptography were advanced only to consolidated fixed pins; complete regression and clean-install gates were rerun |
| Optional ExifTool subprocess | ACCEPTED RISK | Optional only; resolved executable path, argument list with `shell=False`, timeout, bounded output, randomized temporary file and cleanup |
| Release-builder `extractall` | FALSE POSITIVE | It extracts only the builder's own allow-listed archive after rejecting absolute and parent paths |
| Streamlit `unsafe_allow_html` | FALSE POSITIVE | Static layout or values passed through `html.escape`; raw file-derived values are rendered with normal Streamlit text components |
| Broad exception handling | ACCEPTED RISK | Trust-boundary failures are intentionally converted to non-sensitive status messages and local sanitization is isolated from anchoring failure |
| Loopback HTTP RPC | ACCEPTED RISK | Explicit local-development model; URL validation permits only loopback and identity checks bind chain, contract, code and interface |

`pip check` reported no broken requirements. The final `pip-audit` run must be read together with the exact release pins; no blind or untested upgrade is accepted.

## Cryptographic review

- GFE uses AES-256-GCM with a fresh OS-generated 12-byte nonce and 16-byte salt.
- Scrypt defaults to `N=32768, r=8, p=1`; parsing accepts only bounded power-of-two costs with a 256 MB memory ceiling.
- The complete canonical header and length prefix are authenticated as AAD.
- Wrong passphrases and byte/header modification fail authentication.
- Canonical JSON rejects duplicates, floating-point/non-finite values and non-canonical encodings.
- Domain-separated commitments bind evidence, inspection, schema and lifecycle meanings.
- Audit events bind index, previous hash, operation, timestamp, event type and optional payload commitment.
- Production paths contain no fixed nonce, hardcoded key, plaintext evidence persistence, or passphrase/key logging.

Python cannot guarantee immediate erasure of immutable strings, derived keys or cryptographic buffers from process memory.

## GFP package review

GFP 1.0 and 2.0 require exactly `manifest.json`, `evidence.gfe` and `receipts.json`. Parsing rejects duplicate members, unsafe/absolute/parent paths, backslashes, symlinks, special files, encrypted ZIP members, excessive entry/member/expanded/compressed sizes, excessive compression ratios, non-canonical JSON, hash/size mismatches, unknown future versions, v1/v2 confusion, malformed receipt states, receipt substitution and cross-operation receipts.

## Smart-contract review

`GhostFrameAnchor` has no payable entry point, fallback, receive function, external call or dynamic delegate call; unexpected ETH transfers revert and reentrancy is not relevant. Inspection requires four non-zero commitments and is write-once. Verification requires an existing inspection, the same submitter, four non-zero values and is write-once. Events mirror state. Solidity 0.8.30 supplies checked integer behavior; timestamps are block observations rather than trusted wall-clock time. The first inspection submitter controls the second stage, so hostile-mempool front-running is a documented residual risk outside the supported local-EVM model. Chain/contract replay is rejected by the client-side verification domain checks.

## Accepted contract identity

| Property | Value |
|---|---|
| Solidity source SHA-256 | `87acee5282f5aa06d66265e84bed20024b56bb59ff34cd360d648a1a7b69e5fd` |
| Compiled artifact SHA-256 | `7a655902a8f273dcd4b5c5bf42a0b29fe2f21a70ab0764ade13a15db1dcad177` |
| Runtime bytecode SHA-256 | `0x06861ae7af83ca73b1922e08b5f9321a82649795a28c190163bcec3c4b2dc021` |
| Interface version | `ghostframe-anchor/1.0` |
| Compiler | `solc-0.8.30` |
| Optimizer | enabled, 200 runs |
| Metadata | bytecode hash disabled; CBOR append disabled |

The contract source and accepted artifact were not changed during Phase 8.
