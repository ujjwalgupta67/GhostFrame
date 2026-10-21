# GhostFrame evidence formats

These are versioned security protocols. Once released, the meaning or encoding of an existing version must not change. Incompatible changes require a new version.

## Encrypted evidence (`ghostframe-gfe/1.0`)

Binary layout, in network byte order:

```text
8 bytes   magic: GFE 00 01 0D 0A 1A
4 bytes   canonical JSON header length
8 bytes   ciphertext length
N bytes   canonical JSON header
M bytes   AES-256-GCM ciphertext with its 16-byte authentication tag
```

The AES-GCM additional authenticated data is the complete fixed prefix plus the canonical header. The header declares the evidence and canonicalization versions, AES-256-GCM, a 12-byte base64 nonce, Scrypt, its versioned parameters, and a 16-byte base64 salt. Unknown versions or algorithms fail closed.

The plaintext is exactly the Phase 1 canonical JSON bytes for one `EvidenceRecord`. Plaintext is never written to a temporary file.

Scrypt defaults are `N=32768`, `r=8`, `p=1`, and a 32-byte output. The estimated core Scrypt memory is approximately 32 MiB. Parsing accepts only power-of-two `N` from 16384 through 131072, `r` from 1 through 16, `p` from 1 through 4, a 32-byte output, and at most 256 MiB estimated core memory. Bounds are checked before key derivation.

Every production encryption uses a fresh OS-generated salt and nonce. Passphrases must contain at least 12 characters. There is no recovery, escrow, developer key, or master key.

## Audit chain (`ghostframe-audit/1.0`)

Events commit to their version, zero-based sequential index, event type, public operation commitment, UTC timestamp, optional non-sensitive payload commitment, and previous event hash using `GhostFrame/audit-event/v1`.

The genesis previous hash is exactly 64 ASCII zeroes. Each later event uses the preceding event hash. Modification, middle deletion, duplication, reordering, sequence gaps, operation substitution, and invalid hashes are detectable.

One chain is limited to 256 events before parsing or appending further events.

A valid local chain without an externally retained expected head cannot prove that its tail was not truncated. The verifier reports this limitation explicitly.

## Evidence package (`ghostframe-gfp/1.0`)

One operation per ZIP package, with exactly:

```text
manifest.json
evidence.gfe
receipts.json
```

The public manifest contains only format identifiers, public commitments, and the expected SHA-256 and size of `evidence.gfe` and `receipts.json`. It contains no filename or raw metadata. `receipts.json` contains the minimal audit chain and explicit `NOT_APPLICABLE` blockchain states; Phase 2 never invents blockchain receipts.

The manifest detects individual member substitution. AES-GCM authenticates the encrypted evidence. The audit chain authenticates its internal ordering. Complete replacement by another valid package requires an externally retained expected operation commitment to detect; future blockchain anchoring will provide that external binding.

Version 1 is immutable. It accepts only `ghostframe-receipts/1.0` and the two
exact `NOT_APPLICABLE` placeholders. A parser never interprets a v2 receipt
under v1 rules.

## Blockchain-aware evidence package (`ghostframe-gfp/2.0`)

Version 2 retains the same three-member ZIP topology and all v1 resource
limits. Its `receipts.json` uses `ghostframe-receipts/2.0` and stores two strict
`ghostframe-blockchain-receipt/1.0` objects: inspection and verification. Each
receipt is bound to the manifest's operation commitment and its exact lifecycle
stage. State-specific validation rejects incomplete confirmed identities,
fabricated fields on `NOT_REQUESTED`, incoherent block identities, disabled v1
placeholders, and cross-version combinations.

The canonical JSON receipts object has exactly these required keys:

```text
audit_chain       object  ghostframe-audit/1.0 object
blockchain        object  exactly inspection_anchor and verification_anchor
receipts_version  string  exactly ghostframe-receipts/2.0
```

Each anchor object has exactly these required keys (nullable means the JSON
value may be `null`; keys are never omitted):

```text
receipt_version       string       ghostframe-blockchain-receipt/1.0
state                 string       NOT_REQUESTED | PENDING | CONFIRMED | FAILED
stage                 string       INSPECTION | VERIFICATION
chain_id              integer|null positive when present
contract_address      string|null  20-byte hexadecimal address
contract_code_hash    string|null  lowercase 0x-prefixed bytes32
contract_version      string|null
transaction_hash      string|null  lowercase 0x-prefixed bytes32
block_number          integer|null non-negative when present
block_hash            string|null  lowercase 0x-prefixed bytes32
log_index             integer|null non-negative when present
confirmations         integer      non-negative depth observed at creation
submitter_address     string|null  20-byte hexadecimal address
operation_commitment  string       lowercase non-zero 0x-prefixed bytes32
failure_category      string|null  supported failure enum
detail                string       generic public-safe explanation
```

`CONFIRMED` requires complete chain, contract, transaction, block, event, and
submitter identity with at least one observed confirmation. `PENDING` requires
chain/contract/transaction/submitter identity and
`INSUFFICIENT_CONFIRMATIONS`; its block triple is either complete or wholly
absent. `FAILED` requires a category and never fabricates identity fields.
`NOT_REQUESTED` requires every chain/transaction identity field to be null and
zero confirmations. `DISABLED` is deliberately excluded from v2: disabled
operations are represented by v1.

The v2 manifest has the same exact fields and descriptor shapes as v1. Its
`package_version` is `ghostframe-gfp/2.0`, and the `receipts.json` member
descriptor declares `ghostframe-receipts/2.0`. Manifest and receipts JSON must
be canonical UTF-8 JSON with sorted keys and no insignificant whitespace;
duplicate keys, non-canonical encodings, unknown fields, and unsupported
versions fail closed. Member SHA-256 and byte length cover the exact stored
member bytes.

The receipt `confirmations` value is the count observed when the package was
created. It is historical evidence, not a claim about current chain state.
Offline verification reports the recorded states and marks current blockchain
checks `NOT_CHECKED`. Online verification requires a separately supplied
adapter and configuration, reconstructs requests from authenticated evidence,
and queries that independent source. Receipt contents are never a trust root.

The inspection transaction is attempted only after inspection evidence is
finalized and before sanitization begins. The verification transaction is
attempted only after local verification and the final lifecycle commitment.
Blockchain failure never invalidates otherwise valid local evidence. A failed
inspection records verification as `NOT_REQUESTED`; confirmed and pending
inspection submissions may proceed to the verification attempt, where the
adapter and contract state enforce ordering.

Blockchain controller events are an outer, privacy-safe lifecycle log. They are
not inserted into `ghostframe-audit/1.0`, because placing a transaction receipt
inside the evidence chain whose head is itself anchored would create a circular
commitment and would change the released audit protocol.

Limits are centralized in `package.py`: exactly 3 entries, 36 MiB compressed package, 34 MiB expanded content, 32 KiB manifest, 2 MiB receipts, bounded encrypted evidence, and maximum 100:1 compression ratio for members of at least 1 MiB. Parsing never calls `extractall()`.

## Verification semantics

Checks independently report `VERIFIED`, `FAILED`, `NOT_PROVIDED`, `NOT_APPLICABLE`, or `NOT_CHECKED`. Missing source or sanitized bytes are never described as verified. Matching file hashes prove byte equality to the recorded artifact, not authorship, origin, ownership, or truthfulness of metadata. Blockchain checks are `NOT_APPLICABLE` for v1, `NOT_CHECKED` for offline v2 verification, and independently evaluated when a verifier adapter is supplied.
