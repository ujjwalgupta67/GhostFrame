# GhostFrame 2.2.0 Threat Model

## Scope and objectives

GhostFrame protects supported metadata and evidence integrity while processing files locally. It does not prove identity, authorship, ownership, lawful provenance, visible-content safety, malware absence, or metadata truth. The supported blockchain model is a loopback local EVM with unlocked development accounts.

| Threat | Control | Residual risk | User/operator responsibility |
|---|---|---|---|
| Malicious upload or parser input | Magic-byte/type agreement, 25 MB input limit, image pixel limit, hardened library parsers and generic UI errors | Parser-library vulnerabilities and unsupported structures remain possible | Open only the sanitized output; keep dependencies patched |
| Malicious PDF | pikepdf parsing, size/type checks, reinspection | Complex visible content and unparsed structures can remain | Visually review rendered output |
| Malicious DOCX/ZIP, traversal, XML entities or decompression bomb | Entry/path/count/expanded-size limits, safe XML checks, no archive extraction, DOCTYPE/ENTITY rejection | Highly complex but limit-compliant documents can consume resources | Do not use GhostFrame as a malware sandbox |
| Malicious GFP, path/symlink/special member, duplicate or package substitution | Exact three-member allow-list, duplicate/path/type rejection, compressed/expanded/member/ratio limits, canonical JSON, member hashes | Resource use remains bounded rather than eliminated | Verify packages only from expected workflows |
| Malicious GFE or KDF exhaustion | Exact header schema, strict sizes, Scrypt bounds and AES-GCM authentication | Maximum accepted Scrypt parameters can still be intentionally slow | Avoid repeatedly testing untrusted containers |
| Weak or lost passphrase | Minimum length and warning; Scrypt; no recovery or escrow | User-chosen passphrases may be guessable; loss is unrecoverable | Use a long unique passphrase and store it safely |
| Fixed nonce, key reuse or plaintext persistence | Fresh OS-generated 16-byte salt and 12-byte nonce; AES-256-GCM; no key persistence | Python cannot guarantee immediate memory erasure | Protect the local process and machine |
| Evidence, member or receipt tampering | Authenticated encryption, canonical commitments, package hashes and strict receipt binding | Integrity does not establish real-world truth | Retain expected artifacts and context |
| Source or sanitized-file substitution | Optional exact SHA-256 byte comparison against encrypted evidence | If bytes are not supplied, verification reports NOT PROVIDED | Supply exact files when byte identity matters |
| Audit-chain tampering or tail truncation | Hash-linked indexed events and operation binding | Tail truncation is not excluded without an externally retained expected head | Retain a trusted head when truncation resistance is required |
| Cross-package receipt substitution | Operation/stage/domain binding and strict v1/v2 dispatch | A malicious local chain can still lie consistently | Configure chain and contract identity independently |
| Wrong chain, contract, code or replay domain | Expected chain ID, address, runtime hash and interface checks | RPC controls the view of chain state | Use a trusted loopback RPC and copied deployment values |
| Malicious/unavailable RPC | Loopback-only URL policy, timeouts, failure isolation, no raw metadata sent | RPC can withhold, delay or misreport state | Treat failures as not verified; do not expose RPC publicly |
| Transaction spoofing, reversion or insufficient confirmation | Receipt status, transaction, event, state and confirmation checks | Local development consensus is not production consensus | Inspect stage status and transaction details |
| First-submitter/front-running | Verification requires the inspection submitter for stage two | The first valid submitter controls that operation commitment; hostile mempools are unsupported | Use only the local development model |
| Development accounts and secrets | UI never accepts private keys or mnemonics; uses unlocked local accounts | Anvil credentials are public test credentials | Never reuse them on public networks |
| Streamlit rerun duplication | Session request fingerprint and exact-byte reuse | Browser/session reset intentionally creates a new operation | Confirm the displayed operation before retaining evidence |
| Secret leakage | Passphrases are staged only for submission; errors omit underlying secrets; release allow-list excludes secret files | Process memory, OS swap and local debugging remain outside guarantees | Secure the workstation and do not enable unsafe debugging |
| Temporary files and symlinks | Standard temporary APIs, randomized paths, cleanup, non-following exclusive persistence writes | OS-level privileged attackers remain out of scope | Use a trusted local account and filesystem |
| Optional local persistence | Disabled by default; private directory/file permissions and collision refusal | Backups and administrators may access stored ciphertext | Protect `.ghostframe` and remove it when no longer needed |
| Known-file hash correlation | Plain hashes are disclosed only where required for evidence/anchoring | An observer with candidate bytes can compare hashes | Do not anchor sensitive, guessable files on shared chains |
| Release secret leakage | Deterministic strict allow-list excludes environments, keys, GFP/GFE, logs and chain state | Human-added sensitive text in allowed source/docs is still possible | Audit archive contents before distribution |

## Severity calibration

- **Critical:** realistic remote compromise or plaintext/key disclosure without prior local control. No such path was identified in the reviewed local-only design.
- **High:** broadly reachable arbitrary code execution or authentication/key bypass. The local-only deployment and strict parsers reduce reachability, but dependency vulnerabilities could qualify.
- **Medium:** meaningful evidence-integrity or local filesystem boundary failure requiring a malicious file and user action.
- **Low:** constrained local denial of service or misleading state with clear warnings and no privilege gain.

Controls reduce risk; they do not make hostile files safe or convert GhostFrame into a malware scanner.
