# GhostFrame 2.2.0 Release Notes

GhostFrame 2.2.0 is the final planned release of the research/educational prototype.

## Included capabilities

- Local JPG/JPEG, PNG, PDF and DOCX metadata privacy analysis.
- Format-specific sanitization followed by re-inspection and before/after verification.
- AES-256-GCM encrypted GFE evidence with bounded Scrypt key derivation.
- Deterministic GFP 1.0 evidence packages, hash-linked audit history and independent offline verification.
- Optional GFP 2.0 two-stage commitment anchoring on a local Anvil EVM.
- Separation of recorded receipts from a fresh, independently configured current-chain re-check.
- Optional local encrypted-evidence persistence, disabled by default.
- Cross-platform Streamlit launchers and a deterministic source archive.

## Security and compatibility

GFE 1.0, GFP 1.0, GFP 2.0, receipt formats, commitments, lifecycle semantics and the `GhostFrameAnchor` interface remain unchanged. The accepted contract source and compiled artifact remain unchanged. One release defect was fixed: `python scripts/deploy_local_anchor.py` now resolves project imports when invoked exactly as documented.

The final dependency audit identified advisories in the previously pinned Streamlit 1.50.0, Pillow 11.3.0 and cryptography 46.0.3. The release pins were narrowly updated to Streamlit 1.54.0, Pillow 12.3.0 and cryptography 50.0.0, followed by the complete release test program. The optional blockchain pins were unchanged.

## Limitations

GhostFrame does not prove authorship, ownership, identity, lawful provenance, metadata truth, malware absence or complete anonymity. Weak passphrases remain guessable; lost passphrases cannot be recovered; Python cannot guarantee immediate memory erasure. A configured RPC controls the verifier's chain view. Local Anvil accounts are public development credentials. File hashes permit known-file correlation. Blockchain timestamps are chain observations, not trusted real-world timestamps. Public-chain deployment and production private-key management are not supported in 2.2.0.
