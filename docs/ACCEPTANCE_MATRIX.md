# GhostFrame 2.2.0 Acceptance Matrix

| Capability | Result | Evidence |
|---|---|---|
| JPEG inspection and sanitization | PASS | Real-browser upload, verification summary, sanitized download; regression fixtures |
| PNG inspection and sanitization | PASS | Real-browser upload/download; RGBA transparency retained |
| PDF inspection and sanitization | PASS | Real-browser upload/download; sanitized PDF opens with one page |
| DOCX inspection and sanitization | PASS | Real-browser upload/download; valid DOCX archive and document part |
| GFE encryption | PASS | AES-256-GCM/Scrypt tests and wrong-passphrase/tamper tests |
| GFP 1.0 | PASS | Default offline evidence lifecycle and strict parser tests |
| GFP 2.0 | PASS | Real Anvil lifecycle and restart/re-upload verification |
| Offline verification | PASS | GFP 2.0 reports local checks VERIFIED and anchors NOT CHECKED |
| Current blockchain verification | PASS | Independently configured Anvil re-check reports both anchors VERIFIED |
| Audit/package tamper detection | PASS | Audit-link, canonical member and hash mutation tests |
| Source/sanitized substitution detection | PASS | Exact-byte SHA-256 verification tests |
| Inspection/verification anchoring | PASS | Real Anvil transactions plus contract state/event checks |
| Failure isolation | PASS | RPC/anchor failures preserve local sanitization results |
| Optional local persistence | PASS | Disabled by default; permissions/collision tests |
| Base-only installation | PASS | Fresh `requirements.txt` environment acceptance |
| Blockchain installation | PASS | Separate optional dependency environment acceptance |
| Release extraction | PASS | Clean extracted-source regression acceptance |

This matrix records the final release checks; it is not a claim of production assurance or public-chain readiness.
