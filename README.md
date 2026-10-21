# GhostFrame 2.1

GhostFrame is a local, browser-based metadata privacy analysis and sanitization system for JPG, JPEG, PNG, PDF, and DOCX files. It extracts evidence, explains it in plain language, derives only deterministic correlations, creates a separate sanitized copy, and re-inspects that copy using stable finding identities and source locations.

Everything runs on your computer. GhostFrame does not send files, metadata, analytics, prompts, or telemetry to external servers, APIs, AI providers, mapping services, or reverse-geocoding services. No domain, hosting plan, cloud account, or internet connection is needed after dependencies are installed.

## Four-step website flow

The default interface is designed for non-technical users:

1. **Upload:** choose a supported file or generate the fully fictional, local synthetic example.
2. **Understand:** review the exposure score, share-readiness verdict, top actions, and structured potential-misuse scenarios.
3. **Protect:** inspect the evidence-specific removal plan and create a separate safer copy.
4. **Verify and Download:** re-scan the safer copy, review scenario mitigation and residual findings, then download the file and offline reports.

Values that may expose people, precise locations, device identifiers, comments, or URL parameters are masked in the website and reports by default. Revealing them—or exporting full evidence—requires a deliberate opt-in. Masking changes only the presentation; analysis still uses the complete local evidence.

## Privacy and evidence workflows

The sidebar provides three explicit workflows:

- **Local Privacy Mode** is the default. It preserves the existing inspection, sanitization, re-inspection, comparison, and report-download experience. It does not require a passphrase, create encrypted evidence, or persist evidence.
- **Verifiable Evidence Mode** runs the tested evidence lifecycle only after the user submits the evidence form. It creates one exact sanitized file, an encrypted `.gfe`, and a self-verified `.gfp` package. The `.gfp` is the primary evidence artifact; it already contains the `.gfe`.
- **Verify Evidence Package** independently checks an existing `.gfp` using the public hardened verifier. The original and sanitized files are optional. If omitted, their states are shown as **NOT PROVIDED**, never as verified.

Evidence passphrases must contain at least 12 characters, are preserved exactly, and cannot be recovered by GhostFrame. Losing the passphrase makes the encrypted evidence unreadable. GhostFrame does not provide a master key, recovery key, escrow, or developer backdoor. Python and Streamlit cannot guarantee immediate physical erasure of immutable strings or cryptographic buffers from process memory.

### Evidence downloads

After successful evidence generation, the browser offers the exact sanitized bytes committed by the EvidenceRecord, the exact generated `.gfp`, and the exact standalone `.gfe`. Streamlit reruns and download clicks reuse these bytes; they do not repeat sanitization, generate a new operation ID, or create new encryption salt and nonce values.

The verification view reports package structure, encrypted-evidence authenticity, evidence commitment, audit chain, source file, sanitized file, inspection blockchain anchor, and verification blockchain anchor separately. “Local evidence integrity verified” means the required local cryptographic checks passed. It does not establish authorship, origin, ownership, or metadata truth.

### Optional local evidence storage

Browser download is the default. Local persistence is off by default and must be selected before evidence generation. When enabled, GhostFrame stores only the `.gfp` and, if separately selected, the standalone `.gfe` under `.ghostframe/evidence/`. It never persists the passphrase, plaintext evidence, original file, or sanitized file through this option.

Writes use a completed temporary file followed by a collision-safe atomic link in the destination directory. Existing operation artifacts are never overwritten. POSIX systems receive restrictive directory/file modes where supported; Windows and other filesystems may enforce permissions differently. `.ghostframe/` is excluded from Git and source releases.

Blockchain anchoring remains disabled by default, so normal local runs create frozen-format v1 packages and both blockchain dimensions report **NOT APPLICABLE**. **Local Blockchain-Anchored Evidence Mode** may explicitly use the optional local-EVM adapter to create strict v2 packages with two-stage inspection and verification receipts. GhostFrame never invents transaction hashes, chain IDs, or wallet state.

## Inspection modes

### Default view

Designed for ordinary users. Its four tabs are Summary, Potential Misuse, All Metadata, and Sanitize and Verify. It prioritizes what the file may reveal about identity, location, devices, software, timelines, collaboration, hidden content, and external behavior. It includes an explainable exposure score, recommended actions, limitations, and evidence-backed correlations.

### Advanced forensic details

Shows every extracted field with its stable ID, raw and normalized values, exact source path/tag/object, backend, confidence, evidence type, interpretation, severity, sanitization capability, and limitations. Evidence can be searched, filtered, and sorted.

Observed evidence and derived correlations are visually separated. Every correlation lists the finding IDs used, its confidence, and an alternative interpretation. GhostFrame does not infer a person's real identity.

## Potential-misuse scenarios

GhostFrame 2.1 converts supported evidence into deterministic, structured privacy scenarios such as precise-location exposure, identity disclosure, device linking, timeline reconstruction, collaboration leakage, organization profiling, software fingerprinting, external-resource tracking, hidden-content disclosure, and active-content risk. A scenario is created only when its documented evidence conditions are met.

Each scenario includes its stable ID, category, title, summary, exact finding IDs, required conditions, likelihood, impact, confidence, protective action, safer alternative, limitations, and a clear statement of what the evidence does not prove. These explanations are defensive and non-operational:

> Potential misuse explanations describe plausible privacy consequences, not proof that exploitation occurred or that the file is malicious.

## What GhostFrame analyzes

### JPG and PNG

- EXIF and safely accessible EXIF/GPS sub-IFDs
- Camera make/model, owner and serial fields, lens information, software, descriptions, copyright, comments, and timestamps
- GPS DMS values converted locally to validated decimal coordinates, including southern and western references
- IPTC information when Pillow exposes it
- JPEG comments, XMP application markers, and Photoshop/IPTC resource indicators
- PNG `tEXt`, `zTXt`, `iTXt`, `tIME`, `pHYs`, and ICC-profile indicators
- Dimensions, color mode, orientation, and other technical/rendering evidence without automatically treating it as sensitive

GhostFrame does not contact a map service. Coordinates are deliberately hidden behind an expandable section. A single coordinate is not used to claim a home, workplace, routine, or person's identity.

### PDF

- Document information fields and normalized common PDF dates
- XMP metadata stream and safely parsed fields
- PDF version, page count, encryption state, permissions, and trailer identifiers
- Embedded filenames, declared types, and sizes without opening attachments
- Page annotations and page/object source locations
- URI, JavaScript, Launch, SubmitForm, ImportData, GoToR, OpenAction, and additional-action indicators
- AcroForm presence and field names
- Rich-media and multimedia structure indicators

Active content is reported as present; it is never executed and is not described as malware.

### DOCX

- Core, application, and custom properties
- Creator, last editor, company, manager, timestamps, revisions, templates, application, and version fields
- Comments with author, initials, timestamp, and shortened preview
- Insertions, deletions, moves, and other tracked-review evidence
- External relationships from every relationship file, including source part and relationship ID
- Hyperlinks, external templates/data sources, linked images, OLE/package relationships, ActiveX, and VBA presence
- Custom XML, `altChunk`, mail merge, document variables, hidden-text indicators, thumbnails, people/comment-person data, printer settings, headers, footers, footnotes, and endnotes where applicable

Macros, ActiveX, OLE objects, packages, templates, and links are inventoried but never run or opened.

## Exposure score

The 0–100 score is a deterministic metadata-exposure estimate, not a scientific certainty or malware score. It sums severity-weighted evidence inside capped groups so many harmless fields cannot create an extreme rating. Equivalent normalized values and raw/derived GPS representations are deduplicated. Small, capped bonuses apply only to evidence-backed correlations, while ordinary technical metadata contributes little or nothing.

| Risk group | Maximum points |
|---|---:|
| Precise location | 30 |
| Direct identity | 24 |
| Device identifiers | 20 |
| Collaboration history | 16 |
| Hidden or embedded content | 18 |
| Active or external behavior | 24 |
| Timeline and provenance | 10 |
| Low-risk software fingerprints | 6 |
| Technical metadata | 2 |

The interface shows every contributor, its cap, the finding IDs involved, and why it mattered. Ratings are Minimal, Low, Moderate, High, or Severe.

## Share readiness and recommendations

GhostFrame reports one of three plain-language states: **Ready for supported-metadata sharing**, **Review recommended**, or **Do not share yet**. This verdict considers meaningful findings, manual-review items, incomplete analysis, verification status, residual evidence, and unexpectedly introduced evidence. It is intentionally limited to supported metadata and never claims that visible content is safe.

Recommendations cite the exact evidence IDs that triggered them and distinguish **Remove before sharing**, **Review**, **No action needed**, and **Do not share until resolved**.

## Sanitization and verification

Before sanitization, GhostFrame shows:

- What will be removed
- What will be preserved
- What cannot be automatically removed
- Which features may be affected
- What requires manual review

The original file is never overwritten. Sanitization creates a separate copy:

- **JPG/PNG:** re-encodes visible pixels without supported EXIF, GPS, XMP, IPTC, comments, and textual metadata. JPEG is lossy and is re-encoded at high quality.
- **PDF:** clears document/XMP metadata, removes attachments, supported scripts, open/additional/external actions, and regenerates file identifiers while preserving ordinary page content where practical.
- **DOCX:** clears document properties and removes comments, collaboration-person data, external relationships, supported embedded/active parts, document variables, mail-merge configuration, custom XML, and included chunks. Visible insertions are accepted and deleted tracked content is removed.

The sanitized copy is then re-inspected. The comparison reports removed, remaining, changed, and unexpectedly introduced findings; performed actions; both SHA-256 hashes and sizes; verified types; and one of these statuses:

- Verified
- Verified with residual findings
- Verification incomplete
- Sanitization failed

A verified result means supported metadata and active references were removed. It never means “completely safe.” Visible content and unsupported structures may still reveal information.

## Reports

After verification, download:

- The sanitized file
- A machine-readable JSON report
- A human-readable offline HTML report

Reports include the schema/version, UTC scan time, normalized filename, verified type, size, SHA-256, findings, correlations, timeline, score explanation, sanitization plan, comparison, limitations, and extraction backends. HTML output escapes file-derived content and contains no scripts, remote assets, or tracking resources.

Reports mask sensitive evidence by default. The website offers a clearly labelled full-evidence option only after verification. Full-evidence reports should be handled as sensitive files.

## Optional ExifTool enrichment

ExifTool is optional and never required for core analysis, sanitization, or verification. When detected, GhostFrame invokes it locally with an argument list and `shell=False`, structured JSON output, a six-second timeout, a 2 MB output limit, and a temporary file that is removed in a `finally` block. Enrichment findings use the same evidence model and are deduplicated against built-in results.

If ExifTool is absent, times out, fails, or returns malformed data, built-in analysis continues.

## Install

Requirements: Windows 10/11, macOS, or a common Linux distribution with Python 3.10 or newer.

Open a terminal in the GhostFrame folder, then create an isolated environment.

**Windows Command Prompt:**

```bat
py -3 -m venv .venv
.venv\Scripts\activate
py -3 -m pip install -r requirements.txt
```

**Windows PowerShell:**

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

**macOS or Linux:**

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

After installation, the application works offline.

## Start

The standard manual command is:

```sh
streamlit run app.py
```

Streamlit normally opens the default browser automatically. Otherwise visit [http://localhost:8501](http://localhost:8501).

Launchers are also included:

- Windows: double-click `start.bat`.
- macOS/Linux: run `./start.sh` (use `chmod +x start.sh` once if needed).

Both launchers use a local `.venv` when present and display helpful errors when Python or dependencies are missing.

### Start from Visual Studio Code

1. Open Visual Studio Code and choose **File > Open Folder**, then select the GhostFrame folder.
2. Install Microsoft's Python extension if it is not already installed.
3. Open **Terminal > New Terminal**.
4. Create and activate `.venv` using the command for your operating system in the Install section.
5. Install dependencies with `python -m pip install -r requirements.txt` (use `py -3 -m pip` on Windows if `python` is unavailable).
6. Run `streamlit run app.py`.
7. Use the browser page at `http://localhost:8501`. Keep the VS Code terminal open while using GhostFrame; press `Ctrl+C` there to stop it.

If VS Code asks for an interpreter, choose the Python executable inside `.venv`.

## Synthetic demonstration

Use **Learn using a synthetic example** on the first screen for a repeatable, privacy-safe demonstration. The generated DOCX uses only fictional values and never contacts a network service. A ready-to-read presentation sequence is included in [DEMO.md](DEMO.md).

## Tests

Install development requirements and run the generated-file test suite:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests use generated images, PDFs, and DOCX packages; they require no private files or network access.

### Optional local blockchain development

GhostFrame includes an isolated local-EVM blockchain foundation for development and security testing. **Local Privacy Mode remains the default.** Normal installation and offline use do not require Web3, an RPC service, a wallet, or the optional packages, and continue to create v1 packages.

With an injected adapter, GhostFrame anchors the finalized inspection commitment before sanitization and the completed verification/lifecycle commitment after local verification. It then creates a v2 package containing the recorded receipts. Blockchain errors are isolated from local sanitization and evidence verification. Offline v2 verification does not claim current chain confirmation; a separate adapter must be supplied to check current state.

After installing the optional dependencies, start Anvil and deploy the approved contract as described below. Copy the command's public chain ID, contract address, code hash, and interface version into **Local Blockchain-Anchored Evidence Mode**. The UI permits only explicit loopback HTTP(S) endpoints and never accepts private keys, mnemonics, keystores, public RPC defaults, or public-network selections. Use **Test local blockchain connection** before creating evidence.

The **Verify Evidence Package** workflow always performs local verification first. GFP 1.0 reports blockchain as not applicable. GFP 2.0 displays the states recorded at package creation separately from current verification. **Re-check blockchain status** uses independently entered local configuration and never rewrites the package, re-sanitizes the file, or submits another transaction.

Streamlit reruns, tab changes, and download clicks reuse the exact completed result in session memory. A transaction-producing lifecycle starts only after deliberate form submission. Starting over or discarding the result clears its public blockchain presentation state. Passphrases are staged for one run and removed; decrypted evidence and blockchain secrets are not stored in session state.

For contract architecture, local Anvil setup, optional dependencies, privacy boundaries, confirmation rules, RPC trust assumptions, and limitations, see [ghostframe/blockchain/README.md](ghostframe/blockchain/README.md).

## Build a clean portable ZIP

Create a source-only release archive with:

```sh
python scripts/build_release.py
```

The archive is written to `dist/GhostFrame-2.2.0-source.zip`. The build uses a strict allow-list and excludes virtual environments, caches, generated reports, uploaded files, test output, secrets, local-chain state, version-control data, and previous ZIP files. The build command also verifies archive paths and required source files before succeeding.

## Deeper documentation

- [Architecture and data flow](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Final security review and contract identity](docs/SECURITY_REVIEW.md)
- [Reproducibility guide](docs/REPRODUCIBILITY.md)
- [Final acceptance matrix](docs/ACCEPTANCE_MATRIX.md)
- [2.2.0 release notes](RELEASE_NOTES.md)

## Security limits and known limitations

- 25 MB input limit
- 50-megapixel image limit and multi-frame-image rejection
- DOCX limit of 3,000 internal entries and 100 MB expanded size
- Path-traversal rejection and bounded XML part sizes
- XML declarations containing DTDs/entities are rejected
- Embedded objects and active content are never executed
- Encrypted, malformed, damaged, or unsupported files may be rejected
- Metadata can be copied, edited, stale, or created by defaults
- GhostFrame does not redact visible content, recognize faces, inspect image meaning, determine authorship, prove tampering, guarantee anonymity, or detect malware

## Ethical use

GhostFrame is intended to help users inspect files they own or are authorized to analyze. Metadata findings are clues, not proof of identity, ownership, intent, or malicious activity.
