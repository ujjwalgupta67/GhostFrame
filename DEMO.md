# GhostFrame 2.1 demonstration

This is a short, repeatable classroom demonstration. It uses only fictional data generated locally by GhostFrame.

## Before presenting

1. Install the dependencies from `requirements.txt`.
2. Start the website with `streamlit run app.py`.
3. Open `http://localhost:8501` if the browser does not open automatically.

## Three-minute demonstration script

1. **Introduce the problem.** “A file can reveal more than its visible contents. GhostFrame inspects supported metadata locally and explains plausible privacy consequences without claiming that misuse occurred.”
2. **Load safe demonstration data.** Click **Learn using a synthetic example**. Explain that the DOCX is created on the computer and contains only fictional names, coordinates, identifiers, and an `.invalid` URL.
3. **Show the summary.** Point out the exposure score, share-readiness verdict, meaningful risk count, and top three actions. Say: “The score is deterministic and evidence-based; it is not a malware score.”
4. **Open Potential Misuse.** Expand one scenario. Show the exact findings, conditions, likelihood, impact, confidence, protection, and “What this does not prove.” Emphasize that the explanation is a plausible consequence, not proof of exploitation.
5. **Show privacy-safe evidence.** Open **All Metadata**. Values are masked by default. Demonstrate that precise coordinates require a deliberate reveal action. Turn on **Advanced forensic view** only briefly to show stable evidence IDs and source locations.
6. **Protect the file.** Open **Sanitize and Verify**, review what will be removed or preserved, then click **Create safer copy**. Explain that the original is never overwritten.
7. **Verify the result.** Show removed, remaining, manual-review, and introduced counts; scenario mitigation; the post-sanitization share-readiness verdict; and the two SHA-256 hashes. Say: “Verified means the supported checks completed—it does not guarantee anonymity or inspect visible content.”
8. **Download the outputs.** Download the safer file and the masked HTML or JSON report. Mention that full evidence is available only through an explicit opt-in.
9. **Close with the privacy claim.** “Files, extracted metadata, and reports stay on this computer. GhostFrame uses no external API, AI provider, analytics service, map service, domain, or cloud account.”

## Expected result

The synthetic document should produce understandable identity, location, collaboration, timeline, software, and external-resource evidence. Sanitization should remove the supported metadata and relationships, then re-scan the safer copy and report scenario-by-scenario mitigation.
