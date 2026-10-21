from __future__ import annotations

import html
import hashlib
from pathlib import Path

import streamlit as st
from streamlit.runtime.scriptrunner import get_script_run_ctx

from ghostframe import MAX_FILE_SIZE, UnsafeFileError, UnsupportedFileError, inspect_file, sanitize_with_verification
from ghostframe.demo import build_synthetic_demo
from ghostframe.masking import is_sensitive_finding, mask_value
from ghostframe.models import CONFIDENCE_ORDER, SEVERITY_ORDER, Finding, MisuseScenario
from ghostframe.normalization import sha256_bytes
from ghostframe.reporting import SAFETY_STATEMENT, html_report, json_report
from ghostframe.security import safe_display_name
from ghostframe.evidence import EvidenceCollisionError, EvidencePersistenceError, VerificationState
from ghostframe.blockchain.models import AnchorState
from ghostframe.blockchain.ui import (
    LocalBlockchainUIError,
    LocalEVMSettings,
    create_local_evm_adapter,
    local_development_account,
)
from ghostframe.evidence.ui import (
    EVIDENCE_PERSISTED_KEY,
    EVIDENCE_REQUEST_KEY,
    EVIDENCE_RESULT_KEY,
    EvidenceUIError,
    clear_evidence_session,
    evidence_download_names,
    evidence_request_key,
    generate_evidence_once,
    persist_evidence_result,
    verify_package_for_ui,
)


st.set_page_config(page_title="GhostFrame", page_icon="👻", layout="wide")
st.markdown("""
<style>
.stApp{background:linear-gradient(135deg,#07111f,#0d1729 55%,#111b31)}[data-testid="stHeader"]{background:transparent}.block-container{max-width:1160px;padding-top:1.2rem;padding-bottom:3rem}
.hero{padding:1.65rem 2rem;border:1px solid #30476a;border-radius:22px;background:linear-gradient(135deg,rgba(25,45,75,.96),rgba(12,23,42,.98));margin-bottom:1rem}.eyebrow{color:#8ee8d0;font-size:.78rem;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.hero h1{color:#fff;font-size:clamp(2.1rem,5vw,3.7rem);margin:.15rem 0;line-height:1}.hero p{color:#c6d3e6;max-width:780px}.privacy{display:inline-block;color:#a9f3df;background:#123234;border:1px solid #32615b;border-radius:999px;padding:.4rem .78rem;font-size:.84rem}
.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:.65rem;margin:1rem 0}.step{border:1px solid #324766;border-radius:12px;padding:.7rem .8rem;background:#0f1b2e;color:#aabbd2}.step strong{color:#fff}.step.active{border-color:#70e1c2;background:#133036}.metric{border:1px solid #304665;border-radius:16px;padding:1rem;background:#0e1a2c;min-height:112px}.metric .big{font-size:1.8rem;font-weight:800;color:#fff}.metric .small{color:#aabbd2;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}.misuse-card{border:1px solid #526486;border-left:5px solid #c7a2ff;border-radius:12px;padding:1rem;margin:.8rem 0;background:#121c31}.finding-card{border:1px solid #314969;border-left:5px solid #70e1c2;border-radius:12px;padding:1rem;margin:.7rem 0;background:#101d31}.readiness{border:1px solid #557091;border-radius:14px;padding:1rem;background:#14243a}.footer{color:#91a4bf;text-align:center;font-size:.8rem;margin-top:2rem}@media(max-width:760px){.steps{grid-template-columns:1fr 1fr}.hero{padding:1.2rem}.block-container{padding-left:.8rem;padding-right:.8rem}}@media(max-width:440px){.steps{grid-template-columns:1fr}}
</style>
""", unsafe_allow_html=True)


def reset_app() -> None:
    nonce = st.session_state.get("upload_nonce", 0) + 1
    for key in list(st.session_state):
        if key.startswith("gf_") or key.startswith("reveal_"):
            del st.session_state[key]
    st.session_state["upload_nonce"] = nonce


def stage_and_clear_secret(passphrase_key: str, staged_key: str, confirmation_key: str | None = None, staged_confirmation_key: str | None = None) -> None:
    """Move submitted secrets into one-run state, then clear password widgets."""
    st.session_state[staged_key] = st.session_state.get(passphrase_key, "")
    st.session_state[passphrase_key] = ""
    if confirmation_key is not None and staged_confirmation_key is not None:
        st.session_state[staged_confirmation_key] = st.session_state.get(confirmation_key, "")
        st.session_state[confirmation_key] = ""


def progress(current: int) -> None:
    labels = ["1. Upload", "2. Understand", "3. Protect", "4. Verify and Download"]
    cards = "".join(f'<div class="step {"active" if index == current else ""}"><strong>{label}</strong></div>' for index, label in enumerate(labels, 1))
    st.markdown(f'<div class="steps">{cards}</div>', unsafe_allow_html=True)


def severity_label(finding: Finding) -> str:
    symbol = {"Critical": "●", "High": "▲", "Medium": "◆", "Low": "■", "Informational": "○"}.get(finding.severity, "○")
    return f"{symbol} {finding.severity} priority"


def evidence_value(finding: Finding) -> str:
    return mask_value(finding) if is_sensitive_finding(finding) else finding.normalized_value


def render_finding(finding: Finding, advanced: bool = False, context: str = "finding") -> None:
    st.markdown('<div class="finding-card"><strong>OBSERVED EVIDENCE</strong></div>', unsafe_allow_html=True)
    st.markdown(f"### {finding.field_name}")
    st.caption(f"{severity_label(finding)} · {finding.confidence} confidence · {finding.actionability}")
    st.write(finding.meaning)
    st.markdown("**Why it matters**")
    st.write(finding.privacy_impact)
    st.markdown("**Value**")
    if is_sensitive_finding(finding):
        st.code(evidence_value(finding), language=None)
        reveal_key = f"reveal_{context}_{finding.finding_id}"
        if finding.risk_group == "precise_location":
            reveal = st.checkbox("I understand that revealing exact coordinates may expose a location", key=reveal_key)
        else:
            reveal = st.checkbox("Reveal sensitive value", key=reveal_key)
        if reveal:
            st.code(finding.normalized_value, language=None)
    else:
        st.code(finding.normalized_value, language=None)
    if advanced:
        with st.expander("Technical evidence"):
            st.text(finding.raw_value if not is_sensitive_finding(finding) or st.session_state.get(reveal_key, False) else mask_value(finding, finding.raw_value))
            st.write({
                "Finding ID": finding.finding_id, "Exact source": finding.source, "Backend": finding.backend,
                "Evidence type": finding.evidence_type, "Sanitizable": finding.sanitizable,
                "Sanitization action": finding.sanitization_action, "Limitations": finding.limitations or "None recorded",
            })


def render_scenario(scenario: MisuseScenario, expanded: bool = False) -> None:
    with st.expander(f"{scenario.title} · {scenario.impact} impact", expanded=expanded):
        st.markdown("**Found**")
        st.write(scenario.summary)
        st.markdown("**Possible misuse**")
        st.write(scenario.possible_misuse)
        st.markdown("**Conditions required**")
        for condition in scenario.required_conditions:
            st.write("• " + condition)
        st.write(f"**Likelihood:** {scenario.likelihood}  ·  **Impact:** {scenario.impact}  ·  **Confidence:** {scenario.confidence}")
        st.markdown("**Protect yourself**")
        for action in scenario.recommended_protection:
            st.write("• " + action)
        st.markdown("**What this does not prove**")
        st.write(scenario.not_proven)
        st.caption("Evidence: " + ", ".join(scenario.evidence_finding_ids))


def render_package_verification(verification) -> None:
    st.caption(
        "Evidence package: GFP 2.0"
        if verification.recorded_inspection_anchor_state is not None
        else "Evidence package: GFP 1.0"
    )
    if verification.locally_verified:
        st.success("LOCAL EVIDENCE INTEGRITY VERIFIED")
        st.caption("This verifies the local evidence structure and commitments, not authorship, origin, or metadata truth.")
    else:
        st.error("LOCAL EVIDENCE INTEGRITY NOT VERIFIED")
    checks = [
        ("Package structure", verification.package_structure),
        ("Encrypted evidence authenticity", verification.encrypted_evidence_authenticity),
        ("Evidence commitment", verification.evidence_commitment),
        ("Audit chain", verification.audit_chain),
        ("Source file", verification.source_file),
        ("Sanitized file", verification.sanitized_file),
        ("Inspection blockchain anchor", verification.inspection_blockchain_anchor),
        ("Verification blockchain anchor", verification.verification_blockchain_anchor),
    ]
    for label, check in checks:
        state = check.state.value.replace("_", " ")
        if check.state == VerificationState.VERIFIED:
            st.success(f"{label}: {state}")
        elif check.state == VerificationState.FAILED:
            st.error(f"{label}: {state}")
        else:
            st.info(f"{label}: {state}")
        st.caption(check.detail)
    if verification.recorded_inspection_anchor_state is not None:
        st.subheader("Recorded blockchain receipts")
        st.caption("These states were recorded when the GFP 2.0 package was created; they are not current chain verification.")
        left, right = st.columns(2)
        left.info(f"Recorded inspection state\n\n{verification.recorded_inspection_anchor_state}")
        right.info(f"Recorded verification state\n\n{verification.recorded_verification_anchor_state}")


def local_evm_settings(prefix: str) -> LocalEVMSettings:
    st.warning("LOCAL EVM / DEVELOPMENT MODE — loopback endpoints and unlocked development accounts only.")
    rpc_url = st.text_input("Local RPC URL", value="http://127.0.0.1:8545", key=f"{prefix}_rpc")
    chain_id = int(st.number_input("Expected chain ID", min_value=1, value=31337, step=1, key=f"{prefix}_chain"))
    contract = st.text_input("Expected contract address", value="", key=f"{prefix}_contract")
    code_hash = st.text_input("Expected contract code hash", value="", key=f"{prefix}_code")
    version = st.text_input("Expected interface version", value="ghostframe-anchor/1.0", key=f"{prefix}_version")
    confirmations = int(st.number_input("Required confirmations", min_value=1, max_value=100, value=1, step=1, key=f"{prefix}_confirmations"))
    return LocalEVMSettings(rpc_url, chain_id, contract, code_hash, version, confirmations)


def render_anchor_receipt(title: str, receipt) -> None:
    st.markdown(f"**{title}: {receipt.state.value}**")
    if receipt.state == AnchorState.PENDING:
        st.warning("The transaction was observed but has not reached the configured confirmation requirement.")
    elif receipt.state == AnchorState.FAILED:
        st.error(receipt.detail)
    elif receipt.state == AnchorState.NOT_REQUESTED:
        st.info("Not requested because the inspection stage did not establish a usable anchor.")
    elif receipt.state == AnchorState.CONFIRMED:
        st.success("Blockchain anchor confirmed on the configured local chain.")
    with st.expander(f"{title} public transaction details"):
        for label, value in (
            ("Transaction", receipt.transaction_hash), ("Block", receipt.block_number),
            ("Block hash", receipt.block_hash), ("Log index", receipt.log_index),
            ("Submitter", receipt.submitter_address), ("Contract", receipt.contract_address),
            ("Chain ID", receipt.chain_id), ("Confirmations observed at creation", receipt.confirmations),
        ):
            st.write(f"{label}: `{value}`" if value is not None else f"{label}: Not available")


def render_package_verification_workflow() -> None:
    st.header("Verify Evidence Package")
    st.write("Verify an existing `.gfp` locally. The source and sanitized files are optional and are not embedded automatically.")
    package_upload = st.file_uploader("GhostFrame evidence package (.gfp)", type=["gfp"], key="gf_verify_package_upload")
    optional_source = st.file_uploader("Optional claimed original file", type=["jpg", "jpeg", "png", "pdf", "docx"], key="gf_verify_source_upload")
    optional_sanitized = st.file_uploader("Optional claimed sanitized file", type=["jpg", "jpeg", "png", "pdf", "docx"], key="gf_verify_sanitized_upload")
    with st.form("gf_verify_form", clear_on_submit=True):
        st.text_input("Evidence passphrase", type="password", key="gf_verify_passphrase")
        submitted = st.form_submit_button(
            "Verify package",
            type="primary",
            width="stretch",
            on_click=stage_and_clear_secret,
            args=("gf_verify_passphrase", "gf_verify_submitted_passphrase"),
        )
    if submitted:
        passphrase = st.session_state.pop("gf_verify_submitted_passphrase", "")
        try:
            package_bytes = package_upload.getvalue() if package_upload is not None else b""
            verification = verify_package_for_ui(
                package=package_bytes,
                passphrase=passphrase,
                source_file=optional_source.getvalue() if optional_source is not None else None,
                sanitized_file=optional_sanitized.getvalue() if optional_sanitized is not None else None,
            )
            st.session_state["gf_verify_result"] = verification
            st.session_state["gf_verify_request_key"] = hashlib.sha256(package_bytes).hexdigest()
        except EvidenceUIError as exc:
            st.error(str(exc))
    if package_upload is not None:
        current_key = hashlib.sha256(package_upload.getvalue()).hexdigest()
        if st.session_state.get("gf_verify_request_key") == current_key and "gf_verify_result" in st.session_state:
            verification = st.session_state["gf_verify_result"]
            render_package_verification(verification)
            if verification.recorded_inspection_anchor_state is not None:
                st.divider()
                st.subheader("Current local blockchain verification")
                st.write("The uploaded package does not choose the trusted chain. Your independent local configuration verifies its receipt claims.")
                with st.expander("Configure trusted local EVM", expanded=True):
                    settings = local_evm_settings("gf_verify_chain")
                with st.form("gf_verify_chain_form", clear_on_submit=True):
                    st.text_input("Evidence passphrase for re-check", type="password", key="gf_verify_chain_passphrase")
                    recheck = st.form_submit_button(
                        "Re-check blockchain status", width="stretch",
                        on_click=stage_and_clear_secret,
                        args=("gf_verify_chain_passphrase", "gf_verify_chain_submitted_passphrase"),
                    )
                if recheck:
                    recheck_passphrase = st.session_state.pop("gf_verify_chain_submitted_passphrase", "")
                    try:
                        adapter = create_local_evm_adapter(settings)
                        current = verify_package_for_ui(
                            package=package_upload.getvalue(), passphrase=recheck_passphrase,
                            source_file=optional_source.getvalue() if optional_source is not None else None,
                            sanitized_file=optional_sanitized.getvalue() if optional_sanitized is not None else None,
                            blockchain_anchor=adapter,
                        )
                        st.session_state["gf_verify_result"] = current
                        st.rerun()
                    except (EvidenceUIError, LocalBlockchainUIError) as exc:
                        st.error(str(exc))
    st.warning("GhostFrame cannot recover a lost evidence passphrase. Offline verification never treats a recorded blockchain receipt as current chain proof.")


st.markdown("""
<section class="hero"><div class="eyebrow">Metadata privacy, explained clearly</div><h1>GhostFrame</h1>
<p>Understand what a file reveals, how that information could matter, and whether a safer copy was verified.</p>
<span class="privacy">● Runs locally · no telemetry · no external metadata services</span></section>
""", unsafe_allow_html=True)

with st.sidebar:
    st.header("Controls")
    workflow_mode = st.radio(
        "Workflow",
        ["Local Privacy Mode", "Verifiable Evidence Mode", "Local Blockchain-Anchored Evidence Mode", "Verify Evidence Package"],
        help="Ordinary privacy analysis remains the default. Evidence generation and package verification are explicit workflows.",
    )
    advanced_mode = st.toggle("Advanced forensic view", value=False, help="Shows raw evidence, exact package paths, filters, and extraction details.")
    use_exiftool = st.toggle("Optional ExifTool enrichment", value=True, help="Used locally only when installed. Core analysis never depends on it.")
    if st.button("Start over", width="stretch"):
        reset_app(); st.rerun()
    st.divider()
    st.caption("GhostFrame never overwrites the original. Embedded content is inventoried but never opened or executed.")

if workflow_mode == "Verify Evidence Package":
    render_package_verification_workflow()
    st.markdown('<div class="footer">Verification runs locally. Hash equality proves byte equality, not authorship or origin.</div>', unsafe_allow_html=True)
    st.stop()

progress(1)
upload_key = f"ghostframe_upload_{st.session_state.get('upload_nonce', 0)}"
uploaded = st.file_uploader("Choose a JPG, JPEG, PNG, PDF, or DOCX file", type=["jpg", "jpeg", "png", "pdf", "docx"], key=upload_key)
demo_col, demo_text = st.columns([1, 2])
with demo_col:
    if st.button("Learn using a synthetic example", width="stretch"):
        demo_data, demo_name, demo_notice = build_synthetic_demo()
        st.session_state["gf_demo"] = (demo_data, demo_name, demo_notice)
        st.rerun()
with demo_text:
    st.caption("Creates a local training document using only fictional names, coordinates, identifiers, comments, and a reserved `.invalid` link.")

if uploaded is not None:
    data = uploaded.getvalue(); display_name = safe_display_name(uploaded.name); demo_notice = ""
    st.session_state.pop("gf_demo", None)
elif "gf_demo" in st.session_state:
    data, display_name, demo_notice = st.session_state["gf_demo"]
    st.info(demo_notice)
else:
    st.subheader("What you will get")
    c1, c2, c3 = st.columns(3)
    c1.info("**Understand**\n\nA short verdict and the three most important discoveries.")
    c2.info("**Protect**\n\nEvidence-specific actions and a separate sanitized copy.")
    c3.info("**Verify**\n\nReinspection, scenario mitigation, readiness, and offline reports.")
    st.stop()
    # Streamlit's stop is intentionally a no-op during a plain Python import.
    # Use the local fictional sample only for that diagnostic context so the
    # module remains importable without weakening the real empty-first-run UI.
    if get_script_run_ctx() is None:
        data, display_name, demo_notice = build_synthetic_demo()

if len(data) > MAX_FILE_SIZE:
    st.error("This file is larger than the 25 MB safety limit. Choose a smaller file."); st.stop()
source_key = sha256_bytes(data)
scan_key = f"{source_key}:{use_exiftool}"
try:
    if st.session_state.get("gf_scan_key") != scan_key:
        clear_evidence_session(st.session_state)
        for state_key in list(st.session_state):
            if state_key.startswith("reveal_"):
                del st.session_state[state_key]
        st.session_state["gf_full_export"] = False
        with st.status("Inspecting locally…", expanded=True) as status:
            st.write("Verifying the real file type")
            st.write("Reading metadata without executing embedded content")
            result = inspect_file(data, display_name, use_exiftool=use_exiftool)
            st.session_state["gf_result"] = result; st.session_state["gf_scan_key"] = scan_key
            st.session_state.pop("gf_outcome", None); st.session_state.pop("gf_outcome_key", None)
            status.update(label="Local analysis complete", state="complete", expanded=False)
    result = st.session_state["gf_result"]
except (UnsupportedFileError, UnsafeFileError) as exc:
    st.error(str(exc)); st.stop()
except Exception:
    st.error("GhostFrame could not inspect this file. It may be damaged, encrypted, or use an unsupported structure."); st.stop()

if result.partial_analysis:
    st.warning("Partial analysis: one or more bounded or optional checks could not be completed. Review the backend status before sharing.")

progress(2)
meaningful = [item for item in result.findings if SEVERITY_ORDER.get(item.severity, 0) >= SEVERITY_ORDER["Medium"]]
top = sorted(meaningful, key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), item.field_name))[:3]
verdict = (
    "High-priority metadata should be removed or resolved before this file is shared."
    if result.high_count else
    "Some metadata deserves review before sharing." if meaningful else
    "No supported high-priority metadata was found, but visible content still needs review."
)
a, b, c = st.columns(3)
a.markdown(f'<div class="metric"><div class="big">{html.escape(result.exposure_score.rating)}</div><div class="small">Overall exposure · {result.exposure_score.score}/100</div></div>', unsafe_allow_html=True)
b.markdown(f'<div class="metric"><div class="big">{len(meaningful)}</div><div class="small">Meaningful risks</div></div>', unsafe_allow_html=True)
c.markdown(f'<div class="metric"><div class="big">{html.escape(result.share_readiness.state)}</div><div class="small">Current share readiness</div></div>', unsafe_allow_html=True)
st.markdown(f"### {verdict}")
st.caption(SAFETY_STATEMENT)

summary_tab, misuse_tab, metadata_tab, protect_tab = st.tabs(["Summary", "Potential Misuse", "All Metadata", "Sanitize and Verify"])

with summary_tab:
    st.subheader("Top privacy discoveries")
    if not top:
        st.success("No medium, high, or critical supported metadata findings were detected.")
    for index, item in enumerate(top):
        render_finding(item, advanced=False, context=f"top_{index}")
    st.subheader("How this could be misused")
    if result.misuse_scenarios:
        for scenario in result.misuse_scenarios[:3]:
            st.write(f"**{scenario.title}:** {scenario.possible_misuse}")
    else:
        st.info("No deterministic potential-misuse scenario met its evidence requirements.")
    st.subheader("Recommended next actions")
    for recommendation in result.recommendations:
        st.write(f"**{recommendation.priority} — {recommendation.title}:** {recommendation.detail}")
        if recommendation.finding_ids:
            st.caption("Evidence: " + ", ".join(recommendation.finding_ids))
    st.markdown("### Protect this file")
    st.info("Open **Sanitize and Verify**, review what may change, then choose **Create safer copy**.")
    with st.expander("Show all findings"):
        for index, item in enumerate(result.findings):
            render_finding(item, advanced=advanced_mode, context=f"summary_all_{index}")

with misuse_tab:
    st.subheader("Potential misuse")
    st.caption(SAFETY_STATEMENT)
    if not result.misuse_scenarios:
        st.info("No evidence-backed misuse scenario was generated. Ordinary technical fields are not exaggerated.")
    for index, scenario in enumerate(result.misuse_scenarios):
        render_scenario(scenario, expanded=index == 0)

with metadata_tab:
    if not advanced_mode:
        st.info("This page keeps values masked and explanations simple. Enable **Advanced forensic view** in the sidebar for filters and raw evidence.")
        for index, item in enumerate(result.findings):
            render_finding(item, advanced=False, context=f"metadata_{index}")
    else:
        st.subheader("Advanced forensic view")
        categories = sorted({item.category for item in result.findings})
        f1, f2, f3 = st.columns(3)
        severities = f1.multiselect("Filter by severity", list(SEVERITY_ORDER), default=list(SEVERITY_ORDER))
        confidences = f2.multiselect("Filter by confidence", list(CONFIDENCE_ORDER), default=list(CONFIDENCE_ORDER))
        selected_categories = f3.multiselect("Filter by category", categories, default=categories)
        search = st.text_input("Search field names and sources")
        filtered = [item for item in result.findings if item.severity in severities and item.confidence in confidences and item.category in selected_categories and (not search or search.casefold() in f"{item.field_name} {item.source}".casefold())]
        st.dataframe([{"ID": item.finding_id, "Priority": item.severity, "Field": item.field_name, "Masked value": evidence_value(item), "Source": item.source, "Backend": item.backend, "Sanitizable": item.sanitizable} for item in filtered], width="stretch", hide_index=True)
        for index, item in enumerate(filtered):
            render_finding(item, advanced=True, context=f"advanced_{index}")

with protect_tab:
    progress(3)
    st.subheader("Protection plan")
    for section in ["Will remove", "Will preserve", "Cannot automatically remove", "May affect document features", "Requires manual review"]:
        with st.expander(section, expanded=section in {"Will remove", "Requires manual review"}):
            items = result.sanitization_plan.in_section(section)
            if not items: st.caption("No items in this section.")
            for item in items:
                st.write(f"**{item.title}** — {item.detail}")
                if item.finding_ids: st.caption("Evidence: " + ", ".join(item.finding_ids))
    st.warning("A safer copy removes supported metadata. It does not redact visible text, faces, screenshots, landmarks, or filenames.")
    evidence_result = None
    if workflow_mode == "Local Privacy Mode":
        st.caption("Local Privacy Mode is the default. It creates no encrypted evidence and requires no passphrase.")
        if st.button("Create safer copy", type="primary", width="stretch"):
            try:
                with st.status("Protecting and verifying a separate copy…", expanded=True) as status:
                    st.write("Creating a separate sanitized file")
                    st.write("Re-inspecting supported metadata and active references")
                    outcome = sanitize_with_verification(data, display_name, result, use_exiftool=use_exiftool)
                    st.session_state["gf_outcome"] = outcome; st.session_state["gf_outcome_key"] = scan_key
                    status.update(label="Safer copy created and re-inspected", state="complete", expanded=False)
            except (UnsupportedFileError, UnsafeFileError) as exc:
                st.error(str(exc))
            except Exception:
                st.error("GhostFrame could not complete sanitization and verification. The original file was not modified.")
    else:
        blockchain_mode = workflow_mode == "Local Blockchain-Anchored Evidence Mode"
        settings = None
        blockchain_fingerprint = "disabled"
        if blockchain_mode:
            st.info("Local blockchain anchoring creates a GFP 2.0 package. It remains a development/research feature and is not approved for public networks or hostile mempools.")
            with st.expander("Configure LOCAL EVM / DEVELOPMENT MODE", expanded=True):
                settings = local_evm_settings("gf_generate_chain")
                blockchain_fingerprint = settings.fingerprint()
                if st.button("Test local blockchain connection", width="stretch"):
                    try:
                        health_adapter = create_local_evm_adapter(settings)
                        health = health_adapter.health()
                        if health.state == AnchorState.CONFIRMED:
                            st.success("RPC connected; expected chain, contract code, and interface version verified.")
                            st.write(f"Chain ID: `{health.chain_id}`  Contract: `{health.contract_address}`")
                            account = local_development_account(health_adapter)
                            if account:
                                st.write(f"LOCAL DEVELOPMENT ACCOUNT: `{account}`")
                            else:
                                st.error("No unlocked local development account is available.")
                        else:
                            st.error(health.detail)
                    except LocalBlockchainUIError as exc:
                        st.error(str(exc))
            st.caption("GhostFrame stores no raw metadata on-chain—only cryptographic commitments and public transaction information.")
        else:
            st.info("Verifiable Evidence Mode creates one sanitized copy, encrypted evidence, and a self-verified `.gfp` package only when you submit this form.")
        current_evidence_key = evidence_request_key(
            data, use_exiftool=use_exiftool, blockchain_fingerprint=blockchain_fingerprint,
        )
        has_evidence = (
            st.session_state.get(EVIDENCE_REQUEST_KEY) == current_evidence_key
            and EVIDENCE_RESULT_KEY in st.session_state
        )
        if not has_evidence:
            st.warning("The evidence passphrase cannot be recovered by GhostFrame. If it is lost, the encrypted evidence cannot be decrypted.")
            with st.form("gf_evidence_generation_form", clear_on_submit=True):
                st.text_input("Evidence passphrase", type="password", key="gf_evidence_passphrase")
                st.text_input("Confirm passphrase", type="password", key="gf_evidence_confirmation")
                st.caption("Use a long, unique passphrase. GhostFrame preserves it exactly and never trims it.")
                persist_locally = st.checkbox(
                    "Also save the encrypted evidence package locally",
                    value=False,
                    help="Disabled by default. Browser download remains the normal storage method.",
                    key="gf_evidence_persist_choice",
                )
                persist_gfe = st.checkbox(
                    "Also save the standalone .gfe file",
                    value=False,
                    disabled=not persist_locally,
                    key="gf_evidence_persist_gfe_choice",
                )
                submitted = st.form_submit_button(
                    "Create locally anchored evidence" if blockchain_mode else "Create verifiable sanitized copy",
                    type="primary",
                    width="stretch",
                    on_click=stage_and_clear_secret,
                    args=(
                        "gf_evidence_passphrase",
                        "gf_evidence_submitted_passphrase",
                        "gf_evidence_confirmation",
                        "gf_evidence_submitted_confirmation",
                    ),
                )
            if submitted:
                passphrase = st.session_state.pop("gf_evidence_submitted_passphrase", "")
                confirmation = st.session_state.pop("gf_evidence_submitted_confirmation", "")
                try:
                    with st.status("Creating and independently verifying evidence…", expanded=True) as status:
                        st.write("Running the real GhostFrame inspection and sanitization lifecycle")
                        if blockchain_mode:
                            st.write("Anchoring the inspection commitment before sanitization")
                            st.write("Anchoring the verification commitment after local verification")
                        st.write("Encrypting evidence and creating one package")
                        st.write("Independently verifying the package and exact file bytes")
                        adapter = create_local_evm_adapter(settings) if blockchain_mode and settings is not None else None
                        evidence_result = generate_evidence_once(
                            st.session_state,
                            source_data=data,
                            source_name=display_name,
                            passphrase=passphrase,
                            confirmation=confirmation,
                            use_exiftool=use_exiftool,
                            blockchain_anchor=adapter,
                            blockchain_fingerprint=blockchain_fingerprint,
                        )
                        status.update(label="Verifiable evidence created", state="complete", expanded=False)
                    if persist_locally:
                        try:
                            persisted = persist_evidence_result(
                                evidence_result,
                                root=Path(__file__).resolve().parent,
                                include_encrypted_evidence=persist_gfe,
                            )
                            st.session_state[EVIDENCE_PERSISTED_KEY] = persisted
                        except EvidenceCollisionError:
                            st.error("Downloads are ready, but local saving was stopped because evidence for this operation already exists.")
                        except EvidencePersistenceError:
                            st.error("Downloads are ready, but GhostFrame could not save the encrypted evidence locally.")
                except (EvidenceUIError, LocalBlockchainUIError) as exc:
                    st.error(str(exc))
                    if exc.sanitization_succeeded:
                        st.info("Sanitization reached completion, but no successful evidence package was retained for download.")
        else:
            evidence_result = st.session_state[EVIDENCE_RESULT_KEY]
            st.caption("Reruns and download clicks reuse the exact previously generated bytes.")
            if st.button("Discard this evidence result and create a new operation", width="stretch"):
                clear_evidence_session(st.session_state)
                st.rerun()

    outcome = None
    if workflow_mode in {"Verifiable Evidence Mode", "Local Blockchain-Anchored Evidence Mode"} and evidence_result is not None:
        outcome = evidence_result.sanitization_outcome
    elif workflow_mode == "Local Privacy Mode" and st.session_state.get("gf_outcome_key") == scan_key and "gf_outcome" in st.session_state:
        outcome = st.session_state["gf_outcome"]

    if outcome is not None:
        report = outcome.verification
        progress(4)
        st.subheader("Verification summary")
        if evidence_result is not None:
            s1, s2, s3, s4 = st.columns(4)
            s1.success("SANITIZATION\n\nSUCCESS")
            s2.success("LOCAL VERIFICATION\n\nVERIFIED")
            s3.success("EVIDENCE PACKAGE\n\nCREATED")
            if evidence_result.package_version == "ghostframe-gfp/2.0":
                s4.info("LOCAL BLOCKCHAIN\n\nSTAGE RESULTS BELOW")
                st.caption("Evidence package: GFP 2.0")
                render_anchor_receipt("Inspection anchor", evidence_result.inspection_anchor)
                render_anchor_receipt("Verification anchor", evidence_result.verification_anchor)
                st.info("A confirmed anchor shows that a cryptographic commitment was registered in the verified local contract state. It does not prove authorship, ownership, legal provenance, or that metadata was truthful.")
            else:
                s4.info("BLOCKCHAIN\n\nNOT APPLICABLE")
                st.caption("Evidence package: GFP 1.0")
        st.markdown(f'<div class="readiness"><strong>{html.escape(report.share_readiness.state)}</strong><br>{html.escape(report.share_readiness.summary)}</div>', unsafe_allow_html=True)
        v1, v2, v3, v4 = st.columns(4)
        v1.metric("Removed successfully", len(report.removed))
        v2.metric("Still present", len(report.remaining))
        manual_count = sum(1 for item in outcome.after.findings if not item.sanitizable and item.severity != "Informational")
        v3.metric("Needs manual review", manual_count)
        v4.metric("Unexpectedly introduced", len(report.introduced))
        st.write(report.message)
        st.subheader("Potential-misuse mitigation")
        if not report.scenario_mitigations: st.info("No original scenario required mitigation.")
        for mitigation in report.scenario_mitigations:
            st.write(f"**{mitigation.title}: {mitigation.status}** — {mitigation.detail}")
        with st.expander("Exact before-and-after comparison"):
            st.write(f"Original SHA-256: `{report.original_sha256}`")
            st.write(f"Sanitized SHA-256: `{report.sanitized_sha256}`")
            for title, changes in (("Removed", report.removed), ("Still present", report.remaining), ("Changed", report.changed), ("Unexpectedly introduced", report.introduced)):
                st.markdown(f"**{title} ({len(changes)})**")
                if changes: st.dataframe([item.to_dict() for item in changes], width="stretch", hide_index=True)
        full_export = st.checkbox("Include full sensitive values in exported reports", key="gf_full_export", help="Masked reports are recommended. Select this only when the recipient is authorized to receive exact evidence.")
        if full_export:
            st.warning("Full-evidence reports may contain exact names, coordinates, serials, comments, URLs, and hidden values.")
        json_bytes = json_report(display_name, result, report, sanitized_result=outcome.after, full_evidence=full_export)
        html_bytes = html_report(display_name, result, report, sanitized_result=outcome.after, full_evidence=full_export)
        stem = display_name.rsplit(".", 1)[0]
        if evidence_result is not None:
            names = evidence_download_names(evidence_result.public_operation_commitment)
            d1, d2 = st.columns(2)
            d1.download_button("Download exact sanitized file", outcome.data, outcome.filename, width="stretch")
            d2.download_button("Download .gfp evidence package", evidence_result.evidence_package, names.package, "application/octet-stream", type="primary", width="stretch")
            with st.expander("Advanced evidence and reports"):
                st.download_button("Download standalone .gfe", evidence_result.encrypted_evidence, names.encrypted_evidence, "application/octet-stream", width="stretch")
                st.download_button("Download JSON report", json_bytes, f"{stem}_ghostframe_report.json", "application/json", width="stretch")
                st.download_button("Download offline HTML report", html_bytes, f"{stem}_ghostframe_report.html", "text/html", width="stretch")
            if EVIDENCE_PERSISTED_KEY in st.session_state:
                persisted_names = [names.package]
                if st.session_state[EVIDENCE_PERSISTED_KEY].encrypted_evidence_path is not None:
                    persisted_names.append(names.encrypted_evidence)
                st.success("Saved locally in `.ghostframe/evidence/`: " + ", ".join(persisted_names))
            render_package_verification(evidence_result.local_verification)
        else:
            d1, d2, d3 = st.columns(3)
            d1.download_button("Download sanitized file", outcome.data, outcome.filename, width="stretch")
            d2.download_button("Download JSON report", json_bytes, f"{stem}_ghostframe_report.json", "application/json", width="stretch")
            d3.download_button("Download offline HTML report", html_bytes, f"{stem}_ghostframe_report.html", "text/html", width="stretch")

st.markdown('<div class="footer">GhostFrame is intended for files you own or are authorized to analyze. Potential misuse is explained defensively and never activated.</div>', unsafe_allow_html=True)
