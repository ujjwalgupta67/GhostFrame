import io
import subprocess
import sys

from PIL import Image
from streamlit.testing.v1 import AppTest

from ghostframe import inspect_file
from ghostframe.demo import build_synthetic_demo
from ghostframe.normalization import sha256_bytes


def _empty_app():
    return AppTest.from_file("app.py", default_timeout=45).run()


def _demo_app():
    app = _empty_app()
    next(button for button in app.button if button.label == "Learn using a synthetic example").click()
    return app.run()


def test_empty_first_run_has_clear_upload_and_learning_choices():
    app = _empty_app()
    assert not app.exception
    assert len(app.get("file_uploader")) == 1
    assert any(button.label == "Learn using a synthetic example" for button in app.button)
    assert any(button.label == "Start over" for button in app.button)
    assert {"Understand", "Protect", "Verify"}.issubset({item.value.split("\n", 1)[0].strip("*") for item in app.info})
    assert next(item for item in app.radio if item.label == "Workflow").value == "Local Privacy Mode"
    assert not app.text_input


def test_app_module_imports_in_plain_python():
    completed = subprocess.run(
        [sys.executable, "-c", "import app"], capture_output=True, text=True, timeout=20, check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_synthetic_upload_summary_scenario_masking_and_advanced_mode():
    app = _demo_app()
    assert not app.exception
    assert [tab.label for tab in app.tabs] == ["Summary", "Potential Misuse", "All Metadata", "Sanitize and Verify"]
    assert any(expander.label.startswith("Collaboration and revision leakage") for expander in app.expander)
    assert any(checkbox.label == "I understand that revealing exact coordinates may expose a location" for checkbox in app.checkbox)
    assert not any("Example Person" in str(block.value) for block in app.code)
    next(toggle for toggle in app.toggle if toggle.label == "Advanced forensic view").set_value(True)
    app.run()
    assert not app.exception and app.dataframe
    assert any(text.value == "Advanced forensic view" for text in app.subheader)


def test_sanitization_verification_summary_and_report_downloads():
    app = _demo_app()
    next(button for button in app.button if button.label == "Create safer copy").click()
    app.run()
    assert not app.exception
    labels = {metric.label for metric in app.metric}
    assert {"Removed successfully", "Still present", "Needs manual review", "Unexpectedly introduced"}.issubset(labels)
    assert any(text.value == "Verification summary" for text in app.subheader)
    assert any(checkbox.label == "Include full sensitive values in exported reports" for checkbox in app.checkbox)
    downloads = {item.label for item in app.get("download_button")}
    assert downloads == {"Download sanitized file", "Download JSON report", "Download offline HTML report"}


def test_partial_analysis_warning():
    data, name, notice = build_synthetic_demo()
    result = inspect_file(data, name, use_exiftool=True); result.partial_analysis = True
    app = AppTest.from_file("app.py", default_timeout=45)
    app.session_state["gf_demo"] = (data, name, notice)
    app.session_state["gf_result"] = result
    app.session_state["gf_scan_key"] = f"{sha256_bytes(data)}:True"
    app.run()
    assert any("Partial analysis" in warning.value for warning in app.warning)


def test_no_metadata_state_does_not_exaggerate_technical_fields():
    image = Image.new("RGB", (3, 3), "white"); output = io.BytesIO(); image.save(output, "PNG")
    data = output.getvalue(); name = "blank.png"; notice = "Synthetic blank image."
    app = AppTest.from_file("app.py", default_timeout=45)
    app.session_state["gf_demo"] = (data, name, notice)
    app.run()
    assert not app.exception
    assert any("No medium, high, or critical" in success.value for success in app.success)
    assert any("No deterministic potential-misuse scenario" in info.value for info in app.info)


def test_evidence_mode_validation_generation_rerun_downloads_and_reset():
    app = _demo_app()
    next(item for item in app.radio if item.label == "Workflow").set_value("Verifiable Evidence Mode")
    app.run()
    assert {item.label for item in app.text_input} == {"Evidence passphrase", "Confirm passphrase"}
    persistence = next(item for item in app.checkbox if item.label == "Also save the encrypted evidence package locally")
    assert persistence.value is False
    next(button for button in app.button if button.label == "Create verifiable sanitized copy").click()
    app.run()
    assert any("Enter an evidence passphrase" in item.value for item in app.error)

    passphrase = "correct synthetic passphrase"
    next(item for item in app.text_input if item.label == "Evidence passphrase").set_value(passphrase)
    next(item for item in app.text_input if item.label == "Confirm passphrase").set_value("different synthetic passphrase")
    next(button for button in app.button if button.label == "Create verifiable sanitized copy").click()
    app.run()
    assert any("does not match" in item.value for item in app.error)

    next(item for item in app.text_input if item.label == "Evidence passphrase").set_value(passphrase)
    next(item for item in app.text_input if item.label == "Confirm passphrase").set_value(passphrase)
    next(button for button in app.button if button.label == "Create verifiable sanitized copy").click()
    app.run()
    assert not app.exception
    evidence = app.session_state["gf_evidence_result"]
    package = evidence.evidence_package
    encrypted = evidence.encrypted_evidence
    sanitized = evidence.sanitization_outcome.data
    labels = {item.label for item in app.get("download_button")}
    assert {"Download exact sanitized file", "Download .gfp evidence package", "Download standalone .gfe"}.issubset(labels)
    assert any("LOCAL EVIDENCE INTEGRITY VERIFIED" in item.value for item in app.success)
    assert any("BLOCKCHAIN" in item.value and "NOT APPLICABLE" in item.value for item in app.info)
    assert "gf_evidence_passphrase" not in app.session_state or app.session_state["gf_evidence_passphrase"] == ""
    assert "gf_evidence_confirmation" not in app.session_state or app.session_state["gf_evidence_confirmation"] == ""

    app.run()
    rerun = app.session_state["gf_evidence_result"]
    assert rerun.evidence_package == package
    assert rerun.encrypted_evidence == encrypted
    assert rerun.sanitization_outcome.data == sanitized

    next(button for button in app.button if button.label == "Start over").click()
    app.run()
    assert "gf_evidence_result" not in app.session_state


def test_verification_mode_is_independent_and_has_optional_file_inputs():
    app = _empty_app()
    next(item for item in app.radio if item.label == "Workflow").set_value("Verify Evidence Package")
    app.run()
    assert not app.exception
    upload_labels = {item.label for item in app.get("file_uploader")}
    assert upload_labels == {
        "GhostFrame evidence package (.gfp)",
        "Optional claimed original file",
        "Optional claimed sanitized file",
    }
    assert any(item.label == "Evidence passphrase" for item in app.text_input)
    assert any(button.label == "Verify package" for button in app.button)
    assert not any(tab.label == "Sanitize and Verify" for tab in app.tabs)
