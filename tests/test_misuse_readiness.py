import pytest

from ghostframe.comparison import compare_results
from ghostframe.inspectors.common import make_finding
from ghostframe.masking import is_sensitive_finding, mask_url, mask_value
from ghostframe.misuse import build_misuse_scenarios
from ghostframe.models import Correlation, InspectionResult, MisuseScenario
from ghostframe.readiness import evaluate_share_readiness
from ghostframe.scoring import calculate_exposure_score


def finding(name: str, value: str, source: str, **overrides):
    return make_finding("docx", "Test", name, value, source, overrides=overrides or None)


def test_every_misuse_rule_trigger_and_evidence_traceability():
    items = [
        finding("GPSLatitudeDecimal", "12.345", "gps/lat", severity="High", risk_group="precise_location"),
        finding("GPSLongitudeDecimal", "-98.765", "gps/lon", severity="High", risk_group="precise_location"),
        finding("Creator", "Example Person", "core/creator", severity="High", risk_group="direct_identity", subcategory="identity"),
        finding("CameraSerialNumber", "DEMO-1234", "exif/serial", severity="High", risk_group="device_identifiers", subcategory="device identifier"),
        finding("Created", "2026-01-01T10:00:00", "core/created", severity="Medium", risk_group="timeline_provenance", subcategory="timeline"),
        finding("Comment", "Example review", "comments/0", severity="High", risk_group="collaboration_history", subcategory="comment"),
        finding("Company", "Example Labs", "app/company", severity="High", risk_group="direct_identity", subcategory="identity"),
        finding("Application", "Example Editor 1.0", "app/name", severity="Low", risk_group="software_fingerprint", subcategory="software"),
        finding("URI", "https://example.invalid/open?token=demo", "pdf/action", severity="High", risk_group="active_external_behavior", subcategory="active or external behavior"),
        finding("CustomXMLPart", "Present", "customXml/item1.xml", severity="Medium", risk_group="hidden_embedded_content", subcategory="hidden structured data"),
        finding("JavaScript", "Present", "pdf/openAction", severity="High", risk_group="active_external_behavior", subcategory="active content"),
    ]
    scenarios = build_misuse_scenarios(items)
    categories = {item.category for item in scenarios}
    assert {"precise_location", "identity_disclosure", "device_linking", "timeline_reconstruction", "collaboration_leakage", "organization_profiling", "software_fingerprinting", "external_resource_tracking", "hidden_content_disclosure", "active_content"}.issubset(categories)
    known = {item.finding_id for item in items}
    assert all(set(item.evidence_finding_ids).issubset(known) for item in scenarios)
    assert all(item.required_conditions and item.alternative_explanation and item.not_proven for item in scenarios)


def test_rules_do_not_trigger_for_harmless_technical_fields():
    items = [
        finding("ImageWidth", "800", "header/width", severity="Informational", risk_group="technical", subcategory="technical"),
        finding("PageCount", "2", "pdf/pages", severity="Informational", risk_group="technical", subcategory="technical"),
        finding("ICCProfile", "sRGB", "image/icc", severity="Informational", risk_group="technical", subcategory="technical"),
    ]
    assert build_misuse_scenarios(items) == []
    assert calculate_exposure_score(items).score == 0
    assert all(item.actionability == "No action needed" for item in items)


def test_scenario_validation_and_deduplication():
    kwargs = dict(
        scenario_id="S", title="T", category="c", summary="s", possible_misuse="p", exposed_asset="a",
        required_conditions=["c"], likelihood="Impossible", impact="Low", confidence="High",
        evidence_finding_ids=["F"], why_it_matters="w", recommended_protection=["r"],
        alternative_explanation="a", not_proven="n",
    )
    with pytest.raises(ValueError, match="likelihood"):
        MisuseScenario(**kwargs)
    author = finding("Author", "Example Person", "info/author", severity="High", risk_group="direct_identity", subcategory="identity")
    duplicate = finding("Creator", "Example Person", "info/creator", severity="High", risk_group="direct_identity", subcategory="identity")
    scenarios = build_misuse_scenarios([author, duplicate])
    assert [item.category for item in scenarios].count("identity_disclosure") == 1


def test_masking_names_serial_coordinates_email_and_url_tokens():
    name = finding("Author", "Example Person", "info/author", severity="High", risk_group="direct_identity", subcategory="identity")
    serial = finding("BodySerialNumber", "SERIAL-123456", "exif/serial", severity="High", risk_group="device_identifiers")
    gps = finding("GPSLatitudeDecimal", "12.345678", "gps/lat", severity="High", risk_group="precise_location")
    email = finding("Author", "example.person@example.invalid", "info/email", severity="High", risk_group="direct_identity")
    assert mask_value(name) == "E… P…"
    assert mask_value(serial).endswith("3456") and "SERIAL" not in mask_value(serial)
    assert mask_value(gps) == "[exact coordinate masked]"
    assert "example.person" not in mask_value(email)
    masked_url = mask_url("https://example.invalid/path?token=secret&id=42#fragment")
    assert "secret" not in masked_url and "42" not in masked_url and "fragment" not in masked_url
    assert "token=%2A%2A%2A" in masked_url
    assert all(is_sensitive_finding(item) for item in (name, serial, gps, email))


def test_scoring_deduplicates_gps_and_same_author_representation():
    lat_raw = finding("GPSLatitude", "12, 20, 0", "gps/rawlat", severity="Medium", risk_group="precise_location")
    lon_raw = finding("GPSLongitude", "98, 30, 0", "gps/rawlon", severity="Medium", risk_group="precise_location")
    lat = finding("GPSLatitudeDecimal", "12.333", "gps/lat", severity="High", risk_group="precise_location")
    lon = finding("GPSLongitudeDecimal", "98.5", "gps/lon", severity="High", risk_group="precise_location")
    author = finding("Author", "Example Person", "info/author", severity="High", risk_group="direct_identity")
    creator = finding("Creator", "Example Person", "info/creator", severity="High", risk_group="direct_identity")
    score = calculate_exposure_score([lat_raw, lon_raw, lat, lon, author, creator])
    location = next(item for item in score.contributions if item.group == "precise_location")
    identity = next(item for item in score.contributions if item.group == "direct_identity")
    assert set(location.finding_ids) == {lat.finding_id, lon.finding_id}
    assert identity.points == 12
    assert score.base_points == location.points + identity.points


def test_scoring_ignores_uncited_and_duplicate_correlations_and_stays_bounded():
    item = finding("Creator", "Example Person", "info/creator", severity="High", risk_group="direct_identity")
    correlation = Correlation("C1", "Related clue", "Evidence combines.", "High", [item.finding_id], "Could be stale.", severity="High")
    duplicate = Correlation("C2", "Same evidence again", "Evidence combines.", "High", [item.finding_id], "Could be stale.", severity="High")
    uncited = Correlation("C3", "Missing evidence", "Invalid reference.", "High", ["F-NOT-PRESENT"], "No evidence.", severity="High")
    score = calculate_exposure_score([item], [correlation, duplicate, uncited])
    assert score.correlation_bonus == 3
    assert score.score == score.base_points + 3
    assert score.score <= 100


def test_share_readiness_and_scenario_mitigation():
    high = finding("Author", "Example Person", "info/author", severity="High", risk_group="direct_identity", subcategory="identity")
    before = InspectionResult("PDF", [high], misuse_scenarios=build_misuse_scenarios([high]))
    assert evaluate_share_readiness(before).state == "Do not share yet"
    after = InspectionResult("PDF", [])
    report = compare_results(before, after)
    assert report.scenario_mitigations[0].status == "Mitigated"
    assert report.share_readiness.state == "Ready for supported-metadata sharing"


def test_partial_analysis_blocks_readiness_and_mitigation():
    item = finding("Author", "Example Person", "info/author", severity="High", risk_group="direct_identity", subcategory="identity")
    before = InspectionResult("PDF", [item], partial_analysis=True, misuse_scenarios=build_misuse_scenarios([item]))
    after = InspectionResult("PDF", [], partial_analysis=True)
    report = compare_results(before, after)
    assert report.scenario_mitigations[0].status == "Verification unavailable"
    assert report.share_readiness.state == "Do not share yet"


def test_partial_mitigation_when_one_identity_is_removed_but_equivalent_remains():
    author = finding("Author", "Example Person", "info/author", severity="High", risk_group="direct_identity", subcategory="identity")
    creator = finding("Creator", "Example Person", "info/creator", severity="High", risk_group="direct_identity", subcategory="identity")
    before = InspectionResult("PDF", [author, creator], misuse_scenarios=build_misuse_scenarios([author, creator]))
    after = InspectionResult("PDF", [creator], misuse_scenarios=build_misuse_scenarios([creator]))
    report = compare_results(before, after)
    assert report.scenario_mitigations[0].status == "Partially mitigated"
    assert report.share_readiness.state == "Do not share yet"


def test_unexpected_introduced_evidence_blocks_sharing():
    introduced = finding("Creator", "Unexpected Person", "info/creator", severity="High", risk_group="direct_identity", subcategory="identity")
    before = InspectionResult("PDF", [])
    after = InspectionResult("PDF", [introduced], misuse_scenarios=build_misuse_scenarios([introduced]))
    report = compare_results(before, after)
    assert report.introduced
    assert report.share_readiness.state == "Do not share yet"
