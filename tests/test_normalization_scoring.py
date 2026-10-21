from ghostframe.comparison import compare_results
from ghostframe.correlation import build_correlations, build_timeline
from ghostframe.inspectors.common import make_finding
from ghostframe.models import InspectionResult
from ghostframe.normalization import gps_dms_to_decimal, normalize_datetime, stable_finding_id
from ghostframe.scoring import GROUP_CAPS, calculate_exposure_score


def test_gps_conversion_north_east_and_south_west():
    north, _ = gps_dms_to_decimal((12, 30, 0), "N")
    east, _ = gps_dms_to_decimal((77, 35, 30), "E")
    south, _ = gps_dms_to_decimal((12, 30, 0), "S")
    west, _ = gps_dms_to_decimal((77, 35, 30), "W")
    assert north == 12.5 and south == -12.5
    assert east == 77.5916667 and west == -77.5916667


def test_incomplete_and_invalid_gps_are_explained():
    assert gps_dms_to_decimal((12, 30), "N")[0] is None
    assert "incomplete" in gps_dms_to_decimal((12, 30), "N")[1]
    assert gps_dms_to_decimal((91, 0, 0), "N")[0] is None
    assert "range" in gps_dms_to_decimal((91, 0, 0), "N")[1]
    assert gps_dms_to_decimal((12, 60, 0), "E")[0] is None


def test_pdf_and_iso_dates_preserve_timezone_information():
    value, note = normalize_datetime("D:20260920112233+05'30'")
    assert value == "2026-09-20T11:22:33+05:30"
    assert "+05'30'" in note
    value, note = normalize_datetime("2026-09-20T11:22:33")
    assert value == "2026-09-20T11:22:33"
    assert "not present" in note


def test_scoring_is_deterministic_and_group_caps_apply():
    findings = [make_finding("jpg", "EXIF", f"Author{i}", f"Person {i}", f"EXIF/tag/{i}", overrides={"severity": "High", "risk_group": "direct_identity"}) for i in range(30)]
    first = calculate_exposure_score(findings)
    second = calculate_exposure_score(list(reversed(findings)))
    assert first.to_dict() == second.to_dict()
    identity = next(item for item in first.contributions if item.group == "direct_identity")
    assert identity.points == GROUP_CAPS["direct_identity"]
    assert 0 <= first.score <= 100


def test_score_boundaries():
    assert calculate_exposure_score([]).rating == "Minimal"
    critical = [make_finding("pdf", "Action", f"Action{i}", "present", f"obj/{i}", overrides={"severity": "Critical", "risk_group": group}) for i, group in enumerate(GROUP_CAPS)]
    score = calculate_exposure_score(critical)
    assert score.score <= 100
    assert score.rating in {"High", "Severe"}


def test_correlations_cite_evidence_and_timeline_preserves_source():
    creator = make_finding("docx", "Core", "Creator", "Alice", "docProps/core.xml/creator")
    company = make_finding("docx", "App", "Company", "Example Ltd", "docProps/app.xml/company")
    created = make_finding("docx", "Core", "Created", "2026-09-20T10:00:00Z", "docProps/core.xml/created")
    correlations = build_correlations([creator, company, created])
    assert correlations
    assert {creator.finding_id, company.finding_id}.issubset(correlations[0].evidence_finding_ids)
    assert correlations[0].alternative_interpretation
    timeline = build_timeline([created])
    assert timeline[0].source_finding_id == created.finding_id
    assert timeline[0].normalized_time.endswith("+00:00")


def test_stable_comparison_uses_identity_and_source_not_count():
    old = make_finding("pdf", "Info", "Author", "Alice", "trailer/Info/Author")
    new = make_finding("pdf", "Info", "Producer", "Tool", "trailer/Info/Producer")
    before = InspectionResult("PDF", [old], file_sha256="a", file_size=10)
    after = InspectionResult("PDF", [new], file_sha256="b", file_size=12)
    report = compare_results(before, after)
    assert len(report.removed) == 1 and len(report.introduced) == 1
    assert report.status == "Verified with residual findings"
    assert stable_finding_id("pdf", "Info", "Author", "trailer/Info/Author") == old.finding_id
