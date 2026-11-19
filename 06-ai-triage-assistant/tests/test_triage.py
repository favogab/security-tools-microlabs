
import json

import pytest
from pydantic import ValidationError

from triage import (
    SecurityAlert,
    TriageAssessment,
    load_alert,
    mock_analyze_alert,
    build_report,
    render_markdown
)


@pytest.fixture
def alert():
    return load_alert("samples/alert.json")


def test_alert_loads_successfully(alert):
    assert alert.alert_id == "SOC-2026-0042"


def test_alert_contains_process_information(alert):
    assert alert.process.image == "powershell.exe"
    assert alert.process.parent_image == "WINWORD.EXE"


def test_invalid_severity_is_rejected():
    with pytest.raises(ValidationError):
        SecurityAlert.model_validate({
            "alert_id": "TEST-001",
            "alert_name": "Test",
            "timestamp": "2026-11-19T09:45:00Z",
            "severity": "extreme",
            "hostname": "TEST-PC",
            "username": "user",
            "process": {},
            "network": {},
            "evidence": ["Test evidence"]
        })


def test_mock_provider_returns_valid_assessment(alert):
    assessment = mock_analyze_alert(alert)

    assert isinstance(assessment, TriageAssessment)
    assert assessment.incident_status == "needs_investigation"


def test_mock_provider_preserves_evidence(alert):
    assessment = mock_analyze_alert(alert)

    assert assessment.evidence_references == alert.evidence


def test_mock_provider_requires_human_decision(alert):
    assessment = mock_analyze_alert(alert)

    assert assessment.analyst_decision_required is True


def test_report_contains_alert_and_assessment(alert):
    assessment = mock_analyze_alert(alert)
    report = build_report(alert, assessment)

    assert report["alert"]["alert_id"] == alert.alert_id
    assert report["human_review_required"] is True


def test_markdown_report_contains_investigation_sections(alert):
    assessment = mock_analyze_alert(alert)
    report = build_report(alert, assessment)

    markdown = render_markdown(report)

    assert "AI Assessment" in markdown
    assert "Recommended investigation actions" in markdown
    assert "Missing context" in markdown
    assert "Human review required" in markdown
