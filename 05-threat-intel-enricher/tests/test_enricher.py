import json, sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enricher import (classify_indicator, load_indicators, is_publicly_queryable,
                      virustotal_lookup, abuseipdb_lookup, enrich_indicators,
                      build_report, render_markdown)

PROJECT = Path(__file__).resolve().parents[1]
SAMPLE = PROJECT / "samples" / "iocs.json"

def test_classifies_ip():
    assert classify_indicator("8.8.8.8") == ("ip", "8.8.8.8")

def test_normalizes_domain():
    assert classify_indicator("EXAMPLE.ORG") == ("domain", "example.org")

def test_classifies_url():
    assert classify_indicator("https://example.org/path") == ("url", "https://example.org/path")

def test_normalizes_sha256():
    value = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert classify_indicator(value) == ("sha256", value.lower())

def test_rejects_invalid_indicator():
    with pytest.raises(ValueError):
        classify_indicator("not an indicator")

def test_load_deduplicates_and_rejects_invalid():
    indicators, rejected = load_indicators(SAMPLE)
    assert len(indicators) == 8
    assert len(rejected) == 1

def test_documentation_ip_is_not_public():
    assert not is_publicly_queryable({"type": "ip", "value": "192.0.2.55"})

def test_example_domain_is_not_public():
    assert not is_publicly_queryable({"type": "domain", "value": "malware-delivery.example"})

def test_offline_mode_makes_no_provider_calls():
    result = enrich_indicators([{"type": "ip", "value": "8.8.8.8"}])
    assert result[0]["enrichment_status"] == "offline"
    assert result[0]["providers"] == []

def test_live_skips_reserved_indicator():
    result = enrich_indicators([{"type": "ip", "value": "192.0.2.55"}],
                               live=True, vt_key="dummy")
    assert result[0]["enrichment_status"] == "skipped_non_public_indicator"

def test_virustotal_url_uses_urlsafe_id():
    class Response:
        def raise_for_status(self): pass
        def json(self):
            return {"data": {"attributes": {"reputation": 2,
                    "last_analysis_stats": {"malicious": 1, "harmless": 4}}}}
    class Session:
        def get(self, url, **kwargs):
            self.url = url
            return Response()
    session = Session()
    result = virustotal_lookup(session, "dummy", "url", "https://example.org/path")
    assert "/urls/" in session.url
    assert result["reputation"] == 2

def test_abuseipdb_response_is_normalized():
    class Response:
        def raise_for_status(self): pass
        def json(self):
            return {"data": {"abuseConfidenceScore": 25, "totalReports": 10,
                    "countryCode": "US", "isp": "Example ISP", "lastReportedAt": None}}
    class Session:
        def get(self, url, **kwargs): return Response()
    result = abuseipdb_lookup(Session(), "dummy", "8.8.8.8")
    assert result["abuse_score"] == 25
    assert result["total_reports"] == 10

def test_report_contains_analyst_caveat():
    enriched = enrich_indicators([{"type": "ip", "value": "192.0.2.55"}])
    report = build_report(enriched, [], live=False)
    assert report["summary"]["indicators_processed"] == 1
    assert "not proof of compromise" in render_markdown(report)


def test_reserved_example_org_is_not_public():
    assert not is_publicly_queryable({"type": "domain", "value": "example.org"})
