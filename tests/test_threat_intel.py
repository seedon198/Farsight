"""Tests for farsight.modules.threat_intel.

Covers the IntelX result-date parsing fix: IntelX returns `date` as an
ISO-8601 string (e.g. "2026-07-13T00:50:45.484249Z"), not a Unix epoch
number, but the code previously passed it straight into
time.localtime(), which requires a number and raised
"TypeError: 'str' object cannot be interpreted as an integer" --
silently discarding any successfully-found leak/dark-web results.
"""

from farsight.modules.threat_intel import ThreatIntel


def test_process_intelx_results_parses_iso_date_string():
    threat_intel = ThreatIntel()
    records = [
        {
            "bucket": "pastes",
            "name": "Example Paste",
            "date": "2026-07-13T00:50:45.484249Z",
            "snippet": "leaked content",
        }
    ]

    threat_intel._process_intelx_results(records, "example.com")

    assert len(threat_intel.results["leaks"]) == 1
    assert threat_intel.results["leaks"][0]["date"] == "2026-07-13"


def test_process_intelx_results_handles_missing_date():
    threat_intel = ThreatIntel()
    records = [
        {
            "bucket": "darknet",
            "name": "Example",
            "date": "",
            "snippet": "dark web mention",
        }
    ]

    threat_intel._process_intelx_results(records, "example.com")

    assert threat_intel.results["dark_web"][0]["date"] == "Unknown"
