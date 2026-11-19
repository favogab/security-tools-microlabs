import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detector import load_rule, event_matches, evaluate_events, build_report


PROJECT = Path(__file__).resolve().parents[1]
RULE_PATH = PROJECT / "rules" / "powershell_encoded.yml"


@pytest.fixture
def rule():
    return load_rule(RULE_PATH)


def test_load_rule_title(rule):
    assert rule["title"] == "PowerShell Encoded Command Execution"


def test_load_rule_has_supported_condition(rule):
    assert rule["detection"]["condition"] == "selection"


def test_encoded_powershell_event_matches(rule):
    event = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA"
    }
    assert event_matches(event, rule)


def test_pwsh_short_encoded_switch_matches(rule):
    event = {
        "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
        "CommandLine": "pwsh.exe -enc SQBFAFgA"
    }
    assert event_matches(event, rule)


def test_normal_powershell_does_not_match(rule):
    event = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe Get-Process"
    }
    assert not event_matches(event, rule)


def test_cmd_with_encoded_text_does_not_match(rule):
    event = {
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd.exe /c echo -EncodedCommand"
    }
    assert not event_matches(event, rule)


def test_matching_is_case_insensitive(rule):
    event = {
        "Image": r"C:\WINDOWS\SYSTEM32\POWERSHELL.EXE",
        "CommandLine": "POWERSHELL.EXE -ENCODEDCOMMAND ABC"
    }
    assert event_matches(event, rule)


def test_missing_field_does_not_match(rule):
    event = {"CommandLine": "powershell.exe -EncodedCommand ABC"}
    assert not event_matches(event, rule)


def test_evaluate_events_returns_two_matches(rule):
    events_path = PROJECT / "samples" / "process_events.json"
    import json
    events = json.loads(events_path.read_text(encoding="utf-8"))
    assert len(evaluate_events(events, rule)) == 2


def test_report_summary(rule):
    events_path = PROJECT / "samples" / "process_events.json"
    events = __import__("json").loads(events_path.read_text(encoding="utf-8"))
    report = build_report(events, rule)
    assert report["summary"] == {
        "events_analyzed": 4,
        "matches": 2,
        "non_matches": 2
    }


def test_unsupported_condition_is_rejected(tmp_path):
    bad_rule = {
        "title": "Unsupported condition",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"Image|endswith": "powershell.exe"},
            "condition": "selection or filter"
        }
    }
    path = tmp_path / "bad.yml"
    path.write_text(
        __import__("yaml").safe_dump(bad_rule),
        encoding="utf-8"
    )
    with pytest.raises(ValueError, match="condition"):
        load_rule(path)


def test_unsupported_modifier_is_rejected(tmp_path):
    bad_rule = {
        "title": "Unsupported modifier",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {"CommandLine|startswith": "powershell"},
            "condition": "selection"
        }
    }
    path = tmp_path / "bad_modifier.yml"
    path.write_text(
        __import__("yaml").safe_dump(bad_rule),
        encoding="utf-8"
    )
    with pytest.raises(ValueError, match="Unsupported field expression"):
        load_rule(path)
