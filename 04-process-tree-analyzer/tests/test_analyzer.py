import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzer import (
    process_name,
    load_events,
    build_process_index,
    reconstruct_processes,
    build_chains,
    create_report
)

PROJECT = Path(__file__).resolve().parents[1]
SAMPLE = PROJECT / "samples" / "sysmon_events.json"


@pytest.fixture
def events():
    return load_events(SAMPLE)


def test_process_name_extracts_windows_executable():
    assert process_name(r"C:\Windows\System32\POWERSHELL.EXE") == "powershell.exe"


def test_loads_only_process_creation_events(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps([
        {"EventID": 3, "ProcessGuid": "{net}", "Image": "network"},
        {"EventID": 1, "ProcessGuid": "{proc}", "Image": "cmd.exe"}
    ]), encoding="utf-8")
    assert len(load_events(path)) == 1


def test_rejects_non_array_input(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"EventID": 1}', encoding="utf-8")
    with pytest.raises(ValueError, match="JSON array"):
        load_events(path)


def test_rejects_event_missing_process_guid(tmp_path):
    path = tmp_path / "bad_event.json"
    path.write_text(json.dumps([{"EventID": 1, "Image": "cmd.exe"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="ProcessGuid"):
        load_events(path)


def test_indexes_all_processes(events):
    assert len(build_process_index(events)) == 6


def test_rejects_duplicate_process_guid(events):
    with pytest.raises(ValueError, match="Duplicate ProcessGuid"):
        build_process_index(events + [events[0]])


def test_reconstructs_parent_relationship(events):
    processes = reconstruct_processes(events)
    powershell = next(p for p in processes if p["process_name"] == "powershell.exe")
    assert powershell["parent_image"].endswith("WINWORD.EXE")
    assert powershell["parent_process_guid"] == events[0]["ProcessGuid"]


def test_detects_office_spawning_powershell(events):
    processes = reconstruct_processes(events)
    powershell = next(p for p in processes if p["process_name"] == "powershell.exe")
    assert powershell["suspicious"] is True


def test_detects_outlook_spawning_wscript(events):
    processes = reconstruct_processes(events)
    wscript = next(p for p in processes if p["process_name"] == "wscript.exe")
    assert wscript["suspicious"] is True


def test_notepad_from_explorer_is_not_flagged(events):
    processes = reconstruct_processes(events)
    notepad = next(p for p in processes if p["process_name"] == "notepad.exe")
    assert notepad["suspicious"] is False


def test_builds_full_process_chain(events):
    processes = reconstruct_processes(events)
    chains = build_chains(processes)
    rundll = next(p for p in processes if p["process_name"] == "rundll32.exe")
    assert chains[rundll["process_guid"]] == [
        "winword.exe", "powershell.exe", "cmd.exe", "rundll32.exe"
    ]


def test_report_summary(events):
    report = create_report(events)
    assert report["summary"] == {
        "events_analyzed": 6,
        "processes_indexed": 6,
        "suspicious_relationships": 3
    }


def test_missing_parent_is_retained_as_external_parent(events):
    processes = reconstruct_processes(events)
    word = next(p for p in processes if p["process_name"] == "winword.exe")
    assert word["parent_resolved_from_events"] is False
    assert word["parent_image"].endswith("explorer.exe")
