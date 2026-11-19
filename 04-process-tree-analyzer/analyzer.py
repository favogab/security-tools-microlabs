import argparse
import json
from collections import defaultdict
from pathlib import Path
from ntpath import basename


OFFICE_PROCESSES = {
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "onenote.exe"
}
SCRIPTING_CHILDREN = {
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"
}
SCRIPTING_PARENTS = {
    "powershell.exe", "pwsh.exe", "wscript.exe",
    "cscript.exe", "mshta.exe"
}
FOLLOW_ON_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe"
}


def process_name(image):
    """Return a Windows executable name from an image path."""
    return basename(image or "").casefold()


def load_events(path):
    with Path(path).open("r", encoding="utf-8-sig") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Sysmon input must be a JSON array.")

    valid = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"Event at index {index} must be an object.")
        if event.get("EventID") != 1:
            continue
        if not event.get("ProcessGuid") or not event.get("Image"):
            raise ValueError(
                f"Event at index {index} is missing ProcessGuid or Image."
            )
        valid.append(event)

    return valid


def build_process_index(events):
    """Index process creation events by Sysmon ProcessGuid."""
    index = {}
    for event in events:
        guid = event["ProcessGuid"]
        if guid in index:
            raise ValueError(f"Duplicate ProcessGuid found: {guid}")
        index[guid] = event
    return index


def reconstruct_processes(events):
    """Return normalized process records with resolved parent relationships."""
    process_index = build_process_index(events)
    processes = []

    for event in events:
        parent_guid = event.get("ParentProcessGuid")
        parent_event = process_index.get(parent_guid)

        parent_image = (
            parent_event.get("Image") if parent_event else event.get("ParentImage")
        )

        child_name = process_name(event.get("Image"))
        parent_name = process_name(parent_image)

        reasons = []
        if parent_name in OFFICE_PROCESSES and child_name in SCRIPTING_CHILDREN:
            reasons.append("Office application spawned a scripting or command utility")
        if parent_name in SCRIPTING_PARENTS and child_name in FOLLOW_ON_CHILDREN:
            reasons.append("Scripting process spawned another command or execution utility")

        processes.append({
            "process_guid": event["ProcessGuid"],
            "process_id": event.get("ProcessId"),
            "image": event.get("Image"),
            "process_name": child_name,
            "command_line": event.get("CommandLine"),
            "user": event.get("User"),
            "utc_time": event.get("UtcTime"),
            "parent_process_guid": parent_guid,
            "parent_process_id": event.get("ParentProcessId"),
            "parent_image": parent_image,
            "parent_resolved_from_events": parent_event is not None,
            "suspicious": bool(reasons),
            "reasons": reasons
        })

    return processes


def build_chains(processes):
    """Build root-to-process chains using ProcessGuid relationships."""
    by_guid = {process["process_guid"]: process for process in processes}
    chains = {}

    for process in processes:
        chain = []
        current = process
        visited = set()

        while current:
            guid = current["process_guid"]
            if guid in visited:
                chain.insert(0, "[cycle detected]")
                break
            visited.add(guid)
            chain.insert(0, current["process_name"])

            parent_guid = current["parent_process_guid"]
            current = by_guid.get(parent_guid)

        chains[process["process_guid"]] = chain

    return chains


def create_report(events):
    processes = reconstruct_processes(events)
    chains = build_chains(processes)

    for process in processes:
        process["process_chain"] = chains[process["process_guid"]]

    flagged = [process for process in processes if process["suspicious"]]

    return {
        "summary": {
            "events_analyzed": len(events),
            "processes_indexed": len(processes),
            "suspicious_relationships": len(flagged)
        },
        "flagged_processes": flagged,
        "processes": processes,
        "notes": [
            "Heuristic findings are investigation leads, not proof of compromise.",
            "Parent resolution uses Sysmon ProcessGuid values when the parent event is present.",
            "Missing parent events are retained using ParentImage from the child event."
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="Reconstruct process relationships from Sysmon Event ID 1 JSON."
    )
    parser.add_argument(
        "--input", default="samples/sysmon_events.json",
        help="Path to a JSON array of Sysmon Event ID 1 records."
    )
    parser.add_argument(
        "--output", default="process_tree_report.json",
        help="Path for the JSON investigation report."
    )
    args = parser.parse_args()

    events = load_events(args.input)
    report = create_report(events)
    Path(args.output).write_text(json.dumps(report, indent=4), encoding="utf-8")

    print("\n=== PROCESS TREE ANALYZER ===")
    print(f"Events analyzed: {report['summary']['events_analyzed']}")
    print(f"Processes indexed: {report['summary']['processes_indexed']}")
    print(
        "Suspicious relationships: "
        f"{report['summary']['suspicious_relationships']}"
    )
    for item in report["flagged_processes"]:
        print(f"\n[FLAG] {item['parent_image']} -> {item['image']}")
        print(f"       Reason: {', '.join(item['reasons'])}")
        print(f"       Chain: {' -> '.join(item['process_chain'])}")
    print(f"\nReport saved to: {args.output}")


if __name__ == "__main__":
    main()
