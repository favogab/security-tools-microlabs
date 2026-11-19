# Process Tree Analyzer

A Python security automation tool that reconstructs parent-child process relationships from Sysmon Event ID 1 (Process Creation) records and highlights selected suspicious execution patterns.

## Features

- Loads JSON-exported Sysmon process creation events.
- Indexes processes by Sysmon `ProcessGuid`.
- Resolves parent processes using `ParentProcessGuid`.
- Retains parent image metadata when the parent's creation event is absent.
- Reconstructs root-to-process execution chains.
- Flags selected Office-to-script and script-to-command relationships.
- Exports a JSON investigation report.
- Includes automated tests using synthetic telemetry.

## Project structure

```text
04-process-tree-analyzer/
├── samples/
│   └── sysmon_events.json
├── tests/
│   └── test_analyzer.py
├── analyzer.py
├── requirements.txt
└── README.md
```

## Setup

From this directory, with the repository virtual environment activated:

```powershell
python -m pip install -r requirements.txt
```

## Run

```powershell
python analyzer.py
```

Use alternate input and output paths:

```powershell
python analyzer.py --input samples/sysmon_events.json --output process_tree_report.json
```

## Test

```powershell
python -m pytest -v
```

## Detection heuristics

The sample analyzer flags two relationship categories:

1. Microsoft Office applications spawning PowerShell, command prompt, Windows Script Host, MSHTA, or Rundll32.
2. Selected scripting processes spawning additional command or execution utilities.

These are behavioral heuristics. They can generate false positives and should be investigated with command-line content, user context, timestamps, file reputation, network activity, and surrounding endpoint telemetry.

## Data model

The analyzer uses Sysmon process identifiers:

- `ProcessGuid`: unique identifier for the created process.
- `ParentProcessGuid`: identifier for its parent process.
- `Image`: executable path.
- `ParentImage`: parent executable path.
- `CommandLine` and `ParentCommandLine`: execution context.

The sample data is synthetic and intended for learning. Real Sysmon exports may require field mapping before use.

## Limitations

- Accepts a JSON array, not raw EVTX files or XML exports.
- Requires Sysmon Event ID 1 fields.
- Does not correlate across hosts or boot sessions.
- Uses a small set of hard-coded behavioral heuristics, not a full detection framework.
- Does not prove that a flagged process is malicious.

## Future improvements

- Add EVTX/XML ingestion.
- Add time-aware process correlation and host identifiers.
- Export a visual process tree.
- Support configurable detection rules and Sigma integration.
