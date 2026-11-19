# 03 — Sigma Detection Rule Lab

A small Python detection-testing tool that loads a Sigma-style YAML rule and evaluates it against a JSON array of Windows process-creation events.

The project implements a deliberately limited subset of Sigma selection matching. It is an educational evaluator, not a complete Sigma backend.

## Problem

Detection rules need to be tested against representative events so analysts can understand what matches, what does not, and where false positives may occur.

This lab provides a small, inspectable evaluator for one PowerShell detection example.

## Features

- Loads YAML safely with `yaml.safe_load`.
- Checks required rule sections and supported Windows process-creation log source metadata.
- Validates the supported `selection` condition and field expressions.
- Supports the `endswith` and `contains` string modifiers.
- Applies AND logic across selection fields and OR logic among values in a field's list.
- Performs case-insensitive string comparisons.
- Evaluates JSON event objects and records matching event indexes.
- Generates a JSON report with rule metadata, event counts, matches and evaluator capabilities.
- Includes tests for matching, non-matching, case-insensitive behavior and unsupported rule constructs.

## Technologies

- Python 3
- PyYAML
- JSON
- pytest

## Project structure

```text
03-sigma-rule-lab/
├── rules/
│   └── powershell_encoded.yml
├── samples/
│   └── process_events.json
├── tests/
│   └── test_detector.py
├── detector.py
├── requirements.txt
├── detection_report.json   # generated output
└── README.md
```

## Installation

From this directory:

```powershell
python -m pip install -r requirements.txt
```

The requirements file installs PyYAML and pytest.

## Run with the supplied rule and events

```powershell
python detector.py
```

The default paths are:

- Rule: `rules/powershell_encoded.yml`
- Events: `samples/process_events.json`
- Report: `detection_report.json`

The supplied sample currently produces:

```text
=== SIGMA DETECTION LAB ===
Rule: PowerShell Encoded Command Execution
Events analyzed: 4
Matches: 2
Non-matches: 2
Report saved to: detection_report.json
```

## Run with alternate files

```powershell
python detector.py --rule rules/powershell_encoded.yml --events samples/process_events.json --output detection_report.json
```

All three paths can be supplied through command-line arguments.

## Test

```powershell
python -m pytest -v
```

The tests cover rule loading, encoded PowerShell matches, normal PowerShell non-matches, a command prompt event containing encoded-command text, case-insensitive matching, missing fields, report counts and rejection of unsupported conditions or modifiers.

## Detection logic

The supplied rule is titled **PowerShell Encoded Command Execution**.

It requires both of these selection fields to match:

1. `Image|endswith` — the process image must end in `\powershell.exe` or `\pwsh.exe`.
2. `CommandLine|contains` — the command line must contain one of the configured switches: `-EncodedCommand`, `-enc ` or `-e `.

The evaluator applies:

- AND between the selection fields.
- OR between multiple expected values for one field.
- Case-insensitive comparisons.

The rule metadata declares a Windows `process_creation` log source. The evaluator validates that metadata, but event matching itself uses the configured selection fields; it does not independently enforce an `EventID` value.

## Scope and limitations

This lab supports only:

- Windows `process_creation` log-source metadata.
- One non-empty `selection` mapping.
- The condition exactly equal to `selection`.
- `endswith` and `contains` modifiers.
- String-valued event fields and string expected values.

It does not implement full Sigma condition syntax, `all of`, `1 of`, named filters, field references, regular expressions, wildcards, CIDR, numeric comparisons, aggregation or SIEM backend conversion.

For full Sigma rule validation and SIEM query conversion, use the official Sigma ecosystem and pySigma.

The sample events are synthetic. Encoded PowerShell is not inherently malicious; investigate parent process, user, command content, document origin and surrounding endpoint telemetry before drawing conclusions. Matches are detection leads, not incident confirmation.

## MITRE ATT&CK

The sample rule references [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/).

## Future improvements

- Add more Sigma modifiers and condition expressions.
- Validate rules with official Sigma tooling.
- Convert rules to SIEM queries using pySigma backends.
- Add additional Windows event categories and detection fixtures.
- Add configurable event-field mappings.
