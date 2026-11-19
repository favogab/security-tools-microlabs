# Sigma Detection Rule Lab

A small Python-based detection testing tool that loads a Sigma-style YAML rule and evaluates it against synthetic Windows process-creation events.

## What it demonstrates

- Safe YAML loading and basic rule validation
- Sigma selection matching for `endswith` and `contains`
- AND logic across selection fields and OR logic within a list of values
- Case-insensitive string matching
- JSON reporting of matched events
- Automated tests for positive, negative, and invalid-rule cases

## Project structure

```text
03-sigma-detection-lab/
├── rules/
│   └── powershell_encoded.yml
├── samples/
│   └── process_events.json
├── tests/
│   └── test_detector.py
├── detector.py
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
python detector.py
```

Expected sample result:

```text
=== SIGMA DETECTION LAB ===
Rule: PowerShell Encoded Command Execution
Events analyzed: 4
Matches: 2
Non-matches: 2
Report saved to: detection_report.json
```

You can provide alternate files:

```powershell
python detector.py --rule rules/powershell_encoded.yml --events samples/process_events.json --output detection_report.json
```

## Test

```powershell
python -m pytest -v
```

## Detection logic

The sample rule detects a Windows process event when both conditions are true:

1. `Image|endswith` matches `\powershell.exe` or `\pwsh.exe`.
2. `CommandLine|contains` matches one of the configured encoded-command switches.

The evaluator applies AND between the fields and OR between values in each list. Matching is case-insensitive.

## Scope and limitations

This is an educational evaluator for a deliberately limited Sigma subset, not the official Sigma rule specification or a complete Sigma backend. It supports only:

- Windows `process_creation` log sources
- A single `selection` condition
- `endswith` and `contains` modifiers
- String-valued event fields

It does not implement `all of`, `1 of`, named filters, field references, regex, wildcard, CIDR, numeric comparisons, aggregation, or backend-specific conversion. For production Sigma parsing and SIEM query conversion, use the official Sigma ecosystem and pySigma.

The sample events are synthetic. The rule is a learning example and may require tuning before operational use. Encoded PowerShell is not inherently malicious; investigate context, parent process, user, command content, and endpoint telemetry.

## MITRE ATT&CK

The sample rule references [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/).

## Future improvements

- Add additional Sigma modifiers and condition expressions
- Validate rules with the official Sigma tooling
- Convert rules to a SIEM query using pySigma backends
- Add more Windows event categories and detection test fixtures
