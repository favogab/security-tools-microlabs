# 06 — AI-Assisted Triage Assistant

A Python application that validates a structured security alert and produces a structured triage assessment using either the OpenAI API or a deterministic offline mock provider.

The tool is designed to assist SOC analysts, not replace their decisions.

## Problem

Security alerts often contain a mixture of process, network and evidence details. Analysts need a consistent way to summarize the alert, identify what is known, identify missing context and plan the next investigation steps.

This lab demonstrates structured alert validation, provider-based analysis and report generation while keeping human review explicit.

## Features

- Loads a security alert from JSON.
- Validates input with Pydantic models.
- Supports a live OpenAI Responses API integration using structured parsing.
- Supports a deterministic offline mock provider.
- Validates the AI assessment against a Pydantic output model.
- Checks that AI evidence references are exact strings from the supplied alert evidence.
- Produces JSON and Markdown investigation reports.
- Requires human analyst review in the assessment and report.
- Includes automated tests for validation, mock assessment and report generation.

## Technologies

- Python 3
- OpenAI Python SDK
- OpenAI Responses API (`responses.parse`)
- Pydantic
- python-dotenv
- JSON
- pytest

## Project structure

```text
06-ai-triage-assistant/
├── samples/
│   └── alert.json
├── tests/
│   └── test_triage.py
├── .env.example
├── requirements.txt
├── triage.py
└── README.md
```

A local `.env` file is used for credentials and must not be committed. The generated `triage_report.json` and `triage_report.md` are output files.

## Installation

From this directory:

```powershell
python -m pip install -r requirements.txt
```

## Input schema

The sample alert is a JSON object with these required fields:

- `alert_id`, `alert_name`, `timestamp`, `severity`, `hostname` and `username`
- `process`: executable image, command line, parent image and process ID
- `network`: destination IP, destination port and protocol
- `evidence`: a non-empty array of evidence strings

Pydantic validates the structure, rejects unexpected fields, constrains severity to `low`, `medium`, `high` or `critical`, and validates the network destination port range.

## Offline usage

Run the deterministic mock provider:

```powershell
python triage.py --mock
```

This mode does not call an external API and requires no API key, internet connection or API credits. It produces:

- `triage_report.json`
- `triage_report.md`

The mock provider returns predefined assessment content based on the supplied alert. It is intended for development and repeatable tests; it is **not** genuine AI analysis and should not be presented as such.

## OpenAI API usage

The live integration requires an OpenAI API key, available API billing/credits, network access and a model identifier supported by the API and your account.

Create a local `.env` file using `.env.example` as a guide:

```dotenv
OPENAI_API_KEY=your_api_key
OPENAI_MODEL=your_supported_model_id
```

Then run:

```powershell
python triage.py
```

The live path uses the OpenAI Python SDK's `client.responses.parse()` method with `TriageAssessment` as the structured output format. It sends the validated alert context to the configured model and does not store the response (`store=False`).

The live integration is implemented but has not been verified against a successful live API request in this project because API credits were unavailable during development. Do not assume a configured key alone proves that a live request will succeed.

Never commit `.env`, expose API keys in screenshots or send sensitive endpoint telemetry to an external provider unless you are authorized to do so.

## Output and analyst safeguards

The assessment schema includes:

- Assessment summary and suggested severity.
- Incident status: `needs_investigation`, `likely_malicious` or `likely_benign`.
- Reasoning.
- Evidence references.
- Recommended investigation actions.
- Missing context.
- Confidence: `low`, `medium` or `high`.
- `analyst_decision_required`, which is constrained to `True`.

The live analysis instructions tell the model to treat alert content as untrusted data, avoid inventing telemetry or reputation results, distinguish facts from hypotheses and avoid declaring an incident confirmed. The application rejects evidence references that do not exactly match an evidence string in the input alert.

These safeguards reduce certain failure modes; they do not guarantee that AI-generated reasoning or recommendations are correct.

## Tests

```powershell
python -m pytest -v
```

The tests cover successful alert loading, process information, invalid severity rejection, mock assessment structure, evidence preservation, human-review requirement and JSON/Markdown report content.

The tests exercise the offline workflow and do not require API credits.

## Limitations

- The mock provider uses predefined logic and content; it does not reason like an AI model.
- The live OpenAI path requires separately funded API access and has not been verified with a successful live request in this project.
- The input schema covers a specific structured alert format, not arbitrary SIEM alert formats.
- The evidence check validates exact references against the supplied evidence list; it does not independently verify whether the evidence itself is accurate.
- Recommendations are advisory. The application does not isolate hosts, block indicators or take containment actions.
- Human review is required before security decisions.

## Future improvements

- Add additional alert input adapters for common SIEM and EDR formats.
- Add stronger validation and provenance for evidence references.
- Add provider-independent interfaces and additional provider implementations.
- Add tests for API failures, malformed responses and evidence-reference violations.
- Add redaction controls before external AI submission.
