
# 06 — AI-Assisted Triage Assistant

An AI-assisted security alert triage tool built with Python, Pydantic
and the OpenAI API, with an offline mock provider for development
and testing without API costs.

## Project Objective

Help SOC analysts interpret structured security alerts by producing
consistent investigation summaries, evidence references, recommended
actions and missing-context assessments.

The tool is designed to assist analysts, not replace their decisions.

## Features

- JSON security alert ingestion
- Pydantic input validation
- Structured triage assessment
- OpenAI Responses API integration
- Offline mock provider
- Evidence reference validation
- JSON investigation reports
- Markdown investigation reports
- Human-review requirement

## Architecture

1. Load and validate a security alert.
2. Select an AI provider or offline mock provider.
3. Generate a structured triage assessment.
4. Validate the assessment against the output schema.
5. Verify that evidence references exist in the original alert.
6. Generate JSON and Markdown reports.

## Project Structure

```text
06-ai-triage-assistant/
├── samples/
│   └── alert.json
├── tests/
│   └── test_triage.py
├── .env.example
├── README.md
├── requirements.txt
└── triage.py
```

## Installation

From the project directory:

```powershell
python -m pip install -r requirements.txt
```

## Offline Usage

Run the deterministic mock provider:

```powershell
python triage.py --mock
```

This mode requires no API key, internet connection or API credits.

It produces:

- `triage_report.json`
- `triage_report.md`

**Note:** Mock assessments are simulated outputs. They are not
genuine AI-generated security analysis.

## OpenAI Integration

Create a `.env` file:

```env
OPENAI_API_KEY=your_api_key
OPENAI_MODEL=your_supported_model_id
```

Then run:

```powershell
python triage.py
```

A valid API key, available API credits and a supported model are
required. The OpenAI integration is implemented but has not been
verified against a live API request in this project.

## Testing

Run:

```powershell
python -m pytest -v
```

The automated tests cover input validation, assessment structure,
evidence preservation, human-review safeguards and report generation.

## Security Considerations

- API credentials are stored in environment variables.
- Alert contents are treated as untrusted data.
- AI evidence references are checked against supplied evidence.
- AI assessments do not constitute incident confirmation.
- Human review is required before security decisions.
- Real security telemetry should be appropriately redacted before
  sending it to an external AI provider.

## Limitations

- The mock provider uses predefined assessment logic.
- The mock provider does not perform live threat intelligence lookups.
- AI recommendations require analyst verification.
- Live OpenAI integration requires separately funded API access.

## Technologies

Python · OpenAI API · Pydantic · pytest · JSON · python-dotenv

## Learning Outcomes

API integration, structured data validation, prompt design,
evidence integrity, provider abstraction, automated testing
and security report generation.