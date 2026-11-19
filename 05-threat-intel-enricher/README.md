# 05 — Threat Intelligence Enricher

A Python SOC automation tool that validates and normalizes indicators of compromise (IOCs), optionally enriches them with VirusTotal and AbuseIPDB, and generates JSON and Markdown investigation reports.

## Problem

Indicators collected during an investigation often arrive in different formats and need validation, normalization and context before an analyst can use them effectively.

This lab creates a repeatable enrichment workflow while keeping offline validation separate from paid or quota-limited provider requests.

## Features

- Accepts IOC arrays in a JSON object (`ipv4`, `ips`, `domains`, `urls`, `sha256`, `hashes`) or a list of objects containing a `value` field.
- Classifies IP addresses, domains, URLs and 64-character SHA-256 values.
- Normalizes IP addresses, domain names and SHA-256 values.
- Rejects invalid values and deduplicates normalized indicators.
- Identifies indicators that are not publicly queryable, including reserved IP ranges and example/test/local domain suffixes.
- Supports VirusTotal lookups for IPs, domains, URLs and SHA-256 hashes.
- Supports AbuseIPDB lookups for IP addresses.
- Handles provider errors independently and records which provider returned each result.
- Supports offline mode without provider requests.
- Generates JSON and Markdown reports.
- Includes tests using mocked provider responses; tests do not need API keys or network access.

## Technologies

- Python 3
- Requests
- python-dotenv
- VirusTotal API v3
- AbuseIPDB API v2
- `ipaddress`, `base64`, `urllib.parse`, `json` and `pathlib`
- pytest

## Project structure

```text
05-threat-intel-enricher/
├── samples/
│   └── iocs.json
├── tests/
│   └── test_enricher.py
├── .env.example
├── enricher.py
├── requirements.txt
└── README.md
```

A local `.env` file is created during setup and must remain untracked. The generated `enrichment_report.json` and `enrichment_report.md` are output files.

## Installation and configuration

Install the dependencies:

```powershell
python -m pip install -r requirements.txt
```

Create a local environment file:

```powershell
Copy-Item .env.example .env
```

Add whichever provider keys you have:

```dotenv
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

You can configure either provider independently. Never commit `.env` or share its contents.

## Input format

The supplied `samples/iocs.json` uses category arrays, for example:

```json
{
  "ipv4": ["8.8.8.8"],
  "domains": ["example.org"],
  "urls": ["https://example.org/path"],
  "sha256": [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  ]
}
```

These values are documentation examples. The example IP and domain are not evidence of malicious activity.

## Offline run

```powershell
python enricher.py
```

Offline mode validates, classifies, normalizes and deduplicates indicators without contacting VirusTotal or AbuseIPDB. It writes:

- `enrichment_report.json`
- `enrichment_report.md`

The default input is `samples/iocs.json`.

## Live enrichment

Live mode is opt-in:

```powershell
python enricher.py --live
```

You can also provide alternate paths:

```powershell
python enricher.py --live --input samples/iocs.json --output enrichment_report.json --markdown enrichment_report.md
```

Live lookups require a configured provider key and network access. VirusTotal can be used for supported indicator types; AbuseIPDB is used for IP addresses. Non-public or reserved indicators are skipped before provider requests.

Live requests are subject to provider quotas, rate limits, terms and account permissions. Only submit indicators you are authorized to share. The tool queries file records by SHA-256 hash; it does not upload files. It does not submit URLs for scanning.

## Report interpretation

Each normalized indicator includes its type, value, public-query eligibility, provider results and enrichment status. Possible statuses include:

- `offline`
- `skipped_non_public_indicator`
- `no_provider_configured`
- `enriched`
- `partially_enriched`
- `provider_error`

The report summary includes processed and rejected counts, indicator type counts, publicly queryable count and provider error count.

Provider results are observations, not proof of compromise. A low score or absence of reports does not prove that an indicator is benign. Consider source coverage, freshness, context and false-positive potential.

## Tests

```powershell
python -m pytest -v
```

The tests cover indicator classification and normalization, invalid values, deduplication, reserved indicators, offline no-network behavior, live skipping, VirusTotal URL-safe identifiers, AbuseIPDB response normalization and analyst caveats in the report. Provider interactions are mocked.

## Limitations

- This is an educational workflow, not a production threat-intelligence platform.
- It does not combine provider verdicts into a definitive malicious/benign label.
- It does not perform WHOIS or passive DNS lookups.
- It does not download or submit files.
- It does not submit URLs for scanning.
- Provider availability and returned data depend on the configured account and provider service.

## Future improvements

- Add configurable retry and backoff for rate limits and transient errors.
- Add provider-specific quota and status reporting.
- Add more indicator types and normalization tests.
- Add optional integration with the IOC Extractor output.
- Add analyst-configurable enrichment policies.
