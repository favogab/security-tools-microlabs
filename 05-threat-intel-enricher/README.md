# Threat Intelligence Enricher

A Python SOC automation tool that normalizes indicators of compromise (IOCs), optionally enriches them through VirusTotal and AbuseIPDB, and produces JSON and Markdown investigation reports.

## Features
- Accepts Lab 01-style JSON arrays for IPv4 addresses, domains, URLs, and SHA-256 hashes.
- Validates, classifies, normalizes, and deduplicates indicators.
- Supports VirusTotal lookups for IPs, domains, URLs, and SHA-256 hashes.
- Supports AbuseIPDB lookups for IP addresses.
- Skips reserved/non-public indicators before live lookups.
- Handles provider failures independently and attributes results to their source.
- Produces JSON and Markdown reports.
- Keeps API keys in environment variables or a local `.env` file.
- Offline tests do not make network requests.

## Setup
From this directory, with the repository virtual environment activated:

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and add your own API keys. Never commit `.env`.

## Offline run
```powershell
python enricher.py
```
This validates and normalizes sample indicators without contacting providers.

## Live enrichment
Set `VIRUSTOTAL_API_KEY` and/or `ABUSEIPDB_API_KEY` in `.env`, then run:

```powershell
python enricher.py --live
```

You can also specify `--input`, `--output`, and `--markdown` paths. Live lookups are subject to provider quotas, rate limits, terms, and account permissions. Only submit indicators you are authorized to share. The tool does not upload files; VirusTotal file lookups use SHA-256 hashes.

## Tests
```powershell
python -m pytest -v
```
Tests use mocked provider responses and require no API keys or network access.

## Interpretation
Provider results are observations, not proof of compromise. A low score or absence of reports does not prove an indicator is benign. Consider source coverage, freshness, context, and false-positive potential.

The sample uses documentation-only IP addresses and `.example` domains. These are deliberately skipped during live lookups.

## Limitations
This is an educational workflow, not a production threat-intelligence platform. It does not combine provider verdicts into a definitive malicious/benign label, submit URLs for scanning, perform WHOIS/passive DNS, or download files.
