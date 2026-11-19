# 02 — IOC Reputation Checker

A Python command-line tool that validates IPv4 indicators and queries the AbuseIPDB check endpoint for eligible public addresses.

It demonstrates how an analyst can enrich IP indicators with third-party reputation context during an investigation.

## Problem

An IP address found in a log or incident report is not automatically malicious. Analysts need contextual information—such as an abuse confidence score, report count, country and ISP—to help decide what to investigate next.

This lab retrieves that context from AbuseIPDB. It does not make a definitive malicious-or-benign decision.

## Features

- Reads IPv4 indicators from `samples/ips.json`.
- Accepts only strings that parse as IPv4 addresses and are considered globally routable by Python's `ipaddress` module.
- Skips invalid, private, reserved, non-global and non-string values.
- Removes duplicate input addresses while preserving their first-seen order.
- Queries AbuseIPDB with `maxAgeInDays=90` and a 10-second request timeout.
- Normalizes selected response fields into a consistent result structure.
- Continues processing after handled request, response-value or missing-key errors.
- Writes checked indicators, skipped indicators and errors to `reputation_report.json`.
- Includes tests that mock the HTTP response; the tests do not require a live API request.

## Technologies

- Python 3
- Requests
- python-dotenv
- AbuseIPDB API
- `ipaddress`, `json` and `pathlib`
- pytest

## Project structure

```text
02-ioc-reputation-checker/
├── samples/
│   └── ips.json
├── tests/
│   └── test_reputation.py
├── reputation.py
├── reputation_report.json   # generated output
└── README.md
```

Create a local `.env` file in this directory for your API key. Do not commit that file.

## Installation and configuration

Install the dependencies:

```powershell
python -m pip install requests python-dotenv pytest
```

Create `.env` in the project directory:

```dotenv
ABUSEIPDB_API_KEY=your_api_key_here
```

Obtain an API key from [AbuseIPDB](https://www.abuseipdb.com/).

The script loads `.env` relative to its own project directory. If the key is missing, it prints an error and exits without querying the API.

**Security:** Never commit `.env` or expose API credentials in screenshots, logs or source control.

## Input

Edit `samples/ips.json`:

```json
{
  "ipv4": [
    "8.8.8.8",
    "1.1.1.1",
    "192.0.2.55",
    "999.999.999.999"
  ]
}
```

The sample includes two public resolver addresses, one documentation-only reserved address and one invalid IPv4 value.

## Run

From this directory:

```powershell
python reputation.py
```

For each eligible address, the script requests the AbuseIPDB `/api/v2/check` endpoint and records:

- IP address
- Abuse confidence score
- Total report count
- Country code
- ISP
- Last reported timestamp

The output JSON has three top-level lists:

- `checked` — successfully normalized provider results
- `skipped` — values that failed the public IPv4 eligibility check
- `errors` — eligible addresses whose request or response processing failed

The input and output paths are fixed relative to the script. Command-line input/output arguments are not currently implemented.

## Example report shape

```json
{
  "checked": [
    {
      "ip": "8.8.8.8",
      "abuse_score": 0,
      "total_reports": 237,
      "country": "US",
      "isp": "Google LLC",
      "last_reported": null
    }
  ],
  "skipped": [
    "192.0.2.55",
    "999.999.999.999"
  ],
  "errors": []
}
```

The values above are illustrative. Provider results change over time and may differ between runs.

## Tests

Run:

```powershell
python -m pytest -v
```

The included tests cover public IPv4 acceptance, invalid/reserved/private address rejection, IPv6 rejection and normalization of a mocked successful AbuseIPDB response.

The API test uses a fake key and a mocked HTTP response. It does not contact AbuseIPDB.

## Interpretation and limitations

- Supports IPv4 only; IPv6 is explicitly rejected.
- Requires an AbuseIPDB API key and network access for live checks.
- Results depend on AbuseIPDB's reporting data, coverage, age window and account limits.
- The configured report age window is 90 days.
- The script records provider data; it does not apply a severity threshold or label an address definitively malicious.
- A zero abuse score or absence of reports does not prove that an address is safe.
- Reputation should be assessed alongside network, endpoint, identity and incident context.

## Future improvements

- Add command-line input and output paths.
- Add tests for HTTP errors, timeouts and malformed provider responses.
- Make the report age window configurable.
- Add explicit rate-limit handling and retry/backoff behavior.
- Accept validated IPv4 indicators from Lab 01 as an input source.
