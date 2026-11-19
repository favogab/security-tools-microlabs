# Python Security Micro-Labs

**Independent tools. Practical SOC automation. Detection engineering.**

A collection of six independent Python projects exploring practical cybersecurity automation, threat intelligence, detection engineering, endpoint investigation and AI-assisted security analysis.

This repository documents my hands-on development journey as I build practical tools that solve small but meaningful problems encountered in security operations.

Rather than building one large application, each micro-lab focuses on a specific security task, its underlying engineering concepts and a working implementation.

## Projects

| # | Project | Description | Key Technologies |
|---|---|---|---|
| 01 | [IOC Extractor](./01-ioc-extractor/) | Extract IP addresses, domains, URLs and SHA-256-shaped indicators from security reports. | Python, Regex, JSON |
| 02 | [IOC Reputation Checker](./02-ioc-reputation-checker/) | Validate public IPv4 addresses and retrieve reputation information from AbuseIPDB. | Python, Requests, REST API |
| 03 | [Sigma Detection Rule Lab](./03-sigma-rule-lab/) | Load a Sigma-style YAML rule and evaluate its supported detection logic against sample process events. | Python, YAML, Detection Logic |
| 04 | [Process Tree Analyzer](./04-process-tree-analyzer/) | Reconstruct parent-child process relationships from Sysmon Event ID 1 data and flag suspicious execution chains. | Python, Sysmon, JSON |
| 05 | [Threat Intelligence Enricher](./05-threat-intel-enricher/) | Normalize indicators and optionally enrich them using VirusTotal and AbuseIPDB. | Python, APIs, Threat Intelligence |
| 06 | [AI-Assisted Triage Assistant](./06-ai-triage-assistant/) | Generate structured security alert assessments, investigation recommendations and reports using an OpenAI integration or offline mock provider. | Python, OpenAI API, Pydantic |

## Repository Structure

```text
security-microlabs/
│
├── 01-ioc-extractor/
│
├── 02-ioc-reputation-checker/
│
├── 03-sigma-rule-lab/
│
├── 04-process-tree-analyzer/
│
├── 05-threat-intel-enricher/
│
├── 06-ai-triage-assistant/
│
├── .gitignore
├── LICENSE
└── README.md
```

Each project has its own README, source code, sample data and tests where applicable.

## Technical Skills Demonstrated

### Python Development
- File handling and structured data processing
- Regular expressions and input validation
- Data normalization and deduplication
- Exception handling
- Modular application design
- Command-line interfaces

### Security Operations
- Indicator of Compromise (IOC) extraction
- IP reputation investigation
- Threat intelligence enrichment
- Windows process investigation
- Sysmon telemetry analysis
- Parent-child process correlation
- Suspicious process execution detection

### Detection Engineering
- Sigma-style YAML rule interpretation
- Detection condition evaluation
- Event matching
- False-positive considerations
- Automated detection testing

### Security Automation and APIs
- REST API integration
- API authentication
- Environment variable management
- Provider response normalization
- JSON and Markdown reporting
- Offline testing and mocked API responses

### AI-Assisted Security Analysis
- OpenAI API integration
- Structured model outputs
- Pydantic validation
- Evidence-reference validation
- Human-in-the-loop investigation
- Offline mock provider implementation

## Technologies and Tools

**Languages:** Python

**Libraries:** Requests, PyYAML, Pydantic, python-dotenv, pytest

**Security technologies:** Sysmon, Sigma, VirusTotal, AbuseIPDB

**Data formats:** JSON, YAML, Markdown

**Development tools:** Visual Studio Code, Git, GitHub

## Running the Projects

Each micro-lab is independently executable.

Clone the repository:

```bash
git clone https://github.com/favogab/security-tools-microlabs.git
cd security-microlabs
```

Navigate into the project you want to explore.

For example:

```powershell
cd 01-ioc-extractor
python extractor.py
```

Other project entry points:

| Project | Command |
|---|---|
| IOC Extractor | `python extractor.py` |
| IOC Reputation Checker | `python reputation.py` |
| Sigma Detection Rule Lab | `python detector.py` |
| Process Tree Analyzer | `python analyzer.py` |
| Threat Intelligence Enricher | `python enricher.py` |
| AI-Assisted Triage Assistant | `python triage.py --mock` |

For projects with a `requirements.txt`, install their dependencies using:

```powershell
python -m pip install -r requirements.txt
```

See each project's README for its specific configuration, usage instructions and testing commands.

## Testing

Automated tests are included in the individual projects.

Run a project's tests from its directory:

```powershell
python -m pytest -v
```

The test suites cover functionality such as input validation, indicator normalization, detection logic, process relationships, API response handling and structured report generation.

Mocked provider responses and offline execution are used where appropriate to avoid unnecessary external API requests during testing.

## Security and Responsible Use

These projects are educational security tools intended for authorized analysis and controlled lab environments.

A few important considerations:

- Reputation results are investigative context, not definitive proof of malicious activity.
- Detection matches require analyst investigation and validation.
- Real endpoint telemetry should be reviewed and sanitized before publication.
- API credentials must be stored in local environment files and excluded from source control.
- AI-generated assessments are advisory and require human review.
- Offline mock results must not be represented as genuine AI analysis.

## Project Philosophy

The goal of this repository is to develop practical engineering skills through small, focused cybersecurity tools.

Each project follows a problem-first approach:

1. Identify a practical security problem.
2. Understand the data and investigation requirements.
3. Build a working Python solution.
4. Validate the implementation through testing.
5. Document its behavior, limitations and possible improvements.

The emphasis is not simply on writing code, but on understanding how automation can support real security workflows.

## Author

**Favogab — Favour Gabriel**

Cybersecurity | Blue Team | SOC Operations | Security Automation | Python

[GitHub](https://github.com/favogab) · [Security Micro-Labs Repository](https://github.com/favogab/security-tools-microlabs)