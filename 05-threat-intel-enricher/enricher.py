import argparse, base64, ipaddress, json, os, re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv

SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\.?$")
RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local")
RESERVED_EXAMPLE_DOMAINS = {"example.com", "example.net", "example.org"}


def classify_indicator(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Indicator must be a non-empty string.")
    value = value.strip()
    if SHA256.fullmatch(value):
        return "sha256", value.lower()
    try:
        return "ip", str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        parsed = urlparse(value)
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: {value}")
        return "url", value
    domain = value.rstrip(".")
    if DOMAIN.fullmatch(domain):
        return "domain", domain.encode("idna").decode("ascii").lower()
    raise ValueError(f"Unsupported or invalid indicator: {value}")


def load_indicators(path):
    with Path(path).open("r", encoding="utf-8-sig") as f:
        payload = json.load(f)
    candidates = []
    if isinstance(payload, dict):
        keys = {"ipv4": "ip", "ips": "ip", "domains": "domain",
                "urls": "url", "sha256": "sha256", "hashes": "sha256"}
        for key in keys:
            values = payload.get(key, [])
            if not isinstance(values, list):
                raise ValueError(f"{key} must be an array.")
            candidates.extend(values)
    elif isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict) or "value" not in item:
                raise ValueError("List entries must be objects with a value field.")
            candidates.append(item["value"])
    else:
        raise ValueError("Input must be a JSON object of IOC arrays or a list.")
    normalized, rejected, seen = [], [], set()
    for raw in candidates:
        try:
            kind, value = classify_indicator(raw)
            if (kind, value) not in seen:
                seen.add((kind, value))
                normalized.append({"type": kind, "value": value})
        except ValueError as exc:
            rejected.append({"value": raw, "reason": str(exc)})
    return normalized, rejected


def is_publicly_queryable(indicator):
    kind, value = indicator["type"], indicator["value"]
    if kind == "ip":
        return ipaddress.ip_address(value).is_global
    host = urlparse(value).hostname if kind == "url" else value
    host = (host or "").lower().rstrip(".")
    return host not in RESERVED_EXAMPLE_DOMAINS and not host.endswith(RESERVED_SUFFIXES)


def abuseipdb_lookup(session, api_key, ip):
    response = session.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15)
    response.raise_for_status()
    data = response.json()["data"]
    return {"provider": "AbuseIPDB", "status": "success",
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"), "isp": data.get("isp"),
            "last_reported": data.get("lastReportedAt")}


def virustotal_lookup(session, api_key, kind, value):
    if kind == "ip":
        endpoint = f"ip_addresses/{value}"
    elif kind == "domain":
        endpoint = f"domains/{value}"
    elif kind == "sha256":
        endpoint = f"files/{value}"
    elif kind == "url":
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        endpoint = f"urls/{url_id}"
    else:
        raise ValueError(f"Unsupported VirusTotal indicator type: {kind}")
    response = session.get(
        f"https://www.virustotal.com/api/v3/{endpoint}",
        headers={"x-apikey": api_key}, timeout=15)
    response.raise_for_status()
    attrs = response.json()["data"]["attributes"]
    return {"provider": "VirusTotal", "status": "success",
            "reputation": attrs.get("reputation"),
            "analysis_stats": attrs.get("last_analysis_stats"),
            "country": attrs.get("country"), "as_owner": attrs.get("as_owner")}


def enrich_indicators(indicators, live=False, abuse_key=None, vt_key=None, session=requests):
    results = []
    for indicator in indicators:
        item = {**indicator, "publicly_queryable": is_publicly_queryable(indicator),
                "providers": []}
        if not live:
            item["enrichment_status"] = "offline"
            results.append(item)
            continue
        if not item["publicly_queryable"]:
            item["enrichment_status"] = "skipped_non_public_indicator"
            results.append(item)
            continue
        attempted = succeeded = 0
        lookups = []
        if vt_key:
            lookups.append(("VirusTotal", lambda: virustotal_lookup(
                session, vt_key, indicator["type"], indicator["value"])))
        if abuse_key and indicator["type"] == "ip":
            lookups.append(("AbuseIPDB", lambda: abuseipdb_lookup(
                session, abuse_key, indicator["value"])))
        for provider_name, lookup in lookups:
            attempted += 1
            try:
                item["providers"].append(lookup())
                succeeded += 1
            except requests.RequestException as exc:
                item["providers"].append({"provider": provider_name, "status": "error",
                                          "error": str(exc)})
            except (KeyError, TypeError, ValueError) as exc:
                item["providers"].append({"provider": provider_name, "status": "error",
                                          "error": f"Unexpected response: {exc}"})
        if attempted == 0:
            item["enrichment_status"] = "no_provider_configured"
        elif succeeded == attempted:
            item["enrichment_status"] = "enriched"
        elif succeeded:
            item["enrichment_status"] = "partially_enriched"
        else:
            item["enrichment_status"] = "provider_error"
        results.append(item)
    return results


def build_report(enriched, rejected, live):
    type_counts = {}
    for item in enriched:
        type_counts[item["type"]] = type_counts.get(item["type"], 0) + 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "live" if live else "offline",
        "summary": {
            "indicators_processed": len(enriched),
            "indicators_rejected": len(rejected),
            "types": type_counts,
            "public_indicators": sum(x["publicly_queryable"] for x in enriched),
            "provider_errors": sum(p.get("status") == "error"
                for x in enriched for p in x["providers"])
        },
        "indicators": enriched, "rejected": rejected,
        "analyst_notes": [
            "Provider results are observations, not proof of compromise.",
            "A low reputation score or absence of reports does not prove an indicator is benign.",
            "Consider source coverage, freshness, context, and false-positive potential."
        ]}


def render_markdown(report):
    lines = ["# Threat Intelligence Enrichment Report", "",
        f"- **Generated:** {report['generated_at']}",
        f"- **Mode:** {report['mode']}",
        f"- **Processed:** {report['summary']['indicators_processed']}",
        f"- **Rejected:** {report['summary']['indicators_rejected']}", "",
        "## Indicator findings", ""]
    for item in report["indicators"]:
        lines += [f"### {item['type'].upper()}: `{item['value']}`",
                  f"- **Enrichment status:** {item['enrichment_status']}",
                  f"- **Publicly queryable:** {item['publicly_queryable']}"]
        if not item["providers"]:
            lines.append("- **Provider results:** No provider results available.")
        for provider in item["providers"]:
            lines.append(f"- **{provider['provider']} ({provider['status']})**")
            for key, value in provider.items():
                if key not in ("provider", "status"):
                    lines.append(f"  - {key.replace('_', ' ').title()}: {value}")
        lines.append("")
    if report["rejected"]:
        lines += ["## Rejected indicators", ""]
        lines += [f"- `{x['value']}` — {x['reason']}" for x in report["rejected"]]
        lines.append("")
    lines += ["## Analyst notes", ""]
    lines += [f"- {note}" for note in report["analyst_notes"]]
    return "\n".join(lines) + "\n"


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Normalize and enrich IOCs.")
    parser.add_argument("--input", default="samples/iocs.json")
    parser.add_argument("--output", default="enrichment_report.json")
    parser.add_argument("--markdown", default="enrichment_report.md")
    parser.add_argument("--live", action="store_true",
                        help="Enable provider lookups using API keys from .env.")
    args = parser.parse_args()
    indicators, rejected = load_indicators(args.input)
    enriched = enrich_indicators(indicators, live=args.live,
        abuse_key=os.getenv("ABUSEIPDB_API_KEY"),
        vt_key=os.getenv("VIRUSTOTAL_API_KEY"))
    report = build_report(enriched, rejected, args.live)
    Path(args.output).write_text(json.dumps(report, indent=4), encoding="utf-8")
    Path(args.markdown).write_text(render_markdown(report), encoding="utf-8")
    print("\n=== THREAT INTELLIGENCE ENRICHER ===")
    print(f"Mode: {report['mode']}")
    print(f"Indicators processed: {report['summary']['indicators_processed']}")
    print(f"Indicators rejected: {report['summary']['indicators_rejected']}")
    print(f"Provider errors: {report['summary']['provider_errors']}")
    print(f"JSON report: {args.output}")
    print(f"Markdown report: {args.markdown}")
    if args.live and not (os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("ABUSEIPDB_API_KEY")):
        print("[WARNING] --live selected, but no API keys are configured.")


if __name__ == "__main__":
    main()
