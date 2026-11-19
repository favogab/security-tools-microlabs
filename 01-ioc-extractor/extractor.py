
import re
import json
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit


# IOC extraction patterns
IP_PATTERN = r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"

URL_PATTERN = r"""https?://[^\s<>"']+"""

DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

HASH_PATTERN = r"\b[a-fA-F0-9]{64}\b"


# Common file extensions that should not be classified as domains
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "msi",
    "zip", "rar", "7z",
    "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx",
    "txt", "csv", "json", "xml",
    "html", "htm", "js", "ps1",
    "bat", "cmd", "py", "sh",
    "iso", "bin", "dat", "log"
}


def is_likely_domain(domain):
    """Exclude common file extensions from domain candidates."""
    suffix = domain.rsplit(".", 1)[-1].lower()

    return suffix not in FILE_EXTENSIONS


def extract_ips(text):
    """Extract and validate unique IPv4 addresses."""
    valid_ips = set()

    for match in re.findall(IP_PATTERN, text):
        try:
            valid_ips.add(str(ipaddress.IPv4Address(match)))
        except ipaddress.AddressValueError:
            continue

    return sorted(valid_ips)


def extract_urls(text):
    """Extract unique URLs and remove trailing punctuation."""
    urls = set()

    for match in re.findall(URL_PATTERN, text):
        url = match.rstrip(".,;!?")

        parsed = urlsplit(url)

        if parsed.hostname:
            urls.add(url)

    return sorted(urls)


def extract_domains(text):
    """Extract domains while excluding common file extensions."""
    domains = set()

    # Extract domain-like strings from the report
    domain_matches = re.findall(DOMAIN_PATTERN, text)

    for domain in domain_matches:
        domain = domain.lower()

        if is_likely_domain(domain):
            domains.add(domain)

    # Extract hostnames from URLs
    for url in extract_urls(text):
        hostname = urlsplit(url).hostname

        if hostname:
            hostname = hostname.lower()

            if is_likely_domain(hostname):
                domains.add(hostname)

    return sorted(domains)


def extract_hashes(text):
    """Extract unique 64-character hexadecimal SHA-256 candidates."""
    return sorted(set(re.findall(HASH_PATTERN, text)))


def analyze_report(text):
    """Extract all supported IOC categories."""
    return {
        "ipv4": extract_ips(text),
        "domains": extract_domains(text),
        "urls": extract_urls(text),
        "sha256": extract_hashes(text),
    }


def main():
    base_dir = Path(__file__).resolve().parent

    report_path = base_dir / "samples" / "report.txt"
    output_path = base_dir / "indicators.json"

    report = report_path.read_text(encoding="utf-8")

    results = analyze_report(report)

    print("\n=== IOC EXTRACTOR ===")

    for category, indicators in results.items():
        print(f"\n{category.upper()} ({len(indicators)})")

        for indicator in indicators:
            print(f"  - {indicator}")

    output_path.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8"
    )

    print(f"\nResults saved to {output_path.name}")


if __name__ == "__main__":
    main()
