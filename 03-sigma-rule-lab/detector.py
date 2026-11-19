import argparse
import json
from pathlib import Path

import yaml


SUPPORTED_MODIFIERS = {"endswith", "contains"}


def load_rule(rule_path):
    """Load a YAML rule and validate the subset this lab supports."""
    with Path(rule_path).open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError("Rule must be a YAML mapping.")

    for field in ("title", "logsource", "detection"):
        if field not in rule:
            raise ValueError(f"Missing required rule field: {field}")

    logsource = rule["logsource"]
    if not isinstance(logsource, dict):
        raise ValueError("logsource must be a mapping.")
    if logsource.get("category") != "process_creation":
        raise ValueError("This lab supports only process_creation rules.")
    if logsource.get("product") != "windows":
        raise ValueError("This lab supports only Windows rules.")

    detection = rule["detection"]
    if not isinstance(detection, dict):
        raise ValueError("detection must be a mapping.")
    if detection.get("condition") != "selection":
        raise ValueError("This lab supports only the condition: selection.")

    selection = detection.get("selection")
    if not isinstance(selection, dict) or not selection:
        raise ValueError("detection.selection must be a non-empty mapping.")

    for expression, expected in selection.items():
        if not isinstance(expression, str) or "|" not in expression:
            raise ValueError(
                f"Unsupported field expression: {expression!r}. "
                "Use Field|modifier."
            )
        field_name, modifier = expression.rsplit("|", 1)
        if not field_name or modifier not in SUPPORTED_MODIFIERS:
            raise ValueError(f"Unsupported field expression: {expression!r}.")
        values = expected if isinstance(expected, list) else [expected]
        if not values or not all(isinstance(value, str) for value in values):
            raise ValueError(f"Values for {expression} must be strings.")

    return rule


def _matches_value(actual, expected_values, modifier):
    if not isinstance(actual, str):
        return False

    actual = actual.casefold()
    for expected in expected_values:
        expected = expected.casefold()
        if modifier == "endswith" and actual.endswith(expected):
            return True
        if modifier == "contains" and expected in actual:
            return True
    return False


def event_matches(event, rule):
    """Evaluate the supported Sigma selection: AND across fields, OR within lists."""
    selection = rule["detection"]["selection"]

    for expression, expected in selection.items():
        field_name, modifier = expression.rsplit("|", 1)
        expected_values = expected if isinstance(expected, list) else [expected]

        if field_name not in event:
            return False
        if not _matches_value(event[field_name], expected_values, modifier):
            return False

    return True


def evaluate_events(events, rule):
    matches = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        if event_matches(event, rule):
            matches.append({
                "event_index": index,
                "event": event
            })
    return matches


def build_report(events, rule):
    matches = evaluate_events(events, rule)
    return {
        "rule": {
            "title": rule["title"],
            "id": rule.get("id"),
            "level": rule.get("level", "unknown")
        },
        "summary": {
            "events_analyzed": len(events),
            "matches": len(matches),
            "non_matches": len(events) - len(matches)
        },
        "matches": matches,
        "engine": {
            "supported_condition": "selection",
            "supported_modifiers": sorted(SUPPORTED_MODIFIERS),
            "case_sensitive": False
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate a supported Sigma rule against JSON process events."
    )
    parser.add_argument(
        "--rule",
        default="rules/powershell_encoded.yml",
        help="Path to a Sigma YAML rule."
    )
    parser.add_argument(
        "--events",
        default="samples/process_events.json",
        help="Path to a JSON array of process events."
    )
    parser.add_argument(
        "--output",
        default="detection_report.json",
        help="Path for the JSON detection report."
    )
    args = parser.parse_args()

    rule = load_rule(args.rule)
    with Path(args.events).open("r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Event input must be a JSON array.")

    report = build_report(events, rule)
    Path(args.output).write_text(
        json.dumps(report, indent=4),
        encoding="utf-8"
    )

    print(f"\n=== SIGMA DETECTION LAB ===")
    print(f"Rule: {report['rule']['title']}")
    print(f"Events analyzed: {report['summary']['events_analyzed']}")
    print(f"Matches: {report['summary']['matches']}")
    print(f"Non-matches: {report['summary']['non_matches']}")
    print(f"Report saved to: {args.output}")


if __name__ == "__main__":
    main()
