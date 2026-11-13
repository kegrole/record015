"""JSON report assembly."""

import json
import os


def build_report(alerts, stats) -> dict:
    ordered = sorted(alerts, key=lambda a: (a.first_seen, a.rule, a.key))
    return {
        "summary": stats,
        "alerts": [alert.to_dict() for alert in ordered],
    }


def write_report(path: str, report: dict):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
