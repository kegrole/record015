"""Command line entry point.

    python -m detectlog.cli --log <log> --rules <rules> --out <report>
"""

import argparse
import sys

from .aggregate import Detector
from .logparse import read_log
from .report import build_report, write_report
from .rules import load_rules


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="detectlog",
        description="Detect attack patterns in line-oriented logs.",
    )
    parser.add_argument("--log", required=True, help="path to the log file")
    parser.add_argument("--rules", required=True, help="path to the rules file")
    parser.add_argument("--out", required=True, help="path for the JSON report")
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)
    events, lines_read, lines_parsed = read_log(args.log)

    detector = Detector(rules)
    for event in events:
        detector.process(event)

    stats = {
        "lines_read": lines_read,
        "lines_parsed": lines_parsed,
        "matched": detector.matched,
        "alerts": len(detector.alerts),
    }
    write_report(args.out, build_report(detector.alerts, stats))
    print("read=%d matched=%d alerts=%d"
          % (lines_read, detector.matched, len(detector.alerts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
