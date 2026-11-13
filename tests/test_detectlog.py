"""Unit tests for detectlog, covering the six acceptance criteria."""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detectlog.aggregate import Detector
from detectlog.logparse import parse_line, read_log
from detectlog.rules import load_rules
from detectlog.cli import main as cli_main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_LOG = os.path.join(REPO_ROOT, "demo", "access.log")
DEMO_RULES = os.path.join(REPO_ROOT, "demo", "rules.yaml")

BASE = datetime(2026, 11, 14, 8, 0, 0, tzinfo=timezone.utc)

RULES_YAML = """rules:
  - name: brute_force_login
    dimension: src_ip
    window: 300
    threshold: 10
    merge_window: 60
    where:
      - field: path
        pattern: /login
      - field: status
        pattern: "^(401|403)$"
  - name: sqli_tautology
    dimension: src_ip
    window: 300
    threshold: 1
    merge_window: 60
    where:
      - field: path
        pattern: "' OR 1=1"
  - name: unregistered_egress
    dimension: dst
    window: 300
    threshold: 1
    merge_window: 60
    where:
      - field: dst
        not_in:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
"""


def ts(offset_seconds):
    """ISO timestamp BASE + offset (offsets may be negative)."""
    moment = BASE + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def fail_line(offset, ip="203.0.113.7"):
    return "%s src=%s method=POST path=/login status=401" % (ts(offset), ip)


def ok_line(offset, ip="192.168.1.10", path="/"):
    return "%s src=%s method=GET path=%s status=200" % (ts(offset), ip, path)


def sqli_line(offset, ip="198.51.100.23"):
    return "%s src=%s method=GET path=\"/search?q=' OR 1=1--\" status=200" % (
        ts(offset), ip,
    )


def egress_line(offset, dst="203.0.113.99"):
    return "%s host=web01 proc=curl src=10.1.2.3 dst=%s action=connect" % (
        ts(offset), dst,
    )


def normal_traffic():
    """A large body of benign traffic, including a few sub-threshold failures."""
    lines = []
    for index in range(40):
        lines.append(ok_line(index * 30, ip="192.168.1.%d" % (10 + index % 20),
                             path="/res/%d" % index))
    # a handful of failed logins, well below the brute-force threshold
    for index in range(3):
        lines.append(fail_line(5 + index * 20, ip="192.168.1.10"))
    # registered egress destinations only
    lines.append("%s host=web01 proc=curl src=10.1.2.3 dst=10.0.0.8 action=connect" % ts(7))
    lines.append("%s host=web01 proc=wget src=10.1.2.4 dst=192.168.5.5 action=connect" % ts(9))
    return lines


def run_detection(log_lines, rules_text=RULES_YAML):
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "input.log")
        rules_path = os.path.join(tmp, "rules.yaml")
        with open(log_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(log_lines) + "\n")
        with open(rules_path, "w", encoding="utf-8") as handle:
            handle.write(rules_text)
        rules = load_rules(rules_path)
        events, lines_read, _ = read_log(log_path)
        detector = Detector(rules)
        for event in events:
            detector.process(event)
    return detector, lines_read


class CriterionTests(unittest.TestCase):
    # -- criteria 1 & 2: three attack classes, exactly three alerts --------

    def test_demo_log_yields_exactly_three_alerts(self):
        rules = load_rules(DEMO_RULES)
        events, lines_read, _ = read_log(DEMO_LOG)
        detector = Detector(rules)
        for event in events:
            detector.process(event)
        self.assertGreater(lines_read, 50)  # plenty of normal traffic
        self.assertEqual(len(detector.alerts), 3)
        by_rule = {alert.rule: alert for alert in detector.alerts}
        self.assertEqual(
            set(by_rule),
            {"brute_force_login", "sqli_tautology", "unregistered_egress"},
        )
        self.assertEqual(by_rule["brute_force_login"].key, "203.0.113.7")
        self.assertEqual(by_rule["brute_force_login"].count, 12)
        self.assertEqual(by_rule["sqli_tautology"].key, "198.51.100.23")
        self.assertEqual(by_rule["sqli_tautology"].count, 3)
        self.assertEqual(by_rule["unregistered_egress"].key, "203.0.113.99")
        self.assertEqual(by_rule["unregistered_egress"].count, 4)

    def test_normal_traffic_produces_no_alerts(self):
        detector, _ = run_detection(normal_traffic())
        self.assertEqual(detector.alerts, [])

    # -- criterion 3: exact window boundary --------------------------------

    def test_window_boundary_splits_alert(self):
        offsets = list(range(-9, 1)) + [301]  # 10th hit at t=0, 11th at t=301
        detector, _ = run_detection([fail_line(o) for o in offsets])
        counts = sorted(alert.count for alert in detector.alerts)
        self.assertEqual(counts, [1, 10])
        self.assertEqual(len(detector.alerts), 2)
        first, second = detector.alerts
        self.assertEqual(first.count, 10)
        self.assertEqual(first.last_seen, BASE.timestamp())
        self.assertEqual(second.count, 1)
        self.assertEqual(second.first_seen, (BASE + timedelta(seconds=301)).timestamp())

    # -- criterion 4: repeated triggers merge into one alert ---------------

    def test_repeated_triggers_merge_within_merge_window(self):
        offsets = list(range(0, 10)) + list(range(30, 40))  # two bursts, 21s apart
        detector, _ = run_detection([fail_line(o) for o in offsets])
        self.assertEqual(len(detector.alerts), 1)
        self.assertEqual(detector.alerts[0].count, 20)

    def test_triggers_beyond_merge_window_split(self):
        offsets = list(range(0, 10)) + list(range(300, 310))  # 291s gap
        detector, _ = run_detection([fail_line(o) for o in offsets])
        self.assertEqual(len(detector.alerts), 2)
        self.assertEqual([a.count for a in detector.alerts], [10, 10])

    # -- criterion 5: alert schema and sample provenance -------------------

    def test_alert_fields_and_sample(self):
        log_lines = (
            normal_traffic()
            + [fail_line(o) for o in range(0, 12)]
            + [sqli_line(o) for o in (100, 110, 120)]
            + [egress_line(o) for o in (200, 210, 220, 230)]
        )
        detector, _ = run_detection(log_lines)
        self.assertEqual(len(detector.alerts), 3)
        required = {
            "rule", "dimension", "key", "count",
            "first_seen", "last_seen", "sample",
        }
        for alert in detector.alerts:
            record = alert.to_dict()
            self.assertEqual(set(record), required)
            self.assertIn(alert.sample, log_lines)
            self.assertLessEqual(alert.first_seen, alert.last_seen)
            self.assertGreaterEqual(alert.count, 1)

    # -- criterion 6: behaviour follows the rules file ---------------------

    def test_rules_file_drives_detection(self):
        log_lines = [fail_line(o) for o in range(5)]  # only 5 failures
        quiet, _ = run_detection(log_lines)  # demo rules: threshold 10
        self.assertEqual(quiet.alerts, [])

        strict_rules = RULES_YAML.replace("threshold: 10", "threshold: 3")
        loud, _ = run_detection(log_lines, strict_rules)
        self.assertEqual(len(loud.alerts), 1)
        self.assertEqual(loud.alerts[0].count, 5)

        other_rules = RULES_YAML.replace("pattern: /login", "pattern: /admin")
        blind, _ = run_detection(log_lines, other_rules)
        self.assertEqual(blind.alerts, [])


class ParserTests(unittest.TestCase):
    def test_key_value_line(self):
        event = parse_line("2026-11-14T08:00:00Z src=1.2.3.4 method=GET path=/a status=200")
        self.assertIsNotNone(event)
        self.assertEqual(event.fields["src_ip"], "1.2.3.4")
        self.assertEqual(event.fields["path"], "/a")
        self.assertEqual(event.fields["status"], "200")
        self.assertEqual(event.timestamp, BASE.timestamp())

    def test_apache_line_by_position(self):
        event = parse_line(
            '1.2.3.4 - - [14/Nov/2026:08:00:00 +0000] "GET /a HTTP/1.1" 200 12'
        )
        self.assertIsNotNone(event)
        self.assertEqual(event.fields["src_ip"], "1.2.3.4")
        self.assertEqual(event.fields["path"], "/a")
        self.assertEqual(event.fields["status"], "200")
        self.assertEqual(event.timestamp, BASE.timestamp())

    def test_quoted_value_with_spaces(self):
        event = parse_line(
            "2026-11-14T08:00:00Z src=1.2.3.4 path=\"/search?q=' OR 1=1--\" status=200"
        )
        self.assertIsNotNone(event)
        self.assertIn(" OR 1=1", event.fields["path"])

    def test_epoch_timestamp(self):
        event = parse_line("ts=%d src=1.2.3.4 path=/ status=200" % int(BASE.timestamp()))
        self.assertIsNotNone(event)
        self.assertEqual(event.timestamp, BASE.timestamp())


class CliTests(unittest.TestCase):
    def test_cli_end_to_end_and_summary_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "report.json")
            stream = io.StringIO()
            with redirect_stdout(stream):
                code = cli_main([
                    "--log", DEMO_LOG,
                    "--rules", DEMO_RULES,
                    "--out", out_path,
                ])
            self.assertEqual(code, 0)
            summary = stream.getvalue().strip()
            self.assertRegex(summary, r"^read=\d+ matched=\d+ alerts=3$")
            with open(out_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
            self.assertEqual(len(report["alerts"]), 3)
            self.assertEqual(report["summary"]["alerts"], 3)


if __name__ == "__main__":
    unittest.main()

