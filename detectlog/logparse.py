"""Heuristic line-oriented log parser (standard library only).

Two log shapes are recognised:

* key=value pair lines (field names are mapped to canonical fields via
  common alias tables), and
* Apache/Nginx common log format lines (fields inferred by position).

As a last resort a line is scanned for a timestamp and the first IPv4
address, which are taken as the event time and source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

_KV_RE = re.compile(r"([A-Za-z_@][\w@.]*)=(\"[^\"]*\"|'[^']*'|\S+)")
_ISO_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_APACHE_TS_RE = re.compile(r"\[(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
_APACHE_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"\[(?P<ts>[^\]]+)\]\s+\"(?:(?P<method>[A-Z]+)\s+(?P<path>\S+)[^\"]*|-)\"\s+"
    r"(?P<status>\d{3})\b"
)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_FIELD_ALIASES = {
    "timestamp": {"ts", "time", "timestamp", "datetime", "date", "@timestamp"},
    "src_ip": {
        "src", "src_ip", "source", "source_ip", "src_addr", "client",
        "client_ip", "remote", "remote_addr", "remote_ip", "ip",
    },
    "dst": {
        "dst", "dst_ip", "dest", "destination", "dest_ip", "dst_addr",
        "target", "target_ip", "server_ip",
    },
    "path": {"path", "url", "uri", "request", "endpoint"},
    "command": {"cmd", "command", "proc", "process", "exe", "program"},
    "status": {"status", "status_code", "code", "resp_status"},
    "method": {"method", "verb", "action"},
}

_ALIAS_TO_FIELD = {}
for _canonical, _aliases in _FIELD_ALIASES.items():
    for _alias in _aliases:
        _ALIAS_TO_FIELD[_alias] = _canonical


@dataclass
class LogEvent:
    # One parsed log line. ``fields`` holds canonical field names plus any
    # original keys found on the raw line.
    timestamp: float
    raw: str
    fields: dict = field(default_factory=dict)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_epoch(text: str):
    try:
        value = float(text)
    except ValueError:
        return None
    if 1_000_000_000 <= value < 4_000_000_000:
        return value
    if 1_000_000_000_000 <= value < 4_000_000_000_000:
        return value / 1000.0
    return None


def _parse_iso(text: str):
    match = _ISO_RE.search(text.strip())
    if not match:
        return None
    token = match.group(0)
    if token.endswith("Z"):
        token = token[:-1] + "+00:00"
    # normalise offsets like +0800 to +08:00
    if len(token) >= 5 and token[-5] in "+-" and token[-3] != ":":
        token = token[:-2] + ":" + token[-2:]
    try:
        moment = datetime.fromisoformat(token)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _parse_apache_ts(text: str):
    try:
        moment = datetime.strptime(text.strip(), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return moment.timestamp()


def parse_timestamp(value: str):
    """Parse a timestamp string: epoch seconds/ms, ISO 8601, or Apache."""
    text = str(value).strip()
    if not text:
        return None
    epoch = _parse_epoch(text)
    if epoch is not None:
        return epoch
    iso = _parse_iso(text)
    if iso is not None:
        return iso
    return _parse_apache_ts(text)


def _find_timestamp(line: str):
    match = _ISO_RE.search(line)
    if match:
        return _parse_iso(match.group(0))
    match = _APACHE_TS_RE.search(line)
    if match:
        return _parse_apache_ts(match.group(1))
    return None


def parse_line(line: str):
    """Parse one raw log line into a LogEvent, or None if no timestamp."""
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return None

    pairs = _KV_RE.findall(raw)
    fields = {}
    timestamp = None

    if pairs:
        for key, value in pairs:
            value = _unquote(value)
            canonical = _ALIAS_TO_FIELD.get(key.lower())
            if canonical == "timestamp":
                if timestamp is None:
                    timestamp = parse_timestamp(value)
                continue
            if canonical and canonical not in fields:
                fields[canonical] = value
            fields.setdefault(key, value)
        if timestamp is None:
            timestamp = _find_timestamp(raw)
    else:
        apache = _APACHE_RE.match(raw)
        if apache:
            fields["src_ip"] = apache.group("ip")
            if apache.group("method"):
                fields["method"] = apache.group("method")
            if apache.group("path"):
                fields["path"] = apache.group("path")
            fields["status"] = apache.group("status")
            timestamp = _parse_apache_ts(apache.group("ts"))
        else:
            timestamp = _find_timestamp(raw)
            ip_match = _IPV4_RE.search(raw)
            if ip_match:
                fields["src_ip"] = ip_match.group(0)

    if timestamp is None:
        return None
    return LogEvent(timestamp=timestamp, raw=raw, fields=fields)


def read_log(path: str):
    """Read a log file; return (events, lines_read, lines_parsed).

    Events are returned sorted by timestamp (stable for equal timestamps)
    so the sliding window logic sees a chronological stream.
    """
    events = []
    lines_read = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for seq, line in enumerate(handle):
            lines_read += 1
            event = parse_line(line)
            if event is not None:
                events.append((event.timestamp, seq, event))
    events.sort(key=lambda item: (item[0], item[1]))
    return [event for _, _, event in events], lines_read, len(events)
