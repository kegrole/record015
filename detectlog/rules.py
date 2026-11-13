"""Rule engine: loads rules from a readable config file and evaluates them.

The config uses a small YAML subset (no third-party dependency): nested
dicts/lists by indentation, quoted or bare scalars, inline [a, b] lists,
and # comments. Example:

    rules:
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
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


class RuleError(ValueError):
    """Raised when a rules file is malformed."""


# ---------------------------------------------------------------------------
# Minimal YAML-subset parser
# ---------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _split_inline(text: str):
    parts, buffer, quote = [], [], None
    for char in text:
        if quote:
            buffer.append(char)
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
            buffer.append(char)
        elif char == ",":
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
    parts.append("".join(buffer))
    return [part.strip() for part in parts if part.strip()]


def _parse_scalar(token: str):
    token = token.strip()
    if not token:
        return None
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in _split_inline(inner)]
    lowered = token.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if lowered in ("null", "~", "none"):
        return None
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


_KEY_RE = re.compile(r"^[A-Za-z_][\w.-]*$")


def _split_key(text: str):
    """Split "key: value" -> (key, value); return None if not a mapping."""
    quote = None
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == ":" and (index + 1 == len(text) or text[index + 1] == " "):
            key = text[:index].strip()
            if _KEY_RE.match(key):
                return key, text[index + 1:].strip()
            return None
    return None


def _prepare_lines(text: str):
    prepared = []
    for raw in text.splitlines():
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        prepared.append([indent, stripped.strip()])
    return prepared


def _parse_block(lines, index, indent):
    if lines[index][1] == "-" or lines[index][1].startswith("- "):
        return _parse_list(lines, index, indent)
    return _parse_dict(lines, index, indent)


def _parse_dict(lines, index, indent):
    result = {}
    while index < len(lines) and lines[index][0] == indent:
        pair = _split_key(lines[index][1])
        if pair is None:
            break
        key, rest = pair
        index += 1
        if rest:
            result[key] = _parse_scalar(rest)
        elif index < len(lines) and lines[index][0] > indent:
            result[key], index = _parse_block(lines, index, lines[index][0])
        else:
            result[key] = None
    return result, index


def _parse_list(lines, index, indent):
    items = []
    while index < len(lines) and lines[index][0] == indent and (
        lines[index][1] == "-" or lines[index][1].startswith("- ")
    ):
        content = lines[index][1][1:].strip()
        if not content:
            index += 1
            if index < len(lines) and lines[index][0] > indent:
                item, index = _parse_block(lines, index, lines[index][0])
            else:
                item = None
            items.append(item)
        elif _split_key(content) is not None:
            # inline first pair of a mapping, e.g. "- name: brute_force"
            lines[index] = [indent + 2, content]
            item, index = _parse_dict(lines, index, indent + 2)
            items.append(item)
        else:
            items.append(_parse_scalar(content))
            index += 1
    return items, index


def parse_config(text: str):
    """Parse the YAML-subset text into Python dicts/lists/scalars."""
    lines = _prepare_lines(text)
    if not lines:
        return None
    result, index = _parse_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise RuleError(
            "could not parse rules file near line: %r" % (lines[index][1],)
        )
    return result


# ---------------------------------------------------------------------------
# Conditions and rules
# ---------------------------------------------------------------------------

def _compile_members(entries):
    """Split an in/not_in list into IP networks and plain strings."""
    networks, strings = [], []
    for entry in entries:
        text = str(entry)
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
            continue
        except ValueError:
            pass
        strings.append(text)
    return networks, strings


def _is_member(value, networks, strings):
    text = str(value)
    if text in strings:
        return True
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return any(address in network for network in networks)


@dataclass
class Condition:
    field: str
    op: str  # pattern | not_pattern | in | not_in
    value: object

    def matches(self, event) -> bool:
        if self.field == "raw":
            target = event.raw
        else:
            target = event.fields.get(self.field)
        if target is None:
            return False
        if self.op == "pattern":
            return bool(self.value.search(str(target)))
        if self.op == "not_pattern":
            return not self.value.search(str(target))
        networks, strings = self.value
        member = _is_member(target, networks, strings)
        return member if self.op == "in" else not member


_CONDITION_OPS = ("pattern", "not_pattern", "in", "not_in")


def _build_condition(raw, rule_name):
    if not isinstance(raw, dict):
        raise RuleError(
            "rule %r: each where entry must be a mapping" % (rule_name,)
        )
    field = raw.get("field")
    if not field:
        raise RuleError("rule %r: condition missing 'field'" % (rule_name,))
    ops = [op for op in _CONDITION_OPS if op in raw]
    if len(ops) != 1:
        raise RuleError(
            "rule %r: condition on %r needs exactly one of %s"
            % (rule_name, field, "/".join(_CONDITION_OPS)),
        )
    op = ops[0]
    if op in ("pattern", "not_pattern"):
        try:
            value = re.compile(str(raw[op]))
        except re.error as exc:
            raise RuleError("rule %r: bad regex: %s" % (rule_name, exc))
    else:
        entries = raw[op]
        if not isinstance(entries, list):
            entries = [entries]
        value = _compile_members(entries)
    return Condition(field=str(field), op=op, value=value)


@dataclass
class Rule:
    name: str
    dimension: str
    window: float
    threshold: int
    merge_window: float
    conditions: list

    def matches(self, event) -> bool:
        return all(condition.matches(event) for condition in self.conditions)

    def dimension_value(self, event):
        if self.dimension == "raw":
            return event.raw
        value = event.fields.get(self.dimension)
        return None if value is None else str(value)


def _build_rule(raw, index):
    if not isinstance(raw, dict):
        raise RuleError("rule #%d must be a mapping" % (index,))
    name = raw.get("name")
    if not name:
        raise RuleError("rule #%d is missing 'name'" % (index,))
    dimension = raw.get("dimension")
    if not dimension:
        raise RuleError("rule %r is missing 'dimension'" % (name,))
    try:
        window = float(raw["window"])
    except (KeyError, TypeError, ValueError):
        raise RuleError("rule %r needs a numeric 'window'" % (name,))
    try:
        threshold = int(raw["threshold"])
    except (KeyError, TypeError, ValueError):
        raise RuleError("rule %r needs an integer 'threshold'" % (name,))
    if window <= 0:
        raise RuleError("rule %r: window must be positive" % (name,))
    if threshold < 1:
        raise RuleError("rule %r: threshold must be >= 1" % (name,))
    try:
        merge_window = float(raw.get("merge_window", 60))
    except (TypeError, ValueError):
        raise RuleError("rule %r: bad merge_window" % (name,))
    conditions = [_build_condition(c, name) for c in raw.get("where") or []]
    return Rule(
        name=str(name),
        dimension=str(dimension),
        window=window,
        threshold=threshold,
        merge_window=merge_window,
        conditions=conditions,
    )


def load_rules(path: str):
    """Load rules from a config file; returns a list of Rule objects."""
    with open(path, "r", encoding="utf-8") as handle:
        config = parse_config(handle.read())
    if isinstance(config, dict):
        raw_rules = config.get("rules")
    else:
        raw_rules = config
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleError("rules file must define a non-empty 'rules' list")
    return [_build_rule(raw, index) for index, raw in enumerate(raw_rules)]
