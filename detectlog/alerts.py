"""Alert record produced by the aggregation engine."""

from dataclasses import dataclass
from datetime import datetime, timezone

ALERT_FIELDS = (
    "rule",
    "dimension",
    "key",
    "count",
    "first_seen",
    "last_seen",
    "sample",
)


def iso_utc(timestamp: float) -> str:
    moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    if moment.microsecond:
        return moment.isoformat().replace("+00:00", "Z")
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Alert:
    rule: str
    dimension: str
    key: str
    count: int
    first_seen: float
    last_seen: float
    sample: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "dimension": self.dimension,
            "key": self.key,
            "count": self.count,
            "first_seen": iso_utc(self.first_seen),
            "last_seen": iso_utc(self.last_seen),
            "sample": self.sample,
        }
