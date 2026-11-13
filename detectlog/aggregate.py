"""Sliding-window aggregation and alert merging.

Semantics:

* Each rule hit is bucketed by the rule's aggregation dimension.
* Within a bucket, a SlidingWindow counts hits in (t - window, t].
* The first time the window count reaches ``threshold`` the bucket is
  "confirmed" and an alert opens, covering every hit in the window.
* Once a bucket is confirmed, every later hit is attributed to an alert:
  it is merged into the open alert when it arrives within
  ``merge_window`` seconds of that alert's last hit, otherwise the open
  alert is closed and a new one starts with this single hit.
* Hits in buckets that never reach the threshold are discarded.
"""

from .alerts import Alert
from .window import SlidingWindow


class _Bucket:
    __slots__ = ("window", "confirmed", "current")

    def __init__(self, window_seconds: float):
        self.window = SlidingWindow(window_seconds)
        self.confirmed = False
        self.current = None


class Detector:
    def __init__(self, rules):
        self.rules = list(rules)
        self._buckets = {}
        self.alerts = []
        self.matched = 0

    def process(self, event):
        for rule in self.rules:
            if not rule.matches(event):
                continue
            key = rule.dimension_value(event)
            if key is None:
                continue
            self.matched += 1
            bucket_key = (rule.name, key)
            bucket = self._buckets.get(bucket_key)
            if bucket is None:
                bucket = _Bucket(rule.window)
                self._buckets[bucket_key] = bucket
            self._apply(rule, key, bucket, event)

    def _apply(self, rule, key, bucket, event):
        bucket.window.add(event.timestamp, event)
        current = bucket.current
        if bucket.confirmed:
            if (
                current is not None
                and event.timestamp - current.last_seen <= rule.merge_window
            ):
                current.count += 1
                current.last_seen = event.timestamp
            else:
                self._open_alert(bucket, rule, key, 1, event, event)
        elif len(bucket.window) >= rule.threshold:
            bucket.confirmed = True
            first_ts, first_event = bucket.window.items[0]
            self._open_alert(
                bucket, rule, key, len(bucket.window), first_event, event,
                first_ts=first_ts,
            )

    def _open_alert(self, bucket, rule, key, count, first_event, last_event,
                    first_ts=None):
        alert = Alert(
            rule=rule.name,
            dimension=rule.dimension,
            key=key,
            count=count,
            first_seen=first_ts if first_ts is not None else first_event.timestamp,
            last_seen=last_event.timestamp,
            sample=first_event.raw,
        )
        self.alerts.append(alert)
        bucket.current = alert
