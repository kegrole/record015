"""Sliding time-window counter used by the aggregation engine."""

from collections import deque


class SlidingWindow:
    """Keeps the events that fall inside the trailing ``seconds`` window.

    The window is the half-open interval (now - seconds, now]: an event
    exactly ``seconds`` older than the newest event has just expired.
    """

    def __init__(self, seconds: float):
        self.seconds = float(seconds)
        self._items = deque()

    def add(self, timestamp: float, payload):
        self._items.append((timestamp, payload))
        cutoff = timestamp - self.seconds
        while self._items and self._items[0][0] <= cutoff:
            self._items.popleft()

    def __len__(self) -> int:
        return len(self._items)

    @property
    def items(self):
        return list(self._items)
