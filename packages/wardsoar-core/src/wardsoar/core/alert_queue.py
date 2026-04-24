"""Async priority queue for alert processing.

Buffers incoming alerts and feeds them to the pipeline
in priority order. Handles burst scenarios (port scans, etc.)
with backpressure to prevent system overload.
"""

from __future__ import annotations

import asyncio
import heapq
import logging
from enum import IntEnum
from typing import Any

from wardsoar.core.models import SuricataAlert

logger = logging.getLogger("ward_soar.alert_queue")


class AlertPriority(IntEnum):
    """Alert priority levels for queue ordering (lower = higher priority)."""

    CRITICAL = 1  # Severity 1 alerts
    HIGH = 2  # Severity 2 or burst-escalated alerts
    NORMAL = 3  # Severity 3 alerts
    LOW = 4  # Deduplicated / low-score alerts


class AlertQueueItem:
    """Wrapper for an alert in the queue with priority and metadata.

    Attributes:
        alert: The Suricata alert.
        priority: Processing priority.
    """

    def __init__(self, alert: SuricataAlert, priority: AlertPriority) -> None:
        self.alert = alert
        self.priority = priority

    def __lt__(self, other: AlertQueueItem) -> bool:
        """Compare by priority for heap ordering."""
        return self.priority < other.priority


class AlertQueue:
    """Async priority queue with backpressure protection.

    Uses a heap-based list for the overflow drop_lowest strategy,
    and wraps asyncio.PriorityQueue for standard get/put.

    Args:
        config: Queue configuration dict from config.yaml.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self._max_size: int = config.get("max_size", 1000)
        self._overflow_strategy: str = config.get("overflow_strategy", "drop_lowest")
        self._heap: list[AlertQueueItem] = []
        self._event = asyncio.Event()
        self._dropped_count: int = 0

    async def put(self, alert: SuricataAlert, priority: AlertPriority) -> bool:
        """Add an alert to the queue.

        If the queue is full, applies the overflow strategy:
        - "drop_lowest": drop lowest-priority item to make room
        - "drop_new": reject the new alert

        Args:
            alert: The alert to enqueue.
            priority: Processing priority.

        Returns:
            True if the alert was enqueued, False if dropped.
        """
        item = AlertQueueItem(alert=alert, priority=priority)

        if len(self._heap) < self._max_size:
            heapq.heappush(self._heap, item)
            self._event.set()
            return True

        # Queue is full — apply overflow strategy
        if self._overflow_strategy == "drop_new":
            self._dropped_count += 1
            logger.warning(
                "Queue full, dropping new alert (strategy=drop_new, priority=%s)",
                priority.name,
            )
            return False

        # drop_lowest: find and remove the lowest-priority item
        return self._drop_lowest_and_insert(item)

    def _drop_lowest_and_insert(self, new_item: AlertQueueItem) -> bool:
        """Drop the lowest-priority item and insert the new one.

        If the new item has lower priority than all existing items,
        the new item is dropped instead.

        Args:
            new_item: The new item to insert.

        Returns:
            True if the new item was inserted, False if dropped.
        """
        # Find the item with the highest priority value (= lowest priority)
        worst_idx = 0
        for i in range(1, len(self._heap)):
            if self._heap[i].priority > self._heap[worst_idx].priority:
                worst_idx = i

        worst_item = self._heap[worst_idx]

        if new_item.priority >= worst_item.priority:
            # New item is equal or lower priority — drop the new item
            self._dropped_count += 1
            logger.warning(
                "Queue full, dropping new alert (lower priority than queue contents)",
            )
            return False

        # Drop the worst item and insert the new one
        self._heap[worst_idx] = self._heap[-1]
        self._heap.pop()
        heapq.heapify(self._heap)
        heapq.heappush(self._heap, new_item)
        self._dropped_count += 1
        logger.info(
            "Queue full, dropped priority=%s to make room for priority=%s",
            worst_item.priority.name,
            new_item.priority.name,
        )
        return True

    async def get(self) -> AlertQueueItem:
        """Get the highest-priority alert from the queue.

        Blocks until an alert is available.

        Returns:
            The next AlertQueueItem to process.
        """
        while not self._heap:
            self._event.clear()
            await self._event.wait()

        item = heapq.heappop(self._heap)
        return item

    @property
    def size(self) -> int:
        """Current number of alerts in the queue."""
        return len(self._heap)

    @property
    def is_full(self) -> bool:
        """Whether the queue has reached max capacity."""
        return len(self._heap) >= self._max_size

    @property
    def dropped_count(self) -> int:
        """Total number of alerts dropped due to overflow."""
        return self._dropped_count
