"""Intelligence feed package.

Each submodule implements one external intelligence source (a feed
downloader, a HTTP API client, or a WHOIS service). Every source
exposes the same simple interface via the :class:`FeedRegistry`
base: ``refresh_if_stale()`` to pull the latest data, and
``lookup_ip(ip)`` to check a single indicator against the in-memory
index.

The :class:`IntelManager` singleton owns every registry, schedules
background refreshes, and exposes a synchronous ``query_all_for_ip``
helper the alert pipeline uses to build the reputation rows.
"""

from src.intel.base import FeedEntry, FeedRegistry

__all__ = ["FeedEntry", "FeedRegistry"]
