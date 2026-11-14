"""Threat intelligence: the virus-database update subsystem.

Two halves:

* :mod:`aegis.intel.baseline` - the offline starter database that ships in the
  repository, so a fresh install detects something before the first update.
* :mod:`aegis.intel.feeds` - pulling fresh indicators from open sources on the
  internet (abuse.ch, ClamAV, a curated list in this repo).

Importing this package has no side effects: no network, no file I/O, no
directories created.
"""

from __future__ import annotations

from .baseline import builtin_indicators, ensure_baseline
from .feeds import AVAILABLE_FEEDS, USER_AGENT, FeedSpec, IntelUpdater, fetch, parse_feed

__all__ = [
    "AVAILABLE_FEEDS",
    "USER_AGENT",
    "FeedSpec",
    "IntelUpdater",
    "builtin_indicators",
    "ensure_baseline",
    "fetch",
    "parse_feed",
]
