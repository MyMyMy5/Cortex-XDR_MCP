"""
Tool: investigate_browser_session

Unified browser investigation tool that supports three modes:

- **history mode** (default): Collects browsing history, download history, or both
  from an endpoint via the XDR Agent Script Library. This is the straightforward
  "show me what this user browsed/downloaded" use case.

- **investigate mode**: Runs browser history collection and browser network activity
  search concurrently, then correlates them by timestamp proximity to produce a
  unified timeline showing user intent alongside network context (proxy usage,
  remote IPs, on/off-network status). Includes DNS enrichment (bare-IP events
  resolved to hostnames), download correlation, and optional aggregation.

- **network mode**: Queries the XDR data lake for browser network connections
  without collecting browser history. Returns enriched network events with proxy
  detection, network location metadata, and DNS enrichment. Does not require the
  endpoint to be online.

Supports multi-endpoint parallel queries (``hostnames`` parameter), process-aware
browser filtering (``browser_filter``), configurable XQL result limits (``limit``),
and aggregated summaries (``summarize``).
"""

import asyncio
import logging
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Annotated, Optional, Union
from urllib.parse import urlparse

from fastmcp import Context, FastMCP
from pydantic import Field

from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIClientError,
    PAPIClientRequestError,
    PAPIConnectionError,
    PAPIResponseError,
    PAPIServerError,
)
from pkg.util import create_response
from usecase.base_module import BaseModule
from usecase.custom_components.browser_activity import _classify_connection, _is_internal_ip
from usecase.custom_components.browser_history import (
    _download_result_files,
    _resolve_endpoint,
    _resolve_script_uid,
    _run_script_on_endpoint,
)
from usecase.custom_components.xql_helpers import _run_xql, _to_epoch_ms
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

# Browser process names for XQL filtering (same as browser_activity.py)
_BROWSER_PROCESSES = (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe",
)

_MAX_ROWS = 50

# Friendly browser name → Windows process image name
_BROWSER_MAP: dict[str, str] = {
    "chrome": "chrome.exe",
    "edge": "msedge.exe",
    "firefox": "firefox.exe",
    "brave": "brave.exe",
    "opera": "opera.exe",
}

_MAX_LIMIT = 500


# ── Pure helper functions (correlation engine) ───────────────────────────


def _extract_domain(url: str) -> str | None:
    """Extract the hostname from a URL using urllib.parse.urlparse.

    Returns None if the URL is empty, malformed, or has no hostname.
    Examples:
        "https://evil.com/page?q=1" → "evil.com"
        "http://sub.example.org:8080/path" → "sub.example.org"
        "" → None
        "not-a-url" → None
    """
    if not url or not url.strip():
        return None
    try:
        parsed = urlparse(url.strip())
        hostname = parsed.hostname
        if hostname:
            return hostname
        return None
    except Exception:
        return None


def _resolve_browser_filter(browser_filter: str) -> tuple[tuple[str, ...], str | None]:
    """Map a friendly browser name to the process-name tuple used in XQL queries.

    Returns:
        (process_names, error_message)
        - ``"*"`` → all browser processes, no error
        - valid key in ``_BROWSER_MAP`` → single-element tuple, no error
        - anything else → empty tuple, descriptive error string
    """
    if browser_filter == "*":
        return (_BROWSER_PROCESSES, None)
    if browser_filter in _BROWSER_MAP:
        return ((_BROWSER_MAP[browser_filter],), None)
    valid = ", ".join(sorted(_BROWSER_MAP.keys()))
    return ((), f"Invalid browser_filter '{browser_filter}'. Valid values: {valid}, *")


def _cap_limit(limit: int) -> tuple[int, str | None]:
    """Validate and cap the XQL result limit.

    Returns:
        (effective_limit, warning_or_none)
        - limit ≤ 500 → (limit, None)
        - limit > 500 → (500, warning string)
    """
    if limit > _MAX_LIMIT:
        return (_MAX_LIMIT, f"limit was reduced from {limit} to {_MAX_LIMIT} (maximum)")
    return (limit, None)


_TZ_HEADER_RE = re.compile(
    r"Endpoint TZ:\s*.+?\(UTC([+-]?)(\d{1,2}):(\d{2}):(\d{2})\)",
    re.IGNORECASE,
)


def _parse_tz_offset(output: str) -> int:
    """Extract timezone offset in seconds from the Endpoint TZ header line.

    Scans for a line matching: Endpoint TZ: <name> (UTC<sign><H>:<M>:<S>)
    Examples:
        "Endpoint TZ: Israel Standard Time (UTC3:00:00)" → 10800
        "Endpoint TZ: Eastern Standard Time (UTC-5:00:00)" → -18000
        "Endpoint TZ: UTC (UTC0:00:00)" → 0

    Returns 0 if no header found or offset cannot be parsed.
    Logs a warning if header is present but malformed.
    """
    if not output:
        return 0

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("endpoint tz:"):
            continue

        # Found the header line — try to parse it
        m = _TZ_HEADER_RE.search(line)
        if m:
            sign_str, hours_str, minutes_str, seconds_str = m.groups()
            sign = -1 if sign_str == "-" else 1
            try:
                total = int(hours_str) * 3600 + int(minutes_str) * 60 + int(seconds_str)
                return sign * total
            except (ValueError, OverflowError):
                logger.warning("Malformed timezone offset values in header: %s", line)
                return 0
        else:
            logger.warning("Endpoint TZ header found but offset is malformed: %s", line)
            return 0

    return 0


def _parse_history_output(standard_output: str) -> list[dict]:
    """Parse pipe-delimited browser history output into structured dicts.

    The History_Script_Library script prints browsing history lines in the format:
        [Timestamp] | User | Browser | VisitType | URL | ReferrerURL

    Lines that are headers, separators (dashes), section banners (=), or empty
    are skipped.  Timestamp strings like ``2024-01-15 10:30:00`` are converted
    to epoch milliseconds; if conversion fails the raw string is kept and
    ``timestamp_ms`` is set to 0.

    Enhanced: Extracts the Endpoint TZ offset from the header and passes
    it to _parse_timestamp_to_epoch_ms for each timestamp conversion.

    Returns:
        List of dicts with keys: timestamp_ms, url, visit_type, referrer_url,
        user, browser, title.
    """
    if not standard_output:
        return []

    tz_offset = _parse_tz_offset(standard_output)

    results: list[dict] = []

    for raw_line in standard_output.splitlines():
        line = raw_line.strip()

        # Skip empty lines, separator lines, and banner lines
        if not line:
            continue
        if line.startswith("-") or line.startswith("="):
            continue

        # Skip known header/info lines
        lower = line.lower()
        if lower.startswith("timestamp") or lower.startswith("browsing history") or lower.startswith("browser history"):
            continue
        if lower.startswith("found ") or lower.startswith("processing:") or lower.startswith("no "):
            continue
        if lower.startswith("hostname:") or lower.startswith("endpoint tz:") or lower.startswith("user filter:"):
            continue
        if lower.startswith("browser:") or lower.startswith("mode:") or lower.startswith("max results:"):
            continue
        if lower.startswith("url filter:") or lower.startswith("search range:") or lower.startswith("total:"):
            continue
        if lower.startswith("download history:"):
            continue
        # Skip download data lines (they have more fields and different structure)
        # We only parse browsing history lines

        # Split on pipe delimiter
        parts = [p.strip() for p in line.split("|")]

        # We expect at least 6 fields for the standard_output format:
        # [Timestamp] | User | Browser | VisitType | URL | ReferrerURL
        # Or 7 fields if Title is included:
        # Timestamp | User | Browser | VisitType | Title | URL | ReferrerURL
        if len(parts) < 6:
            continue

        # Extract timestamp — may be wrapped in brackets like [2024-01-15 10:30:00]
        ts_raw = parts[0].strip("[] ")
        timestamp_ms = _parse_timestamp_to_epoch_ms(ts_raw, tz_offset_seconds=tz_offset)

        user = parts[1]
        browser = parts[2]
        visit_type = parts[3]

        if len(parts) == 6:
            # Format: Timestamp | User | Browser | VisitType | URL | ReferrerURL
            title = ""
            url = parts[4]
            referrer_url = parts[5]
        else:
            # Format: Timestamp | User | Browser | VisitType | Title | URL | ReferrerURL
            title = parts[4]
            url = parts[5]
            referrer_url = parts[6] if len(parts) > 6 else ""

        results.append({
            "timestamp_ms": timestamp_ms,
            "url": url,
            "visit_type": visit_type,
            "referrer_url": referrer_url,
            "user": user,
            "browser": browser,
            "title": title,
        })

    return results


def _parse_download_output(standard_output: str) -> list[dict]:
    """Parse pipe-delimited download history output into structured dicts.

    The History_Script_Library script prints download history lines in the format:
        [Timestamp] | User | Browser | State | DangerType | SizeMB | Opened | MimeType | FilePath | SourceURL | Referrer

    Lines with fewer than 11 pipe-delimited fields are skipped.
    Reuses ``_parse_tz_offset`` and ``_parse_timestamp_to_epoch_ms`` for timestamp
    conversion.

    Returns:
        List of dicts with keys: timestamp_ms, user, browser, state, danger_type,
        size_mb, opened, mime_type, file_path, source_url, referrer.
    """
    if not standard_output:
        return []

    tz_offset = _parse_tz_offset(standard_output)
    results: list[dict] = []

    for raw_line in standard_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 11:
            continue

        ts_raw = parts[0].strip("[] ")
        timestamp_ms = _parse_timestamp_to_epoch_ms(ts_raw, tz_offset_seconds=tz_offset)

        results.append({
            "timestamp_ms": timestamp_ms,
            "user": parts[1],
            "browser": parts[2],
            "state": parts[3],
            "danger_type": parts[4],
            "size_mb": parts[5],
            "opened": parts[6],
            "mime_type": parts[7],
            "file_path": parts[8],
            "source_url": parts[9],
            "referrer": parts[10],
        })

    return results


def _aggregate_network_events(events: list[dict]) -> list[dict]:
    """Group network events by key dimensions and produce summary records.

    Groups by ``(action_external_hostname, _through_proxy, _network_location,
    actor_process_image_name)`` and returns aggregated records sorted by
    ``count`` descending.

    Each record contains: ``external_hostname``, ``through_proxy``,
    ``network_location``, ``process_name``, ``count``, ``first_seen``,
    ``last_seen``, ``unique_remote_ips``.

    Events with ``None`` hostname are grouped under ``None`` key.
    """
    if not events:
        return []

    groups: dict[tuple, list[dict]] = {}
    for ev in events:
        key = (
            ev.get("action_external_hostname"),
            ev.get("_through_proxy"),
            ev.get("_network_location"),
            ev.get("actor_process_image_name"),
        )
        groups.setdefault(key, []).append(ev)

    records: list[dict] = []
    for (hostname, through_proxy, network_location, process_name), group in groups.items():
        timestamps = [e.get("event_timestamp", 0) for e in group]
        ips = list({e.get("action_remote_ip") for e in group if e.get("action_remote_ip") is not None})
        records.append({
            "external_hostname": hostname,
            "through_proxy": through_proxy,
            "network_location": network_location,
            "process_name": process_name,
            "count": len(group),
            "first_seen": min(timestamps),
            "last_seen": max(timestamps),
            "unique_remote_ips": ips,
        })

    records.sort(key=lambda r: r["count"], reverse=True)
    return records


def _merge_endpoint_results(per_endpoint: list[tuple[str, list[dict]]]) -> list[dict]:
    """Merge per-endpoint result lists, tagging each entry with ``source_hostname``.

    Args:
        per_endpoint: List of ``(hostname, entries)`` tuples where *entries* is
            a list of dicts (timeline entries or network events).

    Returns:
        A single flat list containing every entry from every endpoint, each
        augmented with a ``source_hostname`` field.
    """
    merged: list[dict] = []
    for hostname, entries in per_endpoint:
        for entry in entries:
            entry["source_hostname"] = hostname
            merged.append(entry)
    return merged


def _merge_endpoint_timelines(per_endpoint: list[tuple[str, list[dict]]]) -> list[dict]:
    """Merge per-endpoint timeline entries and sort chronologically.

    Calls :func:`_merge_endpoint_results` to tag and flatten, then sorts by
    the ``timestamp`` key in non-decreasing order.

    Args:
        per_endpoint: List of ``(hostname, timeline_entries)`` tuples.

    Returns:
        Chronologically sorted list of tagged timeline entries.
    """
    merged = _merge_endpoint_results(per_endpoint)
    merged.sort(key=lambda e: e.get("timestamp", 0))
    return merged


def _enrich_dns_batch(network_events: list[dict], dns_events: list[dict]) -> list[dict]:
    """Enrich bare-IP network events with DNS resolution data.

    For each network event where both ``action_external_hostname`` and
    ``dst_action_external_hostname`` are null, find DNS events with a matching
    ``action_remote_ip`` and select the one whose ``event_timestamp`` is closest
    to the network event's ``event_timestamp``.  Set the network event's
    ``action_external_hostname`` to the matching ``dns_query_name``.

    Events that already have a hostname are left unchanged.  Events with no
    matching DNS record are left unchanged.

    Mutates *network_events* in-place and returns the same list.
    """
    if not network_events or not dns_events:
        return network_events

    # Build an index: remote_ip → list of (event_timestamp, dns_query_name)
    dns_index: dict[str, list[tuple[int, str]]] = {}
    for dns_ev in dns_events:
        ip = dns_ev.get("action_remote_ip")
        query_name = dns_ev.get("dns_query_name")
        ts = dns_ev.get("event_timestamp", 0)
        if ip and query_name:
            dns_index.setdefault(ip, []).append((ts, query_name))

    for ev in network_events:
        # Only enrich events where both hostname fields are null
        if ev.get("action_external_hostname") is not None or ev.get("dst_action_external_hostname") is not None:
            continue

        remote_ip = ev.get("action_remote_ip")
        if not remote_ip or remote_ip not in dns_index:
            continue

        ev_ts = ev.get("event_timestamp", 0)
        candidates = dns_index[remote_ip]

        # Select the DNS event with the smallest absolute timestamp difference
        best_query_name = min(candidates, key=lambda c: abs(c[0] - ev_ts))[1]
        ev["action_external_hostname"] = best_query_name

    return network_events


def _parse_timestamp_to_epoch_ms(ts_str: str, tz_offset_seconds: int = 0) -> int:
    """Convert a timestamp string to UTC epoch milliseconds.

    Supports formats: ``YYYY-MM-DD HH:MM:SS``, ``YYYY-MM-DD``,
    ``YYYY-MM-DDTHH:MM:SSZ``, ``YYYY-MM-DDTHH:MM:SS``.

    When *tz_offset_seconds* is non-zero the parsed timestamp is interpreted
    as local time and the offset is subtracted to produce UTC:

        utc_epoch_ms = local_epoch_ms - (tz_offset_seconds * 1000)

    Returns 0 if parsing fails.
    """
    if not ts_str:
        return 0
    # Try numeric (already epoch ms)
    stripped = ts_str.strip()
    if stripped.isdigit():
        return int(stripped)
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(stripped, fmt).replace(tzinfo=timezone.utc)
            local_epoch_ms = int(dt.timestamp() * 1000)
            return local_epoch_ms - (tz_offset_seconds * 1000)
        except ValueError:
            continue
    return 0


def _correlate_timeline(
    history_entries: list[dict],
    network_events: list[dict],
    tolerance_ms: int,
    download_entries: list[dict] | None = None,
) -> list[dict]:
    """Match history entries to network events by domain + timestamp proximity.

    Enhanced algorithm:
    1. Sort both lists by timestamp.
    2. For each history entry:
       a. Extract domain from the history entry's URL.
       b. Collect all network events within tolerance_ms.
       c. Partition candidates into domain-matches (where extracted domain
          equals action_external_hostname or dst_action_external_hostname,
          case-insensitive) and timestamp-only matches.
       d. If domain-matches exist, select the one with smallest timestamp diff.
       e. Otherwise, select the closest timestamp-only match.
       f. Mark the selected network event as matched.
    3. Correlate download entries similarly using domain from source_url.
    4. Append unmatched network events as network_only entries.
    5. Sort final timeline chronologically.

    Args:
        history_entries: Parsed history dicts with ``timestamp_ms`` key.
        network_events: Network event dicts with ``event_timestamp`` key.
        tolerance_ms: Maximum allowed timestamp difference in milliseconds.
        download_entries: Optional parsed download dicts with ``timestamp_ms``
            and ``source_url`` keys.

    Returns:
        Chronologically sorted list of unified timeline entries.
    """
    timeline: list[dict] = []

    if not history_entries and not network_events:
        return timeline

    # Sort both lists by timestamp
    sorted_history = sorted(history_entries, key=lambda h: h.get("timestamp_ms", 0))
    sorted_network = sorted(network_events, key=lambda n: n.get("event_timestamp", 0))

    matched_network_indices: set[int] = set()

    # For each history entry, find the closest network event within tolerance
    ptr = 0  # sliding pointer into sorted_network
    for hist in sorted_history:
        h_ts = hist.get("timestamp_ms", 0)

        # Extract domain from the history entry's URL
        hist_domain = _extract_domain(hist.get("url", ""))
        hist_domain_lower = hist_domain.lower() if hist_domain else None

        best_domain_idx: int | None = None
        best_domain_diff = tolerance_ms + 1
        best_ts_idx: int | None = None
        best_ts_diff = tolerance_ms + 1

        # Move pointer forward to the first network event that could be within range
        while ptr < len(sorted_network) and sorted_network[ptr].get("event_timestamp", 0) < h_ts - tolerance_ms:
            ptr += 1

        # Scan forward from ptr to find candidates
        scan = ptr
        while scan < len(sorted_network):
            n_ts = sorted_network[scan].get("event_timestamp", 0)
            diff = abs(h_ts - n_ts)

            # If we've gone past the tolerance window, stop scanning
            if n_ts > h_ts + tolerance_ms:
                break

            if diff <= tolerance_ms and scan not in matched_network_indices:
                # Check if this is a domain match
                is_domain_match = False
                if hist_domain_lower:
                    net_host = sorted_network[scan].get("action_external_hostname") or ""
                    dst_host = sorted_network[scan].get("dst_action_external_hostname") or ""
                    if (net_host and net_host.lower() == hist_domain_lower) or \
                       (dst_host and dst_host.lower() == hist_domain_lower):
                        is_domain_match = True

                if is_domain_match and diff < best_domain_diff:
                    best_domain_diff = diff
                    best_domain_idx = scan
                elif diff < best_ts_diff:
                    best_ts_diff = diff
                    best_ts_idx = scan

            scan += 1

        # Prefer domain match over timestamp-only match
        best_idx = best_domain_idx if best_domain_idx is not None else best_ts_idx

        if best_idx is not None:
            matched_network_indices.add(best_idx)
            timeline.append(_build_timeline_entry(hist, sorted_network[best_idx]))
        else:
            timeline.append(_build_timeline_entry(hist, None))

    # Append unmatched network events
    for idx, net in enumerate(sorted_network):
        if idx not in matched_network_indices:
            timeline.append(_build_timeline_entry(None, net))

    # ── Download entry correlation ───────────────────────────────────
    if download_entries:
        sorted_downloads = sorted(download_entries, key=lambda d: d.get("timestamp_ms", 0))
        for dl in sorted_downloads:
            dl_ts = dl.get("timestamp_ms", 0)
            dl_domain = _extract_domain(dl.get("source_url", ""))
            dl_domain_lower = dl_domain.lower() if dl_domain else None

            best_domain_idx: int | None = None
            best_domain_diff = tolerance_ms + 1
            best_ts_idx: int | None = None
            best_ts_diff = tolerance_ms + 1

            for scan_idx, net in enumerate(sorted_network):
                if scan_idx in matched_network_indices:
                    continue
                n_ts = net.get("event_timestamp", 0)
                diff = abs(dl_ts - n_ts)
                if diff > tolerance_ms:
                    continue

                is_domain_match = False
                if dl_domain_lower:
                    net_host = net.get("action_external_hostname") or ""
                    dst_host = net.get("dst_action_external_hostname") or ""
                    if (net_host and net_host.lower() == dl_domain_lower) or \
                       (dst_host and dst_host.lower() == dl_domain_lower):
                        is_domain_match = True

                if is_domain_match and diff < best_domain_diff:
                    best_domain_diff = diff
                    best_domain_idx = scan_idx
                elif diff < best_ts_diff:
                    best_ts_diff = diff
                    best_ts_idx = scan_idx

            best_idx = best_domain_idx if best_domain_idx is not None else best_ts_idx

            if best_idx is not None:
                matched_network_indices.add(best_idx)
                timeline.append(_build_timeline_entry(None, sorted_network[best_idx], download=dl))
            else:
                timeline.append(_build_timeline_entry(None, None, download=dl))

    # Sort final timeline chronologically
    timeline.sort(key=lambda e: e.get("timestamp", 0))

    return timeline


def _build_timeline_entry(
    history: Optional[dict] = None,
    network: Optional[dict] = None,
    download: Optional[dict] = None,
) -> dict:
    """Construct a single unified timeline entry from history and/or network data.

    Sets ``source`` to ``"correlated"``, ``"history_only"``, or ``"network_only"``
    depending on which inputs are provided.  When *download* is supplied the
    source is ``"download_correlated"`` (if a network event is also present) or
    ``"download"`` (standalone).

    Always includes all required fields: ``timestamp``, ``url``, ``visit_type``,
    ``referrer_url``, ``through_proxy``, ``remote_ip``, ``remote_port``,
    ``external_hostname``, ``network_location``, ``source``.

    Download-specific fields (``file_path``, ``download_state``, ``danger_type``,
    ``size_mb``, ``mime_type``, ``source_url``) are set to ``None`` for
    non-download entries.
    """
    if download and network:
        source = "download_correlated"
        timestamp = download.get("timestamp_ms", 0)
    elif download:
        source = "download"
        timestamp = download.get("timestamp_ms", 0)
    elif history and network:
        source = "correlated"
        timestamp = history.get("timestamp_ms", 0)
    elif history:
        source = "history_only"
        timestamp = history.get("timestamp_ms", 0)
    else:
        source = "network_only"
        timestamp = network.get("event_timestamp", 0) if network else 0

    # History fields (use download's source_url as url when download is present)
    if download:
        url = download.get("source_url")
        visit_type = None
        referrer_url = download.get("referrer")
    elif history:
        url = history.get("url")
        visit_type = history.get("visit_type")
        referrer_url = history.get("referrer_url")
    else:
        url = None
        visit_type = None
        referrer_url = None

    # Network fields
    through_proxy = network.get("_through_proxy") if network else None
    remote_ip = network.get("action_remote_ip") if network else None
    remote_port = network.get("action_remote_port") if network else None
    external_hostname = (
        network.get("action_external_hostname") or network.get("dst_action_external_hostname")
    ) if network else None
    network_location = network.get("_network_location") if network else None

    # Download-specific fields
    entry = {
        "timestamp": timestamp,
        "url": url,
        "visit_type": visit_type,
        "referrer_url": referrer_url,
        "through_proxy": through_proxy,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "external_hostname": external_hostname,
        "network_location": network_location,
        "source": source,
        "file_path": download.get("file_path") if download else None,
        "download_state": download.get("state") if download else None,
        "danger_type": download.get("danger_type") if download else None,
        "size_mb": download.get("size_mb") if download else None,
        "mime_type": download.get("mime_type") if download else None,
        "source_url": download.get("source_url") if download else None,
    }

    return entry


def _build_summary(timeline: list[dict], data_sources: list[str]) -> dict:
    """Compute summary statistics from the unified timeline.

    Args:
        timeline: List of unified timeline entries.
        data_sources: List of source names that contributed data
            (e.g. ``["browser_history", "network_activity"]``).

    Returns:
        Summary dict with counts, unique URLs, proxy stats, and network location.
    """
    total_events = len(timeline)
    correlated_events = sum(1 for e in timeline if e.get("source") == "correlated")
    history_only_events = sum(1 for e in timeline if e.get("source") == "history_only")
    network_only_events = sum(1 for e in timeline if e.get("source") == "network_only")

    # Unique URLs from non-None url fields
    unique_urls = sorted({e["url"] for e in timeline if e.get("url") is not None})

    # Proxy / direct counts — only from entries that have network data
    proxy_connections = sum(
        1 for e in timeline if e.get("through_proxy") is True
    )
    direct_connections = sum(
        1 for e in timeline if e.get("through_proxy") is False
    )

    # Network location — most common non-None value
    locations = [e["network_location"] for e in timeline if e.get("network_location") is not None]
    if locations:
        network_location = Counter(locations).most_common(1)[0][0]
    else:
        network_location = "unknown"

    return {
        "total_events": total_events,
        "correlated_events": correlated_events,
        "history_only_events": history_only_events,
        "network_only_events": network_only_events,
        "unique_urls": unique_urls,
        "proxy_connections": proxy_connections,
        "direct_connections": direct_connections,
        "network_location": network_location,
        "data_sources": data_sources,
    }


async def investigate_browser_session(
    ctx: Context,
    hostname: Annotated[str, Field(description=(
        "The hostname of the endpoint to investigate (e.g. 'LAP-89491')."
    ))],
    mode: Annotated[str, Field(description=(
        "Operation mode: 'history' (default) returns plain browsing/download history; "
        "'investigate' correlates browser history with network activity into a unified timeline; "
        "'network' queries the XDR data lake for browser network connections without collecting browser history."
    ))] = "history",
    indicator: Annotated[Optional[str], Field(description=(
        "Domain, IP address, or URL substring to filter on. "
        "Optional in both modes. In 'history' mode it is used as url_filter. "
        "In 'investigate' mode, when provided it filters the XQL query and history "
        "collection; when omitted, all browser activity is returned."
    ))] = None,
    timeframe_from: Annotated[Optional[Union[int, str]], Field(description=(
        "Start of search window. Accepts epoch ms (int) or ISO 8601 string "
        "(e.g. '2026-04-09'). Optional."
    ))] = None,
    timeframe_to: Annotated[Optional[Union[int, str]], Field(description=(
        "End of search window. Accepts epoch ms (int) or ISO 8601 string. Optional."
    ))] = None,
    tolerance_seconds: Annotated[int, Field(description=(
        "Maximum time difference in seconds for matching a browser history entry "
        "to a network connection event. Only used in 'investigate' mode. Default 5."
    ))] = 5,
    timeout: Annotated[int, Field(description=(
        "Maximum wait time in seconds for data collection. Default 60."
    ))] = 60,
    history_mode: Annotated[str, Field(description=(
        "Controls which browser data to collect: 'history' for browsing history only, "
        "'downloads' for download history only, 'both' for both. Default 'both'."
    ))] = "both",
    output_file_path: Annotated[Optional[str], Field(description=(
        "When provided in 'history' mode, downloads the full untruncated result files "
        "from XDR and writes them to this file path on the analyst's machine. "
        "Enables complete data dumps for large datasets. "
        "Example: 'C:/Users/analyst/Desktop/LAP-89491_browsing_history.txt'."
    ))] = None,
    hostnames: Annotated[Optional[list[str]], Field(description=(
        "List of hostnames for multi-endpoint queries. When provided, overrides "
        "the single 'hostname' parameter and queries all listed endpoints in parallel."
    ))] = None,
    summarize: Annotated[bool, Field(description=(
        "When True, aggregate network events by key dimensions (hostname, proxy, "
        "location, process). Default False."
    ))] = False,
    browser_filter: Annotated[str, Field(description=(
        "Filter to a specific browser: 'chrome', 'edge', 'firefox', 'brave', "
        "'opera', or '*' for all. Default '*'."
    ))] = "*",
    limit: Annotated[int, Field(description=(
        "Max XQL results per query. Capped at 500. Default 50."
    ))] = 50,
) -> str:
    """Investigate browser activity on an endpoint.

    Supports three modes:

    **history mode** (default): Collects browsing history, download history, or both
    from the target endpoint by running the History_Script_Library script via the
    XDR Agent Script Library. The endpoint must be online. When ``output_file_path``
    is provided, the full untruncated output is also saved to a local file.
    Supports ``browser_filter`` to target a specific browser.

    **investigate mode**: Runs both browser history collection and browser network
    activity search (XQL) concurrently, then correlates entries by timestamp
    proximity within ``tolerance_seconds``. Returns a unified timeline where each
    entry shows user intent (URL, visit type, referrer) alongside network context
    (proxy usage, remote IP, on/off-network status). Includes DNS enrichment
    (bare-IP events resolved to hostnames via XDR DNS telemetry), download
    correlation (downloads matched to network events when ``history_mode`` is
    ``'downloads'`` or ``'both'``), and optional aggregation (``summarize=True``).
    Gracefully degrades if one data source is unavailable.

    **network mode**: Queries the XDR data lake for browser network connections
    without collecting browser history. Returns enriched network events with proxy
    detection, network location metadata, and DNS enrichment. Does not require the
    endpoint to be online. Supports ``summarize=True`` for aggregated output.

    All modes support multi-endpoint parallel queries via ``hostnames``,
    process-aware browser filtering via ``browser_filter``, and configurable
    XQL result limits via ``limit``.

    Args:
        ctx: The FastMCP context.
        hostname: The hostname of the target endpoint.
        mode: ``'history'``, ``'investigate'``, or ``'network'``.
        indicator: Domain/IP/URL to filter on. Optional in all modes.
        timeframe_from: Optional start of search window.
        timeframe_to: Optional end of search window.
        tolerance_seconds: Correlation window in seconds (investigate mode only).
        timeout: Max wait time in seconds for data collection.
        history_mode: ``'history'``, ``'downloads'``, or ``'both'``.
        output_file_path: File path to save full output (history mode only).
        hostnames: List of hostnames for multi-endpoint parallel queries.
            When provided, overrides ``hostname``.
        summarize: When True, aggregate network events by key dimensions.
        browser_filter: Filter to a specific browser (``'chrome'``, ``'edge'``,
            ``'firefox'``, ``'brave'``, ``'opera'``, or ``'*'`` for all).
        limit: Max XQL results per query. Capped at 500.

    Returns:
        JSON response with browser history (history mode), a correlated
        unified timeline with summary (investigate mode), or enriched
        network events (network mode).
    """
    # ── Validate new parameters ──────────────────────────────────────
    warnings: list[str] = []

    # Validate hostnames
    if hostnames is not None and len(hostnames) == 0:
        return create_response(
            data={"error": "hostnames list must not be empty"},
            is_error=True,
        )

    # Validate limit
    if limit < 1:
        return create_response(
            data={"error": "limit must be at least 1"},
            is_error=True,
        )
    effective_limit, limit_warning = _cap_limit(limit)
    if limit_warning:
        warnings.append(limit_warning)

    # Validate browser_filter
    browser_processes, bf_error = _resolve_browser_filter(browser_filter)
    if bf_error:
        return create_response(
            data={"error": bf_error},
            is_error=True,
        )

    # ── Validate mode parameter ──────────────────────────────────────
    if mode not in ("history", "investigate", "network"):
        return create_response(
            data={"error": "mode must be 'history', 'investigate', or 'network'"},
            is_error=True,
        )

    if mode == "investigate":
        try:
            fetcher = await get_fetcher(ctx)

            # ── Per-endpoint worker (shared by single and multi-endpoint) ──
            async def _investigate_single(
                ep_hostname: str,
            ) -> tuple[str, list[dict], list[dict], list[str], list[str], list[dict] | None]:
                """Run investigate logic for one endpoint.

                Returns:
                    (hostname, history_entries, network_events, data_sources, warnings, download_entries)
                """
                ep_warnings: list[str] = []
                ep_data_sources: list[str] = []
                ep_history: list[dict] = []
                ep_network: list[dict] = []

                endpoint_id, endpoint_status = await _resolve_endpoint(fetcher, ep_hostname)
                if not endpoint_id:
                    raise RuntimeError("Endpoint '{}' not found".format(ep_hostname))

                # --- History collection coroutine ---
                async def _collect_history() -> tuple[list[dict], str]:
                    """Returns (history_entries, raw_standard_output)."""
                    script_uid = await _resolve_script_uid(fetcher)
                    if not script_uid:
                        raise RuntimeError("Script 'History_Script_Library' not found in the XDR Script Library")

                    parameters = {
                        "target_user": "*",
                        "browser_filter": browser_filter,
                        "mode": history_mode,
                        "start_date": str(timeframe_from) if timeframe_from else "*",
                        "end_date": str(timeframe_to) if timeframe_to else "*",
                        "url_filter": indicator if indicator else "*",
                        "max_results": "0",
                    }

                    result = await _run_script_on_endpoint(fetcher, endpoint_id, script_uid, parameters)
                    raw_output = result.get("standard_output", "")
                    return (_parse_history_output(raw_output), raw_output)

                # --- Network activity search coroutine ---
                async def _collect_network() -> list[dict]:
                    tf_from = _to_epoch_ms(timeframe_from)
                    tf_to = _to_epoch_ms(timeframe_to)

                    browser_values = ", ".join('"{}"'.format(b) for b in browser_processes)
                    filter_clause = (
                        'agent_id = "{}" and event_type = NETWORK '
                        'and actor_process_image_name in ({})'.format(endpoint_id, browser_values)
                    )
                    if indicator:
                        filter_clause += (
                            ' and (action_external_hostname contains "{indicator}"'
                            ' or dst_action_external_hostname contains "{indicator}")'.format(indicator=indicator)
                        )

                    query = (
                        "dataset = xdr_data "
                        "| filter {} "
                        "| fields actor_process_image_name, "
                        "action_remote_ip, action_remote_port, "
                        "action_external_hostname, dst_action_external_hostname, "
                        "action_local_ip, action_local_port, "
                        "dns_query_name, event_timestamp "
                        "| limit {}".format(filter_clause, effective_limit)
                    )

                    rows = await _run_xql(fetcher, query, timeframe_from=tf_from, timeframe_to=tf_to, timeout=timeout)
                    return [_classify_connection(r) for r in rows]

                # --- DNS enrichment coroutine ---
                async def _collect_dns() -> list[dict]:
                    tf_from = _to_epoch_ms(timeframe_from)
                    tf_to = _to_epoch_ms(timeframe_to)

                    dns_query = (
                        'dataset = xdr_data '
                        '| filter agent_id = "{}" and event_type = NETWORK '
                        'and dns_query_name != null '
                        '| fields dns_query_name, action_remote_ip, event_timestamp '
                        '| limit {}'.format(endpoint_id, effective_limit)
                    )
                    return await _run_xql(fetcher, dns_query, timeframe_from=tf_from, timeframe_to=tf_to, timeout=timeout)

                # Determine which coroutines to run
                history_coro = None
                network_coro = _collect_network()

                if endpoint_status == "CONNECTED":
                    history_coro = _collect_history()
                else:
                    ep_warnings.append(
                        "Endpoint '{}' is currently {} (not connected). "
                        "Browser history collection was skipped; only network activity data is available.".format(
                            ep_hostname, endpoint_status
                        )
                    )

                # Run concurrently with graceful degradation
                ep_raw_output = ""
                if history_coro is not None:
                    history_result, network_result = await asyncio.gather(
                        history_coro, network_coro, return_exceptions=True
                    )

                    if isinstance(history_result, BaseException):
                        logger.warning("History collection failed for %s: %s", ep_hostname, history_result)
                        ep_warnings.append("Browser history collection failed: {}".format(history_result))
                    else:
                        ep_history, ep_raw_output = history_result
                        if ep_history:
                            ep_data_sources.append("browser_history")

                    if isinstance(network_result, BaseException):
                        logger.warning("Network activity search failed for %s: %s", ep_hostname, network_result)
                        ep_warnings.append("Network activity search failed: {}".format(network_result))
                    else:
                        ep_network = network_result
                        if ep_network:
                            ep_data_sources.append("network_activity")
                else:
                    try:
                        ep_network = await network_coro
                        if ep_network:
                            ep_data_sources.append("network_activity")
                    except Exception as e:
                        logger.warning("Network activity search failed for %s: %s", ep_hostname, e)
                        ep_warnings.append("Network activity search failed: {}".format(e))

                # DNS enrichment (single batch query, applied before correlation)
                if ep_network:
                    try:
                        dns_events = await _collect_dns()
                        if dns_events:
                            _enrich_dns_batch(ep_network, dns_events)
                    except Exception as e:
                        logger.warning("DNS enrichment failed for %s: %s", ep_hostname, e)
                        ep_warnings.append("DNS enrichment failed: {}".format(e))

                # Parse download entries if applicable
                ep_downloads: list[dict] | None = None
                if history_mode in ("downloads", "both") and ep_raw_output:
                    ep_downloads = _parse_download_output(ep_raw_output) or None

                return (ep_hostname, ep_history, ep_network, ep_data_sources, ep_warnings, ep_downloads)

            # ── Multi-endpoint vs single-endpoint dispatch ───────────
            if hostnames is not None:
                # Multi-endpoint: resolve all, run in parallel, merge
                resolve_results: list[tuple[str, list[dict], list[dict], list[str], list[str], list[dict] | None]] = []

                async def _safe_investigate(hn: str):
                    try:
                        return await _investigate_single(hn)
                    except Exception as e:
                        return (hn, e)

                raw_results = await asyncio.gather(
                    *[_safe_investigate(hn) for hn in hostnames]
                )

                all_data_sources: set[str] = set()
                per_endpoint_timelines: list[tuple[str, list[dict]]] = []

                for res in raw_results:
                    if isinstance(res[1], BaseException):
                        # Resolution or execution failed for this hostname
                        hn, err = res[0], res[1]
                        warnings.append("Hostname '{}' failed: {}".format(hn, err))
                        continue

                    hn, ep_history, ep_network, ep_ds, ep_warns, ep_downloads = res
                    warnings.extend(ep_warns)
                    all_data_sources.update(ep_ds)

                    if not ep_history and not ep_network:
                        warnings.append("Hostname '{}': neither data source returned results".format(hn))
                        continue

                    tolerance_ms = tolerance_seconds * 1000
                    ep_timeline = _correlate_timeline(ep_history, ep_network, tolerance_ms, download_entries=ep_downloads)
                    per_endpoint_timelines.append((hn, ep_timeline))

                if not per_endpoint_timelines:
                    return create_response(
                        data={"error": "No endpoints could be resolved", "warnings": warnings},
                        is_error=True,
                    )

                data_sources = sorted(all_data_sources)
                timeline = _merge_endpoint_timelines(per_endpoint_timelines)

                # Summarize mode: aggregate network_only entries, preserve correlated/history_only
                if summarize:
                    network_only = [e for e in timeline if e["source"] == "network_only"]
                    non_network = [e for e in timeline if e["source"] != "network_only"]
                    aggregated = _aggregate_network_events(network_only)
                    summary = _build_summary(timeline, data_sources)
                    return create_response(data={
                        "hostnames": hostnames,
                        "indicator": indicator,
                        "tolerance_seconds": tolerance_seconds,
                        "summary": summary,
                        "timeline": non_network,
                        "aggregated_network": aggregated,
                        "warnings": warnings,
                        "data_sources": data_sources,
                    })

                summary = _build_summary(timeline, data_sources)

                return create_response(data={
                    "hostnames": hostnames,
                    "indicator": indicator,
                    "tolerance_seconds": tolerance_seconds,
                    "summary": summary,
                    "timeline": timeline,
                    "warnings": warnings,
                    "data_sources": data_sources,
                })

            else:
                # Single-endpoint (original behavior)
                try:
                    _, ep_history, ep_network, ep_ds, ep_warns, ep_downloads = await _investigate_single(hostname)
                except RuntimeError as e:
                    return create_response(
                        data={"error": str(e)},
                        is_error=True,
                    )

                warnings.extend(ep_warns)
                data_sources = ep_ds

                if not ep_history and not ep_network:
                    if warnings:
                        return create_response(
                            data={"error": "Neither data source returned results", "warnings": warnings},
                            is_error=True,
                        )
                    return create_response(
                        data={"error": "Neither data source returned results"},
                        is_error=True,
                    )

                tolerance_ms = tolerance_seconds * 1000
                timeline = _correlate_timeline(ep_history, ep_network, tolerance_ms, download_entries=ep_downloads)

                # Summarize mode: aggregate network_only entries, preserve correlated/history_only
                if summarize:
                    network_only = [e for e in timeline if e["source"] == "network_only"]
                    non_network = [e for e in timeline if e["source"] != "network_only"]
                    aggregated = _aggregate_network_events(network_only)
                    summary = _build_summary(timeline, data_sources)
                    return create_response(data={
                        "hostname": hostname,
                        "indicator": indicator,
                        "tolerance_seconds": tolerance_seconds,
                        "summary": summary,
                        "timeline": non_network,
                        "aggregated_network": aggregated,
                        "warnings": warnings,
                        "data_sources": data_sources,
                    })

                summary = _build_summary(timeline, data_sources)

                return create_response(data={
                    "hostname": hostname,
                    "indicator": indicator,
                    "tolerance_seconds": tolerance_seconds,
                    "summary": summary,
                    "timeline": timeline,
                    "warnings": warnings,
                    "data_sources": data_sources,
                })

        except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
                PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
            logger.exception("PAPI error in investigate_browser_session: %s", e)
            return create_response(data={"error": str(e)}, is_error=True)
        except Exception as e:
            logger.exception("Failed to investigate browser session: %s", e)
            return create_response(data={"error": str(e)}, is_error=True)

    elif mode == "network":
        try:
            fetcher = await get_fetcher(ctx)

            # ── Per-endpoint network worker ──────────────────────────
            async def _network_single(ep_hostname: str) -> tuple[str, list[dict]]:
                """Run network query for one endpoint.

                Returns:
                    (hostname, classified_events)
                """
                endpoint_id, endpoint_status = await _resolve_endpoint(fetcher, ep_hostname)
                if not endpoint_id:
                    raise RuntimeError("Endpoint '{}' not found".format(ep_hostname))

                browser_values = ", ".join('"{}"'.format(b) for b in browser_processes)
                filter_clause = (
                    'agent_id = "{}" and event_type = NETWORK '
                    'and actor_process_image_name in ({})'.format(endpoint_id, browser_values)
                )
                if indicator:
                    filter_clause += (
                        ' and (action_external_hostname contains "{indicator}"'
                        ' or dst_action_external_hostname contains "{indicator}")'.format(indicator=indicator)
                    )

                query = (
                    "dataset = xdr_data "
                    "| filter {} "
                    "| fields actor_process_image_name, "
                    "action_remote_ip, action_remote_port, "
                    "action_external_hostname, dst_action_external_hostname, "
                    "action_local_ip, action_local_port, "
                    "dns_query_name, event_timestamp "
                    "| limit {}".format(filter_clause, effective_limit)
                )

                tf_from = _to_epoch_ms(timeframe_from)
                tf_to = _to_epoch_ms(timeframe_to)

                rows = await _run_xql(
                    fetcher, query,
                    timeframe_from=tf_from,
                    timeframe_to=tf_to,
                    timeout=timeout,
                )
                classified = [_classify_connection(r) for r in rows]

                # DNS enrichment (single batch query)
                try:
                    dns_query = (
                        'dataset = xdr_data '
                        '| filter agent_id = "{}" and event_type = NETWORK '
                        'and dns_query_name != null '
                        '| fields dns_query_name, action_remote_ip, event_timestamp '
                        '| limit {}'.format(endpoint_id, effective_limit)
                    )
                    dns_events = await _run_xql(
                        fetcher, dns_query,
                        timeframe_from=tf_from,
                        timeframe_to=tf_to,
                        timeout=timeout,
                    )
                    if dns_events:
                        _enrich_dns_batch(classified, dns_events)
                except Exception as e:
                    logger.warning("DNS enrichment failed for %s: %s", ep_hostname, e)

                return (ep_hostname, classified)

            if hostnames is not None:
                # Multi-endpoint network mode
                async def _safe_network(hn: str):
                    try:
                        return await _network_single(hn)
                    except Exception as e:
                        return (hn, e)

                raw_results = await asyncio.gather(
                    *[_safe_network(hn) for hn in hostnames]
                )

                per_endpoint_events: list[tuple[str, list[dict]]] = []
                for res in raw_results:
                    if isinstance(res[1], BaseException):
                        hn, err = res[0], res[1]
                        warnings.append("Hostname '{}' failed: {}".format(hn, err))
                        continue
                    hn, events = res
                    per_endpoint_events.append((hn, events))

                if not per_endpoint_events:
                    return create_response(
                        data={"error": "No endpoints could be resolved", "warnings": warnings},
                        is_error=True,
                    )

                merged_events = _merge_endpoint_results(per_endpoint_events)

                # Summarize mode: aggregate all network events
                if summarize:
                    aggregated = _aggregate_network_events(merged_events)
                    return create_response(data={
                        "hostnames": hostnames,
                        "indicator": indicator,
                        "mode": "network",
                        "aggregated_network": aggregated,
                        "total_events": len(merged_events),
                        "warnings": warnings,
                    })

                return create_response(data={
                    "hostnames": hostnames,
                    "indicator": indicator,
                    "mode": "network",
                    "network_events": merged_events,
                    "total_events": len(merged_events),
                    "warnings": warnings,
                })

            else:
                # Single-endpoint network mode
                _, enriched = await _network_single(hostname)

                # Summarize mode: aggregate all network events
                if summarize:
                    aggregated = _aggregate_network_events(enriched)
                    return create_response(data={
                        "hostname": hostname,
                        "indicator": indicator,
                        "mode": "network",
                        "aggregated_network": aggregated,
                        "total_events": len(enriched),
                        "warnings": warnings,
                    })

                return create_response(data={
                    "hostname": hostname,
                    "indicator": indicator,
                    "mode": "network",
                    "network_events": enriched,
                    "total_events": len(enriched),
                    "warnings": warnings,
                })

        except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
                PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
            logger.exception("PAPI error in investigate_browser_session: %s", e)
            return create_response(data={"error": str(e)}, is_error=True)
        except Exception as e:
            logger.exception("Failed to investigate browser session: %s", e)
            return create_response(data={"error": str(e)}, is_error=True)

    # ── History mode ─────────────────────────────────────────────────
    try:
        fetcher = await get_fetcher(ctx)

        # Resolve hostname to endpoint_id and check connectivity
        endpoint_id, endpoint_status = await _resolve_endpoint(fetcher, hostname)
        if not endpoint_id:
            return create_response(
                data={"error": "Endpoint '{}' not found".format(hostname)},
                is_error=True,
            )

        # Resolve script UID from the Script Library
        script_uid = await _resolve_script_uid(fetcher)
        if not script_uid:
            return create_response(
                data={"error": "Script 'History_Script_Library' not found in the XDR Script Library"},
                is_error=True,
            )

        # Build script parameters
        parameters = {
            "target_user": "*",
            "browser_filter": browser_filter,
            "mode": history_mode,
            "start_date": str(timeframe_from) if timeframe_from else "*",
            "end_date": str(timeframe_to) if timeframe_to else "*",
            "url_filter": indicator if indicator else "*",
            "max_results": "0",
        }

        # If endpoint is not connected, queue the script and return immediately
        if endpoint_status != "CONNECTED":
            start_payload = {
                "request_data": {
                    "script_uid": script_uid,
                    "timeout": 600,
                    "filters": [
                        {"field": "endpoint_id_list", "operator": "in", "value": [endpoint_id]}
                    ],
                    "parameters_values": parameters,
                }
            }
            start_resp = await fetcher.send_request("scripts/run_script/", data=start_payload)
            action_id = start_resp.get("reply", {}).get("action_id")

            return create_response(data={
                "hostname": hostname,
                "endpoint_id": endpoint_id,
                "endpoint_status": endpoint_status,
                "history_mode": history_mode,
                "script_status": "queued_pending_connection",
                "action_id": action_id,
                "standard_output": "",
                "error": None,
                "message": (
                    "Endpoint '{}' is currently {} (not connected). "
                    "The script has been queued (action_id: {}) and will execute "
                    "when the endpoint reconnects. Use get_action_status to check "
                    "progress later."
                ).format(hostname, endpoint_status, action_id),
            })

        # Endpoint is connected — execute and wait for results
        result = await _run_script_on_endpoint(fetcher, endpoint_id, script_uid, parameters)

        # Build the response
        response_data = {
            "hostname": hostname,
            "endpoint_id": endpoint_id,
            "history_mode": history_mode,
            "script_status": result.get("status"),
            "action_id": result.get("action_id"),
            "standard_output": result.get("standard_output", ""),
            "return_value": result.get("return_value", ""),
            "error": result.get("error"),
        }

        # If output_file_path is set, download the full result files
        if output_file_path and result.get("action_id"):
            try:
                file_size = await _download_result_files(
                    fetcher, result["action_id"], endpoint_id, output_file_path
                )
                response_data["output_file_path"] = output_file_path
                response_data["output_file_size_bytes"] = file_size
                response_data["output_file_message"] = "Full output written to {}".format(output_file_path)
            except Exception as e:
                logger.warning(
                    "Failed to download result files for action %s: %s. "
                    "Returning standard_output only.",
                    result.get("action_id"), e,
                )
                response_data["output_file_error"] = (
                    "Failed to download full result files: {}. "
                    "The standard_output above is still available but may be truncated."
                ).format(e)

        return create_response(data=response_data)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception("PAPI error in investigate_browser_session: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("Failed to investigate browser session: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


class BrowserSessionModule(BaseModule):
    """Module for unified browser investigation combining history and network activity."""

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)

    def register_tools(self):
        self._add_tool(investigate_browser_session)

    def register_resources(self):
        pass
