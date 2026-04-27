"""
DEPRECATED: This tool has been replaced by investigate_browser_session (in browser_session.py).

Tool: search_browser_activity

Search for browser network connections on a specific endpoint to understand
what websites a user visited, whether traffic went through the corporate
proxy or directly, and whether the user was on-network or off-network.

This tool addresses a common investigation gap: determining browsing context
around an IOC hit without writing raw XQL.
"""

import logging
from typing import Annotated, Optional, Union

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
from usecase.custom_components.xql_helpers import _run_xql, _to_epoch_ms
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

_MAX_ROWS = 50

_BROWSER_PROCESSES = (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe",
)

# Common corporate proxy indicators — internal IPs on typical proxy ports
_PROXY_PORTS = {8080, 3128, 8443, 9090}


def _is_internal_ip(ip: str) -> bool:
    """Check if an IP is in a private/internal range (RFC 1918)."""
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    # 10.0.0.0/8
    if first == 10:
        return True
    # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if first == 172 and 16 <= second <= 31:
        return True
    # 192.168.0.0/16
    if first == 192 and second == 168:
        return True
    # 127.0.0.0/8 (loopback)
    if first == 127:
        return True
    return False


def _classify_connection(event: dict) -> dict:
    """Add proxy and network location classification to a connection event."""
    remote_ip = event.get("action_remote_ip", "")
    remote_port = event.get("action_remote_port")
    local_ip = event.get("action_local_ip", "")

    # Proxy detection: remote IP is internal AND on a known proxy port
    through_proxy = (
        _is_internal_ip(remote_ip)
        and remote_port in _PROXY_PORTS
    )

    # Network location: local IP in 10.x.x.x = corporate, 192.168.x.x = likely home/VPN
    if local_ip.startswith("10."):
        network_location = "corporate"
    elif local_ip.startswith("192.168.") or local_ip.startswith("172.16."):
        network_location = "off-network (home/VPN)"
    else:
        network_location = "unknown"

    event["_through_proxy"] = through_proxy
    event["_network_location"] = network_location
    return event


async def search_browser_activity(
    ctx: Context,
    agent_id: Annotated[str, Field(description=(
        "The endpoint agent_id to search browser connections on. "
        "Get this from get_incidents, get_filtered_endpoints, or alert details."
    ))],
    hostname_filter: Annotated[Optional[str], Field(description=(
        "Filter connections to a specific external hostname (contains match). "
        "Example: 'portableapps.com', 'myexternalip'. "
        "Optional — if omitted, returns all browser connections."
    ))] = None,
    timeframe_from: Annotated[Optional[Union[int, str]], Field(description=(
        "Start of search window. Accepts epoch ms (int) or ISO 8601 string "
        "(e.g. '2026-04-09'). Optional."
    ))] = None,
    timeframe_to: Annotated[Optional[Union[int, str]], Field(description=(
        "End of search window. Accepts epoch ms (int) or ISO 8601 string. Optional."
    ))] = None,
    limit: Annotated[int, Field(
        description="Max results to return. Default 30, max 50.",
        default=30,
    )] = 30,
    timeout: Annotated[int, Field(
        description="Max seconds to wait for query results. Default 30. Increase to 120 for wide timeframe queries.",
        default=30,
    )] = 30,
) -> str:
    """
    Search for browser network connections on a specific endpoint.

    Returns all network connections made by browser processes (Chrome, Edge, Firefox, etc.)
    with automatic classification of:
    - Whether each connection went through the corporate proxy or directly
    - Whether the user was on the corporate network or off-network (home/VPN)
    - The destination hostname, IP, and port

    Use this tool when:
    - Investigating IOC incidents to understand browsing context
    - Checking if a user visited a specific domain directly or via proxy
    - Determining if a user was on-network or off-network during an incident
    - Building a timeline of websites visited around an alert

    The tool automatically detects proxy usage by checking if the remote IP is
    an internal address on a common proxy port (8080, 3128, 8443, 9090).

    Args:
        ctx: The FastMCP context.
        agent_id: The endpoint agent_id to search.
        hostname_filter: Optional hostname filter (contains match).
        timeframe_from: Optional start of search window.
        timeframe_to: Optional end of search window.
        limit: Max results. Default 30, max 50.

    Returns:
        JSON with browser connections, each annotated with proxy status and network location.
        Includes a summary with unique hostnames visited and proxy/direct breakdown.
    """
    try:
        fetcher = await get_fetcher(ctx)
        tf_from = _to_epoch_ms(timeframe_from)
        tf_to = _to_epoch_ms(timeframe_to)

        browser_values = ", ".join(f'"{b}"' for b in _BROWSER_PROCESSES)
        filter_clause = (
            f'agent_id = "{agent_id}" and event_type = NETWORK '
            f"and actor_process_image_name in ({browser_values})"
        )
        if hostname_filter:
            filter_clause += (
                f' and (action_external_hostname contains "{hostname_filter}"'
                f' or dst_action_external_hostname contains "{hostname_filter}")'
            )

        capped = min(limit, _MAX_ROWS)
        query = (
            f"dataset = xdr_data "
            f"| filter {filter_clause} "
            f"| fields actor_process_image_name, "
            f"action_remote_ip, action_remote_port, "
            f"action_external_hostname, dst_action_external_hostname, "
            f"action_local_ip, action_local_port, "
            f"dns_query_name, event_timestamp "
            f"| limit {capped}"
        )

        rows = await _run_xql(fetcher, query, timeframe_from=tf_from, timeframe_to=tf_to, timeout=timeout)

        # Classify each connection
        classified = [_classify_connection(r) for r in rows]

        # Build summary
        hostnames = set()
        proxy_count = 0
        direct_count = 0
        for r in classified:
            hostname = r.get("action_external_hostname") or r.get("dst_action_external_hostname")
            if hostname:
                hostnames.add(hostname)
            if r.get("_through_proxy"):
                proxy_count += 1
            else:
                direct_count += 1

        # Determine user's network location from the most common local IP
        local_ips = [r.get("action_local_ip", "") for r in classified if r.get("action_local_ip")]
        network_location = "unknown"
        if local_ips:
            most_common_ip = max(set(local_ips), key=local_ips.count)
            if most_common_ip.startswith("10."):
                network_location = "corporate"
            elif most_common_ip.startswith("192.168.") or most_common_ip.startswith("172.16."):
                network_location = "off-network (home/VPN)"

        summary = {
            "total_connections": len(classified),
            "unique_hostnames": sorted(hostnames),
            "connections_through_proxy": proxy_count,
            "direct_connections": direct_count,
            "user_network_location": network_location,
        }

        return create_response(data={
            "agent_id": agent_id,
            "hostname_filter": hostname_filter,
            "summary": summary,
            "capped_at": capped,
            "connections": classified,
        })

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error in search_browser_activity: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to search browser activity: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class BrowserActivityModule(BaseModule):
    """Module for searching browser network connections with proxy/location classification.

    Note: The search_browser_activity tool has been replaced by
    investigate_browser_session (in browser_session.py) which provides a unified
    interface for both history retrieval and correlated investigation.
    The helper functions (_classify_connection, _is_internal_ip) are still used
    by the new tool.
    """

    def register_tools(self):
        # Tool removed — replaced by investigate_browser_session
        pass

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
