"""Tool: search_user_activity

Search for all alert activity associated with a specific user across all endpoints.
Supports summary mode (aggregated statistics) and detail mode (paginated alert details).
"""

import logging
from typing import Annotated, Optional

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
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)


# Compact field set for summary mode — minimal per-alert footprint
_SUMMARY_ALERT_FIELDS = {
    "alert_id", "name", "severity", "category", "source",
    "action_pretty", "detection_timestamp", "host_name", "endpoint_id",
    "resolution_status",
}

# Richer field set for detail mode — still bounded by page_size
_DETAIL_ALERT_FIELDS = {
    "alert_id", "external_id", "name", "description", "severity", "category",
    "source", "action", "action_pretty", "resolution_status",
    "detection_timestamp", "last_modified_ts",
    "case_id", "endpoint_id", "host_name", "host_ip",
    "agent_os_type",
    "mitre_technique_id_and_name", "mitre_tactic_id_and_name",
    "bioc_category_enum_key",
    "tags",
    "events",
}

_EVENT_KEEP = {
    "event_id", "event_type", "event_sub_type", "event_timestamp",
    "actor_process_image_name", "actor_process_command_line",
    "actor_process_image_sha256",
    "causality_actor_process_image_name",
    "action_remote_ip", "action_remote_port",
    "action_external_hostname", "dns_query_name",
    "action_file_path", "action_file_name", "action_file_sha256",
    "user_name",
}


def _strip_empty(obj):
    """Recursively remove keys with None, empty string, or empty list values."""
    if isinstance(obj, dict):
        return {k: _strip_empty(v) for k, v in obj.items() if v is not None and v != "" and v != []}
    if isinstance(obj, list):
        return [_strip_empty(i) for i in obj if i is not None and i != "" and i != []]
    return obj


async def search_user_activity(
    ctx: Context,
    username: Annotated[str, Field(description=(
        "The username to search for (e.g. 'JUSTICE\\\\ShiraIc' or just 'ShiraIc'). "
        "The search is case-insensitive and matches partial usernames. "
        "Use the DOMAIN\\\\user format for exact matching."
    ))],
    mode: Annotated[str, Field(description=(
        "Response mode. "
        "'summary' (default): Returns aggregated counts by severity, category, host, and case — "
        "lightweight, safe for large result sets, ideal as a first call. "
        "'detail': Returns full alert details with events, paginated by page_size. "
        "Always start with 'summary' to understand the scope before using 'detail'."
    ))] = "summary",
    timeframe_from: Annotated[Optional[int], Field(description=(
        "Start of time range as epoch milliseconds. Optional."
    ))] = None,
    timeframe_to: Annotated[Optional[int], Field(description=(
        "End of time range as epoch milliseconds. Optional."
    ))] = None,
    severity: Annotated[Optional[list[str]], Field(description=(
        "Filter by severity: 'low', 'medium', 'high', 'critical'. Optional."
    ))] = None,
    page_size: Annotated[int, Field(description=(
        "Max alerts to return per call. Default 10 for detail mode, ignored for summary mode. "
        "Use search_from to paginate."
    ), default=10)] = 10,
    search_from: Annotated[int, Field(description="Pagination offset. Default 0.", default=0)] = 0,
) -> str:
    """
    Search for all alert activity associated with a specific user across all endpoints.

    IMPORTANT — Context window management:
    This tool has two modes to prevent context overflow:

    1. 'summary' mode (default, always use first):
       Returns ONLY aggregated statistics — no individual alert details.
       Includes: total alert count, breakdown by severity, by category, by host,
       by case ID, and time range of activity. This is safe even if the user
       has thousands of alerts.

    2. 'detail' mode (use after summary to drill down):
       Returns individual alerts with events, paginated by page_size (default 10).
       Use search_from to paginate through results.
       Combine with severity/timeframe filters to narrow scope.

    Typical workflow:
    1. Call with mode='summary' to see the scope
    2. Call with mode='detail' + severity=['high','critical'] to see the important ones
    3. Paginate with search_from if needed

    Args:
        ctx: The FastMCP context.
        username: Username to search (e.g. 'JUSTICE\\ShiraIc' or 'ShiraIc').
        mode: 'summary' (default) or 'detail'.
        timeframe_from: Optional start of time range (epoch ms).
        timeframe_to: Optional end of time range (epoch ms).
        severity: Optional severity filter.
        page_size: Max alerts for detail mode. Default 10.
        search_from: Pagination offset. Default 0.

    Returns:
        In summary mode: aggregated statistics about the user's alert activity.
        In detail mode: paginated alert details with events.
    """
    try:
        fetcher = await get_fetcher(ctx)

        # Build filters — we fetch a broad set and filter by username client-side
        # because the alerts API doesn't support direct username filtering
        filters = []
        if timeframe_from is not None:
            filters.append({"field": "creation_time", "operator": "gte", "value": timeframe_from})
        if timeframe_to is not None:
            filters.append({"field": "creation_time", "operator": "lte", "value": timeframe_to})
        if severity:
            filters.append({"field": "severity", "operator": "in", "value": severity})

        username_lower = username.lower()

        if mode == "summary":
            # Scan through alerts in batches to build reliable statistics
            # instead of only checking the first 100
            max_scan = 500
            batch_size = 100
            scanned = 0
            total_count = 0
            user_alerts = []

            while scanned < max_scan:
                payload = {
                    "request_data": {
                        "search_from": scanned,
                        "search_to": scanned + batch_size,
                    }
                }
                if filters:
                    payload["request_data"]["filters"] = filters

                response_data = await fetcher.send_request("/alerts/get_alerts_multi_events", data=payload)
                batch_alerts = response_data.get("reply", {}).get("alerts", [])
                total_count = response_data.get("reply", {}).get("total_count", total_count)

                if not batch_alerts:
                    break

                for alert in batch_alerts:
                    events = alert.get("events", [])
                    for event in events:
                        event_user = (event.get("user_name") or "").lower()
                        if username_lower in event_user:
                            user_alerts.append(alert)
                            break

                scanned += len(batch_alerts)

                # Stop early if we've scanned everything
                if scanned >= total_count:
                    break

        else:
            # Detail mode — single paginated fetch, then filter
            payload = {
                "request_data": {
                    "search_from": search_from,
                    "search_to": search_from + page_size + 50,  # fetch extra to account for filtering
                }
            }
            if filters:
                payload["request_data"]["filters"] = filters

            response_data = await fetcher.send_request("/alerts/get_alerts_multi_events", data=payload)
            all_alerts = response_data.get("reply", {}).get("alerts", [])
            total_count = response_data.get("reply", {}).get("total_count", 0)
            scanned = len(all_alerts)

            user_alerts = []
            for alert in all_alerts:
                events = alert.get("events", [])
                for event in events:
                    event_user = (event.get("user_name") or "").lower()
                    if username_lower in event_user:
                        user_alerts.append(alert)
                        break
                if len(user_alerts) >= page_size:
                    break

        if mode == "summary":
            # Build aggregated statistics — lightweight output
            severity_counts: dict[str, int] = {}
            category_counts: dict[str, int] = {}
            host_counts: dict[str, int] = {}
            case_counts: dict[str, int] = {}
            timestamps = []

            for alert in user_alerts:
                sev = alert.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

                cat = alert.get("category", "unknown")
                category_counts[cat] = category_counts.get(cat, 0) + 1

                host = alert.get("host_name", "unknown")
                host_counts[host] = host_counts.get(host, 0) + 1

                case_id = alert.get("case_id")
                if case_id:
                    case_key = str(case_id)
                    case_counts[case_key] = case_counts.get(case_key, 0) + 1

                ts = alert.get("detection_timestamp")
                if ts:
                    timestamps.append(ts)

            result = {
                "username": username,
                "mode": "summary",
                "total_alerts_matched": len(user_alerts),
                "total_alerts_scanned": scanned,
                "note": (
                    f"Scanned {scanned} of {total_count} total alerts in the system. "
                    "Apply timeframe and severity filters to narrow scope if needed."
                ) if total_count > scanned else None,
                "by_severity": severity_counts,
                "by_category": category_counts,
                "by_host": host_counts,
                "by_case_id": case_counts if case_counts else None,
                "time_range": {
                    "earliest": min(timestamps) if timestamps else None,
                    "latest": max(timestamps) if timestamps else None,
                } if timestamps else None,
            }
            # Clean nulls
            result = {k: v for k, v in result.items() if v is not None}
            return create_response(data=result)

        else:
            # Detail mode — return individual alerts with events, cleaned up
            cleaned_alerts = []
            for alert in user_alerts:
                filtered = {k: v for k, v in alert.items() if k in _DETAIL_ALERT_FIELDS}
                if isinstance(filtered.get("events"), list):
                    filtered["events"] = [
                        {k: v for k, v in event.items() if k in _EVENT_KEEP}
                        for event in filtered["events"][:3]
                    ]
                cleaned_alerts.append(_strip_empty(filtered))

            result = {
                "username": username,
                "mode": "detail",
                "alerts_returned": len(cleaned_alerts),
                "search_from": search_from,
                "alerts": cleaned_alerts,
            }
            return create_response(data=result)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while searching user activity: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to search user activity: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class UserActivityModule(BaseModule):
    """Module for searching alert activity by username with summary/detail modes."""

    def register_tools(self):
        self._add_tool(search_user_activity)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
