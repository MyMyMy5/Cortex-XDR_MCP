"""Tool: search_alerts_by_host

Search for all alerts on a specific host, optionally filtered by time range and
severity. Resolves hostname to endpoint_id internally, then fetches and filters
alerts from the Cortex XDR alerts API.
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


# Same field sets as issues.py for consistency
_ALERT_KEEP = {
    "alert_id", "external_id", "alert_domain", "name", "description", "category",
    "severity", "source", "action", "action_pretty", "resolution_status", "resolution_comment",
    "alert_type", "detection_timestamp", "local_insert_ts", "last_modified_ts",
    "case_id", "endpoint_id", "host_name", "host_ip",
    "agent_os_type", "agent_os_sub_type",
    "mitre_technique_id_and_name", "mitre_tactic_id_and_name",
    "matching_service_rule_id", "matching_status",
    "bioc_category_enum_key",
    "tags", "original_tags",
    "is_whitelisted", "starred",
    "events",
}

_EVENT_KEEP = {
    "event_id", "event_type", "event_sub_type", "event_timestamp",
    "actor_process_image_name", "actor_process_image_path", "actor_process_command_line",
    "actor_process_image_sha256", "actor_process_signature_status", "actor_process_signature_vendor",
    "actor_process_os_pid",
    "causality_actor_process_image_name", "causality_actor_process_command_line",
    "causality_actor_process_image_path", "causality_actor_process_image_sha256",
    "os_actor_process_image_name", "os_actor_process_command_line", "os_actor_process_os_pid",
    "action_local_ip", "action_local_port",
    "action_remote_ip", "action_remote_port",
    "action_external_hostname", "action_country",
    "dns_query_name", "dst_action_external_hostname", "dst_action_country", "dst_action_external_port",
    "action_file_path", "action_file_name", "action_file_sha256",
    "fw_app_id",
    "user_name", "identity_type",
    "cloud_provider",
}


def _strip_empty(obj):
    """Recursively remove keys with None, empty string, or empty list values."""
    if isinstance(obj, dict):
        return {k: _strip_empty(v) for k, v in obj.items() if v is not None and v != "" and v != []}
    if isinstance(obj, list):
        return [_strip_empty(i) for i in obj if i is not None and i != "" and i != []]
    return obj


async def search_alerts_by_host(
    ctx: Context,
    hostname: Annotated[str, Field(description=(
        "The hostname to search alerts for (e.g. 'LAP-108803'). "
        "Case-insensitive — the tool will search for the exact hostname."
    ))],
    timeframe_from: Annotated[Optional[int], Field(description=(
        "Start of time range as epoch milliseconds. "
        "Use detection_timestamp or creation_time values from incidents/cases. "
        "Optional — if omitted, returns alerts from all time."
    ))] = None,
    timeframe_to: Annotated[Optional[int], Field(description=(
        "End of time range as epoch milliseconds. "
        "Optional — if omitted, returns alerts up to now."
    ))] = None,
    severity: Annotated[Optional[list[str]], Field(description=(
        "Filter by severity. Allowed values: 'low', 'medium', 'high', 'critical'. "
        "Pass as a list, e.g. ['high', 'critical']. Optional — if omitted, returns all severities."
    ))] = None,
    search_from: Annotated[int, Field(description="Pagination start offset. Default 0.", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end offset. Default 20.", default=20)] = 20,
) -> str:
    """
    Search for all alerts on a specific host, optionally filtered by time range and severity.

    This is a convenience tool that eliminates the need to manually look up endpoint IDs
    or construct complex filter chains. Just provide a hostname and get all alerts.

    Use this tool when:
    - You want to see all alerts for a specific machine during an investigation
    - You're checking if a host has other suspicious activity beyond the current incident
    - You need a quick host-level alert timeline

    The tool resolves the hostname to an endpoint_id internally, then fetches all matching alerts.

    Args:
        ctx: The FastMCP context.
        hostname: The hostname to search (e.g. 'LAP-108803').
        timeframe_from: Optional start of time range (epoch ms).
        timeframe_to: Optional end of time range (epoch ms).
        severity: Optional severity filter (list of strings).
        search_from: Pagination start. Default 0.
        search_to: Pagination end. Default 20.

    Returns:
        JSON response with all alerts for the host, including event details.
    """
    try:
        fetcher = await get_fetcher(ctx)

        # Step 1: Resolve hostname to endpoint_id
        endpoint_payload = {
            "request_data": {
                "filters": [{"field": "hostname", "operator": "in", "value": [hostname]}],
                "search_from": 0,
                "search_to": 5,
            }
        }
        endpoint_response = await fetcher.send_request("endpoints/get_endpoint/", data=endpoint_payload)
        endpoints = endpoint_response.get("reply", {}).get("endpoints", [])

        if not endpoints:
            return create_response(
                data={"error": f"No endpoint found with hostname '{hostname}'"},
                is_error=True,
            )

        endpoint_ids = [ep["endpoint_id"] for ep in endpoints if ep.get("endpoint_id")]

        # Step 2: Build alert filters.
        # The get_alerts_multi_events API does NOT support endpoint_id_list as a filter.
        # We apply time/severity filters server-side, then filter by endpoint_id client-side.
        filters = []

        # Time range filters
        if timeframe_from is not None:
            filters.append({"field": "creation_time", "operator": "gte", "value": timeframe_from})
        if timeframe_to is not None:
            filters.append({"field": "creation_time", "operator": "lte", "value": timeframe_to})

        # Severity filter
        if severity:
            filters.append({"field": "severity", "operator": "in", "value": severity})

        # Step 3: Fetch alerts in batches and filter by endpoint_id client-side.
        # We over-fetch to account for alerts on other endpoints being filtered out.
        endpoint_id_set = set(endpoint_ids)
        cleaned_alerts = []
        total_scanned = 0
        total_count = 0
        batch_size = 100
        max_scan = 500  # Safety cap to avoid scanning the entire alert database

        while total_scanned < max_scan and len(cleaned_alerts) < search_to:
            alert_payload = {
                "request_data": {
                    "search_from": total_scanned,
                    "search_to": total_scanned + batch_size,
                }
            }
            if filters:
                alert_payload["request_data"]["filters"] = filters

            response_data = await fetcher.send_request("/alerts/get_alerts_multi_events", data=alert_payload)
            batch_alerts = response_data.get("reply", {}).get("alerts", [])
            total_count = response_data.get("reply", {}).get("total_count", total_count)

            if not batch_alerts:
                break

            for alert in batch_alerts:
                if alert.get("endpoint_id") in endpoint_id_set:
                    filtered_alert = {k: v for k, v in alert.items() if k in _ALERT_KEEP}
                    if isinstance(filtered_alert.get("events"), list):
                        filtered_alert["events"] = [
                            {k: v for k, v in event.items() if k in _EVENT_KEEP}
                            for event in filtered_alert["events"][:3]
                        ]
                    cleaned_alerts.append(_strip_empty(filtered_alert))

            total_scanned += len(batch_alerts)

            # Stop if we've scanned everything
            if total_scanned >= total_count:
                break

        # Apply pagination: return only the requested slice
        paged_alerts = cleaned_alerts[search_from:search_to]
        total_for_host = len(cleaned_alerts)

        result = {
            "hostname": hostname,
            "endpoint_ids": endpoint_ids,
            "total_alerts_returned": len(paged_alerts),
            "total_alerts_for_host": total_for_host,
            "has_more": total_for_host > search_to,
            "next_page_from": search_to if total_for_host > search_to else None,
            "alerts_scanned": total_scanned,
            "alerts": paged_alerts,
        }

        return create_response(data=result)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while searching alerts by host: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to search alerts by host: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class SearchAlertsByHostModule(BaseModule):
    """Module for searching alerts by hostname with optional time and severity filters."""

    def register_tools(self):
        self._add_tool(search_alerts_by_host)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
