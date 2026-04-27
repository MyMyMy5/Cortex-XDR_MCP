"""Tool: get_alert_details

Retrieve the full details of a single alert including ALL events (no truncation).
Unlike get_issues which caps events at 3 per alert, this tool returns every event
for deep-dive forensic analysis.
"""

import logging
from typing import Annotated

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


# Keep all investigatively relevant fields — no truncation on events
_ALERT_KEEP = {
    "alert_id", "external_id", "alert_domain", "name", "description", "category",
    "severity", "source", "action", "action_pretty", "resolution_status", "resolution_comment",
    "alert_type", "detection_timestamp", "local_insert_ts", "last_modified_ts",
    "case_id", "endpoint_id", "host_name", "host_ip", "mac_addresses",
    "agent_os_type", "agent_os_sub_type", "agent_version",
    "mitre_technique_id_and_name", "mitre_tactic_id_and_name",
    "matching_service_rule_id", "matching_status",
    "bioc_indicator", "bioc_category_enum_key",
    "tags", "original_tags", "malicious_urls",
    "is_whitelisted", "starred", "is_pcap",
    "dynamic_fields", "events",
}

_EVENT_KEEP = {
    "event_id", "event_type", "event_sub_type", "event_timestamp",
    "actor_process_image_name", "actor_process_image_path", "actor_process_command_line",
    "actor_process_image_sha256", "actor_process_signature_status", "actor_process_signature_vendor",
    "actor_process_os_pid",
    "causality_actor_process_image_name", "causality_actor_process_command_line",
    "causality_actor_process_image_path", "causality_actor_process_image_sha256",
    "causality_actor_process_signature_status", "causality_actor_process_signature_vendor",
    "os_actor_effective_username", "os_actor_process_image_name",
    "os_actor_process_command_line", "os_actor_process_os_pid",
    "action_local_ip", "action_local_port",
    "action_remote_ip", "action_remote_port",
    "action_external_hostname", "action_country",
    "dns_query_name", "dst_action_external_hostname", "dst_action_country", "dst_action_external_port",
    "action_file_path", "action_file_name", "action_file_sha256", "action_file_md5",
    "action_registry_full_key", "action_registry_value_name", "action_registry_data",
    "fw_url_domain", "fw_rule", "fw_app_id", "fw_email_subject", "fw_email_sender", "fw_email_recipient",
    "user_name", "user_agent", "identity_type", "identity_sub_type",
    "cloud_provider", "project", "resource_type", "operation_name",
    "container_name", "namespace", "cluster_name",
}


def _strip_empty(obj):
    """Recursively remove keys with None, empty string, or empty list values."""
    if isinstance(obj, dict):
        return {k: _strip_empty(v) for k, v in obj.items() if v is not None and v != "" and v != []}
    if isinstance(obj, list):
        return [_strip_empty(i) for i in obj if i is not None and i != "" and i != []]
    return obj


async def get_alert_details(
    ctx: Context,
    alert_id: Annotated[int, Field(description="The alert ID to retrieve full details for (integer, e.g. 3330508).")],
) -> str:
    """
    Retrieve the full details of a single alert including ALL events (no truncation).

    Unlike get_issues which caps events at 3 per alert for bulk retrieval, this tool
    returns every event associated with the alert. Use this for deep-dive analysis
    of a specific alert when you need the complete event chain.

    Use this tool when:
    - You need to see ALL events for an alert (not just the first 3)
    - You want the full causality chain and process tree for a single alert
    - You're doing deep forensic analysis on one specific detection

    Args:
        ctx: The FastMCP context.
        alert_id: The alert ID (integer). Get alert IDs from get_issues or get_cases.

    Returns:
        JSON response containing the full alert with all events, process details,
        network connections, and file activity.
    """
    payload = {
        "request_data": {
            "filters": [
                {"field": "alert_id_list", "operator": "in", "value": [alert_id]}
            ],
            "search_from": 0,
            "search_to": 1,
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("/alerts/get_alerts_multi_events", data=payload)

        alerts = response_data.get("reply", {}).get("alerts", [])
        if not alerts:
            return create_response(data={"error": f"No alert found with ID {alert_id}"}, is_error=True)

        alert = alerts[0]

        # Filter to relevant fields but keep ALL events (no [:3] truncation)
        filtered_alert = {k: v for k, v in alert.items() if k in _ALERT_KEEP}
        if isinstance(filtered_alert.get("events"), list):
            filtered_alert["events"] = [
                {k: v for k, v in event.items() if k in _EVENT_KEEP}
                for event in filtered_alert["events"]  # No truncation — all events
            ]
            filtered_alert["total_events"] = len(filtered_alert["events"])

        cleaned = _strip_empty(filtered_alert)
        return create_response(data={"alert": cleaned})
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting alert details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get alert details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class AlertDetailsModule(BaseModule):
    """Module for retrieving full details of a single alert with all events."""

    def register_tools(self):
        self._add_tool(get_alert_details)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
