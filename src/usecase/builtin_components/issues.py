"""Tool: get_issues

Retrieve alerts/issues from the Cortex platform with optional filtering.
Supports case_id for fetching alerts associated with a specific case.
"""

import json
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
from pkg.util import create_response, read_resource, paginated_fetch
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

async def get_issues_response() -> str:
    try:
        issues_json = read_resource("issues_response.json")
        return create_response(data={"response": json.loads(issues_json)})
    except FileNotFoundError as e:
        logger.exception(f"Issues response file not found: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in issues response file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to read issues responses: {e}")
        return create_response(data={"error": str(e)}, is_error=True)

# Alert-level fields to retain (from Fields.txt)
_ALERT_KEEP = {
    "alert_id", "external_id", "alert_domain", "name", "description", "category",
    "severity", "source", "action", "action_pretty", "resolution_status", "resolution_comment",
    "alert_type", "detection_timestamp", "local_insert_ts", "last_modified_ts",
    "case_id", "endpoint_id", "host_name", "host_ip", "mac_addresses",
    "agent_os_type", "agent_os_sub_type", "agent_version", "agent_fqdn",
    "agent_device_domain", "agent_ip_addresses_v6",
    "mitre_technique_id_and_name", "mitre_tactic_id_and_name",
    "matching_service_rule_id", "matching_status",
    "bioc_indicator", "bioc_category_enum_key",
    "tags", "original_tags", "malicious_urls",
    "is_whitelisted", "starred", "is_pcap",
    "dynamic_fields", "events",
}

# Event-level fields to retain (from Fields.txt) - focused on investigative value
_EVENT_KEEP = {
    "event_id", "event_type", "event_sub_type", "event_timestamp",
    # Actor process
    "actor_process_image_name", "actor_process_image_path", "actor_process_command_line",
    "actor_process_image_sha256", "actor_process_signature_status", "actor_process_signature_vendor",
    "actor_process_os_pid",
    # Causality (root cause) process
    "causality_actor_process_image_name", "causality_actor_process_command_line",
    "causality_actor_process_image_path", "causality_actor_process_image_sha256",
    "causality_actor_process_signature_status", "causality_actor_process_signature_vendor",
    # OS actor
    "os_actor_effective_username", "os_actor_process_image_name",
    "os_actor_process_command_line", "os_actor_process_os_pid",
    # Network
    "action_local_ip", "action_local_port",
    "action_remote_ip", "action_remote_port",
    "action_external_hostname", "action_country",
    "dns_query_name", "dst_action_external_hostname", "dst_action_country", "dst_action_external_port",
    # File
    "action_file_path", "action_file_name", "action_file_sha256", "action_file_md5",
    # Registry
    "action_registry_full_key", "action_registry_value_name", "action_registry_data",
    # Firewall
    "fw_url_domain", "fw_rule", "fw_app_id", "fw_email_subject", "fw_email_sender", "fw_email_recipient",
    # User / identity
    "user_name", "user_agent", "identity_type", "identity_sub_type",
    # Cloud / container
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


async def get_issues(ctx: Context,
                    filters: Annotated[list[dict], Field(description="Filters list to get the issues by. Leave empty to get all issues")] = [],
                    search_from: Annotated[int, Field(description="Marker for pagination starting point", default=0)] = 0,
                    search_to: Annotated[int, Field(description="Marker for pagination ending point", default=30)] = 30,
                    sort: Annotated[Optional[dict], Field(description="Dictionary of field and keyword to sort by. By default the sort is defined as observation time, desc")] = None,
                    case_id: Annotated[Optional[int], Field(description="If provided, automatically resolves the alert IDs for this case and fetches their full details")] = None,
                    page_size: Annotated[int, Field(description="Max number of alerts to return per call when using case_id. Default 10. Use search_from to paginate through remaining alerts.", default=10)] = 10,
                    ) -> str:
    """
    Retrieves a list of issues or alerts from the Cortex platform.
    Use this tool to fetch all issues, or a filtered subset of issues, or one issue, based on various criteria such as time range, severity, status, or specific alert IDs.
    This is highly valuable for security monitoring, threat hunting, and reporting on detected security events.

    IMPORTANT — filters parameter:
    - The 'filters' parameter is ALWAYS REQUIRED, even when using case_id.
    - When using case_id, pass filters=[] (empty list). The tool will auto-populate
      the correct alert_id_list filter internally.
    - When NOT using case_id, provide your filter criteria in the list.

    Args:
        ctx: The FastMCP context.
        filters: REQUIRED. Filters list to get the issues by. Pass an empty list [] to get
            all issues or when using case_id. Examples:
            [{"field": "alert_id_list", "operator": "in", "value": [2563179]}]
            [{"field": "severity", "operator": "in", "value": ["high", "critical"]}]
            [{"field": "external_id_list", "operator": "in", "value": ["fdb11e23-b8bb-4dfe-84b8-908c584a76e3"]}]
            Allowed filter fields: "alert_id_list" (integers), "external_id_list", "alert_source",
            "severity", "creation_time", "last_modified_ts", "server_creation_time".
        search_from: Marker for pagination starting point. Default 0.
        search_to: Marker for pagination ending point. Default 30.
        sort: Field to sort by. Example - {"field": "detection_timestamp", "keyword": "desc"}.
            Allowed fields: "detection_timestamp", "severity", "alert_id".
        case_id: Optional incident/case ID. If provided, the tool automatically looks up the
            associated alert IDs and fetches their full details — no need to manually resolve IDs first.
            You MUST still pass filters=[] when using this parameter.
        page_size: When using case_id, controls how many alerts are returned per call (default 10).
            Use search_from to paginate. The response always includes total_alerts_in_case so you
            know how many remain.
    Returns:
        JSON response containing issue data.

    Formatting instructions:
        - Present data as structured markdown. Never fabricate or invent data.
        - Convert timestamps to human-readable format.
        - Use severity color indicators: critical=dark red, high=red, medium=orange, low=blue.
        - For each issue include: ID, severity, category, source, detection time, resolution status, affected hosts/users, MITRE tactics/techniques, and event details.
        - Always inform the user how many alerts were returned vs total, and suggest paginating if there are more.
        - Keep responses concise. Summarize large datasets before detailing.
    """

    try:
        fetcher = await get_fetcher(ctx)

        if case_id is not None:
            case_payload = {
                "request_data": {
                    "filters": [{"field": "case_id", "operator": "in", "value": [case_id]}],
                    "search_from": 0,
                    "search_to": 1,
                }
            }
            case_data = await fetcher.send_request("/case/search/", data=case_payload)
            cases = case_data.get("reply", {}).get("DATA", [])
            if not cases:
                return create_response(data={"error": f"No case found with ID {case_id}"}, is_error=True)
            alert_ids = cases[0].get("issue_ids", [])
            if not alert_ids:
                return create_response(data={"error": f"No alert IDs found for case {case_id}"}, is_error=True)
            total_in_case = len(alert_ids)
            paged_ids = alert_ids[search_from:search_from + page_size]
            filters = [{"field": "alert_id_list", "operator": "in", "value": paged_ids}]
        else:
            total_in_case = None

        payload = {
            "request_data": {}
        }
        if filters:
            payload["request_data"]["filters"] = filters
        if sort:
            payload["request_data"]["sort"] = sort

        effective_from = search_from if case_id is None else 0
        effective_to = search_to if case_id is None else page_size

        response_data = await paginated_fetch(
            fetcher, "/alerts/get_alerts_multi_events", payload,
            effective_from, effective_to,
            results_key="alerts", total_key="total_count"
        )
        if "reply" in response_data and "alerts" in response_data["reply"]:
            cleaned_alerts = []
            alert_list = response_data["reply"]["alerts"]
            for alert in alert_list:
                filtered_alert = {k: v for k, v in alert.items() if k in _ALERT_KEEP}
                if isinstance(filtered_alert.get("events"), list):
                    filtered_alert["events"] = [
                        {k: v for k, v in event.items() if k in _EVENT_KEEP}
                        for event in filtered_alert["events"][:3]
                    ]
                cleaned_alerts.append(_strip_empty(filtered_alert))
            response_data["reply"]["alerts"] = cleaned_alerts
            if total_in_case is not None:
                response_data["reply"]["total_alerts_in_case"] = total_in_case
                response_data["reply"]["returned_range"] = f"{search_from}-{search_from + len(cleaned_alerts)} of {total_in_case}"
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting issues: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get issues: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class IssuesModule(BaseModule):
    """
       Module for managing and retrieving security issues and alerts from the Cortex platform.

       This module provides tools and resources for interacting with the Cortex platform's issue/alert system,
       enabling users to search, filter, and paginate through security issues. It supports various filtering
       criteria such as status, severity, time range, and custom search parameters.

       The module registers:
       - Tools: get_issues - for retrieving filtered and paginated issue data
       - Resources: issues_response.json - example API response for reference

       This module is essential for security monitoring, threat hunting, incident response,
       and generating reports on detected security events within the Cortex platform.
       """

    def register_tools(self):
        self._add_tool(get_issues)

    def register_resources(self):
        self._add_resource(get_issues_response, uri="resources://issues_response.json",
    name="issues_response.json",
    description="Example response from the issues API",
    mime_type="application/json",)

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)

