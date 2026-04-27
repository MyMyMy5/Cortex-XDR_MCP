"""Tool: get_filtered_endpoints

Retrieve endpoints managed by XDR agents with optional filtering.
Response is auto-trimmed to investigation-relevant fields.
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
from pkg.util import create_response, paginated_fetch
from usecase.base_module import BaseModule
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)


async def get_filtered_endpoints(
    ctx: Context,
    filters: Annotated[list[dict], Field(description=(
        "Filters list. Supported fields: "
        "\"endpoint_id_list\" (list of strings), "
        "\"endpoint_status\" (in: connected/disconnected/lost/uninstalled), "
        "\"hostname\" (list of strings), "
        "\"username\" (list of strings), "
        "\"ip_list\" (list of IPs), "
        "\"platform\" (in: windows/linux/macos/android), "
        "\"group_name\" (list of strings), "
        "\"isolate\" (in: isolated/unisolated), "
        "\"scan_status\" (in: none/pending/in_progress/success/error). "
        "Example: [{\"field\": \"hostname\", \"operator\": \"in\", \"value\": [\"PC-93515\"]}]"
    ))] = [],
    search_from: Annotated[int, Field(description="Pagination start offset.", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end offset.", default=100)] = 100,
    sort: Annotated[Optional[dict], Field(description="Sort order. Example: {\"field\": \"last_seen\", \"keyword\": \"DESC\"}. Fields: endpoint_id, first_seen, last_seen, scan_status.")] = None,
) -> str:
    """
    This tool is used to retrieve a filtered list of endpoints managed by the XDR agents based on their ids, status and platform.

    Args:
        ctx: The FastMCP context.
        filters: Filters list to get the endpoints by. Supported filter fields:
            "endpoint_id_list" - list of endpoint ID strings,
            "endpoint_status" - connected/disconnected/lost/uninstalled,
            "hostname" - list of hostnames (e.g. ["PC-93515"]),
            "username" - list of usernames,
            "ip_list" - list of IP addresses,
            "platform" - windows/linux/macos/android,
            "group_name" - list of group names,
            "isolate" - isolated/unisolated,
            "scan_status" - none/pending/in_progress/success/error.
        search_from: Pagination start offset.
        search_to: Pagination end offset, max 100.
        sort: Sort order dict with "field" and "keyword" (ASC/DESC).

    Returns:
        JSON response containing endpoint data including endpoint_id, hostname, users, IP addresses, OS, status, and agent version.
    """
    payload: dict = {"request_data": {}}
    if filters:
        payload["request_data"]["filters"] = filters
    if sort:
        payload["request_data"]["sort"] = sort

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await paginated_fetch(
            fetcher, "endpoints/get_endpoint/", payload,
            search_from, search_to,
            results_key="endpoints", total_key="total_count"
        )

        # Trim endpoint objects to investigation-relevant fields only
        # Removes massive active_directory group lists, token hashes, etc.
        _ENDPOINT_KEEP = {
            "endpoint_id", "endpoint_name", "endpoint_type", "endpoint_status",
            "os_type", "os_version", "operating_system",
            "ip", "ipv6", "public_ip", "mac_address",
            "users", "domain", "alias",
            "first_seen", "last_seen",
            "content_version", "installation_package", "endpoint_version",
            "is_isolated", "isolated_date",
            "group_name", "operational_status", "operational_status_description",
            "scan_status",
            "assigned_prevention_policy", "assigned_extensions_policy",
            "tags",
            "cloud_provider", "cloud_region", "cloud_instance_id",
            "content_status",
        }

        endpoints = response_data.get("reply", {}).get("endpoints", [])
        for i, ep in enumerate(endpoints):
            endpoints[i] = {k: v for k, v in ep.items() if k in _ENDPOINT_KEEP}

        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting endpoints: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get endpoints: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class EndpointsModule(BaseModule):
    """Module for retrieving XDR agent endpoints."""

    def register_tools(self):
        self._add_tool(get_filtered_endpoints)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
