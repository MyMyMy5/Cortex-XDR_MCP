"""Tool: get_incidents

Retrieve incidents from the Cortex XDR platform with optional filtering.
Supports name_contains for efficient pattern-based searching.
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


async def get_incidents(
    ctx: Context,
    filters: Annotated[list[dict], Field(description="Filters list. E.g. [{\"field\": \"status\", \"operator\": \"eq\", \"value\": \"new\"}]. Leave empty to get all incidents.")] = None,
    search_from: Annotated[int, Field(description="Pagination start offset", default=0)] = 0,
    search_to: Annotated[int, Field(description="Pagination end offset", default=100)] = 100,
    sort: Annotated[Optional[dict], Field(description='Sort order. E.g. {"field": "creation_time", "keyword": "desc"}')] = None,
    name_contains: Annotated[Optional[str], Field(description="Optional client-side filter: only return incidents whose name or description contains this string (case-insensitive). When provided, the tool auto-paginates through up to max_scan incidents and returns only compact matches. Much more efficient for pattern searches.")] = None,
    max_scan: Annotated[int, Field(description="When name_contains is used: max incidents to scan. Default 500, max 10000. Ignored otherwise.", default=500)] = 500,
    max_results: Annotated[int, Field(description="When name_contains is used: max matches to return. Default 20. Ignored otherwise.", default=20)] = 20,
) -> str:
    """
    Retrieves a list of incidents from the Cortex XDR platform.
    Use this tool to fetch all incidents, or filter by status, severity, assigned user, time range, etc.

    When name_contains is provided, the tool switches to search mode: it auto-paginates through incidents
    and returns only compact matches (incident_id, name, time, status, severity, hosts, users, alert_count).

    Args:
        ctx: The FastMCP context.
        filters: List of filter objects with "field", "operator", and "value".
            Supported fields: "incident_id", "incident_id_list", "status", "starred",
            "creation_time", "modification_time", "description", "alert_sources".
            Status values: "new", "under_investigation", "resolved_true_positive",
            "resolved_false_positive", "resolved_known_issue", "resolved_duplicate",
            "resolved_other", "resolved_auto".
        search_from: Pagination start offset.
        search_to: Pagination end offset (max 100).
        sort: Sort order with "field" and "keyword" ("asc"/"desc").
            Sortable fields: "incident_id", "creation_time", "modification_time".
        name_contains: Optional search string to filter by name/description (case-insensitive, client-side).
        max_scan: Max incidents to scan when using name_contains (default 500, max 10000).
        max_results: Max matches to return when using name_contains (default 20).

    Returns:
        JSON response containing incident data. When name_contains is used, returns compact matches only.
    """
    # --- Search mode: name_contains provided ---
    if name_contains:
        query_lower = name_contains.strip().lower()
        max_scan = min(max_scan, 10000)
        batch_size = 100
        matches = []
        scanned = 0
        total_count = 0

        try:
            fetcher = await get_fetcher(ctx)

            while scanned < max_scan and len(matches) < max_results:
                payload = {
                    "request_data": {
                        "search_from": scanned,
                        "search_to": min(scanned + batch_size, max_scan),
                        "sort": sort or {"field": "creation_time", "keyword": "desc"},
                    }
                }
                if filters:
                    payload["request_data"]["filters"] = filters

                response_data = await fetcher.send_request("incidents/get_incidents", data=payload)
                reply = response_data.get("reply", {})
                incidents = reply.get("incidents", [])
                total_count = reply.get("total_count", total_count)

                if not incidents:
                    break

                for inc in incidents:
                    name = (inc.get("incident_name") or "").lower()
                    desc = (inc.get("description") or "").lower()
                    if query_lower in name or query_lower in desc:
                        matches.append({
                            "incident_id": inc.get("incident_id"),
                            "incident_name": inc.get("incident_name"),
                            "creation_time": inc.get("creation_time"),
                            "status": inc.get("status"),
                            "severity": inc.get("severity"),
                            "hosts": inc.get("hosts"),
                            "users": inc.get("users"),
                            "alert_count": inc.get("alert_count"),
                            "resolve_comment": inc.get("resolve_comment"),
                        })
                        if len(matches) >= max_results:
                            break

                scanned += len(incidents)

            return create_response(data={
                "search_query": name_contains,
                "total_matches_found": len(matches),
                "incidents_scanned": scanned,
                "total_incidents_in_system": total_count,
                "matches": matches,
            })
        except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
            logger.exception(f"PAPI error while searching incidents: {e}")
            return create_response(data={"error": str(e)}, is_error=True)
        except Exception as e:
            logger.exception(f"Failed to search incidents: {e}")
            return create_response(data={"error": str(e)}, is_error=True)

    # --- Normal mode: no name_contains ---
    payload = {
        "request_data": {}
    }
    if filters:
        payload["request_data"]["filters"] = filters
    if sort:
        payload["request_data"]["sort"] = sort

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await paginated_fetch(
            fetcher, "incidents/get_incidents", payload,
            search_from, search_to,
            results_key="incidents", total_key="total_count"
        )
        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting incidents: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get incidents: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class IncidentsModule(BaseModule):
    """Module for retrieving Cortex XDR incidents."""

    def register_tools(self):
        self._add_tool(get_incidents)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
