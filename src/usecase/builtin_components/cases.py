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


async def get_cases_response() -> str:
    try:
        cases_json = read_resource("cases_response.json")
        return create_response(data={"response": json.loads(cases_json)})
    except FileNotFoundError as e:
        logger.exception(f"Cases response file not found: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except json.JSONDecodeError as e:
        logger.exception(f"Invalid JSON in cases response file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to read cases responses: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_cases(ctx: Context,
                    filters: Annotated[list[dict], Field(description="Filters list to get the cases by. Leave empty go get all cases")] = [],
                    search_from: Annotated[int, Field(description="Marker for pagination starting point", default=0)] = 0,
                    search_to: Annotated[int, Field(description="Marker for pagination ending point", default=100)] = 100,
                    sort: Annotated[Optional[dict], Field(description="Dictionary of field and keyword to sort by. By default the sort is defined as creation_time, desc")] = None,
                    name_contains: Annotated[Optional[str], Field(description="Optional client-side filter: only return cases whose name or description contains this string (case-insensitive). When provided, the tool auto-paginates through up to max_scan cases and returns only compact matches instead of full case objects. Much more efficient for pattern searches like 'DocumentsWebApi' or 'WildFire Malware'.")] = None,
                    max_scan: Annotated[int, Field(description="When name_contains is used: max cases to scan through. Default 500, max 10000. Ignored when name_contains is not set.", default=500)] = 500,
                    max_results: Annotated[int, Field(description="When name_contains is used: max matching cases to return. Default 20. Ignored when name_contains is not set.", default=20)] = 20,
                    ) -> str:
    """
    Retrieves a list of cases or incidents from the Cortex platform.
    Use this tool to fetch all cases, or a filtered subset of cases, based on various criteria such as time range, status, or specific case IDs.
    This is highly valuable for security monitoring, historical analysis, and reporting on detected cases.

    When name_contains is provided, the tool switches to search mode: it auto-paginates through cases
    and returns only compact matches (case_id, name, time, status, severity, hosts, users, resolve_comment).
    This avoids dumping hundreds of full case objects into context when searching for a pattern.

    Args:
        ctx: The FastMCP context.
        filters: Filters list to get the cases by. Example -
            [{
                        "field": "severity",
                        "operator": "in",
                        "value": ["high", "critical"]
            }],
            [{
                        "field": "id",
                        "operator": "in",
                        "value": [123]
            }],
            [{"field": "case_domain", "operator": "in", "value": ["SECURITY"]}, {"field": "creation_time", "operator": "gte", "value": 1762774211000}, {"field": "creation_time", "operator": "lte", "value": 1762860611000}], "search_from": 0, "search_to": 100, "sort": [{"field": "creation_time", "keyword": "desc"}]
            Leave empty go get all cases.
            Allowed values:"case_id","case_domain","severity","creation_time","status_progress"
        search_from: Marker for pagination starting point.
        search_to: Marker for pagination ending point.
        sort: Field to sort by in the structure of "field" with the field name and "keyword" of "desc" or "asc".
            Allowed values:"id","severity","creation_time"
        name_contains: Optional search string to filter cases by name/description (case-insensitive, client-side).
        max_scan: Max cases to scan when using name_contains (default 500, max 10000).
        max_results: Max matches to return when using name_contains (default 20).

    Returns:
        JSON response containing case data. When name_contains is used, returns compact matches only.
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
                    api_filters = []
                    for f in filters:
                        fc = dict(f)
                        if fc.get("field") == "id":
                            fc["value"] = [int(v) for v in fc["value"]]
                        api_filters.append(fc)
                    payload["request_data"]["filters"] = api_filters

                response_data = await fetcher.send_request("case/search/", data=payload)
                cases = response_data.get("reply", {}).get("DATA", [])
                total_count = response_data.get("reply", {}).get("TOTAL_COUNT", total_count)

                if not cases:
                    break

                for case in cases:
                    name = (case.get("case_name") or "").lower()
                    desc = (case.get("description") or "").lower()
                    if query_lower in name or query_lower in desc:
                        matches.append({
                            "case_id": case.get("case_id"),
                            "case_name": case.get("case_name"),
                            "creation_time": case.get("creation_time"),
                            "status": case.get("status_progress"),
                            "resolve_reason": case.get("resolve_reason"),
                            "severity": case.get("severity"),
                            "hosts": case.get("hosts"),
                            "users": case.get("users"),
                            "alert_count": len(case.get("issue_ids", [])),
                            "resolve_comment": case.get("resolve_comment"),
                        })
                        if len(matches) >= max_results:
                            break

                scanned += len(cases)

            return create_response(data={
                "search_query": name_contains,
                "total_matches_found": len(matches),
                "cases_scanned": scanned,
                "total_cases_in_system": total_count,
                "matches": matches,
            })
        except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
            logger.exception(f"PAPI error while searching cases: {e}")
            return create_response(data={"error": str(e)}, is_error=True)
        except Exception as e:
            logger.exception(f"Failed to search cases: {e}")
            return create_response(data={"error": str(e)}, is_error=True)

    # --- Normal mode: no name_contains ---
    payload = {
        "request_data": {}
    }
    if filters:
        for f in filters:
            if f.get("field") == "id":
                f["value"] = [int(v) for v in f["value"]]
        payload["request_data"]["filters"] = filters
    if sort:
        payload["request_data"]["sort"] = sort

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await paginated_fetch(
            fetcher, "case/search/", payload,
            search_from, search_to,
            results_key="DATA", total_key="TOTAL_COUNT"
        )

        cases = response_data.get("reply", {}).get("DATA", [])
        for case in cases:
            issue_ids = case.get("issue_ids", [])
            case["alert_ids"] = issue_ids
            case["alert_count"] = len(issue_ids)

        return create_response(data=response_data)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting cases: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get cases: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class CasesModule(BaseModule):
    """Module for managing Cortex platform cases and incidents."""

    def register_tools(self):
        self._add_tool(get_cases)

    def register_resources(self):
        self._add_resource(get_cases_response, uri="resources://cases_response.json",
            name="cases_response.json",
            description="Example response from the cases API",
            mime_type="application/json")

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
