"""Tool: get_exclusions

Retrieve alert exclusion records from the Cortex XDR / XSIAM management audit log.
Provides visibility into who created exclusions, when, and for which alerts.
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

# Audit log sub_type values that map to exclusion-related actions.
_EXCLUSION_SUBTYPES = ["Exclusion"]


def _strip_empty(obj):
    """Recursively remove keys with None, empty string, or empty list values."""
    if isinstance(obj, dict):
        return {k: _strip_empty(v) for k, v in obj.items()
                if v is not None and v != "" and v != []}
    if isinstance(obj, list):
        return [_strip_empty(i) for i in obj
                if i is not None and i != "" and i != []]
    return obj


def _format_exclusion(record: dict) -> dict:
    """Transform a raw audit log record into a cleaner exclusion entry."""
    return _strip_empty({
        "audit_id": record.get("AUDIT_ID"),
        "created_by": record.get("AUDIT_OWNER_NAME"),
        "created_by_email": record.get("AUDIT_OWNER_EMAIL"),
        "timestamp": record.get("AUDIT_INSERT_TIME"),
        "result": record.get("AUDIT_RESULT"),
        "description": record.get("AUDIT_DESCRIPTION"),
        "entity": record.get("AUDIT_ENTITY"),
        "subtype": record.get("AUDIT_ENTITY_SUBTYPE"),
        "source_ip": record.get("AUDIT_SOURCE_IP"),
        "user_roles": record.get("AUDIT_USER_ROLES"),
    })


async def get_exclusions(
    ctx: Context,
    search_from: Annotated[int, Field(
        description="Pagination start offset. Default 0.", default=0)] = 0,
    search_to: Annotated[int, Field(
        description="Pagination end offset. Default 100.", default=100)] = 100,
) -> str:
    """
    Retrieve alert exclusion records from the Cortex XDR / XSIAM audit log.

    This tool queries the management audit log for all exclusion-related actions,
    showing which alerts/issues were excluded, by whom, and when.

    Each record includes:
    - Who created the exclusion (name, email, role)
    - When it was created (timestamp)
    - Which alert or issue ID was excluded
    - Whether the action succeeded or failed

    Note: Cortex XSIAM does not expose a dedicated API for listing exclusion
    rule definitions (criteria, scope, etc.). This tool surfaces the audit
    trail of exclusion actions, which is the best available data via the
    public API.

    Use this tool when you need to:
    - Check if an exclusion was already created for a specific alert type
    - Audit who has been creating exclusions and when
    - Investigate why certain alerts are not being raised
    - Review exclusion activity for compliance or security review

    Args:
        ctx: The FastMCP context.
        search_from: Pagination start offset.
        search_to: Pagination end offset.

    Returns:
        JSON response containing exclusion audit records.
    """
    payload: dict = {
        "request_data": {
            "filters": [
                {
                    "field": "sub_type",
                    "operator": "in",
                    "value": _EXCLUSION_SUBTYPES,
                }
            ],
            "search_from": search_from,
            "search_to": search_to,
            "sort": {"field": "timestamp", "keyword": "desc"},
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request(
            "audits/management_logs/", data=payload
        )

        reply = response_data.get("reply", {})
        raw_records = reply.get("data", [])
        total_count = reply.get("total_count", 0)

        exclusions = [_format_exclusion(r) for r in raw_records]

        result = {
            "total_exclusion_records": total_count,
            "returned": len(exclusions),
            "search_from": search_from,
            "search_to": search_to,
            "exclusions": exclusions,
        }
        return create_response(data=result)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting exclusions: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get exclusions: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class ExclusionsModule(BaseModule):
    """Module for retrieving exclusion records from Cortex XDR / XSIAM."""

    def register_tools(self):
        self._add_tool(get_exclusions)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
