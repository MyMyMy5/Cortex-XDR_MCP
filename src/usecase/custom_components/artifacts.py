"""Tool: get_incident_artifacts

Retrieve file artifacts and network artifacts for a specific incident from Cortex XDR.
Calls the Get Extra Incident Data API for artifact-level overview.
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


def _strip_empty(obj):
    """Recursively remove keys with None, empty string, or empty list values."""
    if isinstance(obj, dict):
        return {k: _strip_empty(v) for k, v in obj.items() if v is not None and v != "" and v != []}
    if isinstance(obj, list):
        return [_strip_empty(i) for i in obj if i is not None and i != "" and i != []]
    return obj


async def get_incident_artifacts(
    ctx: Context,
    incident_id: Annotated[str, Field(description="The incident ID to retrieve artifacts for (e.g. '6683').")],
    alerts_limit: Annotated[int, Field(description="Maximum number of alerts to return. Default 10. The API rate-limits to 10 requests/minute.", default=10)] = 10,
) -> str:
    """
    Retrieve file artifacts and network artifacts for a specific incident from Cortex XDR.

    This tool calls the Get Extra Incident Data API which returns the key artifacts
    (files, domains, IPs) associated with an incident — information that is NOT available
    from the standard get_incidents or get_issues tools.

    Use this tool when you need to:
    - See which files (with SHA256 hashes, verdicts, file paths) are involved in an incident
    - See which network indicators (domains, IPs, ports) are associated with an incident
    - Get a quick artifact-level overview without writing XQL queries

    The response includes:
    - file_artifacts: file names, SHA256 hashes, file paths, WildFire verdicts, signer info
    - network_artifacts: domains, IPs, ports, protocol info
    - alerts: a summary of alerts (capped by alerts_limit)

    Args:
        ctx: The FastMCP context.
        incident_id: The incident ID to retrieve artifacts for.
        alerts_limit: Max alerts to include in the response. Default 10.

    Returns:
        JSON response containing file_artifacts, network_artifacts, and alerts for the incident.
    """
    payload = {
        "request_data": {
            "incident_id": incident_id,
            "alerts_limit": alerts_limit,
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("incidents/get_incident_extra_data/", data=payload)

        # Clean up the response to reduce noise
        reply = response_data.get("reply", {})
        incident_data = reply.get("incident", {})
        file_artifacts = reply.get("file_artifacts", {}).get("data", [])
        network_artifacts = reply.get("network_artifacts", {}).get("data", [])
        alerts = reply.get("alerts", {}).get("data", [])

        cleaned = {
            "incident_id": incident_id,
            "incident_summary": {
                "description": incident_data.get("description"),
                "severity": incident_data.get("severity"),
                "status": incident_data.get("status"),
                "host_count": incident_data.get("host_count"),
                "user_count": incident_data.get("user_count"),
                "alert_count": incident_data.get("alert_count"),
            },
            "file_artifacts": [_strip_empty(fa) for fa in file_artifacts],
            "file_artifacts_count": len(file_artifacts),
            "network_artifacts": [_strip_empty(na) for na in network_artifacts],
            "network_artifacts_count": len(network_artifacts),
            "alerts_returned": len(alerts),
        }

        return create_response(data=cleaned)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting incident artifacts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get incident artifacts: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class ArtifactsModule(BaseModule):
    """Module for retrieving file and network artifacts from Cortex XDR incidents."""

    def register_tools(self):
        self._add_tool(get_incident_artifacts)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
