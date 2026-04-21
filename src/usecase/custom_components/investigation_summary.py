"""
Tool: get_investigation_summary

Single-call tool that consolidates the first two phases of an incident investigation:
fetches the incident, case, artifacts, and endpoints in parallel and returns a
unified summary. Eliminates the need for 4 separate tool calls at the start of
every investigation.
"""

import asyncio
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


# Endpoint fields worth keeping (same set as endpoints.py)
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
}


async def _fetch_incident(fetcher, incident_id: int) -> dict:
    """Fetch incident details."""
    payload = {
        "request_data": {
            "filters": [{"field": "incident_id", "operator": "eq", "value": incident_id}],
            "search_from": 0,
            "search_to": 1,
        }
    }
    response = await fetcher.send_request("incidents/get_incidents", data=payload)
    incidents = response.get("reply", {}).get("incidents", [])
    return incidents[0] if incidents else {}


async def _fetch_case(fetcher, case_id: int) -> dict:
    """Fetch case details."""
    payload = {
        "request_data": {
            "filters": [{"field": "case_id", "operator": "in", "value": [case_id]}],
            "search_from": 0,
            "search_to": 1,
        }
    }
    response = await fetcher.send_request("case/search/", data=payload)
    cases = response.get("reply", {}).get("DATA", [])
    if not cases:
        return {}
    case = cases[0]
    # Add convenience fields
    issue_ids = case.get("issue_ids", [])
    case["alert_ids"] = issue_ids
    case["alert_count"] = len(issue_ids)
    return case


async def _fetch_artifacts(fetcher, incident_id: int) -> dict:
    """Fetch file and network artifacts for the incident."""
    payload = {
        "request_data": {
            "incident_id": str(incident_id),
            "alerts_limit": 1,  # We only need artifacts, not alerts
        }
    }
    response = await fetcher.send_request("incidents/get_incident_extra_data/", data=payload)
    reply = response.get("reply", {})
    file_artifacts = reply.get("file_artifacts", {}).get("data", [])
    network_artifacts = reply.get("network_artifacts", {}).get("data", [])
    return {
        "file_artifacts": [_strip_empty(fa) for fa in file_artifacts],
        "network_artifacts": [_strip_empty(na) for na in network_artifacts],
    }


async def _fetch_endpoints(fetcher, hostnames: list[str]) -> list[dict]:
    """Fetch endpoint details for the given hostnames."""
    if not hostnames:
        return []
    payload = {
        "request_data": {
            "filters": [{"field": "hostname", "operator": "in", "value": hostnames}],
            "search_from": 0,
            "search_to": 100,
        }
    }
    response = await fetcher.send_request("endpoints/get_endpoint/", data=payload)
    endpoints = response.get("reply", {}).get("endpoints", [])
    return [{k: v for k, v in ep.items() if k in _ENDPOINT_KEEP} for ep in endpoints]


def _extract_iocs(artifacts: dict) -> list[dict]:
    """Extract a deduplicated IOC list from file and network artifacts."""
    iocs = []
    seen = set()

    for fa in artifacts.get("file_artifacts", []):
        sha256 = fa.get("file_sha256")
        if sha256 and sha256 not in seen:
            seen.add(sha256)
            iocs.append({
                "type": "sha256",
                "value": sha256,
                "context": fa.get("file_name"),
                "verdict": fa.get("file_wildfire_verdict"),
            })

    for na in artifacts.get("network_artifacts", []):
        domain = na.get("network_domain")
        if domain and domain not in seen:
            seen.add(domain)
            iocs.append({
                "type": "domain",
                "value": domain,
                "context": f"port {na.get('network_remote_port', 'unknown')}",
            })
        ip = na.get("network_remote_ip")
        if ip and ip not in seen:
            seen.add(ip)
            iocs.append({
                "type": "ip",
                "value": ip,
                "context": f"port {na.get('network_remote_port', 'unknown')}",
            })

    return iocs


async def get_investigation_summary(
    ctx: Context,
    incident_id: Annotated[int, Field(description=(
        "The incident/case ID to investigate. The tool fetches the incident, "
        "case, artifacts, and endpoints all in parallel and returns a consolidated summary."
    ))],
) -> str:
    """
    Get a consolidated investigation summary for an incident in a single call.

    This tool replaces the need to call get_incidents, get_cases, get_incident_artifacts,
    and get_filtered_endpoints separately at the start of every investigation. It runs
    all four queries in parallel and returns a unified response with:

    - Incident metadata (name, severity, status, timestamps, alert count)
    - Case details (alert IDs, hosts, users, status)
    - File artifacts (SHA256, file names, paths, WildFire verdicts)
    - Network artifacts (domains, IPs, ports)
    - Endpoint details (OS, IP, agent status, isolation, policy, groups)
    - Pre-extracted IOC list ready for hunting

    Use this as the FIRST call in any incident investigation. The creation_time
    in the response is your timeframe anchor for all subsequent queries.

    Args:
        ctx: The FastMCP context.
        incident_id: The incident or case ID to investigate.

    Returns:
        JSON with consolidated incident, case, artifact, endpoint, and IOC data.
    """
    try:
        fetcher = await get_fetcher(ctx)

        # Phase 1: Fetch incident and case in parallel
        incident_task = asyncio.create_task(_fetch_incident(fetcher, incident_id))
        case_task = asyncio.create_task(_fetch_case(fetcher, incident_id))

        incident, case = await asyncio.gather(incident_task, case_task)

        if not incident and not case:
            return create_response(
                data={"error": f"No incident or case found with ID {incident_id}"},
                is_error=True,
            )

        # Extract hostnames for endpoint lookup.
        # Incident API returns hosts as "hostname:agent_id" — strip the agent_id suffix.
        # Case API returns hosts as "AGENT_OS_WINDOWS:hostname" — strip the OS prefix.
        raw_hosts = []
        if incident:
            raw_hosts = incident.get("hosts", []) or []
        elif case:
            raw_hosts = case.get("hosts", []) or []

        hostnames = []
        for h in raw_hosts:
            if h.startswith("AGENT_OS_"):
                # Case format: "AGENT_OS_WINDOWS:hostname"
                parts = h.split(":", 1)
                hostnames.append(parts[1] if len(parts) > 1 else h)
            elif ":" in h:
                # Incident format: "hostname:agent_id"
                hostnames.append(h.split(":")[0])
            else:
                hostnames.append(h)

        # Phase 2: Fetch artifacts and endpoints in parallel
        artifacts_task = asyncio.create_task(_fetch_artifacts(fetcher, incident_id))
        endpoints_task = asyncio.create_task(_fetch_endpoints(fetcher, hostnames))

        artifacts, endpoints = await asyncio.gather(artifacts_task, endpoints_task)

        # Extract IOCs from artifacts
        ioc_list = _extract_iocs(artifacts)

        # Build the consolidated summary
        result = {
            "incident_id": incident_id,
        }

        if incident:
            result["incident"] = _strip_empty({
                "name": incident.get("incident_name"),
                "description": incident.get("description"),
                "severity": incident.get("severity"),
                "status": incident.get("status"),
                "creation_time": incident.get("creation_time"),
                "modification_time": incident.get("modification_time"),
                "alert_count": incident.get("alert_count"),
                "host_count": incident.get("host_count"),
                "user_count": incident.get("user_count"),
                "hosts": incident.get("hosts"),
                "users": incident.get("users"),
                "assigned_user_mail": incident.get("assigned_user_mail"),
                "assigned_user_pretty_name": incident.get("assigned_user_pretty_name"),
                "alert_sources": incident.get("alert_sources"),
                "alert_categories": incident.get("alert_categories"),
                "resolve_comment": incident.get("resolve_comment"),
                "mitre_tactics_ids_and_names": incident.get("mitre_tactics_ids_and_names"),
                "mitre_techniques_ids_and_names": incident.get("mitre_techniques_ids_and_names"),
                "tags": incident.get("tags"),
                "incident_domain": incident.get("incident_domain"),
            })

        if case:
            result["case"] = _strip_empty({
                "case_id": case.get("case_id"),
                "case_name": case.get("case_name"),
                "severity": case.get("severity"),
                "status": case.get("status_progress"),
                "creation_time": case.get("creation_time"),
                "alert_ids": case.get("alert_ids"),
                "alert_count": case.get("alert_count"),
                "hosts": case.get("hosts"),
                "users": case.get("users"),
                "resolve_comment": case.get("resolve_comment"),
            })

        result["file_artifacts"] = artifacts.get("file_artifacts", [])
        result["file_artifacts_count"] = len(artifacts.get("file_artifacts", []))
        result["network_artifacts"] = artifacts.get("network_artifacts", [])
        result["network_artifacts_count"] = len(artifacts.get("network_artifacts", []))
        result["endpoints"] = endpoints
        result["endpoints_count"] = len(endpoints)
        result["ioc_list"] = ioc_list
        result["ioc_count"] = len(ioc_list)

        return create_response(data=_strip_empty(result))

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error in get_investigation_summary: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get investigation summary: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class InvestigationSummaryModule(BaseModule):
    """Module for consolidated incident investigation summaries."""

    def register_tools(self):
        self._add_tool(get_investigation_summary)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
