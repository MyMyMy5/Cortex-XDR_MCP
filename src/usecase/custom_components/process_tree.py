"""Tool: get_process_tree

Retrieve the full process execution tree (causality chain) for a specific alert.
Fetches the alert to extract the causality actor, then queries all PROCESS events
in the same causality chain via XQL.
"""

import logging
from typing import Annotated, Optional, Union

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
from usecase.custom_components.xql_helpers import _run_xql, _to_epoch_ms
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)

# Hard cap on process tree nodes to prevent context overflow
_MAX_TREE_NODES = 100


async def get_process_tree(
    ctx: Context,
    alert_id: Annotated[int, Field(description=(
        "The alert ID to retrieve the process tree for. "
        "The tool extracts the causality chain (CGO) from the alert and queries "
        "all related PROCESS events on the same endpoint."
    ))],
    timeframe_from: Annotated[Optional[Union[int, str]], Field(description=(
        "Start of timeframe. Accepts epoch ms (int) or ISO 8601 string (e.g. '2026-04-09'). "
        "Optional but recommended — should cover the alert's detection time."
    ))] = None,
    timeframe_to: Annotated[Optional[Union[int, str]], Field(description=(
        "End of timeframe. Accepts epoch ms (int) or ISO 8601 string. Optional."
    ))] = None,
) -> str:
    """
    Retrieve the full process execution tree (causality chain) for a specific alert.

    This tool:
    1. Fetches the alert to extract the agent_id and causality actor process details
    2. Queries all PROCESS events sharing the same causality chain on that endpoint
    3. Returns the processes organized with parent-child relationships

    The result is naturally bounded (typically 5-30 processes per causality chain),
    so context overflow is not a concern.

    Use this tool when:
    - You need to understand HOW a process was spawned (the full parent chain)
    - You want to see all child processes launched by a suspicious parent
    - You're doing root cause analysis on an alert

    Args:
        ctx: The FastMCP context.
        alert_id: The alert ID to get the process tree for.
        timeframe_from: Optional start of timeframe. Epoch ms or ISO 8601 string.
        timeframe_to: Optional end of timeframe. Epoch ms or ISO 8601 string.

    Returns:
        JSON with the causality chain processes, including process names, command lines,
        PIDs, SHA256 hashes, signature info, and parent-child relationships.
    """
    try:
        fetcher = await get_fetcher(ctx)

        # Step 1: Fetch the alert to get agent_id and causality info
        alert_payload = {
            "request_data": {
                "filters": [{"field": "alert_id_list", "operator": "in", "value": [alert_id]}],
                "search_from": 0,
                "search_to": 1,
            }
        }
        alert_response = await fetcher.send_request("/alerts/get_alerts_multi_events", data=alert_payload)
        alerts = alert_response.get("reply", {}).get("alerts", [])
        if not alerts:
            return create_response(data={"error": f"No alert found with ID {alert_id}"}, is_error=True)

        alert = alerts[0]
        agent_id = alert.get("endpoint_id")
        host_name = alert.get("host_name", "unknown")

        if not agent_id:
            return create_response(data={"error": f"Alert {alert_id} has no endpoint_id"}, is_error=True)

        # Extract causality info from the alert's events
        events = alert.get("events", [])
        causality_process_name = None
        causality_cmd = None
        causality_id = None
        actor_pid = None
        for event in events:
            causality_process_name = event.get("causality_actor_process_image_name")
            causality_cmd = event.get("causality_actor_process_command_line")
            # Try multiple field names — the API uses different names in different contexts
            causality_id = (
                event.get("actor_process_causality_id")
                or event.get("causality_actor_process_instance_id")
            )
            actor_pid = event.get("actor_process_os_pid")
            if causality_process_name:
                break

        # Step 2: Query PROCESS events filtered by causality chain when possible.
        # If we have a causality_id, filter to only processes in the same chain —
        # this eliminates noise from unrelated processes on the same endpoint.
        # Fall back to agent_id-only filtering if causality_id is unavailable.
        if causality_id:
            process_filter = (
                f'agent_id = "{agent_id}" and event_type = PROCESS '
                f'and actor_process_causality_id = "{causality_id}"'
            )
        else:
            logger.warning(
                f"No causality_id found for alert {alert_id} — "
                f"falling back to agent-wide PROCESS query"
            )
            process_filter = f'agent_id = "{agent_id}" and event_type = PROCESS'

        query = (
            f'dataset = xdr_data '
            f'| filter {process_filter} '
            f'| fields agent_hostname, '
            f'  actor_process_image_name, actor_process_image_path, actor_process_command_line, '
            f'  actor_process_image_sha256, actor_process_signature_status, actor_process_signature_vendor, '
            f'  actor_process_os_pid, actor_process_causality_id, '
            f'  causality_actor_process_image_name, causality_actor_process_command_line, '
            f'  causality_actor_process_image_path, causality_actor_process_image_sha256, '
            f'  os_actor_process_image_name, os_actor_process_command_line, os_actor_process_os_pid, '
            f'  action_process_image_name, action_process_image_command_line, '
            f'  action_process_image_sha256, action_process_os_pid, '
            f'  event_sub_type, event_timestamp '
            f'| limit {_MAX_TREE_NODES}'
        )

        tf_from = _to_epoch_ms(timeframe_from)
        tf_to = _to_epoch_ms(timeframe_to)

        # If no timeframe provided, use alert detection time ± 1 hour
        if tf_from is None and tf_to is None:
            detection_ts = alert.get("detection_timestamp")
            if detection_ts:
                tf_from = detection_ts - 3600000  # 1 hour before
                tf_to = detection_ts + 3600000    # 1 hour after

        rows = await _run_xql(fetcher, query, timeframe_from=tf_from, timeframe_to=tf_to)

        # Step 3: Deduplicate processes by PID + image name
        seen = set()
        unique_processes = []
        for row in rows:
            pid = row.get("actor_process_os_pid")
            name = row.get("actor_process_image_name")
            key = (pid, name)
            if key not in seen:
                seen.add(key)
                # Clean out None/empty values
                cleaned = {k: v for k, v in row.items() if v is not None and v != "" and v != []}
                unique_processes.append(cleaned)

        result = {
            "alert_id": alert_id,
            "host_name": host_name,
            "agent_id": agent_id,
            "causality_actor": {
                "process_name": causality_process_name,
                "command_line": causality_cmd,
            },
            "causality_id": causality_id,
            "filtered_by_causality": causality_id is not None,
            "total_processes": len(unique_processes),
            "processes": unique_processes,
        }

        return create_response(data=result)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while getting process tree: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get process tree: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class ProcessTreeModule(BaseModule):
    """Module for retrieving process execution trees from Cortex XDR alerts."""

    def register_tools(self):
        self._add_tool(get_process_tree)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
