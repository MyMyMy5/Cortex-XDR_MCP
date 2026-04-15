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

# Max rows returned per query — keeps results well within context limits
_MAX_ROWS = 50


async def enrich_hash(
    ctx: Context,
    sha256: Annotated[str, Field(description="SHA256 hash to look up across all process and file telemetry.")],
    timeframe_from: Annotated[Optional[Union[int, str]], Field(description="Start of timeframe. Accepts epoch ms (int) or ISO 8601 string (e.g. '2026-04-09'). Optional.")] = None,
    timeframe_to: Annotated[Optional[Union[int, str]], Field(description="End of timeframe. Accepts epoch ms (int) or ISO 8601 string. Optional.")] = None,
    limit: Annotated[int, Field(description="Max results to return. Default 10, max 50. Use a small value for quick lookups; increase only if you need broader spread analysis.", default=10)] = 10,
    timeout: Annotated[int, Field(description="Max seconds to wait for query results. Default 30. Increase to 120 for wide timeframe queries (e.g. 30+ days).", default=30)] = 30,
) -> str:
    """
    Search for a SHA256 hash across all process and file events in the XDR data lake.
    Returns where the hash was seen: which endpoints (with hostnames), processes, file paths, and timestamps.
    Capped at 50 results to avoid context overflow.

    IMPORTANT — Timeframe:
    - If no timeframe is provided, the XDR data lake uses its default search window (typically last 24h).
    - When investigating a specific incident, ALWAYS provide timeframe_from and timeframe_to
      matching the incident's detection timestamps to ensure relevant events are found.
    - Accepts epoch ms integers or ISO 8601 strings (e.g. '2026-04-09').

    Args:
        ctx: The FastMCP context.
        sha256: The SHA256 hash to enrich.
        timeframe_from: Optional start of search window. Epoch ms or ISO 8601 string.
        timeframe_to: Optional end of search window. Epoch ms or ISO 8601 string.
        limit: Max results to return. Default 10, max 50.
        timeout: Max seconds to wait for query results. Default 30. Increase to 120 for wide timeframe queries (e.g. 30+ days).

    Returns:
        JSON with matching events showing endpoint hostname, process name, file path, and timestamp.
    """
    sha256 = sha256.strip().lower()

    query = (
        f'dataset = xdr_data '
        f'| filter actor_process_image_sha256 = "{sha256}" '
        f'  or causality_actor_process_image_sha256 = "{sha256}" '
        f'  or action_file_sha256 = "{sha256}"'
        f'| fields agent_id, agent_hostname, event_type, event_sub_type, event_timestamp, '
        f'  actor_process_image_name, actor_process_image_path, actor_process_command_line, '
        f'  actor_process_image_sha256, causality_actor_process_image_name, '
        f'  action_file_name, action_file_path, action_file_sha256, '
        f'  os_actor_effective_username '
        f'| limit {min(limit, _MAX_ROWS)}'
    )

    try:
        fetcher = await get_fetcher(ctx)
        tf_from = _to_epoch_ms(timeframe_from)
        tf_to = _to_epoch_ms(timeframe_to)
        rows = await _run_xql(fetcher, query, timeframe_from=tf_from, timeframe_to=tf_to, timeout=timeout)
        return create_response(data={
            "sha256": sha256,
            "total_results": len(rows),
            "capped_at": min(limit, _MAX_ROWS),
            "events": rows,
        })
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error in enrich_hash: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to enrich hash: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def search_ioc(
    ctx: Context,
    indicator: Annotated[str, Field(description=(
        "The IOC value to hunt for. Supports: "
        "domain (e.g. 'content-website-analytics.com'), "
        "IP address (e.g. '1.2.3.4'), "
        "SHA256 hash (64 hex chars), "
        "or URL substring."
    ))],
    timeframe_from: Annotated[Optional[Union[int, str]], Field(description="Start of timeframe. Accepts epoch ms (int) or ISO 8601 string (e.g. '2026-04-09'). Optional.")] = None,
    timeframe_to: Annotated[Optional[Union[int, str]], Field(description="End of timeframe. Accepts epoch ms (int) or ISO 8601 string. Optional.")] = None,
    limit: Annotated[int, Field(description="Max results to return. Default 10, max 50. Use a small value for quick lookups; increase only if you need broader spread analysis.", default=10)] = 10,
    timeout: Annotated[int, Field(description="Max seconds to wait for query results. Default 30. Increase to 120 for wide timeframe queries (e.g. 30+ days).", default=30)] = 30,
) -> str:
    """
    Hunt for an IOC (domain, IP, or hash) across all network and file events in the XDR data lake.
    Searches DNS queries, external hostnames, remote IPs, and file hashes.
    Returns results with endpoint hostnames for immediate identification.
    Capped at 50 results to avoid context overflow.

    IMPORTANT — Timeframe:
    - If no timeframe is provided, the XDR data lake uses its default search window (typically last 24h).
    - When investigating a specific incident, ALWAYS provide timeframe_from and timeframe_to
      matching the incident's detection timestamps to ensure relevant events are found.
    - Accepts epoch ms integers or ISO 8601 strings (e.g. '2026-04-09').

    Args:
        ctx: The FastMCP context.
        indicator: Domain, IP, or SHA256 to search for.
        timeframe_from: Optional start of search window. Epoch ms or ISO 8601 string.
            Provide this when investigating a specific incident.
        timeframe_to: Optional end of search window. Epoch ms or ISO 8601 string.
        limit: Max results to return. Default 10, max 50.
        timeout: Max seconds to wait for query results. Default 30. Increase to 120 for wide timeframe queries (e.g. 30+ days).

    Returns:
        JSON with matching events showing endpoint hostname, process, connection details, and timestamp.
    """
    indicator = indicator.strip()

    # Detect indicator type and build appropriate filter
    is_hash = len(indicator) == 64 and all(c in "0123456789abcdefABCDEF" for c in indicator)

    if is_hash:
        ioc_filter = (
            f'actor_process_image_sha256 = "{indicator}" '
            f'or causality_actor_process_image_sha256 = "{indicator}" '
            f'or action_file_sha256 = "{indicator}"'
        )
        fields = (
            "agent_id, agent_hostname, event_type, event_sub_type, event_timestamp, "
            "actor_process_image_name, actor_process_image_path, "
            "actor_process_image_sha256, action_file_name, action_file_path, action_file_sha256, "
            "os_actor_effective_username"
        )
    else:
        # Domain or IP — search network events
        ioc_filter = (
            f'dns_query_name contains "{indicator}" '
            f'or action_external_hostname contains "{indicator}" '
            f'or dst_action_external_hostname contains "{indicator}" '
            f'or action_remote_ip = "{indicator}"'
        )
        fields = (
            "agent_id, agent_hostname, event_type, event_sub_type, event_timestamp, "
            "actor_process_image_name, actor_process_command_line, "
            "action_remote_ip, action_remote_port, action_local_ip, "
            "action_external_hostname, dns_query_name, "
            "os_actor_effective_username"
        )

    query = (
        f'dataset = xdr_data '
        f'| filter {ioc_filter}'
        f'| fields {fields}'
        f'| limit {min(limit, _MAX_ROWS)}'
    )

    try:
        fetcher = await get_fetcher(ctx)
        tf_from = _to_epoch_ms(timeframe_from)
        tf_to = _to_epoch_ms(timeframe_to)
        rows = await _run_xql(fetcher, query, timeframe_from=tf_from, timeframe_to=tf_to, timeout=timeout)
        return create_response(data={
            "indicator": indicator,
            "indicator_type": "hash" if is_hash else "domain_or_ip",
            "total_results": len(rows),
            "capped_at": min(limit, _MAX_ROWS),
            "events": rows,
        })
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error in search_ioc: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to search IOC: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class ThreatIntelModule(BaseModule):
    """Module for hash enrichment and IOC hunting via XQL."""

    def register_tools(self):
        self._add_tool(enrich_hash)
        self._add_tool(search_ioc)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
