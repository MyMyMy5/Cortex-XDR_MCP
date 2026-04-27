"""Tool: run_xql_query

Run XQL queries against the Cortex XDR data lake for custom investigations.
Supports timeframe parameters and automatic stream fetching for large result sets.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
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
from usecase.fetcher import get_fetcher

logger = logging.getLogger(__name__)


def _to_epoch_ms(value: Union[int, str, None]) -> Optional[int]:
    """Accept epoch ms (int) or ISO 8601 / human-readable string and return epoch ms."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timeframe value: {value!r}. Use epoch ms or ISO 8601 (e.g. '2024-01-15T00:00:00Z' or '2024-01-15').")


async def _fetch_stream(fetcher, stream_id: str) -> list[dict]:
    """Fetch NDJSON stream results for large XQL result sets (>1000 rows)."""
    stream_payload = {"request_data": {"stream_id": stream_id, "is_gzip_compressed": False}}
    # stream=True returns io.BytesIO; pass Content-Type to override the default application/zip header
    buf = await fetcher.send_request(
        "xql/get_query_results_stream",
        data=stream_payload,
        headers={"Content-Type": "application/json"},
        stream=True,
    )
    text = buf.read().decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


async def run_xql_query(
    ctx: Context,
    query: Annotated[str, Field(description=(
        "XQL query string. Uses xdr_data dataset. "
        "Example: 'dataset = xdr_data | filter agent_id = \"<id>\" and event_type = FILE "
        "| fields action_file_path, action_file_name, event_sub_type, actor_process_image_name, "
        "actor_process_command_line, event_timestamp | limit 100'"
    ))],
    timeframe_from: Annotated[Optional[Union[int, str]], Field(description="Start of timeframe. Accepts epoch milliseconds (e.g. 1705276800000) OR a human-readable string: '2024-01-15', '2024-01-15T00:00:00Z', '2024-01-15 00:00:00'. Incident fields like creation_time and detection_timestamp are already epoch ms and can be passed directly. Optional.")] = None,
    timeframe_to: Annotated[Optional[Union[int, str]], Field(description="End of timeframe. Accepts epoch milliseconds OR a human-readable string: '2024-01-16', '2024-01-16T00:00:00Z', '2024-01-16 00:00:00'. Optional.")] = None,
    timeout: Annotated[int, Field(description="Max seconds to wait for query results. Default 30.", default=30)] = 30,
) -> str:
    """
    Run an XQL (Extended Query Language) query against the Cortex XDR data lake.

    This is a two-step operation: first starts the query, then polls for results.
    Useful for investigating file events, process activity, network connections,
    registry changes, and any other telemetry stored in xdr_data.

    For large result sets (>1000 rows), automatically fetches all results via the stream API.

    Common event_type values: FILE, NETWORK, PROCESS, REGISTRY
    Common event_sub_type values for FILE: FILE_CREATE_NEW, FILE_WRITE, FILE_OPEN,
        FILE_REMOVE, FILE_RENAME, FILE_DIR_CREATE, FILE_DIR_RENAME

    IMPORTANT — XQL sort syntax:
    - Use '| sort field_name asc' or '| sort field_name desc'.
    - The sort clause MUST come AFTER all filter/fields stages and BEFORE '| limit N'.
    - Do NOT combine sort and limit on the same pipe segment.
    - Correct:  '| fields a, b | sort event_timestamp desc | limit 50'
    - Wrong:    '| fields a, b | sort event_timestamp desc | limit 50' with extra trailing tokens
    - If you get a parse error on 'desc' or 'asc', remove the sort clause entirely and just use '| limit N'.
      Sorting is optional; limiting results is more important.

    IMPORTANT — Timeframe parameters:
    - Pass timeframe values as plain strings WITHOUT quotes: timeframe_from='2026-04-09', NOT timeframe_from='"2026-04-09"'
    - Accepted formats: '2026-04-09', '2026-04-09T00:00:00Z', '2026-04-09 00:00:00', or epoch ms as integer (e.g. 1775726175556)
    - The timeframe is applied server-side to scope the data lake scan. If omitted, the server uses its default window (typically last 24h).
    - For investigating incidents, ALWAYS provide timeframe parameters matching the incident's detection timestamps to ensure data is found.

    Args:
        ctx: The FastMCP context.
        query: XQL query string targeting the xdr_data dataset. Do NOT include timeframe
            filters inside the query string — use the timeframe_from/timeframe_to parameters instead.
        timeframe_from: Start of timeframe. Accepts epoch ms as integer (e.g. 1705276800000)
            OR a plain string in ISO 8601 format: '2024-01-15', '2024-01-15T00:00:00Z',
            '2024-01-15 00:00:00'. Do NOT wrap in extra quotes. Incident fields like
            creation_time and detection_timestamp are already epoch ms and can be passed directly.
        timeframe_to: End of timeframe. Same formats as timeframe_from.
        timeout: Seconds to wait for query results before timing out. Default 30.

    Returns:
        JSON response containing query results or error details.
    """
    try:
        fetcher = await get_fetcher(ctx)

        tf_from = _to_epoch_ms(timeframe_from)
        tf_to = _to_epoch_ms(timeframe_to)

        start_payload: dict = {"request_data": {"query": query}}
        if tf_from is not None or tf_to is not None:
            timeframe: dict = {}
            if tf_from is not None:
                timeframe["from"] = tf_from
            if tf_to is not None:
                timeframe["to"] = tf_to
            start_payload["request_data"]["timeframe"] = timeframe

        start_response = await fetcher.send_request("xql/start_xql_query", data=start_payload)
        query_id = start_response.get("reply")
        if not query_id:
            return create_response(data={"error": "Failed to start XQL query", "response": start_response}, is_error=True)

        logger.info(f"XQL query started with ID: {query_id}")

        # Poll for results — request format=json so large results return a stream_id
        poll_payload = {"request_data": {"query_id": query_id, "pending_duration": min(timeout, 30), "format": "json"}}
        elapsed = 0
        poll_interval = 3

        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            result = await fetcher.send_request("xql/get_query_results", data=poll_payload)
            status = result.get("reply", {}).get("status")

            if status == "SUCCESS":
                reply = result["reply"]
                stream_id = reply.get("results", {}).get("stream_id")
                if stream_id:
                    # Large result set — fetch all rows from the stream
                    logger.info(f"XQL result has stream_id {stream_id}, fetching {reply.get('number_of_results')} rows")
                    rows = await _fetch_stream(fetcher, stream_id)
                    reply["results"] = {"data": rows}
                return create_response(data=result)
            elif status == "FAIL":
                return create_response(data={"error": "XQL query failed", "details": result.get("reply", {}).get("error")}, is_error=True)
            elif status in ("PENDING", "RUNNING"):
                continue
            else:
                return create_response(data=result)

        return create_response(data={"error": f"XQL query timed out after {timeout}s", "query_id": query_id}, is_error=True)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while running XQL query: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to run XQL query: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class XQLModule(BaseModule):
    """Module for running XQL queries against the Cortex XDR data lake."""

    def register_tools(self):
        self._add_tool(run_xql_query)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
