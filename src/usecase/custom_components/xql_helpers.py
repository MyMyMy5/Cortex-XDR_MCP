"""
Shared XQL helpers for custom components that need to run XQL queries.

Provides _to_epoch_ms and _run_xql so individual tool modules don't
duplicate the XQL execution logic from threat_intel.py / xql.py.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Union

logger = logging.getLogger(__name__)


def _to_epoch_ms(value: Union[int, str, None]) -> Optional[int]:
    """Accept epoch ms (int) or ISO 8601 / human-readable string and return epoch ms.

    Supports: epoch ms int, epoch ms as string (e.g. '1776277687000'),
    'YYYY-MM-DD', 'YYYY-MM-DDTHH:MM:SSZ', 'YYYY-MM-DDTHH:MM:SS',
    'YYYY-MM-DD HH:MM:SS'.
    """
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        # Handle epoch ms passed as a string (e.g. "1776277687000")
        if stripped.isdigit():
            return int(stripped)
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(stripped, fmt).replace(tzinfo=timezone.utc)
                return int(dt.timestamp() * 1000)
            except ValueError:
                continue
    raise ValueError(
        f"Cannot parse timeframe value: {value!r}. "
        "Use epoch ms or ISO 8601 (e.g. '2024-01-15T00:00:00Z' or '2024-01-15')."
    )


async def _run_xql(
    fetcher,
    query: str,
    timeframe_from: Optional[int] = None,
    timeframe_to: Optional[int] = None,
    timeout: int = 30,
) -> list[dict]:
    """Run an XQL query and return result rows.

    Handles the start → poll → (optional stream fetch) lifecycle.

    Args:
        fetcher: Fetcher instance with send_request().
        query: XQL query string.
        timeframe_from: Optional start epoch ms.
        timeframe_to: Optional end epoch ms.
        timeout: Max seconds to wait.

    Returns:
        List of result dicts.
    """
    start_payload: dict = {"request_data": {"query": query}}
    if timeframe_from is not None or timeframe_to is not None:
        timeframe: dict = {}
        if timeframe_from is not None:
            timeframe["from"] = timeframe_from
        if timeframe_to is not None:
            timeframe["to"] = timeframe_to
        start_payload["request_data"]["timeframe"] = timeframe

    start = await fetcher.send_request("xql/start_xql_query", data=start_payload)
    query_id = start.get("reply")
    if not query_id:
        raise RuntimeError(f"Failed to start XQL query: {start}")

    poll_payload = {
        "request_data": {
            "query_id": query_id,
            "pending_duration": min(timeout, 30),
            "format": "json",
        }
    }
    elapsed = 0
    while elapsed < timeout:
        await asyncio.sleep(3)
        elapsed += 3
        result = await fetcher.send_request("xql/get_query_results", data=poll_payload)
        status = result.get("reply", {}).get("status")
        if status == "SUCCESS":
            reply = result["reply"]
            stream_id = reply.get("results", {}).get("stream_id")
            if stream_id:
                buf = await fetcher.send_request(
                    "xql/get_query_results_stream",
                    data={"request_data": {"stream_id": stream_id, "is_gzip_compressed": False}},
                    headers={"Content-Type": "application/json"},
                    stream=True,
                )
                text = buf.read().decode("utf-8")
                return [json.loads(line) for line in text.splitlines() if line.strip()]
            return reply.get("results", {}).get("data", [])
        elif status == "FAIL":
            err = result.get("reply", {}).get("error")
            raise RuntimeError(f"XQL query failed: {err}")
    raise TimeoutError(f"XQL query timed out after {timeout}s")
