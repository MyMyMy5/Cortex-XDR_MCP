"""
Tool: search_file_activity

Search for file events (downloads, writes, deletions, renames) on a specific
endpoint.  Wraps common XQL patterns into a single, easy-to-call tool so the
agent doesn't have to write raw XQL for the most frequent investigation
question: "was anything downloaded / deleted?"
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

_MAX_ROWS = 50

# Browser process names used to detect user-initiated downloads
_BROWSER_PROCESSES = (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe",
)


async def search_file_activity(
    ctx: Context,
    agent_id: Annotated[str, Field(description=(
        "The endpoint agent_id to search file events on. "
        "Get this from get_incidents (hosts field), get_filtered_endpoints, "
        "or alert details (endpoint_id field)."
    ))],
    filename: Annotated[Optional[str], Field(description=(
        "File name or partial name to filter on (case-insensitive contains match). "
        "Examples: 'qBittorrent', '.exe', 'payload.dll'. "
        "Optional — if omitted, returns all file events matching other filters."
    ))] = None,
    file_path: Annotated[Optional[str], Field(description=(
        "File path or partial path to filter on (case-insensitive contains match). "
        "Examples: 'Downloads', 'AppData\\\\Local\\\\Temp'. "
        "Optional — if omitted, no path filter is applied."
    ))] = None,
    event_types: Annotated[Optional[list[str]], Field(description=(
        "List of FILE event sub-types to include. "
        "Allowed values: FILE_CREATE_NEW, FILE_WRITE, FILE_REMOVE, FILE_RENAME, "
        "FILE_OPEN, FILE_DIR_CREATE, FILE_DIR_RENAME. "
        "Default: ['FILE_CREATE_NEW', 'FILE_WRITE', 'FILE_REMOVE', 'FILE_RENAME'] "
        "(covers downloads, writes, deletions, and renames)."
    ))] = None,
    browser_only: Annotated[bool, Field(description=(
        "If true, only return file events where the actor process is a browser "
        "(Chrome, Edge, Firefox, IE, Brave, Opera). "
        "Useful for checking if a user downloaded something. Default: false."
    ))] = False,
    timeframe_from: Annotated[Optional[Union[int, str]], Field(description=(
        "Start of search window. Accepts epoch ms (int) or ISO 8601 string "
        "(e.g. '2026-04-09'). Optional — if omitted, uses the data lake default."
    ))] = None,
    timeframe_to: Annotated[Optional[Union[int, str]], Field(description=(
        "End of search window. Accepts epoch ms (int) or ISO 8601 string. Optional."
    ))] = None,
    limit: Annotated[int, Field(
        description="Max results to return. Default 30, max 50.",
        default=30,
    )] = 30,
    timeout: Annotated[int, Field(
        description="Max seconds to wait for query results. Default 30. Increase to 120 for wide timeframe queries.",
        default=30,
    )] = 30,
) -> str:
    """
    Search for file events (downloads, writes, deletions, renames) on a specific endpoint.

    This is a convenience tool that eliminates the need to write raw XQL queries for
    the most common file-related investigation questions:
    - Was anything downloaded to this machine?
    - Was a specific file deleted?
    - What files did Chrome write to the Downloads folder?
    - Did any browser create new files recently?

    The tool builds and executes an XQL query internally, returning structured results
    with file paths, names, hashes, actor processes, and timestamps.

    Use this tool when:
    - Investigating IOC incidents to check if a file was downloaded
    - Checking if a downloaded file was subsequently deleted
    - Looking for file activity by browsers or specific processes
    - Searching for a specific filename across all file events on an endpoint

    Args:
        ctx: The FastMCP context.
        agent_id: The endpoint agent_id to search.
        filename: Optional filename filter (contains match).
        file_path: Optional file path filter (contains match).
        event_types: Optional list of FILE event sub-types. Defaults to create/write/remove/rename.
        browser_only: If true, only show browser-initiated file events.
        timeframe_from: Optional start of search window.
        timeframe_to: Optional end of search window.
        limit: Max results. Default 30, max 50.

    Returns:
        JSON with matching file events including actor process, file path, hash, and timestamp.
    """
    try:
        fetcher = await get_fetcher(ctx)
        tf_from = _to_epoch_ms(timeframe_from)
        tf_to = _to_epoch_ms(timeframe_to)

        # Default event types cover the most useful file operations
        if not event_types:
            event_types = ["FILE_CREATE_NEW", "FILE_WRITE", "FILE_REMOVE", "FILE_RENAME"]

        # Build the sub-type filter — event_sub_type is a numeric enum in XQL,
        # so values must be unquoted (e.g. FILE_CREATE_NEW, not "FILE_CREATE_NEW")
        sub_type_values = ", ".join(event_types)
        sub_type_filter = f"event_sub_type in ({sub_type_values})"

        # Build optional filters
        extra_filters = []
        if filename:
            extra_filters.append(f'action_file_name contains "{filename}"')
        if file_path:
            extra_filters.append(f'action_file_path contains "{file_path}"')
        if browser_only:
            browser_values = ", ".join(f'"{b}"' for b in _BROWSER_PROCESSES)
            extra_filters.append(f"actor_process_image_name in ({browser_values})")

        # Assemble query
        filter_clause = f'agent_id = "{agent_id}" and event_type = FILE and {sub_type_filter}'
        if extra_filters:
            filter_clause += " and " + " and ".join(extra_filters)

        capped = min(limit, _MAX_ROWS)
        query = (
            f"dataset = xdr_data "
            f"| filter {filter_clause} "
            f"| fields actor_process_image_name, actor_process_command_line, "
            f"action_file_path, action_file_name, action_file_sha256, "
            f"event_sub_type, event_timestamp "
            f"| limit {capped}"
        )

        rows = await _run_xql(fetcher, query, timeframe_from=tf_from, timeframe_to=tf_to, timeout=timeout)

        # Summarize what was found
        downloads = [r for r in rows if r.get("event_sub_type") in ("FILE_CREATE_NEW", "FILE_WRITE")]
        deletions = [r for r in rows if r.get("event_sub_type") == "FILE_REMOVE"]
        renames = [r for r in rows if r.get("event_sub_type") == "FILE_RENAME"]

        summary = {
            "total_events": len(rows),
            "file_creates_and_writes": len(downloads),
            "file_deletions": len(deletions),
            "file_renames": len(renames),
        }

        return create_response(data={
            "agent_id": agent_id,
            "filters_applied": {
                "filename": filename,
                "file_path": file_path,
                "event_types": event_types,
                "browser_only": browser_only,
            },
            "summary": summary,
            "capped_at": capped,
            "events": rows,
        })

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error in search_file_activity: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to search file activity: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class FileActivityModule(BaseModule):
    """Module for searching file events (downloads, deletions, writes) on endpoints."""

    def register_tools(self):
        self._add_tool(search_file_activity)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
