"""
DEPRECATED: This tool has been replaced by investigate_browser_session (in browser_session.py).

Browser History Collector — runs the History_Script_Library script from the
XDR Agent Script Library on a target endpoint and returns the results.

The script name is hardcoded — this tool can ONLY execute
History_Script_Library.  No other script can be invoked through it.
"""

import asyncio
import io
import logging
import os
import zipfile
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

# ── Hardcoded script identity ────────────────────────────────────────────
_SCRIPT_NAME = "History_Script_Library"
_ENTRY_POINT = "run"
_SCRIPT_TIMEOUT = 600  # seconds


async def _resolve_script_uid(fetcher) -> Optional[str]:
    """Look up the script_uid for History_Script_Library from the XDR Script Library."""
    payload = {"request_data": {}}
    resp = await fetcher.send_request("scripts/get_scripts/", data=payload)
    scripts = resp.get("reply", {}).get("scripts", [])
    for script in scripts:
        if script.get("name") == _SCRIPT_NAME:
            return script.get("script_uid")
    return None


async def _resolve_endpoint(fetcher, hostname: str) -> tuple[Optional[str], Optional[str]]:
    """Resolve a hostname to (endpoint_id, endpoint_status) via the XDR API.

    Returns:
        A tuple of (endpoint_id, endpoint_status).
        endpoint_status is one of: 'CONNECTED', 'DISCONNECTED', 'LOST', 'UNINSTALLED', or None.
    """
    payload = {
        "request_data": {
            "filters": [
                {"field": "hostname", "operator": "in", "value": [hostname]}
            ]
        }
    }
    resp = await fetcher.send_request("endpoints/get_endpoint/", data=payload)
    endpoints = resp.get("reply", {}).get("endpoints", [])
    if not endpoints:
        return None, None
    ep = endpoints[0]
    return ep.get("endpoint_id"), ep.get("endpoint_status")


async def _run_script_on_endpoint(fetcher, endpoint_id, script_uid, parameters, timeout=_SCRIPT_TIMEOUT):
    """Execute History_Script_Library on an endpoint, poll status, then fetch results."""

    # Start the script
    payload = {
        "request_data": {
            "script_uid": script_uid,
            "timeout": timeout,
            "filters": [
                {"field": "endpoint_id_list", "operator": "in", "value": [endpoint_id]}
            ],
            "parameters_values": parameters,
        }
    }

    start_resp = await fetcher.send_request("scripts/run_script/", data=payload)
    logger.info("run_script response: %s", start_resp)
    action_id = start_resp.get("reply", {}).get("action_id")
    if not action_id:
        return {"error": "Failed to start script: {}".format(start_resp)}

    poll_payload = {"request_data": {"group_action_id": action_id}}

    # Phase 1: Poll execution status using get_action_status
    elapsed = 0
    poll_interval = 5
    final_status = None

    while elapsed < timeout:
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval

        try:
            status_resp = await fetcher.send_request(
                "actions/get_action_status/", data=poll_payload
            )
            reply = status_resp.get("reply", {})
            data = reply.get("data", {})

            logger.info("Poll raw reply keys: %s, data: %s", list(reply.keys()), data)

            # data is a dict of endpoint_id -> status
            if data:
                ep_status = list(data.values())[0] if data else ""
                logger.info("Script poll at %ds: status=%s", elapsed, ep_status)

                if ep_status in ("COMPLETED_SUCCESSFULLY", "COMPLETED"):
                    final_status = "success"
                    break
                elif ep_status in ("FAILED", "EXPIRED", "CANCELED", "ABORTED", "TIMEOUT"):
                    final_status = "failed"
                    break
                # PENDING_ABORT, IN_PROGRESS, PENDING — keep polling
        except Exception as e:
            logger.warning("Poll error at %ds: %s", elapsed, e)

    if final_status is None:
        return {
            "status": "timeout",
            "action_id": action_id,
            "endpoint_id": endpoint_id,
            "error": "Script did not complete within {} seconds".format(timeout),
        }

    # Phase 2: Fetch actual results
    results_payload = {"request_data": {"action_id": action_id}}
    try:
        results_resp = await fetcher.send_request(
            "scripts/get_script_execution_results/", data=results_payload
        )
        reply = results_resp.get("reply", {})
        results = reply.get("results", [])

        if results:
            result = results[0]
            return {
                "status": final_status,
                "action_id": action_id,
                "endpoint_id": endpoint_id,
                "standard_output": result.get("standard_output", ""),
                "return_value": result.get("return_value", ""),
                "execution_status": result.get("general_status", final_status),
                "error": result.get("errors") if final_status == "failed" else None,
            }
        return {
            "status": final_status,
            "action_id": action_id,
            "endpoint_id": endpoint_id,
            "standard_output": reply.get("standard_output", str(reply)),
            "return_value": "",
            "execution_status": final_status,
        }
    except Exception as e:
        return {
            "status": final_status,
            "action_id": action_id,
            "endpoint_id": endpoint_id,
            "error": "Script completed but failed to fetch results: {}".format(e),
        }


async def _download_result_files(fetcher, action_id, endpoint_id, output_path: str) -> int:
    """Download the full script execution result files from XDR to a local file.

    This is a two-step process:
    1. Call get_script_execution_results_files to get a signed download URL
    2. Stream-download the ZIP from that URL, extract, and write to output_path

    Args:
        fetcher: The Fetcher instance.
        action_id: The script execution action ID.
        endpoint_id: The endpoint ID the script ran on.
        output_path: Local file path to write the extracted content to.

    Returns:
        The size in bytes of the written file.

    Raises:
        Exception on any failure (API error, download error, extraction error).
    """
    # Step 1: Get the signed download URL
    payload = {
        "request_data": {
            "action_id": str(action_id),
            "endpoint_id": endpoint_id,
        }
    }
    resp = await fetcher.send_request(
        "scripts/get_script_execution_results_files/",
        data=payload,
    )
    download_url = resp.get("reply", {}).get("DATA")
    if not download_url:
        raise ValueError("API did not return a download URL: {}".format(resp))

    # Step 2: Download the actual ZIP from the signed URL.
    # The URL is absolute (https://api-xxx.xdr.../public_api/v1/download/...),
    # so we extract the path portion and use omit_papi_prefix=True.
    from urllib.parse import urlparse
    parsed = urlparse(download_url)
    download_path = parsed.path
    if parsed.query:
        download_path += "?" + parsed.query

    zip_buffer = await fetcher.send_request(
        download_path,
        method="GET",
        omit_papi_prefix=True,
        stream=True,
    )

    # Step 3: Extract ZIP contents and write to output file
    raw_bytes = zip_buffer.read()
    zip_buffer.seek(0)

    # Ensure parent directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_buffer, "r") as zf:
            stdout_content = None
            json_content = None
            for name in zf.namelist():
                with zf.open(name) as member:
                    content = member.read().decode("utf-8", errors="replace")
                    stripped = content.strip()
                    if stripped.startswith("{") or stripped.startswith("["):
                        json_content = stripped
                    else:
                        stdout_content = content

        # Prefer the JSON return_value — it has richer fields (Title, Profile, VisitCount).
        # Parse it and format into clean human-readable lines.
        if json_content:
            import json as json_module
            data = json_module.loads(json_content)
            lines = []
            lines.append("=" * 80)
            lines.append("Browser History — {} | TZ: {}".format(
                data.get("hostname", ""), data.get("timezone", "")))
            lines.append("Total entries: {}".format(data.get("total_entries", 0)))
            lines.append("Total downloads: {}".format(data.get("total_downloads", 0)))
            lines.append("=" * 80)

            entries = data.get("entries", [])
            if entries:
                lines.append("")
                lines.append("Timestamp | User | Browser | Profile | VisitType | VisitCount | Title | URL | ReferrerURL")
                lines.append("-" * 80)
                for e in entries:
                    lines.append("[{}] | {} | {} | {} | {} | {} | {} | {} | {}".format(
                        e.get("Timestamp", ""),
                        e.get("User", ""),
                        e.get("Browser", ""),
                        e.get("Profile", ""),
                        e.get("VisitType", ""),
                        e.get("VisitCount", ""),
                        e.get("Title", ""),
                        e.get("URL", ""),
                        e.get("ReferrerURL", ""),
                    ))

            downloads = data.get("downloads", [])
            if downloads:
                lines.append("")
                lines.append("=" * 80)
                lines.append("DOWNLOAD HISTORY: {} entries".format(len(downloads)))
                lines.append("=" * 80)
                lines.append("Timestamp | User | Browser | State | DangerType | SizeMB | Opened | MimeType | FilePath | SourceURL | Referrer")
                lines.append("-" * 80)
                for d in downloads:
                    lines.append("[{}] | {} | {} | {} | {} | {} | {} | {} | {} | {} | {}".format(
                        d.get("Timestamp", ""),
                        d.get("User", ""),
                        d.get("Browser", ""),
                        d.get("State", ""),
                        d.get("DangerType", ""),
                        d.get("SizeMB", ""),
                        d.get("Opened", ""),
                        d.get("MimeType", ""),
                        d.get("FilePath", ""),
                        d.get("SourceURL", ""),
                        d.get("Referrer", ""),
                    ))

            file_content = "\n".join(lines)
        elif stdout_content:
            file_content = stdout_content
        else:
            file_content = raw_bytes.decode("utf-8", errors="replace")

    except zipfile.BadZipFile:
        # Not a ZIP — write raw bytes as text
        file_content = raw_bytes.decode("utf-8", errors="replace")

    # Normalize line endings to avoid double-spacing from \r\n
    file_content = file_content.replace("\r\n", "\n").replace("\r", "\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(file_content)

    return os.path.getsize(output_path)


async def collect_browser_history(
    ctx: Context,
    hostname: Annotated[str, Field(description="The hostname of the endpoint to collect browser history from (e.g. 'LAP-89491').")],
    target_user: Annotated[str, Field(description="Windows username to collect from, or '*' for all users.", default="*")] = "*",
    browser_filter: Annotated[str, Field(description="Browser to collect: '*' for all, 'chrome', 'edge', 'firefox'.", default="*")] = "*",
    mode: Annotated[str, Field(description="Collection mode: 'history' for browsing history, 'downloads' for download history, 'both' for both.", default="history")] = "history",
    start_date: Annotated[str, Field(description="Start time in endpoint local time: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, HH:MM, epoch ms, or '*' for no limit.", default="*")] = "*",
    end_date: Annotated[str, Field(description="End time in endpoint local time: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, HH:MM, epoch ms, or '*' for no limit.", default="*")] = "*",
    url_filter: Annotated[str, Field(description="URL or domain to filter on (contains match). '*' for all URLs. Example: 'google.com' or '176.32.193.16'.", default="*")] = "*",
    max_results: Annotated[str, Field(description="Maximum number of entries to return. '0' = unlimited.", default="0")] = "0",
    output_file_path: Annotated[Optional[str], Field(description="If provided, downloads the full untruncated result files from XDR (the same data as 'Download Files' in the Action Center) and writes them to this file path on the machine running the MCP server. The file is written in UTF-8 encoding. Use this when the output is too large to fit in the MCP response (e.g. thousands of history entries). When set, the MCP response returns only a compact summary instead of the full output. Example: 'C:/Users/analyst/Desktop/history.txt' or '/tmp/history.txt'.", default=None)] = None,
) -> str:
    """Collect browser history from an endpoint by running the History_Script_Library
    script from the XDR Agent Script Library.

    This tool remotely executes a browser history collection script on the target
    endpoint. The script reads Chrome, Edge, and Firefox history databases and
    returns visit records including URL, timestamp, visit type (Typed/Link/etc.),
    and referrer URL.

    Use this tool when you need to determine:
    - Whether a user directly typed/navigated to a URL or IP address
    - The referrer chain showing how a user reached a specific page
    - Full browsing timeline around an incident detection time
    - Whether a visited URL was a direct navigation vs embedded resource

    The visit_type field is key for intent analysis:
    - "Typed" = user typed the URL in the address bar
    - "Link" = user clicked a link on another page
    - "Generated" = browser-generated navigation (e.g. search results)
    - "Form Submit" = form submission
    - "Reload" = page reload
    - "Auto Subframe" = embedded resource (iframe, etc.)
    - "Bookmark" = opened from bookmarks

    IMPORTANT: The endpoint must be online and connected for this to work.
    The script runs under the SYSTEM account on the endpoint.

    Args:
        ctx: The FastMCP context.
        hostname: The hostname of the target endpoint.
        target_user: Windows username or '*' for all users.
        browser_filter: Browser filter or '*' for all.
        start_date: Start of time range or '*' for no limit.
        end_date: End of time range or '*' for no limit.
        url_filter: URL or domain to filter on (contains match). '*' for all URLs.
        max_results: Max entries, '0' for unlimited.
        output_file_path: If provided, downloads the full untruncated result files
            from XDR (equivalent to "Download Files" in the Action Center) and
            writes them to this file path on the MCP server machine. The standard
            output is still included in the MCP response so the agent can analyze
            it. Use this when collecting large datasets that would be truncated
            in the normal response.

    Returns:
        JSON response containing the browser history entries with timestamps,
        URLs, visit types, and referrer URLs. If output_file_path is set,
        also includes the file path and size of the full downloaded output.
    """
    try:
        fetcher = await get_fetcher(ctx)

        # Resolve hostname to endpoint_id and check connectivity
        endpoint_id, endpoint_status = await _resolve_endpoint(fetcher, hostname)
        if not endpoint_id:
            return create_response(
                data={"error": "Endpoint '{}' not found".format(hostname)},
                is_error=True,
            )

        # Resolve script UID from the Script Library
        script_uid = await _resolve_script_uid(fetcher)
        if not script_uid:
            return create_response(
                data={"error": "Script '{}' not found in the XDR Script Library".format(_SCRIPT_NAME)},
                is_error=True,
            )

        # Build script parameters
        parameters = {
            "target_user": target_user,
            "browser_filter": browser_filter,
            "mode": mode,
            "start_date": start_date,
            "end_date": end_date,
            "url_filter": url_filter,
            "max_results": max_results,
        }

        # If endpoint is not connected, initiate the script (it will queue
        # and execute when the endpoint reconnects) but do NOT wait for
        # results — there is no point blocking for the full timeout.
        if endpoint_status != "CONNECTED":
            # Start the script so it queues for when the endpoint comes online
            start_payload = {
                "request_data": {
                    "script_uid": script_uid,
                    "timeout": _SCRIPT_TIMEOUT,
                    "filters": [
                        {"field": "endpoint_id_list", "operator": "in", "value": [endpoint_id]}
                    ],
                    "parameters_values": parameters,
                }
            }
            start_resp = await fetcher.send_request("scripts/run_script/", data=start_payload)
            action_id = start_resp.get("reply", {}).get("action_id")

            return create_response(data={
                "hostname": hostname,
                "endpoint_id": endpoint_id,
                "endpoint_status": endpoint_status,
                "script_status": "queued_pending_connection",
                "action_id": action_id,
                "standard_output": "",
                "error": None,
                "message": (
                    "Endpoint '{}' is currently {} (not connected). "
                    "The script has been queued (action_id: {}) and will execute "
                    "when the endpoint reconnects. Use get_action_status to check "
                    "progress later."
                ).format(hostname, endpoint_status, action_id),
            })

        # Endpoint is connected — execute and wait for results
        result = await _run_script_on_endpoint(fetcher, endpoint_id, script_uid, parameters)

        standard_output = result.get("standard_output", "")

        # Build the base response (always includes standard_output)
        response_data = {
            "hostname": hostname,
            "endpoint_id": endpoint_id,
            "script_status": result.get("status"),
            "action_id": result.get("action_id"),
            "standard_output": standard_output,
            "return_value": result.get("return_value", ""),
            "error": result.get("error"),
        }

        # If output_file_path is set, also download the full result files from
        # XDR in the background (the same ZIP from "Download Files" in the
        # Action Center) and extract the contents to the specified path.
        # The standard_output is still returned so the agent can analyze it.
        if output_file_path and result.get("action_id"):
            try:
                file_size = await _download_result_files(
                    fetcher, result["action_id"], endpoint_id, output_file_path
                )

                response_data["output_file_path"] = output_file_path
                response_data["output_file_size_bytes"] = file_size
                response_data["output_file_message"] = "Full output written to {}".format(output_file_path)

            except Exception as e:
                logger.warning(
                    "Failed to download result files for action %s: %s. "
                    "Returning standard_output only.",
                    result.get("action_id"), e,
                )
                response_data["output_file_error"] = (
                    "Failed to download full result files: {}. "
                    "The standard_output above is still available but may be truncated."
                ).format(e)

        return create_response(data=response_data)

    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError,
            PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception("PAPI error while collecting browser history: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception("Failed to collect browser history: %s", e)
        return create_response(data={"error": str(e)}, is_error=True)


class BrowserHistoryModule(BaseModule):
    """Module for collecting browser history from endpoints via XDR Script Library.

    Note: The collect_browser_history tool has been replaced by
    investigate_browser_session (in browser_session.py) which provides a unified
    interface for both history retrieval and correlated investigation.
    The helper functions (_resolve_endpoint, _resolve_script_uid,
    _run_script_on_endpoint, _download_result_files) are still used by the new tool.
    """

    def register_tools(self):
        # Tool removed — replaced by investigate_browser_session
        pass

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
