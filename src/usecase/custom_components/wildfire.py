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


async def retrieve_file_from_endpoint(
    ctx: Context,
    endpoint_id: Annotated[str, Field(description="The endpoint ID to retrieve the file from. Get this from get_filtered_endpoints or alert details.")],
    windows_file_paths: Annotated[Optional[list[str]], Field(description="List of Windows file paths to retrieve (e.g. ['C:\\\\Users\\\\user\\\\Downloads\\\\malware.exe']). Use this OR generic_file_path.", default=None)] = None,
    linux_file_paths: Annotated[Optional[list[str]], Field(description="List of Linux file paths to retrieve.", default=None)] = None,
    mac_file_paths: Annotated[Optional[list[str]], Field(description="List of macOS file paths to retrieve.", default=None)] = None,
    generic_file_path: Annotated[Optional[str], Field(description="A single file path that works on any OS. Use this for convenience instead of the OS-specific lists.", default=None)] = None,
) -> str:
    """Initiate a file retrieval from a Cortex XDR endpoint.

    This triggers the XDR agent on the endpoint to collect the specified file(s)
    and upload them to the Cortex XDR cloud. Once complete, use get_file_retrieval_details
    with the returned action_id to get the download link.

    You can retrieve up to 20 files from up to 10 endpoints per request.

    IMPORTANT: This is a response action — it sends a command to the live agent.
    The endpoint must be online and connected for this to work.

    Args:
        ctx: The FastMCP context.
        endpoint_id: The endpoint agent ID.
        windows_file_paths: Windows file paths to retrieve.
        linux_file_paths: Linux file paths to retrieve.
        mac_file_paths: macOS file paths to retrieve.
        generic_file_path: A single file path (any OS).

    Returns:
        JSON with the action_id to track the retrieval status.
    """
    files = {}
    if windows_file_paths:
        files["windows"] = windows_file_paths
    if linux_file_paths:
        files["linux"] = linux_file_paths
    if mac_file_paths:
        files["macos"] = mac_file_paths
    if generic_file_path:
        files["generic_file_path"] = generic_file_path

    if not files:
        return create_response(
            data={"error": "At least one file path must be provided (windows_file_paths, linux_file_paths, mac_file_paths, or generic_file_path)."},
            is_error=True,
        )

    payload = {
        "request_data": {
            "endpoint_id_list": [endpoint_id],
            "files": files,
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/file_retrieval/", data=payload)
        reply = response_data.get("reply", {})
        action_id = reply.get("action_id")

        return create_response(data={
            "action_id": action_id,
            "endpoint_id": endpoint_id,
            "files_requested": files,
            "status": "initiated",
            "next_step": f"Use get_file_retrieval_details with action_id={action_id} to get the download link once the retrieval completes. Use get_action_status with action_id={action_id} to check progress.",
        })
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error during file retrieval: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to initiate file retrieval: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_file_retrieval_details(
    ctx: Context,
    action_id: Annotated[int, Field(description="The action ID returned by retrieve_file_from_endpoint.")],
) -> str:
    """Get the download details for a previously initiated file retrieval.

    After initiating a file retrieval with retrieve_file_from_endpoint, use this
    tool with the returned action_id to get the download link for the retrieved file.

    The file is typically available as a password-protected ZIP. The download link
    is temporary and expires.

    Args:
        ctx: The FastMCP context.
        action_id: The action ID from the retrieve_file_from_endpoint response.

    Returns:
        JSON with the download link and file details.
    """
    payload = {
        "request_data": {
            "group_action_id": action_id,
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("actions/file_retrieval_details/", data=payload)
        reply = response_data.get("reply", {})

        return create_response(data={
            "action_id": action_id,
            "details": reply,
        })
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting file retrieval details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get file retrieval details: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def get_action_status(
    ctx: Context,
    action_id: Annotated[int, Field(description="The action ID to check the status of (from retrieve_file_from_endpoint, quarantine_file, etc.).")],
) -> str:
    """Check the status of a response action (file retrieval, quarantine, scan, etc.).

    Use this to poll whether a previously initiated action has completed.
    Common statuses: PENDING, IN_PROGRESS, COMPLETED_SUCCESSFULLY, FAILED, CANCELED, EXPIRED.

    Args:
        ctx: The FastMCP context.
        action_id: The action ID to check.

    Returns:
        JSON with the action status and details.
    """
    payload = {
        "request_data": {
            "group_action_id": action_id,
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("actions/get_action_status/", data=payload)
        reply = response_data.get("reply", {})

        return create_response(data={
            "action_id": action_id,
            "status": reply,
        })
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error getting action status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to get action status: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def quarantine_file(
    ctx: Context,
    endpoint_id: Annotated[str, Field(description="The endpoint ID where the file should be quarantined.")],
    file_hash: Annotated[str, Field(description="SHA256 hash of the file to quarantine.")],
    file_path: Annotated[str, Field(description="Full path of the file on the endpoint (e.g. 'C:\\\\Users\\\\user\\\\Downloads\\\\malware.exe').")],
) -> str:
    """Quarantine a file on a Cortex XDR endpoint.

    This sends a quarantine command to the XDR agent on the specified endpoint.
    The agent will move the file to a secure quarantine location, preventing execution.

    IMPORTANT: This is a destructive response action. The file will be removed from
    its original location. Use restore_file to undo if needed.

    The endpoint must be online and connected for this to work.

    Args:
        ctx: The FastMCP context.
        endpoint_id: The endpoint agent ID.
        file_hash: SHA256 hash of the file.
        file_path: Full file path on the endpoint.

    Returns:
        JSON with the action_id to track the quarantine status.
    """
    payload = {
        "request_data": {
            "endpoint_id_list": [endpoint_id],
            "file_path": file_path,
            "file_hash": file_hash,
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/quarantine/", data=payload)
        reply = response_data.get("reply", {})
        action_id = reply.get("action_id")

        return create_response(data={
            "action_id": action_id,
            "endpoint_id": endpoint_id,
            "file_hash": file_hash,
            "file_path": file_path,
            "status": "quarantine initiated",
            "next_step": f"Use get_action_status with action_id={action_id} to check if the quarantine completed.",
        })
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error during file quarantine: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to quarantine file: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def scan_endpoints(
    ctx: Context,
    endpoint_id_list: Annotated[list[str], Field(description="List of endpoint IDs to scan. Maximum 1000 endpoints.")],
) -> str:
    """Initiate a full malware scan on one or more Cortex XDR endpoints.

    Sends a scan command to the XDR agents on the specified endpoints.
    The agents will perform a full disk scan using local analysis and WildFire.

    Use get_action_status with the returned action_id to track scan progress.

    Args:
        ctx: The FastMCP context.
        endpoint_id_list: List of endpoint agent IDs to scan.

    Returns:
        JSON with the action_id to track the scan status.
    """
    if not endpoint_id_list:
        return create_response(data={"error": "endpoint_id_list cannot be empty."}, is_error=True)

    payload = {
        "request_data": {
            "filters": [
                {
                    "field": "endpoint_id_list",
                    "operator": "in",
                    "value": endpoint_id_list,
                }
            ],
        }
    }

    try:
        fetcher = await get_fetcher(ctx)
        response_data = await fetcher.send_request("endpoints/scan/", data=payload)
        reply = response_data.get("reply", {})
        action_id = reply.get("action_id")

        return create_response(data={
            "action_id": action_id,
            "endpoints_count": len(endpoint_id_list),
            "status": "scan initiated",
            "next_step": f"Use get_action_status with action_id={action_id} to check scan progress.",
        })
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error during endpoint scan: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to initiate endpoint scan: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


class WildFireModule(BaseModule):
    """Module for file retrieval, quarantine, and scanning via Cortex XDR response actions."""

    def register_tools(self):
        self._add_tool(retrieve_file_from_endpoint)
        self._add_tool(get_file_retrieval_details)
        self._add_tool(get_action_status)
        # self._add_tool(quarantine_file)  # Disabled — destructive action
        self._add_tool(scan_endpoints)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
