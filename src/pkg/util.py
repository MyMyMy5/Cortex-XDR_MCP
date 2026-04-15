import logging
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from pkg.openapi.openapi import bundle_specs

logger = logging.getLogger(__name__)

MAIN_DIR = Path(__file__).parent.parent.parent
SCRIPT_DIR = MAIN_DIR / "src"
RESOURCES_DIR = SCRIPT_DIR / "entities" / "resources"
PKG_DIR = SCRIPT_DIR / "pkg"
OPENAPI_DIR = PKG_DIR / "openapi"
USECASES_DIR = SCRIPT_DIR / "usecase"
BUILTINS_DIR = USECASES_DIR / "builtin_components"
CUSTOM_DIR = USECASES_DIR / "custom_components"
REMOTE_DIR = USECASES_DIR / "remote_components"

# ── Automatic epoch-ms → human-readable timestamp conversion ──────────────
# Field names (exact match) whose integer values are epoch milliseconds.
_EPOCH_MS_FIELDS: set[str] = {
    # Incidents
    "creation_time", "modification_time", "detection_time", "resolved_timestamp",
    # Alerts / Issues
    "detection_timestamp", "local_insert_ts", "last_modified_ts",
    "server_creation_time",
    # Events (XQL, process tree, file activity, etc.)
    "event_timestamp", "insert_timestamp", "_time",
    # Endpoints
    "first_seen", "last_seen", "install_date",
    "content_release_timestamp", "last_content_update_time", "isolated_date",
    # Comments / misc
    "created_time",
}


def _epoch_ms_to_str(epoch_ms: int) -> str:
    """Convert epoch milliseconds to 'YYYY-MM-DD HH:MM:SS IDT/IST' string in Israel timezone."""
    try:
        dt_utc = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
        # Israel: UTC+3 in summer (IDT, last Friday before April 2 → last Sunday before October)
        # UTC+2 in winter (IST). Simplified: March–October = +3, November–February = +2.
        month = dt_utc.month
        if 4 <= month <= 10:
            offset, tz_name = timedelta(hours=3), "IDT"
        elif month == 3:
            # DST starts last Friday before April 2 — approximate as March 26+
            offset, tz_name = (timedelta(hours=3), "IDT") if dt_utc.day >= 26 else (timedelta(hours=2), "IST")
        else:
            offset, tz_name = timedelta(hours=2), "IST"
        dt_local = dt_utc + offset
        return dt_local.strftime(f"%Y-%m-%d %H:%M:%S {tz_name}")
    except (OSError, ValueError, OverflowError):
        return str(epoch_ms)


def _convert_epoch_timestamps(obj):
    """
    Recursively walk a dict/list and add a human-readable '*_str' sibling
    for every known epoch-ms timestamp field.

    Example:
        {"creation_time": 1776194426000}
        →
        {"creation_time": 1776194426000, "creation_time_str": "2026-04-12 ..."}
    """
    if isinstance(obj, dict):
        additions: dict[str, str] = {}
        for key, value in obj.items():
            if key in _EPOCH_MS_FIELDS and isinstance(value, (int, float)) and value > 1_000_000_000_000:
                additions[f"{key}_str"] = _epoch_ms_to_str(int(value))
            elif isinstance(value, (dict, list)):
                _convert_epoch_timestamps(value)
        obj.update(additions)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _convert_epoch_timestamps(item)


def create_response(data: dict, is_error: bool = False) -> str:
    """
    Create a JSON response with success status indicator.

    This function takes a dictionary of data and adds a success field to indicate
    whether the operation was successful or resulted in an error. The response
    is returned as a formatted JSON string.

    Args:
        data (dict): The data dictionary to include in the response.
        is_error (bool, optional): Flag indicating if this is an error response.
                                 Defaults to False.

    Returns:
        str: A JSON string containing the data with an added 'success' field.
             The JSON is formatted with 2-space indentation and non-ASCII
             characters are preserved.

    Example:
        >>> data = {"message": "Operation completed", "count": 5}
        >>> create_response(data)
        '{\n  "message": "Operation completed",\n  "count": 5,\n  "success": "true"\n}'

        >>> error_data = {"error": "Invalid input"}
        >>> create_response(error_data, is_error=True)
        '{\n  "error": "Invalid input",\n  "success": "false"\n}'
    """
    success = "true" if not is_error else "false"
    _convert_epoch_timestamps(data)
    data["success"] = success
    return json.dumps(data, indent=2, ensure_ascii=False)

def read_resource(file_path) -> str:
    """
    Read a file from the resources directory.

    This is a convenience wrapper around read_file() that specifically reads
    files from the predefined RESOURCES_DIR.

    Args:
        file_path (str): Relative path to the file within the resources directory.

    Returns:
        str: The contents of the file as a string.

    Raises:
        ValueError: If path traversal is detected in the file path or if the
                   file cannot be decoded as valid Unicode text.
        FileNotFoundError: If the specified file does not exist in the
                          resources directory.
        PermissionError: If access is denied to the specified file due to
                        insufficient permissions.
    """
    return read_file(file_path, RESOURCES_DIR)

def read_file(file_path: str, file_directory: Path) -> str:
    """
    Safely read a file from a specified directory.

    This function reads a file from the specified directory with security
    measures to prevent path traversal attacks. The file path is validated
    to ensure it stays within the directory boundary.

    Args:
        file_path (str): Relative path to the file within the target directory.
                        Must not contain path traversal sequences like '../'.
        file_directory (Path): The base directory from which to read the file.

    Returns:
        str: The contents of the file as a string.

    Raises:
        ValueError: If path traversal is detected in the file path or if the
                   file cannot be decoded as valid Unicode text.
        FileNotFoundError: If the specified file does not exist in the
                          target directory.
        PermissionError: If access is denied to the specified file due to
                        insufficient permissions.

    Example:
        >>> content = read_file("config.json", Path("/app/resources"))
        >>> print(content)
        # Contents of /app/resources/config.json

        >>> read_file("../../../etc/passwd", Path("/app/resources"))  # This will raise ValueError
        ValueError: Invalid file path: path traversal detected

    Security:
        - Prevents path traversal attacks by validating the resolved path
        - Only allows access to files within the specified directory
        - Handles encoding errors gracefully
    """
    try:
        full_path = (file_directory / file_path).resolve()
        if not str(full_path).startswith(str(file_directory.resolve())):
            raise ValueError("Invalid file path: path traversal detected")

        with open(full_path) as file:
            return file.read()
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Resource file not found: {file_path}") from e
    except PermissionError as e:
        raise PermissionError(f"Access denied to resource file: {file_path}") from e
    except UnicodeDecodeError as e:
        raise ValueError(f"Unable to decode file {file_path}: {e}") from e

def get_papi_auth_headers(api_key: str, api_key_id: str) -> dict:
    """
    Generate authentication headers for Palo Alto Networks API requests.

    Args:
        api_key (str): The API key for authentication.
        api_key_id (str): The API key ID for authentication.

    Returns:
        dict: A dictionary containing the required authentication headers.
    """
    return {
        "Authorization": api_key,
        "X-XDR-AUTH-ID": api_key_id,
    }


def get_papi_url(papi_url_value: str) -> str:
    """
    Construct and return the public API URL from environment variables.

    Checks for custom URL override first, then falls back to the standard URL.
    Ensures the URL uses HTTPS protocol and includes the 'api-' subdomain prefix.

    Args:
        papi_url_value (str): The URL value to construct the URL from.

    Returns:
        str: The properly formatted public API URL with HTTPS protocol and api- prefix.

    Raises:
        ValueError: If the URL environment variable is not set.
    """
    url = papi_url_value
    if not url:
        raise ValueError("No public API URL provided")

    if not url.startswith("https://"):
        if url.startswith("http://"):
            url = url.replace("http://", "https://")
        else:
            url = f"https://{url}"

    if "api-" not in url:
        url = url.replace("https://", "https://api-")

    return url


def bundle_openapi_from_folders():
    """
    Bundle OpenAPI specifications from predefined builtin and custom folders.

    This is a convenience function that bundles OpenAPI specifications from
    the standard builtin tools and custom tools directories.

    Returns:
        dict: A dictionary containing the bundled OpenAPI specifications.

    Raises:
        ValueError: If path traversal is detected in any file paths.
        FileNotFoundError: If any required OpenAPI files are not found.
    """
    openapi_dirs = [base_dir / "openapi" for base_dir in [BUILTINS_DIR, CUSTOM_DIR, REMOTE_DIR]]
    return bundle_openapi_files(*openapi_dirs)

def bundle_openapi_files(*specs_dirs: Path) -> dict:
    """
    Bundle OpenAPI specification files from multiple directories into a single dictionary.

    This function reads the main OpenAPI template file and bundles it with
    additional specification files from the provided directories. It includes
    path traversal protection for the template file.

    Args:
        *specs_dirs (Path): Variable number of Path objects representing directories
                           containing OpenAPI specification files to bundle.

    Returns:
        dict: A dictionary containing the bundled OpenAPI specifications.

    Raises:
        ValueError: If path traversal is detected in the template file path.
        FileNotFoundError: If the OpenAPI template file is not found.

    Note:
        Uses the predefined OPENAPI_DIR for the template file location and
        the provided specs_dirs for additional specification files.
    """
    template_file = (OPENAPI_DIR / "openapi.yaml").resolve()
    if not str(template_file).startswith(str(OPENAPI_DIR.resolve())):
        raise ValueError("Invalid file path: path traversal detected")

    return bundle_specs(template_file, *specs_dirs)


_API_PAGE_LIMIT = 100


async def paginated_fetch(fetcher, endpoint: str, payload_template: dict,
                          search_from: int, search_to: int,
                          results_key: str, total_key: str = None,
                          reply_wrapper: str = "reply") -> dict:
    """
    Transparently paginate an XDR API call that has a 100-per-page limit.

    If the requested range (search_to - search_from) is within the API limit,
    a single call is made. Otherwise, sequential batches of up to 100 are
    fetched and merged.

    Args:
        fetcher: The PAPI fetcher instance.
        endpoint: API endpoint path.
        payload_template: Base payload dict (must contain "request_data").
            search_from/search_to inside it will be overwritten per batch.
        search_from: Start offset requested by the caller.
        search_to: End offset requested by the caller.
        results_key: Key inside reply that holds the list (e.g. "DATA", "incidents").
        total_key: Optional key inside reply for total count (e.g. "TOTAL_COUNT", "total_count").
        reply_wrapper: Top-level key wrapping the response (default "reply").

    Returns:
        The merged response dict, identical in shape to a single-page response.
    """
    requested = search_to - search_from
    if requested <= _API_PAGE_LIMIT:
        payload_template["request_data"]["search_from"] = search_from
        payload_template["request_data"]["search_to"] = search_to
        return await fetcher.send_request(endpoint, data=payload_template)

    all_items = []
    total_count = 0
    cursor = search_from

    while cursor < search_to:
        batch_end = min(cursor + _API_PAGE_LIMIT, search_to)
        payload_template["request_data"]["search_from"] = cursor
        payload_template["request_data"]["search_to"] = batch_end

        response_data = await fetcher.send_request(endpoint, data=payload_template)
        reply = response_data.get(reply_wrapper, {})
        items = reply.get(results_key, [])

        if total_key:
            total_count = reply.get(total_key, total_count)

        if not items:
            break

        all_items.extend(items)
        cursor += len(items)

        if len(items) < (batch_end - (cursor - len(items))):
            break

    merged = {reply_wrapper: {results_key: all_items, "result_count": len(all_items)}}
    if total_key:
        merged[reply_wrapper][total_key] = total_count
    return merged
