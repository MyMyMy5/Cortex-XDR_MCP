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

# Set to True to allow the AI to resolve/close incidents.
ALLOW_RESOLVE = False

# Unicode BiDi control characters
RLM = "\u200F"   # Right-To-Left Mark
RLE = "\u202B"   # Right-To-Left Embedding
PDF = "\u202C"   # Pop Directional Formatting


def _contains_hebrew(text: str) -> bool:
    """Check if text contains Hebrew characters (Unicode block 0x0590-0x05FF)."""
    return any("\u0590" <= ch <= "\u05FF" for ch in text)


def _fix_bidi(text: str) -> str:
    """Wrap Hebrew text with BiDi control characters so mixed Hebrew/English renders correctly.

    Adds RLE at the start and PDF at the end to set the base direction to RTL,
    and prepends each line with an RLM to anchor line-level direction.
    """
    if not _contains_hebrew(text):
        return text
    lines = text.split("\n")
    fixed_lines = [f"{RLM}{line}" for line in lines]
    return f"{RLE}{chr(10).join(fixed_lines)}{PDF}"


def _strip_bidi(text: str) -> str:
    """Remove BiDi control characters from text for clean display."""
    for ch in (RLM, RLE, PDF):
        text = text.replace(ch, "")
    return text


async def _fetch_incident_comments(fetcher, incident_id: str) -> list[dict]:
    """Fetch comments for an incident via the get_incident_extra_data API."""
    payload = {
        "request_data": {
            "incident_id": incident_id,
            "alerts_limit": 1,
        }
    }
    try:
        response_data = await fetcher.send_request("incidents/get_incident_extra_data/", data=payload)
        reply = response_data.get("reply", {})
        incident = reply.get("incident", {})
        raw_comments = incident.get("comments", [])
        comments = []
        for c in raw_comments:
            comments.append({
                "comment_id": c.get("comment_id"),
                "author": c.get("created_by"),
                "created_time": c.get("created_time"),
                "created_time_str": c.get("created_time_str"),
                "comment": _strip_bidi(c.get("value", c.get("comment", ""))),
            })
        return comments
    except Exception as e:
        logger.warning(f"Failed to fetch comments for incident {incident_id}: {e}")
        return []


async def _update_incident_base(
    ctx: Context,
    incident_id: str,
    status: Optional[str],
    comment: Optional[str],
    assigned_user_mail: Optional[str],
    severity: Optional[str],
    fetch_comments: bool = False,
) -> str:
    update_data: dict = {}
    if status:
        update_data["status"] = status
    if comment:
        tagged_comment = f"[Kiro] {comment}"
        update_data["comment"] = {"value": _fix_bidi(tagged_comment), "comment_action": "add"}
    if assigned_user_mail:
        update_data["assigned_user_mail"] = assigned_user_mail
    if severity:
        update_data["severity"] = severity

    if not update_data and not fetch_comments:
        return create_response(data={"error": "At least one field must be provided."}, is_error=True)

    try:
        fetcher = await get_fetcher(ctx)

        # Perform the update if there's anything to update
        if update_data:
            payload = {"request_data": {"incident_id": incident_id, "update_data": update_data}}
            response_data = await fetcher.send_request("incidents/update_incident", data=payload)
            result = dict(response_data)
        else:
            result = {"reply": True}

        # Only fetch comments when explicitly requested
        if fetch_comments:
            comments = await _fetch_incident_comments(fetcher, incident_id)
            result["comments"] = comments
            result["total_comments"] = len(comments)

        return create_response(data=result)
    except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIResponseError, PAPIClientError) as e:
        logger.exception(f"PAPI error while updating incident: {e}")
        return create_response(data={"error": str(e)}, is_error=True)
    except Exception as e:
        logger.exception(f"Failed to update incident: {e}")
        return create_response(data={"error": str(e)}, is_error=True)


async def update_incident(
    ctx: Context,
    incident_id: Annotated[str, Field(description="The incident ID to update (e.g. '5401').")],
    status: Annotated[Optional[str], Field(description=(
        "New status. Allowed: \"new\", \"under_investigation\", \"resolved_true_positive\", "
        "\"resolved_false_positive\", \"resolved_known_issue\", \"resolved_duplicate\", "
        "\"resolved_other\", \"resolved_auto\"."
    ))] = None,
    comment: Annotated[Optional[str], Field(description="Comment text to add to the incident.")] = None,
    assigned_user_mail: Annotated[Optional[str], Field(description="Email of the user to assign the incident to.")] = None,
    severity: Annotated[Optional[str], Field(description="New severity. Allowed: \"low\", \"medium\", \"high\", \"critical\".")] = None,
    fetch_comments: Annotated[bool, Field(description="If true, fetch and return all existing comments on the incident. Default false.")] = False,
) -> str:
    """
    Update an incident in Cortex XDR — add a comment, reassign, change severity, or resolve.

    Comments are automatically prefixed with [Kiro] to identify them as AI-generated.
    Set fetch_comments=true to retrieve all existing comments on the incident (useful for
    reading replies). When false (default), only the update result is returned.

    Args:
        ctx: The FastMCP context.
        incident_id: The incident ID to update.
        status: New resolution status.
        comment: Comment text to add.
        assigned_user_mail: Email to assign the incident to.
        severity: New severity level.
        fetch_comments: If true, include all comments in the response.

    Returns:
        JSON response. reply=true means success. If fetch_comments=true, includes comments array.
    """
    return await _update_incident_base(ctx, incident_id, status, comment, assigned_user_mail, severity, fetch_comments)


async def update_incident_no_resolve(
    ctx: Context,
    incident_id: Annotated[str, Field(description="The incident ID to update (e.g. '5401').")],
    comment: Annotated[Optional[str], Field(description="Comment text to add to the incident.")] = None,
    assigned_user_mail: Annotated[Optional[str], Field(description="Email of the user to assign the incident to.")] = None,
    severity: Annotated[Optional[str], Field(description="New severity. Allowed: \"low\", \"medium\", \"high\", \"critical\".")] = None,
    fetch_comments: Annotated[bool, Field(description="If true, fetch and return all existing comments on the incident. Default false.")] = False,
) -> str:
    """
    Update an incident in Cortex XDR — add a comment, reassign, or change severity.

    Comments are automatically prefixed with [Kiro] to identify them as AI-generated.
    Set fetch_comments=true to retrieve all existing comments on the incident (useful for
    reading replies). When false (default), only the update result is returned.

    Args:
        ctx: The FastMCP context.
        incident_id: The incident ID to update.
        comment: Comment text to add.
        assigned_user_mail: Email to assign the incident to.
        severity: New severity level.
        fetch_comments: If true, include all comments in the response.

    Returns:
        JSON response. reply=true means success. If fetch_comments=true, includes comments array.
    """
    return await _update_incident_base(ctx, incident_id, None, comment, assigned_user_mail, severity, fetch_comments)


class UpdateIncidentModule(BaseModule):
    """Module for updating Cortex XDR incidents."""

    def register_tools(self):
        if ALLOW_RESOLVE:
            self._add_tool(update_incident)
        else:
            self._add_tool(update_incident_no_resolve)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
