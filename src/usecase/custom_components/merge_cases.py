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


async def merge_cases(
    ctx: Context,
    target_case_id: Annotated[int, Field(description="The case ID to merge into (the surviving case).")],
    source_case_ids: Annotated[list[int], Field(description="List of case IDs to merge into the target (these will be resolved as duplicates).")],
) -> str:
    """
    Merge one or more cases into a target case in the Cortex platform.
    The source cases are resolved as 'Resolved - Duplicate Case' with a comment referencing the target.
    The target case remains active.

    Args:
        ctx: The FastMCP context.
        target_case_id: The case ID to merge into (the surviving case).
        source_case_ids: List of case IDs to merge into the target (these will be resolved as duplicates).

    Returns:
        JSON response indicating success or failure for each source case.
    """
    fetcher = await get_fetcher(ctx)
    results = {}

    for source_id in source_case_ids:
        payload = {
            "request_data": {
                "update_data": {
                    "status_progress": "Resolved",
                    "resolve_reason": "Resolved - Duplicate Case",
                    "resolve_comment": f"Merged into case {target_case_id}",
                }
            }
        }
        try:
            await fetcher.send_request(
                f"case/update/{source_id}/",
                data=payload,
                omit_papi_prefix=False,
            )
            results[str(source_id)] = "merged"
        except PAPIResponseError as e:
            # case/update returns 204 No Content on success — treat empty-body parse error as success
            if "Invalid JSON" in str(e) or "JSONDecodeError" in str(e) or "json" in str(e).lower():
                results[str(source_id)] = "merged"
            else:
                logger.exception(f"PAPI response error merging case {source_id}: {e}")
                results[str(source_id)] = f"error: {e}"
        except (PAPIConnectionError, PAPIAuthenticationError, PAPIServerError, PAPIClientRequestError, PAPIClientError) as e:
            logger.exception(f"PAPI error merging case {source_id} into {target_case_id}: {e}")
            results[str(source_id)] = f"error: {e}"
        except Exception as e:
            logger.exception(f"Failed to merge case {source_id} into {target_case_id}: {e}")
            results[str(source_id)] = f"error: {e}"

    all_merged = all(v == "merged" for v in results.values())
    return create_response(
        data={"target_case_id": target_case_id, "results": results},
        is_error=not all_merged,
    )


class MergeCasesModule(BaseModule):
    """Module for merging Cortex platform cases."""

    def register_tools(self):
        self._add_tool(merge_cases)

    def register_resources(self):
        pass

    def __init__(self, mcp: FastMCP):
        super().__init__(mcp)
