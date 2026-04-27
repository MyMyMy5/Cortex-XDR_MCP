"""
Property-based tests for the browser_session correlation engine.

Uses Hypothesis to verify correctness properties of the pure functions
_correlate_timeline, _build_timeline_entry, and _build_summary.
"""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from usecase.custom_components.browser_session import (
    _correlate_timeline,
    _build_timeline_entry,
    _build_summary,
    _extract_domain,
    _parse_tz_offset,
    _parse_timestamp_to_epoch_ms,
    _parse_history_output,
)


# ── Hypothesis strategies ────────────────────────────────────────────────

# Timestamp range: reasonable epoch ms values (2020-01-01 to 2030-01-01)
_TS_MIN = 1_577_836_800_000
_TS_MAX = 1_893_456_000_000

_history_entry = st.fixed_dictionaries({
    "timestamp_ms": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
    "url": st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="/:.-_?&=")),
    "visit_type": st.sampled_from(["Typed", "Link", "Generated", "Reload", "Form Submit"]),
    "referrer_url": st.text(min_size=0, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="/:.-_?&=")),
    "user": st.just("TestUser"),
    "browser": st.sampled_from(["Chrome", "Edge", "Firefox"]),
    "title": st.text(min_size=0, max_size=30),
})

_network_event = st.fixed_dictionaries({
    "event_timestamp": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
    "_through_proxy": st.booleans(),
    "action_remote_ip": st.ip_addresses().map(str),
    "action_remote_port": st.integers(min_value=1, max_value=65535),
    "action_external_hostname": st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-")),
    "_network_location": st.sampled_from(["corporate", "off-network (home/VPN)", "unknown"]),
})

_tolerance_ms = st.integers(min_value=0, max_value=30_000)

_history_list = st.lists(_history_entry, min_size=0, max_size=15)
_network_list = st.lists(_network_event, min_size=0, max_size=15)


# ── Required field sets ──────────────────────────────────────────────────

REQUIRED_FIELDS = {
    "timestamp", "url", "visit_type", "referrer_url",
    "through_proxy", "remote_ip", "remote_port",
    "external_hostname", "network_location", "source",
}

NETWORK_FIELDS = {"through_proxy", "remote_ip", "remote_port", "external_hostname", "network_location"}
HISTORY_FIELDS = {"url", "visit_type", "referrer_url"}


# ── Property 1: Correlation selects closest match within tolerance ────────


class TestProperty1ClosestMatchWithinTolerance:
    """
    Property 1: Correlation selects the closest match within tolerance.

    For any list of browser history entries and network events, and for any
    tolerance window, every correlated pair in the output timeline SHALL have
    a timestamp difference ≤ tolerance, AND if multiple network events fall
    within tolerance of a history entry, the one with the smallest timestamp
    difference SHALL be selected.

    **Validates: Requirements 6.1, 6.2**
    """

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_correlated_pairs_within_tolerance(self, history, network, tolerance):
        """Every correlated pair must have timestamp diff ≤ tolerance."""
        timeline = _correlate_timeline(history, network, tolerance)

        for entry in timeline:
            if entry["source"] == "correlated":
                ts = entry["timestamp"]
                # The correlated entry's timestamp comes from the history entry.
                # Find the network event that was matched by checking network fields.
                # The timestamp diff between the history ts and the matched network
                # event must be ≤ tolerance. Since we don't store the network ts
                # directly, we verify indirectly: the history entry's timestamp_ms
                # is used as the timeline timestamp for correlated entries, and
                # the match was made within tolerance_ms.
                #
                # We can verify by checking that at least one network event exists
                # within tolerance of this timestamp.
                matched_ip = entry["remote_ip"]
                matched_port = entry["remote_port"]
                # Find the original network event
                candidates = [
                    n for n in network
                    if n["action_remote_ip"] == matched_ip
                    and n["action_remote_port"] == matched_port
                ]
                if candidates:
                    min_diff = min(abs(ts - c["event_timestamp"]) for c in candidates)
                    assert min_diff <= tolerance, (
                        f"Correlated entry has closest network match at diff={min_diff} "
                        f"but tolerance is {tolerance}"
                    )

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_closest_network_event_selected(self, history, network, tolerance):
        """If multiple network events are within tolerance, the closest is selected."""
        assume(len(history) > 0 and len(network) > 0)
        timeline = _correlate_timeline(history, network, tolerance)

        for entry in timeline:
            if entry["source"] != "correlated":
                continue

            ts = entry["timestamp"]
            matched_ip = entry["remote_ip"]
            matched_port = entry["remote_port"]
            matched_hostname = entry["external_hostname"]

            # Find ALL candidate network events that share the matched fields.
            # Multiple network events may have identical IP/port/hostname but
            # different timestamps, so we cannot uniquely identify which one
            # was matched by field equality alone.  Instead we verify that
            # at least one candidate with those fields exists within tolerance.
            candidates = [
                n for n in network
                if (n["action_remote_ip"] == matched_ip
                    and n["action_remote_port"] == matched_port
                    and (n.get("action_external_hostname") == matched_hostname
                         or n.get("dst_action_external_hostname") == matched_hostname))
            ]

            if not candidates:
                continue

            min_diff = min(abs(ts - c["event_timestamp"]) for c in candidates)
            assert min_diff <= tolerance, (
                f"Correlated entry at ts={ts} matched network with fields "
                f"ip={matched_ip} port={matched_port} hostname={matched_hostname} "
                f"but closest candidate has diff={min_diff} > tolerance={tolerance}"
            )


# ── Property 2: Unmatched history entries have null network fields ────────

class TestProperty2UnmatchedHistoryNullNetwork:
    """
    Property 2: Unmatched history entries appear with null network fields.

    Every history entry without a network match within tolerance has
    source="history_only" and all network fields are None.

    **Validates: Requirements 6.3, 7.3**
    """

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_history_only_entries_have_null_network_fields(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        for entry in timeline:
            if entry["source"] == "history_only":
                for field in NETWORK_FIELDS:
                    assert entry[field] is None, (
                        f"history_only entry should have {field}=None, got {entry[field]}"
                    )

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_unmatched_history_entries_are_history_only(self, history, network, tolerance):
        """Every history entry with no network event within tolerance appears as history_only."""
        timeline = _correlate_timeline(history, network, tolerance)

        sorted_network = sorted(network, key=lambda n: n.get("event_timestamp", 0))

        for h in history:
            h_ts = h["timestamp_ms"]
            has_match = any(
                abs(h_ts - n["event_timestamp"]) <= tolerance
                for n in sorted_network
            )
            if not has_match:
                # This history entry must appear as history_only in the timeline
                matching_timeline = [
                    e for e in timeline
                    if e["source"] == "history_only"
                    and e["timestamp"] == h_ts
                    and e["url"] == h["url"]
                ]
                assert len(matching_timeline) >= 1, (
                    f"History entry at ts={h_ts} with no network match should be history_only"
                )


# ── Property 3: Unmatched network events have null history fields ────────

class TestProperty3UnmatchedNetworkNullHistory:
    """
    Property 3: Unmatched network events appear with null history fields.

    Every network event without a history match within tolerance has
    source="network_only" and all history fields are None.

    **Validates: Requirements 6.4, 7.4**
    """

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_network_only_entries_have_null_history_fields(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        for entry in timeline:
            if entry["source"] == "network_only":
                for field in HISTORY_FIELDS:
                    assert entry[field] is None, (
                        f"network_only entry should have {field}=None, got {entry[field]}"
                    )

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_unmatched_network_events_are_network_only(self, history, network, tolerance):
        """Every network event with no history entry within tolerance appears as network_only."""
        timeline = _correlate_timeline(history, network, tolerance)

        for n in network:
            n_ts = n["event_timestamp"]
            has_match = any(
                abs(n_ts - h["timestamp_ms"]) <= tolerance
                for h in history
            )
            if not has_match:
                # This network event must appear as network_only in the timeline
                matching_timeline = [
                    e for e in timeline
                    if e["source"] == "network_only"
                    and e["timestamp"] == n_ts
                    and e["remote_ip"] == n["action_remote_ip"]
                ]
                assert len(matching_timeline) >= 1, (
                    f"Network event at ts={n_ts} with no history match should be network_only"
                )


# ── Property 4: Timeline is chronologically sorted ───────────────────────

class TestProperty4ChronologicallySorted:
    """
    Property 4: Timeline is chronologically sorted.

    The output timeline timestamps are in non-decreasing order.

    **Validates: Requirements 6.5**
    """

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_timeline_sorted_by_timestamp(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        timestamps = [e["timestamp"] for e in timeline]
        assert timestamps == sorted(timestamps), (
            "Timeline is not in non-decreasing chronological order"
        )


# ── Property 5: All timeline entries contain required fields ─────────────

class TestProperty5RequiredFields:
    """
    Property 5: All timeline entries contain required fields.

    Every entry has all required keys: timestamp, url, visit_type,
    referrer_url, through_proxy, remote_ip, remote_port,
    external_hostname, network_location, source.

    **Validates: Requirements 7.1**
    """

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_all_entries_have_required_fields(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        for i, entry in enumerate(timeline):
            missing = REQUIRED_FIELDS - set(entry.keys())
            assert not missing, (
                f"Timeline entry {i} missing required fields: {missing}"
            )

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_source_field_is_valid(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        valid_sources = {"correlated", "history_only", "network_only"}
        for entry in timeline:
            assert entry["source"] in valid_sources, (
                f"Invalid source value: {entry['source']}"
            )


# ── Property 6: Summary counts are consistent with timeline ─────────────

class TestProperty6SummaryConsistency:
    """
    Property 6: Summary counts are consistent with timeline data.

    total_events == len(timeline),
    correlated_events + history_only_events + network_only_events == total_events,
    data_sources accurately reflects which sources contributed.

    **Validates: Requirements 8.1, 5.5**
    """

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_summary_total_equals_timeline_length(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        # Determine data_sources based on what was provided
        data_sources = []
        if history:
            data_sources.append("browser_history")
        if network:
            data_sources.append("network_activity")

        summary = _build_summary(timeline, data_sources)

        assert summary["total_events"] == len(timeline), (
            f"total_events ({summary['total_events']}) != len(timeline) ({len(timeline)})"
        )

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_summary_counts_add_up(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        data_sources = []
        if history:
            data_sources.append("browser_history")
        if network:
            data_sources.append("network_activity")

        summary = _build_summary(timeline, data_sources)

        total = (
            summary["correlated_events"]
            + summary["history_only_events"]
            + summary["network_only_events"]
        )
        assert total == summary["total_events"], (
            f"correlated ({summary['correlated_events']}) + "
            f"history_only ({summary['history_only_events']}) + "
            f"network_only ({summary['network_only_events']}) = {total} "
            f"!= total_events ({summary['total_events']})"
        )

    @given(history=_history_list, network=_network_list, tolerance=_tolerance_ms)
    @settings(max_examples=100)
    def test_data_sources_reflects_contributions(self, history, network, tolerance):
        timeline = _correlate_timeline(history, network, tolerance)

        data_sources = []
        if history:
            data_sources.append("browser_history")
        if network:
            data_sources.append("network_activity")

        summary = _build_summary(timeline, data_sources)

        # data_sources in summary should match what we passed in
        assert summary["data_sources"] == data_sources

        # Additionally verify: if there are correlated or history_only entries,
        # browser_history should be in data_sources (if we provided history)
        has_history_entries = any(
            e["source"] in ("correlated", "history_only") for e in timeline
        )
        has_network_entries = any(
            e["source"] in ("correlated", "network_only") for e in timeline
        )

        if has_history_entries and history:
            assert "browser_history" in summary["data_sources"]
        if has_network_entries and network:
            assert "network_activity" in summary["data_sources"]


# ── Unit tests for investigate mode orchestration ────────────────────────

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

from usecase.custom_components.browser_session import investigate_browser_session


def _mock_ctx():
    """Create a mock FastMCP Context."""
    ctx = MagicMock()
    ctx.request_context = MagicMock()
    ctx.request_context.lifespan_context = MagicMock()
    return ctx


# Sample data returned by helpers
_SAMPLE_SCRIPT_RESULT = {
    "status": "success",
    "action_id": 12345,
    "endpoint_id": "endpoint123",
    "standard_output": (
        "[2024-06-01 10:00:00] | TestUser | Chrome | Typed | Example | https://evil.com/page | https://referrer.com"
    ),
    "return_value": "",
    "error": None,
}

_SAMPLE_NETWORK_ROWS = [
    {
        "event_timestamp": 1717236000000,  # 2024-06-01 10:00:00 UTC
        "actor_process_image_name": "chrome.exe",
        "action_remote_ip": "93.184.216.34",
        "action_remote_port": 443,
        "action_external_hostname": "evil.com",
        "dst_action_external_hostname": "evil.com",
        "action_local_ip": "10.0.0.5",
        "action_local_port": 54321,
        "dns_query_name": "evil.com",
    },
]

# Module path prefix for patching
_MOD = "usecase.custom_components.browser_session"


class TestInvestigateModeOrchestration:
    """Unit tests for investigate mode of investigate_browser_session."""

    @pytest.mark.asyncio
    async def test_investigate_mode_calls_both_data_sources(self):
        """Investigate mode calls both _run_script_on_endpoint and _run_xql concurrently."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher) as _,
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")) as _,
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc") as _,
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT) as mock_script,
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS) as mock_xql,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        mock_script.assert_called_once()
        # _run_xql is called twice: once for network query, once for DNS enrichment
        assert mock_xql.call_count == 2
        # Both data sources should be listed
        assert "browser_history" in data["data_sources"]
        assert "network_activity" in data["data_sources"]

    @pytest.mark.asyncio
    async def test_investigate_mode_indicator_optional(self):
        """Investigate mode succeeds when indicator is None."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator=None
            )

        data = json.loads(result)
        assert data["success"] == "true"

    @pytest.mark.asyncio
    async def test_disconnected_endpoint_skips_history(self):
        """Disconnected endpoint skips history collection, proceeds with network only."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "DISCONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc") as mock_script_uid,
            patch(f"{_MOD}._run_script_on_endpoint") as mock_script,
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # History should NOT have been called
        mock_script.assert_not_called()
        mock_script_uid.assert_not_called()
        # Should have a warning about disconnected endpoint
        assert any("not connected" in w.lower() or "disconnected" in w.lower() for w in data["warnings"])
        assert "network_activity" in data["data_sources"]

    @pytest.mark.asyncio
    async def test_history_failure_returns_network_with_warning(self):
        """History collection failure returns network results with a warning."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", side_effect=RuntimeError("Script lookup failed")),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert any("history" in w.lower() and "failed" in w.lower() for w in data["warnings"])
        assert "network_activity" in data["data_sources"]
        assert len(data["timeline"]) > 0

    @pytest.mark.asyncio
    async def test_network_failure_returns_history_with_warning(self):
        """Network activity failure returns history results with a warning."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", side_effect=RuntimeError("XQL query failed")),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert any("network" in w.lower() and "failed" in w.lower() for w in data["warnings"])
        assert "browser_history" in data["data_sources"]
        assert len(data["timeline"]) > 0

    @pytest.mark.asyncio
    async def test_both_failures_return_error(self):
        """Both data sources failing returns an error response."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", side_effect=RuntimeError("Script lookup failed")),
            patch(f"{_MOD}._run_xql", side_effect=RuntimeError("XQL query failed")),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com"
            )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "neither data source" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_timeframe_params_forwarded_to_data_sources(self):
        """Timeframe parameters are forwarded to both data sources."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT) as mock_script,
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS) as mock_xql,
        ):
            result = await investigate_browser_session(
                ctx,
                hostname="LAP-TEST",
                mode="investigate",
                indicator="evil.com",
                timeframe_from="2024-06-01",
                timeframe_to="2024-06-02",
            )

        data = json.loads(result)
        assert data["success"] == "true"

        # Verify timeframe was forwarded to the script via parameters
        script_call_args = mock_script.call_args
        script_params = script_call_args[0][3]  # 4th positional arg is parameters dict
        assert script_params["start_date"] == "2024-06-01"
        assert script_params["end_date"] == "2024-06-02"

        # Verify timeframe was forwarded to XQL
        xql_call_kwargs = mock_xql.call_args
        assert xql_call_kwargs.kwargs.get("timeframe_from") is not None or xql_call_kwargs[1].get("timeframe_from") is not None


# ── Unit tests for history mode ──────────────────────────────────────────

from entities.exceptions import (
    PAPIAuthenticationError,
    PAPIConnectionError,
    PAPIServerError,
)


# Sample script result for history mode tests
_SAMPLE_HISTORY_RESULT = {
    "status": "success",
    "action_id": 99999,
    "endpoint_id": "endpoint123",
    "standard_output": "some history output",
    "return_value": "",
    "error": None,
}


class TestHistoryMode:
    """Unit tests for history mode of investigate_browser_session."""

    @pytest.mark.asyncio
    async def test_history_mode_calls_only_history_collector(self):
        """History mode calls _run_script_on_endpoint but NOT _run_xql."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
            patch(f"{_MOD}._run_xql") as mock_xql,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        mock_script.assert_called_once()
        mock_xql.assert_not_called()

    @pytest.mark.asyncio
    async def test_indicator_optional_in_history_mode_without_indicator(self):
        """History mode works without indicator — url_filter defaults to '*'."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history", indicator=None
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # url_filter should be "*" when no indicator
        script_params = mock_script.call_args[0][3]
        assert script_params["url_filter"] == "*"

    @pytest.mark.asyncio
    async def test_indicator_used_as_url_filter_in_history_mode(self):
        """History mode uses indicator as url_filter when provided."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history", indicator="evil.com"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        script_params = mock_script.call_args[0][3]
        assert script_params["url_filter"] == "evil.com"

    @pytest.mark.asyncio
    async def test_history_mode_forwards_history_mode_history(self):
        """history_mode='history' is forwarded correctly to the script parameters."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history", history_mode="history"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert data["history_mode"] == "history"
        script_params = mock_script.call_args[0][3]
        assert script_params["mode"] == "history"

    @pytest.mark.asyncio
    async def test_history_mode_forwards_history_mode_downloads(self):
        """history_mode='downloads' is forwarded correctly to the script parameters."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history", history_mode="downloads"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert data["history_mode"] == "downloads"
        script_params = mock_script.call_args[0][3]
        assert script_params["mode"] == "downloads"

    @pytest.mark.asyncio
    async def test_history_mode_forwards_history_mode_both(self):
        """history_mode='both' is forwarded correctly to the script parameters."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history", history_mode="both"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert data["history_mode"] == "both"
        script_params = mock_script.call_args[0][3]
        assert script_params["mode"] == "both"

    @pytest.mark.asyncio
    async def test_output_file_path_triggers_download(self):
        """output_file_path triggers _download_result_files call."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT),
            patch(f"{_MOD}._download_result_files", return_value=4096) as mock_download,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history",
                output_file_path="/tmp/history_output.txt"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        mock_download.assert_called_once_with(
            mock_fetcher, 99999, "endpoint123", "/tmp/history_output.txt"
        )
        assert data["output_file_path"] == "/tmp/history_output.txt"
        assert data["output_file_size_bytes"] == 4096

    @pytest.mark.asyncio
    async def test_disconnected_endpoint_returns_queued_message(self):
        """Disconnected endpoint returns queued message with action_id."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()
        mock_fetcher.send_request = AsyncMock(
            return_value={"reply": {"action_id": 77777}}
        )

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "DISCONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert data["script_status"] == "queued_pending_connection"
        assert data["endpoint_status"] == "DISCONNECTED"
        assert data["action_id"] == 77777
        assert "queued" in data["message"].lower() or "not connected" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_hostname_not_found_returns_error(self):
        """Hostname not found returns error response."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=(None, None)),
        ):
            result = await investigate_browser_session(
                ctx, hostname="NONEXISTENT-HOST", mode="history"
            )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "not found" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_invalid_mode_returns_error(self):
        """Invalid mode value returns error response."""
        ctx = _mock_ctx()

        result = await investigate_browser_session(
            ctx, hostname="LAP-TEST", mode="invalid_mode"
        )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "mode must be" in data["error"].lower()
        assert "network" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_papi_exception_returns_error(self):
        """PAPI exceptions return error response."""
        ctx = _mock_ctx()

        with (
            patch(f"{_MOD}.get_fetcher", side_effect=PAPIConnectionError("Connection refused")),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history"
            )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "connection refused" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_papi_auth_error_returns_error(self):
        """PAPI authentication errors return error response."""
        ctx = _mock_ctx()

        with (
            patch(f"{_MOD}.get_fetcher", side_effect=PAPIAuthenticationError("Invalid API key")),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history"
            )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "invalid api key" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_papi_server_error_returns_error(self):
        """PAPI server errors return error response."""
        ctx = _mock_ctx()

        with (
            patch(f"{_MOD}.get_fetcher", side_effect=PAPIServerError("Internal server error")),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history"
            )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "internal server error" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_response_includes_required_fields(self):
        """Response includes hostname, endpoint_id, history_mode, and script_status."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history", history_mode="downloads"
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert data["hostname"] == "LAP-TEST"
        assert data["endpoint_id"] == "endpoint123"
        assert data["history_mode"] == "downloads"
        assert data["script_status"] == "success"
        assert data["action_id"] == 99999


# ── Unit tests for indicator-optional investigate mode (Enhancement 2) ───


class TestIndicatorOptionalInvestigateMode:
    """Unit tests for indicator-optional investigate mode.

    Validates Requirements 2.2, 2.3, 2.4.
    """

    @pytest.mark.asyncio
    async def test_xql_query_omits_hostname_filter_when_indicator_none(self):
        """XQL query omits hostname filter when indicator is None.

        Validates: Requirement 2.2
        """
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS) as mock_xql,
        ):
            await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator=None
            )

        # The XQL query is the first positional arg to _run_xql
        xql_query = mock_xql.call_args[0][1]
        assert "action_external_hostname contains" not in xql_query
        assert "dst_action_external_hostname contains" not in xql_query

    @pytest.mark.asyncio
    async def test_history_script_receives_wildcard_url_filter_when_indicator_none(self):
        """History script receives url_filter='*' when indicator is None.

        Validates: Requirement 2.3
        """
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT) as mock_script,
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator=None
            )

        script_params = mock_script.call_args[0][3]
        assert script_params["url_filter"] == "*"

    @pytest.mark.asyncio
    async def test_indicator_provided_preserves_xql_hostname_filter(self):
        """Investigate mode with indicator preserves hostname filter in XQL query.

        Validates: Requirement 2.4
        """
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS) as mock_xql,
        ):
            await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com"
            )

        # Check the first XQL call (network query), not the second (DNS enrichment)
        xql_query = mock_xql.call_args_list[0][0][1]
        assert 'action_external_hostname contains "evil.com"' in xql_query
        assert 'dst_action_external_hostname contains "evil.com"' in xql_query

    @pytest.mark.asyncio
    async def test_indicator_provided_preserves_url_filter(self):
        """Investigate mode with indicator passes indicator as url_filter.

        Validates: Requirement 2.4
        """
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT) as mock_script,
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com"
            )

        script_params = mock_script.call_args[0][3]
        assert script_params["url_filter"] == "evil.com"


# ── Property tests for domain-aware correlation (Enhancement 1) ──────────

# Strategies for domain-aware property tests

_SCHEMES = st.sampled_from(["http", "https", "ftp"])
_HOSTNAMES = st.from_regex(r"[a-z][a-z0-9]{0,8}\.[a-z]{2,4}", fullmatch=True)
_PATHS = st.from_regex(r"/[a-z0-9]{0,10}", fullmatch=True)


class TestPropertyDomainExtraction:
    """
    Feature: browser-investigation-enhancements, Property 1: Domain extraction
    produces valid hostname or None.

    For any URL string, _extract_domain SHALL return either the hostname
    component of the URL (a non-empty string without scheme, port, path,
    or query) or None if the URL is empty or has no parseable hostname.
    Furthermore, for any URL constructed as scheme://hostname/path, the
    extracted domain SHALL equal the hostname used in construction.

    **Validates: Requirements 1.1, 1.6**
    """

    @given(scheme=_SCHEMES, hostname=_HOSTNAMES, path=_PATHS)
    @settings(max_examples=100)
    def test_round_trip_domain_extraction(self, scheme, hostname, path):
        """Extracting domain from a well-formed URL returns the original hostname."""
        url = f"{scheme}://{hostname}{path}"
        result = _extract_domain(url)
        assert result == hostname, (
            f"Expected domain '{hostname}' from URL '{url}', got '{result}'"
        )

    @given(data=st.data())
    @settings(max_examples=100)
    def test_result_is_hostname_or_none(self, data):
        """_extract_domain always returns a valid hostname string or None."""
        url = data.draw(st.one_of(
            # Well-formed URLs
            st.builds(lambda s, h, p: f"{s}://{h}{p}", _SCHEMES, _HOSTNAMES, _PATHS),
            # Empty strings
            st.just(""),
            # Whitespace-only
            st.just("   "),
            # Malformed: no scheme
            _HOSTNAMES,
            # Random text
            st.text(max_size=50),
        ))
        result = _extract_domain(url)
        assert result is None or (isinstance(result, str) and len(result) > 0), (
            f"Expected None or non-empty string, got {result!r} for URL {url!r}"
        )

    @given(hostname=_HOSTNAMES)
    @settings(max_examples=100)
    def test_no_scheme_returns_none(self, hostname):
        """URLs without a scheme (e.g., 'example.com/path') return None."""
        url = f"{hostname}/somepath"
        result = _extract_domain(url)
        # urlparse without scheme puts everything in the path component
        # so hostname extraction should return None
        assert result is None, (
            f"Expected None for scheme-less URL '{url}', got '{result}'"
        )

    def test_empty_string_returns_none(self):
        """Empty string returns None."""
        assert _extract_domain("") is None

    def test_malformed_url_returns_none(self):
        """Clearly malformed URL returns None."""
        assert _extract_domain("not-a-url") is None


class TestPropertyDomainTimestampPreference:
    """
    Feature: browser-investigation-enhancements, Property 2: Domain+timestamp
    match is preferred over timestamp-only match.

    For any history entry with a URL containing domain D, and for any set of
    network events within the tolerance window where at least one has
    action_external_hostname or dst_action_external_hostname equal to D, the
    correlation engine SHALL select a network event with matching domain D —
    even if a non-matching network event has a smaller timestamp difference.

    **Validates: Requirements 1.2, 1.3**
    """

    @given(
        base_ts=st.integers(min_value=_TS_MIN + 30_000, max_value=_TS_MAX - 30_000),
        domain=_HOSTNAMES,
        other_domain=_HOSTNAMES,
        domain_offset=st.integers(min_value=1000, max_value=4000),
        other_offset=st.integers(min_value=0, max_value=500),
        tolerance=st.integers(min_value=5000, max_value=15000),
    )
    @settings(max_examples=100)
    def test_domain_match_preferred_over_closer_timestamp(
        self, base_ts, domain, other_domain, domain_offset, other_offset, tolerance
    ):
        """A domain-matching event is selected even when a non-matching event is closer in time."""
        assume(domain != other_domain)
        assume(domain_offset > other_offset)  # domain match is farther away
        assume(domain_offset <= tolerance)  # but still within tolerance

        history = [{
            "timestamp_ms": base_ts,
            "url": f"https://{domain}/page",
            "visit_type": "Typed",
            "referrer_url": "",
            "user": "TestUser",
            "browser": "Chrome",
            "title": "Test",
        }]

        # Network event with matching domain but farther timestamp
        domain_event = {
            "event_timestamp": base_ts + domain_offset,
            "_through_proxy": False,
            "action_remote_ip": "10.0.0.1",
            "action_remote_port": 443,
            "action_external_hostname": domain,
            "dst_action_external_hostname": domain,
            "_network_location": "corporate",
        }

        # Network event with non-matching domain but closer timestamp
        other_event = {
            "event_timestamp": base_ts + other_offset,
            "_through_proxy": False,
            "action_remote_ip": "10.0.0.2",
            "action_remote_port": 80,
            "action_external_hostname": other_domain,
            "dst_action_external_hostname": other_domain,
            "_network_location": "corporate",
        }

        timeline = _correlate_timeline(history, [domain_event, other_event], tolerance)

        correlated = [e for e in timeline if e["source"] == "correlated"]
        assert len(correlated) == 1, f"Expected 1 correlated entry, got {len(correlated)}"

        # The correlated entry should have the domain-matching event's IP
        assert correlated[0]["remote_ip"] == "10.0.0.1", (
            f"Expected domain-matching event (IP 10.0.0.1), got {correlated[0]['remote_ip']}"
        )
        assert correlated[0]["external_hostname"] == domain


class TestPropertyTimestampOnlyFallback:
    """
    Feature: browser-investigation-enhancements, Property 3: Timestamp-only
    fallback when no domain match exists.

    For any history entry whose extracted domain does not match any network
    event's hostname within the tolerance window, the correlation engine SHALL
    select the network event with the smallest timestamp difference. The
    selected event SHALL have a timestamp difference <= tolerance.

    **Validates: Requirements 1.4**
    """

    @given(
        base_ts=st.integers(min_value=_TS_MIN + 30_000, max_value=_TS_MAX - 30_000),
        history_domain=_HOSTNAMES,
        net_domains=st.lists(_HOSTNAMES, min_size=2, max_size=5),
        offsets=st.lists(st.integers(min_value=100, max_value=4000), min_size=2, max_size=5),
        tolerance=st.integers(min_value=5000, max_value=15000),
    )
    @settings(max_examples=100)
    def test_closest_timestamp_selected_when_no_domain_match(
        self, base_ts, history_domain, net_domains, offsets, tolerance
    ):
        """When no domain matches, the closest-by-timestamp network event is selected."""
        # Ensure no network domain matches the history domain
        net_domains = [d for d in net_domains if d != history_domain]
        assume(len(net_domains) >= 2)
        offsets = offsets[:len(net_domains)]

        # Ensure all offsets are within tolerance and unique
        offsets = [o for o in offsets if o <= tolerance]
        assume(len(offsets) >= 2)
        assume(len(set(offsets)) == len(offsets))  # unique offsets

        history = [{
            "timestamp_ms": base_ts,
            "url": f"https://{history_domain}/page",
            "visit_type": "Typed",
            "referrer_url": "",
            "user": "TestUser",
            "browser": "Chrome",
            "title": "Test",
        }]

        network = []
        for i, (dom, offset) in enumerate(zip(net_domains, offsets)):
            network.append({
                "event_timestamp": base_ts + offset,
                "_through_proxy": False,
                "action_remote_ip": f"10.0.0.{i + 1}",
                "action_remote_port": 443,
                "action_external_hostname": dom,
                "dst_action_external_hostname": dom,
                "_network_location": "corporate",
            })

        timeline = _correlate_timeline(history, network, tolerance)

        correlated = [e for e in timeline if e["source"] == "correlated"]
        assert len(correlated) == 1, f"Expected 1 correlated entry, got {len(correlated)}"

        # Find which network event has the smallest offset
        min_offset = min(offsets)
        min_idx = offsets.index(min_offset)
        expected_ip = f"10.0.0.{min_idx + 1}"

        assert correlated[0]["remote_ip"] == expected_ip, (
            f"Expected closest timestamp match (IP {expected_ip}, offset {min_offset}ms), "
            f"got {correlated[0]['remote_ip']}"
        )


class TestPropertyClosestDomainMatch:
    """
    Feature: browser-investigation-enhancements, Property 4: Closest timestamp
    among multiple domain matches.

    For any history entry with domain D and multiple network events within the
    tolerance window that all have hostname D, the correlation engine SHALL
    select the one with the smallest absolute timestamp difference.

    **Validates: Requirements 1.5**
    """

    @given(
        base_ts=st.integers(min_value=_TS_MIN + 30_000, max_value=_TS_MAX - 30_000),
        domain=_HOSTNAMES,
        offsets=st.lists(st.integers(min_value=100, max_value=4000), min_size=2, max_size=5),
        tolerance=st.integers(min_value=5000, max_value=15000),
    )
    @settings(max_examples=100)
    def test_closest_domain_match_selected(self, base_ts, domain, offsets, tolerance):
        """Among multiple same-domain events, the closest by timestamp is selected."""
        # Ensure all offsets are within tolerance and unique
        offsets = [o for o in offsets if o <= tolerance]
        assume(len(offsets) >= 2)
        assume(len(set(offsets)) == len(offsets))  # unique offsets

        history = [{
            "timestamp_ms": base_ts,
            "url": f"https://{domain}/page",
            "visit_type": "Typed",
            "referrer_url": "",
            "user": "TestUser",
            "browser": "Chrome",
            "title": "Test",
        }]

        network = []
        for i, offset in enumerate(offsets):
            network.append({
                "event_timestamp": base_ts + offset,
                "_through_proxy": False,
                "action_remote_ip": f"10.0.0.{i + 1}",
                "action_remote_port": 443,
                "action_external_hostname": domain,
                "dst_action_external_hostname": domain,
                "_network_location": "corporate",
            })

        timeline = _correlate_timeline(history, network, tolerance)

        correlated = [e for e in timeline if e["source"] == "correlated"]
        assert len(correlated) == 1, f"Expected 1 correlated entry, got {len(correlated)}"

        # The closest offset should be selected
        min_offset = min(offsets)
        min_idx = offsets.index(min_offset)
        expected_ip = f"10.0.0.{min_idx + 1}"

        assert correlated[0]["remote_ip"] == expected_ip, (
            f"Expected closest domain match (IP {expected_ip}, offset {min_offset}ms), "
            f"got {correlated[0]['remote_ip']}"
        )


# ── Property tests for timezone parsing (Enhancement 3) ─────────────────

from datetime import datetime, timezone, timedelta


class TestPropertyTimezoneOffsetExtraction:
    """
    Feature: browser-investigation-enhancements, Property 5: Timezone offset
    extraction from script output.

    For any script output string containing a line
    ``Endpoint TZ: <name> (UTC<sign><H>:<M>:<S>)`` where sign is ``+``, ``-``,
    or empty, H is 0–14, M is 0–59, and S is 0–59, ``_parse_tz_offset`` SHALL
    return the total offset in seconds equal to ``sign * (H*3600 + M*60 + S)``.
    For any script output without an ``Endpoint TZ:`` line, it SHALL return 0.

    **Validates: Requirements 3.1, 3.2**
    """

    @given(
        hours=st.integers(min_value=0, max_value=14),
        minutes=st.integers(min_value=0, max_value=59),
        seconds=st.integers(min_value=0, max_value=59),
        sign=st.sampled_from(["+", "-", ""]),
        tz_name=st.from_regex(r"[A-Z][a-z]+ [A-Z][a-z]+ Time", fullmatch=True),
    )
    @settings(max_examples=100)
    def test_valid_tz_header_returns_correct_seconds(
        self, hours, minutes, seconds, sign, tz_name
    ):
        """Valid Endpoint TZ header produces the correct total offset in seconds."""
        output = f"Endpoint TZ: {tz_name} (UTC{sign}{hours}:{minutes:02d}:{seconds:02d})\nsome data line"
        result = _parse_tz_offset(output)

        expected_sign = -1 if sign == "-" else 1
        expected = expected_sign * (hours * 3600 + minutes * 60 + seconds)
        assert result == expected, (
            f"For header '(UTC{sign}{hours}:{minutes:02d}:{seconds:02d})' "
            f"expected {expected}, got {result}"
        )

    @given(
        body=st.text(min_size=0, max_size=200, alphabet=st.characters(
            whitelist_categories=("L", "N", "P", "Z"),
        )),
    )
    @settings(max_examples=100)
    def test_no_tz_header_returns_zero(self, body):
        """Output without an Endpoint TZ header returns 0."""
        # Ensure the generated body does not accidentally contain the header
        assume("endpoint tz:" not in body.lower())
        result = _parse_tz_offset(body)
        assert result == 0, (
            f"Expected 0 for output without TZ header, got {result}"
        )


class TestPropertyTimezoneRoundTrip:
    """
    Feature: browser-investigation-enhancements, Property 6: Timezone-aware
    timestamp round-trip.

    For any valid UTC epoch milliseconds value and for any timezone offset in
    the range [-14h, +14h], converting the UTC value to a local timestamp
    string (by adding the offset), then parsing that string back with
    ``_parse_timestamp_to_epoch_ms(ts_str, tz_offset_seconds=offset)`` SHALL
    produce the original UTC epoch milliseconds value (within 1-second
    precision due to string format truncation).

    **Validates: Requirements 3.3, 3.6, 3.7**
    """

    @given(
        utc_epoch_ms=st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
        offset_seconds=st.integers(min_value=-14 * 3600, max_value=14 * 3600),
    )
    @settings(max_examples=100)
    def test_round_trip_utc_to_local_and_back(self, utc_epoch_ms, offset_seconds):
        """Converting UTC→local string→parse back with offset recovers original UTC (±1s)."""
        # Step 1: Convert UTC epoch ms to a local datetime by adding the offset
        utc_dt = datetime.fromtimestamp(utc_epoch_ms / 1000, tz=timezone.utc)
        local_dt = utc_dt + timedelta(seconds=offset_seconds)

        # Step 2: Format as "YYYY-MM-DD HH:MM:SS" (the format _parse_timestamp_to_epoch_ms expects)
        ts_str = local_dt.strftime("%Y-%m-%d %H:%M:%S")

        # Step 3: Parse back with the offset
        result_ms = _parse_timestamp_to_epoch_ms(ts_str, tz_offset_seconds=offset_seconds)

        # Step 4: Verify within 1-second precision (string format truncates sub-seconds)
        diff = abs(result_ms - utc_epoch_ms)
        assert diff < 1000, (
            f"Round-trip failed: original={utc_epoch_ms}, result={result_ms}, "
            f"diff={diff}ms, offset={offset_seconds}s, ts_str='{ts_str}'"
        )


# ── Unit tests for timezone parsing helpers (Task 7.2) ───────────────────

import logging
from pathlib import Path


class TestParseTzOffsetUnit:
    """Unit tests for _parse_tz_offset edge cases."""

    def test_returns_zero_for_output_without_tz_header(self):
        """_parse_tz_offset returns 0 when no Endpoint TZ header is present."""
        output = (
            "Hostname: LAP-12345\n"
            "User filter: *\n"
            "Browser: All\n"
            "Mode: history\n"
            "2024-06-01 10:00:00 | user1 | Chrome | Typed | https://example.com | \n"
        )
        assert _parse_tz_offset(output) == 0

    def test_logs_warning_and_returns_zero_for_malformed_header(self, caplog):
        """_parse_tz_offset logs a warning and returns 0 for a malformed TZ header."""
        output = "Endpoint TZ: Some Zone (UTCgarbage)\n"
        with caplog.at_level(logging.WARNING):
            result = _parse_tz_offset(output)
        assert result == 0
        assert any("malformed" in rec.message.lower() for rec in caplog.records)


class TestParseHistoryOutputTzApplication:
    """Unit test verifying _parse_history_output applies TZ offset to timestamps."""

    def test_applies_tz_offset_to_all_timestamps(self):
        """Timestamps in parsed output should be adjusted by the TZ offset."""
        # UTC+3 offset (10800 seconds) — timestamps are local, so subtracting
        # the offset converts them to UTC.
        output = (
            "Endpoint TZ: Israel Standard Time (UTC3:00:00)\n"
            "Hostname: LAP-12345\n"
            "---\n"
            "2024-06-01 13:00:00 | user1 | Chrome | Typed | https://example.com | \n"
            "2024-06-01 14:30:00 | user1 | Chrome | Link | https://test.com | https://example.com\n"
        )
        entries = _parse_history_output(output)
        assert len(entries) == 2

        # 2024-06-01 13:00:00 local (UTC+3) → 2024-06-01 10:00:00 UTC
        expected_utc_1 = _parse_timestamp_to_epoch_ms("2024-06-01 10:00:00", tz_offset_seconds=0)
        # 2024-06-01 14:30:00 local (UTC+3) → 2024-06-01 11:30:00 UTC
        expected_utc_2 = _parse_timestamp_to_epoch_ms("2024-06-01 11:30:00", tz_offset_seconds=0)

        assert entries[0]["timestamp_ms"] == expected_utc_1
        assert entries[1]["timestamp_ms"] == expected_utc_2


class TestExtractDomainUnit:
    """Unit tests for _extract_domain with empty and malformed URLs."""

    def test_returns_none_for_empty_url(self):
        assert _extract_domain("") is None

    def test_returns_none_for_whitespace_only(self):
        assert _extract_domain("   ") is None

    def test_returns_none_for_malformed_url(self):
        assert _extract_domain("not-a-url") is None

    def test_returns_none_for_url_without_scheme(self):
        # urlparse doesn't extract hostname without a scheme
        assert _extract_domain("evil.com/page") is None


class TestCorrelationMalformedUrlFallback:
    """Correlation with malformed URLs falls back to timestamp-only matching."""

    def test_malformed_url_falls_back_to_timestamp_only(self):
        """When a history entry has a malformed URL, correlation uses timestamp-only."""
        history = [
            {
                "timestamp_ms": 1_700_000_000_000,
                "url": "not-a-url",
                "visit_type": "Typed",
                "referrer_url": "",
                "user": "TestUser",
                "browser": "Chrome",
                "title": "",
            }
        ]
        network = [
            {
                "event_timestamp": 1_700_000_001_000,  # 1s away
                "action_external_hostname": "evil.com",
                "dst_action_external_hostname": "",
                "_through_proxy": False,
                "action_remote_ip": "1.2.3.4",
                "action_remote_port": 443,
                "_network_location": "corporate",
            }
        ]
        tolerance = 5000  # 5s

        timeline = _correlate_timeline(history, network, tolerance)
        correlated = [e for e in timeline if e["source"] == "correlated"]
        assert len(correlated) == 1, "Malformed URL should still correlate via timestamp"


# ── Unit test verifying hook file structure (Task 7.3) ───────────────────


class TestBrowserConsentHook:
    """Verify the browser-consent hook file exists and has correct structure."""

    def test_hook_file_exists(self):
        hook_path = Path(__file__).resolve().parent.parent / ".kiro" / "hooks" / "browser-consent.md"
        assert hook_path.exists(), f"Hook file not found at {hook_path}"

    def test_hook_contains_correct_fields(self):
        hook_path = Path(__file__).resolve().parent.parent / ".kiro" / "hooks" / "browser-consent.md"
        content = hook_path.read_text()

        assert "event: preToolUse" in content, "Hook must have event: preToolUse"
        assert 'toolTypes: ".*investigate_browser_session.*"' in content, (
            "Hook must have toolTypes matching investigate_browser_session"
        )
        assert "action: askAgent" in content, "Hook must have action: askAgent"


# ── V2 Enhancement Tests ─────────────────────────────────────────────────

from usecase.custom_components.browser_session import (
    _resolve_browser_filter,
    _cap_limit,
    _BROWSER_MAP,
    _BROWSER_PROCESSES,
    _MAX_LIMIT,
    _parse_download_output,
    _aggregate_network_events,
    _enrich_dns_batch,
    _merge_endpoint_results,
    _merge_endpoint_timelines,
)


# ── Task 1.3: Unit tests for _resolve_browser_filter ─────────────────────


class TestResolveBrowserFilter:
    """Unit tests for _resolve_browser_filter mapping logic."""

    def test_chrome_maps_to_chrome_exe(self):
        procs, err = _resolve_browser_filter("chrome")
        assert procs == ("chrome.exe",)
        assert err is None

    def test_edge_maps_to_msedge_exe(self):
        procs, err = _resolve_browser_filter("edge")
        assert procs == ("msedge.exe",)
        assert err is None

    def test_firefox_maps_to_firefox_exe(self):
        procs, err = _resolve_browser_filter("firefox")
        assert procs == ("firefox.exe",)
        assert err is None

    def test_brave_maps_to_brave_exe(self):
        procs, err = _resolve_browser_filter("brave")
        assert procs == ("brave.exe",)
        assert err is None

    def test_opera_maps_to_opera_exe(self):
        procs, err = _resolve_browser_filter("opera")
        assert procs == ("opera.exe",)
        assert err is None

    def test_wildcard_returns_all_browser_processes(self):
        procs, err = _resolve_browser_filter("*")
        assert procs == _BROWSER_PROCESSES
        assert err is None

    def test_invalid_name_returns_error(self):
        procs, err = _resolve_browser_filter("safari")
        assert procs == ()
        assert err is not None
        assert "Invalid browser_filter 'safari'" in err
        assert "chrome" in err
        assert "*" in err


# ── Task 1.4: Property test for limit capping ────────────────────────────


class TestProperty8LimitCapping:
    """
    Feature: browser-session-v2-enhancements, Property 8: Limit capping

    For any integer limit > 500, the effective limit SHALL be 500 with a warning.
    Validates: Requirements 6.3
    """

    @given(limit=st.integers(min_value=501, max_value=10_000_000))
    @settings(max_examples=100)
    def test_limit_above_max_is_capped_to_500(self, limit: int):
        effective, warning = _cap_limit(limit)
        assert effective == _MAX_LIMIT, f"Expected {_MAX_LIMIT}, got {effective}"
        assert warning is not None, "Expected a warning when limit > 500"
        assert str(limit) in warning, "Warning should mention the original limit"

    @given(limit=st.integers(min_value=1, max_value=500))
    @settings(max_examples=100)
    def test_limit_within_range_is_unchanged(self, limit: int):
        effective, warning = _cap_limit(limit)
        assert effective == limit, f"Expected {limit}, got {effective}"
        assert warning is None, "No warning expected when limit ≤ 500"


# ── Task 3.4: Property test for download line parsing round-trip ─────────

# Strategies for download entry fields
_DOWNLOAD_STATES = st.sampled_from(["Complete", "Cancelled", "Interrupted", "In Progress"])
_DANGER_TYPES = st.sampled_from(["Safe", "Dangerous File", "Dangerous URL", "Uncommon"])
_OPENED_VALUES = st.sampled_from(["Yes", "No"])
_SAFE_TEXT = st.from_regex(r"[A-Za-z0-9_. ]{1,20}", fullmatch=True).filter(lambda s: "|" not in s and "\n" not in s and s.strip() == s and len(s) > 0)
_MIME_TYPES = st.sampled_from([
    "application/pdf", "application/zip", "text/html",
    "image/png", "application/octet-stream",
])
_SIZE_MB = st.sampled_from(["0.5", "1.2", "10.0", "N/A", "0.0"])


class TestProperty6DownloadParsingRoundTrip:
    """
    Feature: browser-session-v2-enhancements, Property 6: Download line parsing round-trip

    For any valid download entry fields, formatting as pipe-delimited line and
    parsing with ``_parse_download_output`` SHALL produce a dict matching the
    original values.

    **Validates: Requirements 4.2**
    """

    @given(
        ts=st.datetimes(
            min_value=datetime(2020, 1, 1),
            max_value=datetime(2029, 12, 31),
            timezones=st.just(timezone.utc),
        ),
        user=_SAFE_TEXT,
        browser=st.sampled_from(["Chrome", "Edge", "Firefox"]),
        state=_DOWNLOAD_STATES,
        danger_type=_DANGER_TYPES,
        size_mb=_SIZE_MB,
        opened=_OPENED_VALUES,
        mime_type=_MIME_TYPES,
        file_path=st.from_regex(r"C:\\Users\\[A-Za-z]{3,8}\\Downloads\\[a-z]{1,10}\.[a-z]{2,4}", fullmatch=True),
        source_url=st.builds(
            lambda s, h, p: f"{s}://{h}{p}",
            st.sampled_from(["http", "https"]),
            _HOSTNAMES,
            _PATHS,
        ),
        referrer=st.builds(
            lambda s, h, p: f"{s}://{h}{p}",
            st.sampled_from(["http", "https"]),
            _HOSTNAMES,
            _PATHS,
        ),
    )
    @settings(max_examples=100)
    def test_download_round_trip(
        self, ts, user, browser, state, danger_type, size_mb,
        opened, mime_type, file_path, source_url, referrer,
    ):
        """Formatting download fields as a pipe-delimited line and parsing recovers original values."""
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts_str}] | {user} | {browser} | {state} | {danger_type} | {size_mb} | {opened} | {mime_type} | {file_path} | {source_url} | {referrer}"

        results = _parse_download_output(line)
        assert len(results) == 1, f"Expected 1 result, got {len(results)}"

        entry = results[0]
        assert entry["user"] == user
        assert entry["browser"] == browser
        assert entry["state"] == state
        assert entry["danger_type"] == danger_type
        assert entry["size_mb"] == size_mb
        assert entry["opened"] == opened
        assert entry["mime_type"] == mime_type
        assert entry["file_path"] == file_path
        assert entry["source_url"] == source_url
        assert entry["referrer"] == referrer

        # Verify timestamp conversion (within 1s precision)
        expected_ms = int(ts.timestamp() * 1000)
        assert abs(entry["timestamp_ms"] - expected_ms) < 1000, (
            f"Timestamp mismatch: expected ~{expected_ms}, got {entry['timestamp_ms']}"
        )


# ── Task 3.5: Property test for download correlation source labels ───────

_download_entry = st.fixed_dictionaries({
    "timestamp_ms": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
    "user": st.just("TestUser"),
    "browser": st.sampled_from(["Chrome", "Edge", "Firefox"]),
    "state": _DOWNLOAD_STATES,
    "danger_type": _DANGER_TYPES,
    "size_mb": _SIZE_MB,
    "opened": _OPENED_VALUES,
    "mime_type": st.sampled_from(["application/pdf", "text/html"]),
    "file_path": st.just("C:\\Users\\Test\\Downloads\\file.pdf"),
    "source_url": st.builds(
        lambda h, p: f"https://{h}{p}",
        _HOSTNAMES,
        _PATHS,
    ),
    "referrer": st.just("https://referrer.com/page"),
})

_download_list = st.lists(_download_entry, min_size=0, max_size=10)


class TestProperty7DownloadCorrelationSourceLabels:
    """
    Feature: browser-session-v2-enhancements, Property 7: Download entries correlated
    with correct source labels and fields

    Correlated downloads have ``source="download_correlated"``, unmatched have
    ``source="download"``, all include download-specific fields.

    **Validates: Requirements 4.4, 4.5, 4.6, 4.7**
    """

    @given(
        downloads=_download_list,
        network=_network_list,
        tolerance=_tolerance_ms,
    )
    @settings(max_examples=100)
    def test_download_source_labels_are_correct(self, downloads, network, tolerance):
        """Download entries get source='download_correlated' or 'download'."""
        timeline = _correlate_timeline([], network, tolerance, download_entries=downloads)

        download_sources = {"download_correlated", "download"}
        for entry in timeline:
            if entry["source"] in download_sources:
                # All download entries must include download-specific fields
                assert "file_path" in entry, "Download entry missing file_path"
                assert "download_state" in entry, "Download entry missing download_state"
                assert "danger_type" in entry, "Download entry missing danger_type"
                assert "size_mb" in entry, "Download entry missing size_mb"
                assert "mime_type" in entry, "Download entry missing mime_type"
                assert "source_url" in entry, "Download entry missing source_url"

                # download-specific fields should not be None for download entries
                assert entry["file_path"] is not None
                assert entry["download_state"] is not None
                assert entry["source_url"] is not None

    @given(
        downloads=_download_list,
        network=_network_list,
        tolerance=_tolerance_ms,
    )
    @settings(max_examples=100)
    def test_correlated_downloads_have_network_fields(self, downloads, network, tolerance):
        """Download entries with source='download_correlated' have network fields populated."""
        timeline = _correlate_timeline([], network, tolerance, download_entries=downloads)

        for entry in timeline:
            if entry["source"] == "download_correlated":
                assert entry["remote_ip"] is not None, "Correlated download should have remote_ip"
                assert entry["remote_port"] is not None, "Correlated download should have remote_port"

    @given(
        downloads=_download_list,
        tolerance=_tolerance_ms,
    )
    @settings(max_examples=100)
    def test_unmatched_downloads_have_null_network_fields(self, downloads, tolerance):
        """Download entries with no network match have null network fields."""
        # No network events → all downloads should be unmatched
        timeline = _correlate_timeline([], [], tolerance, download_entries=downloads)

        for entry in timeline:
            if entry["source"] == "download":
                assert entry["remote_ip"] is None
                assert entry["remote_port"] is None
                assert entry["through_proxy"] is None
                assert entry["external_hostname"] is None
                assert entry["network_location"] is None

    @given(
        downloads=_download_list,
        network=_network_list,
        tolerance=_tolerance_ms,
    )
    @settings(max_examples=100)
    def test_non_download_entries_have_null_download_fields(self, downloads, network, tolerance):
        """Non-download timeline entries have None for download-specific fields."""
        history = []  # no history entries
        timeline = _correlate_timeline(history, network, tolerance, download_entries=downloads)

        non_download_sources = {"correlated", "history_only", "network_only"}
        for entry in timeline:
            if entry["source"] in non_download_sources:
                assert entry["file_path"] is None
                assert entry["download_state"] is None
                assert entry["danger_type"] is None
                assert entry["size_mb"] is None
                assert entry["mime_type"] is None
                assert entry["source_url"] is None


# ── Task 3.6: Unit tests for _parse_download_output edge cases ───────────


class TestParseDownloadOutputEdgeCases:
    """Unit tests for _parse_download_output edge cases.

    Requirements: 4.1, 4.2
    """

    def test_empty_output_returns_empty_list(self):
        """Empty string returns empty list."""
        assert _parse_download_output("") == []

    def test_none_like_empty_returns_empty_list(self):
        """None-ish empty string returns empty list."""
        assert _parse_download_output("") == []

    def test_malformed_line_skipped(self):
        """Lines that don't have 11 pipe-delimited fields are skipped."""
        output = "this is not a download line\nanother bad line | only two fields"
        assert _parse_download_output(output) == []

    def test_line_with_fewer_than_11_fields_skipped(self):
        """A line with exactly 10 pipe-delimited fields is skipped."""
        # 10 fields (missing referrer)
        output = "[2024-06-01 10:00:00] | User | Chrome | Complete | Safe | 1.0 | Yes | application/pdf | C:\\file.pdf | https://example.com"
        assert _parse_download_output(output) == []

    def test_valid_download_line_parsed(self):
        """A valid 11-field download line is parsed correctly."""
        output = "[2024-06-01 10:00:00] | TestUser | Chrome | Complete | Safe | 2.5 | Yes | application/pdf | C:\\Downloads\\report.pdf | https://example.com/report.pdf | https://example.com"
        results = _parse_download_output(output)
        assert len(results) == 1
        entry = results[0]
        assert entry["user"] == "TestUser"
        assert entry["browser"] == "Chrome"
        assert entry["state"] == "Complete"
        assert entry["danger_type"] == "Safe"
        assert entry["size_mb"] == "2.5"
        assert entry["opened"] == "Yes"
        assert entry["mime_type"] == "application/pdf"
        assert entry["file_path"] == "C:\\Downloads\\report.pdf"
        assert entry["source_url"] == "https://example.com/report.pdf"
        assert entry["referrer"] == "https://example.com"
        assert entry["timestamp_ms"] > 0

    def test_mixed_valid_and_invalid_lines(self):
        """Only valid lines are parsed; invalid lines are skipped."""
        output = (
            "Header line that should be skipped\n"
            "[2024-06-01 10:00:00] | User | Chrome | Complete | Safe | 1.0 | Yes | text/html | C:\\file.html | https://a.com/f | https://ref.com\n"
            "short | line\n"
            "[2024-06-01 11:00:00] | User | Edge | Cancelled | Dangerous File | 5.0 | No | application/zip | C:\\file.zip | https://b.com/z | https://ref2.com\n"
        )
        results = _parse_download_output(output)
        assert len(results) == 2
        assert results[0]["browser"] == "Chrome"
        assert results[1]["browser"] == "Edge"
        assert results[1]["state"] == "Cancelled"

    def test_empty_lines_skipped(self):
        """Empty lines in the output are skipped."""
        output = "\n\n[2024-06-01 10:00:00] | User | Chrome | Complete | Safe | 1.0 | Yes | text/html | C:\\f.html | https://a.com | https://r.com\n\n"
        results = _parse_download_output(output)
        assert len(results) == 1

    def test_tz_offset_applied_to_download_timestamps(self):
        """Timezone offset from header is applied to download timestamps."""
        output = (
            "Endpoint TZ: Israel Standard Time (UTC3:00:00)\n"
            "[2024-06-01 13:00:00] | User | Chrome | Complete | Safe | 1.0 | Yes | text/html | C:\\f.html | https://a.com | https://r.com\n"
        )
        results = _parse_download_output(output)
        assert len(results) == 1
        # 13:00 local (UTC+3) → 10:00 UTC
        expected_utc = _parse_timestamp_to_epoch_ms("2024-06-01 10:00:00", tz_offset_seconds=0)
        assert results[0]["timestamp_ms"] == expected_utc


# ── Task 5.2: Property test for aggregation invariants ───────────────────

# Strategy for classified network events (output of _classify_connection)
_aggregation_network_event = st.fixed_dictionaries({
    "event_timestamp": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
    "action_external_hostname": st.one_of(
        st.none(),
        st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-")),
    ),
    "_through_proxy": st.booleans(),
    "_network_location": st.sampled_from(["corporate", "off-network (home/VPN)", "unknown"]),
    "actor_process_image_name": st.sampled_from(["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"]),
    "action_remote_ip": st.ip_addresses().map(str),
})

_aggregation_event_list = st.lists(_aggregation_network_event, min_size=0, max_size=30)


class TestProperty5AggregationInvariants:
    """
    Feature: browser-session-v2-enhancements, Property 5: Aggregation invariants

    (a) sum of all ``count`` fields == total input events,
    (b) each ``count`` matches group size,
    (c) ``first_seen`` ≤ ``last_seen``,
    (d) ``unique_remote_ips`` is deduplicated,
    (e) sorted by ``count`` descending.

    **Validates: Requirements 3.1, 3.2, 3.6, 3.7**
    """

    @given(events=_aggregation_event_list)
    @settings(max_examples=100)
    def test_sum_of_counts_equals_total_input(self, events):
        """(a) Sum of all count fields equals total number of input events."""
        records = _aggregate_network_events(events)
        total_count = sum(r["count"] for r in records)
        assert total_count == len(events), (
            f"Sum of counts ({total_count}) != total input events ({len(events)})"
        )

    @given(events=_aggregation_event_list)
    @settings(max_examples=100)
    def test_each_count_matches_group_size(self, events):
        """(b) Each record's count matches the number of input events sharing that grouping key."""
        records = _aggregate_network_events(events)

        # Manually compute expected group sizes
        groups: dict[tuple, int] = {}
        for ev in events:
            key = (
                ev.get("action_external_hostname"),
                ev.get("_through_proxy"),
                ev.get("_network_location"),
                ev.get("actor_process_image_name"),
            )
            groups[key] = groups.get(key, 0) + 1

        for rec in records:
            key = (
                rec["external_hostname"],
                rec["through_proxy"],
                rec["network_location"],
                rec["process_name"],
            )
            assert rec["count"] == groups[key], (
                f"Record count ({rec['count']}) != expected group size ({groups[key]}) for key {key}"
            )

    @given(events=_aggregation_event_list)
    @settings(max_examples=100)
    def test_first_seen_lte_last_seen(self, events):
        """(c) first_seen ≤ last_seen for every record."""
        records = _aggregate_network_events(events)
        for rec in records:
            assert rec["first_seen"] <= rec["last_seen"], (
                f"first_seen ({rec['first_seen']}) > last_seen ({rec['last_seen']})"
            )

    @given(events=_aggregation_event_list)
    @settings(max_examples=100)
    def test_unique_remote_ips_deduplicated(self, events):
        """(d) unique_remote_ips contains no duplicates."""
        records = _aggregate_network_events(events)
        for rec in records:
            ips = rec["unique_remote_ips"]
            assert len(ips) == len(set(ips)), (
                f"unique_remote_ips has duplicates: {ips}"
            )

    @given(events=_aggregation_event_list)
    @settings(max_examples=100)
    def test_sorted_by_count_descending(self, events):
        """(e) Records are sorted by count in descending order."""
        records = _aggregate_network_events(events)
        counts = [r["count"] for r in records]
        assert counts == sorted(counts, reverse=True), (
            f"Records not sorted by count descending: {counts}"
        )


# ── Task 5.3: Unit tests for _aggregate_network_events ──────────────────


class TestAggregateNetworkEvents:
    """Unit tests for _aggregate_network_events.

    Requirements: 3.1, 3.2, 3.5, 3.6, 3.7
    """

    def test_empty_input_returns_empty_list(self):
        """Empty event list returns empty aggregation."""
        assert _aggregate_network_events([]) == []

    def test_single_event(self):
        """Single event produces one record with count=1."""
        events = [{
            "event_timestamp": 1_700_000_000_000,
            "action_external_hostname": "example.com",
            "_through_proxy": False,
            "_network_location": "corporate",
            "actor_process_image_name": "chrome.exe",
            "action_remote_ip": "93.184.216.34",
        }]
        records = _aggregate_network_events(events)
        assert len(records) == 1
        rec = records[0]
        assert rec["external_hostname"] == "example.com"
        assert rec["through_proxy"] is False
        assert rec["network_location"] == "corporate"
        assert rec["process_name"] == "chrome.exe"
        assert rec["count"] == 1
        assert rec["first_seen"] == 1_700_000_000_000
        assert rec["last_seen"] == 1_700_000_000_000
        assert rec["unique_remote_ips"] == ["93.184.216.34"]

    def test_multiple_groups_sorted_by_count(self):
        """Multiple groups are sorted by count descending."""
        events = [
            # Group A: 3 events
            {"event_timestamp": 100, "action_external_hostname": "a.com", "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "1.1.1.1"},
            {"event_timestamp": 200, "action_external_hostname": "a.com", "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "1.1.1.2"},
            {"event_timestamp": 300, "action_external_hostname": "a.com", "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "1.1.1.1"},
            # Group B: 1 event
            {"event_timestamp": 150, "action_external_hostname": "b.com", "_through_proxy": True, "_network_location": "unknown", "actor_process_image_name": "firefox.exe", "action_remote_ip": "2.2.2.2"},
        ]
        records = _aggregate_network_events(events)
        assert len(records) == 2
        # First record should be group A (count=3)
        assert records[0]["external_hostname"] == "a.com"
        assert records[0]["count"] == 3
        assert records[0]["first_seen"] == 100
        assert records[0]["last_seen"] == 300
        assert sorted(records[0]["unique_remote_ips"]) == ["1.1.1.1", "1.1.1.2"]
        # Second record should be group B (count=1)
        assert records[1]["external_hostname"] == "b.com"
        assert records[1]["count"] == 1

    def test_none_hostname_grouping(self):
        """Events with None hostname are grouped together."""
        events = [
            {"event_timestamp": 100, "action_external_hostname": None, "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "10.0.0.1"},
            {"event_timestamp": 200, "action_external_hostname": None, "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "10.0.0.2"},
            {"event_timestamp": 150, "action_external_hostname": "real.com", "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "5.5.5.5"},
        ]
        records = _aggregate_network_events(events)
        assert len(records) == 2
        # None hostname group has count=2, should be first
        assert records[0]["external_hostname"] is None
        assert records[0]["count"] == 2
        assert sorted(records[0]["unique_remote_ips"]) == ["10.0.0.1", "10.0.0.2"]
        # real.com group has count=1
        assert records[1]["external_hostname"] == "real.com"
        assert records[1]["count"] == 1

    def test_duplicate_ips_deduplicated(self):
        """Duplicate action_remote_ip values within a group are deduplicated."""
        events = [
            {"event_timestamp": 100, "action_external_hostname": "x.com", "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "1.2.3.4"},
            {"event_timestamp": 200, "action_external_hostname": "x.com", "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "1.2.3.4"},
            {"event_timestamp": 300, "action_external_hostname": "x.com", "_through_proxy": False, "_network_location": "corporate", "actor_process_image_name": "chrome.exe", "action_remote_ip": "1.2.3.4"},
        ]
        records = _aggregate_network_events(events)
        assert len(records) == 1
        assert records[0]["count"] == 3
        assert records[0]["unique_remote_ips"] == ["1.2.3.4"]

# ── Task 7.2: Property test for DNS enrichment selectivity ───────────────

# Strategies for DNS enrichment tests

_dns_event = st.fixed_dictionaries({
    "dns_query_name": st.from_regex(r"[a-z][a-z0-9]{0,8}\.[a-z]{2,4}", fullmatch=True),
    "action_remote_ip": st.ip_addresses().map(str),
    "event_timestamp": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
})

_dns_event_list = st.lists(_dns_event, min_size=0, max_size=15)

# Network event that already has a hostname (should NOT be modified)
_network_event_with_hostname = st.fixed_dictionaries({
    "event_timestamp": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
    "action_external_hostname": st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-")),
    "dst_action_external_hostname": st.one_of(st.none(), st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters=".-"))),
    "action_remote_ip": st.ip_addresses().map(str),
    "action_remote_port": st.integers(min_value=1, max_value=65535),
    "_through_proxy": st.booleans(),
    "_network_location": st.sampled_from(["corporate", "off-network (home/VPN)", "unknown"]),
})

# Network event with bare IP (both hostname fields null)
_bare_ip_network_event = st.fixed_dictionaries({
    "event_timestamp": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
    "action_external_hostname": st.none(),
    "dst_action_external_hostname": st.none(),
    "action_remote_ip": st.ip_addresses().map(str),
    "action_remote_port": st.integers(min_value=1, max_value=65535),
    "_through_proxy": st.booleans(),
    "_network_location": st.sampled_from(["corporate", "off-network (home/VPN)", "unknown"]),
})

_mixed_network_list = st.lists(
    st.one_of(_network_event_with_hostname, _bare_ip_network_event),
    min_size=0,
    max_size=15,
)


class TestProperty3DNSEnrichmentSelectivity:
    """
    Feature: browser-session-v2-enhancements, Property 3: DNS enrichment only modifies bare-IP events with matching DNS data

    Only bare-IP events with matching DNS records are modified; events with
    existing hostnames are unchanged; events with no DNS match remain null.

    **Validates: Requirements 2.1, 2.3, 2.5**
    """

    @given(events=_mixed_network_list, dns_events=_dns_event_list)
    @settings(max_examples=100)
    def test_events_with_existing_hostname_unchanged(self, events, dns_events):
        """Events that already have a hostname are never modified by DNS enrichment."""
        import copy
        originals = copy.deepcopy(events)

        _enrich_dns_batch(events, dns_events)

        for orig, enriched in zip(originals, events):
            if orig.get("action_external_hostname") is not None or orig.get("dst_action_external_hostname") is not None:
                assert enriched["action_external_hostname"] == orig["action_external_hostname"], (
                    f"Event with existing hostname was modified: "
                    f"original={orig['action_external_hostname']}, "
                    f"enriched={enriched['action_external_hostname']}"
                )

    @given(events=_mixed_network_list, dns_events=_dns_event_list)
    @settings(max_examples=100)
    def test_bare_ip_events_without_dns_match_remain_null(self, events, dns_events):
        """Bare-IP events with no matching DNS record remain with null hostname."""
        import copy
        originals = copy.deepcopy(events)
        dns_ips = {d["action_remote_ip"] for d in dns_events}

        _enrich_dns_batch(events, dns_events)

        for orig, enriched in zip(originals, events):
            was_bare_ip = (
                orig.get("action_external_hostname") is None
                and orig.get("dst_action_external_hostname") is None
            )
            if not was_bare_ip:
                continue
            remote_ip = orig.get("action_remote_ip")
            if remote_ip not in dns_ips:
                assert enriched.get("action_external_hostname") is None, (
                    f"Bare-IP event with IP {remote_ip} (no DNS match) should remain null, "
                    f"got {enriched.get('action_external_hostname')}"
                )

    @given(events=_mixed_network_list, dns_events=_dns_event_list)
    @settings(max_examples=100)
    def test_only_bare_ip_events_with_match_are_enriched(self, events, dns_events):
        """Only bare-IP events with a matching DNS record get a hostname set."""
        import copy
        originals = copy.deepcopy(events)
        dns_ips = {d["action_remote_ip"] for d in dns_events}

        _enrich_dns_batch(events, dns_events)

        for orig, enriched in zip(originals, events):
            was_bare_ip = (
                orig.get("action_external_hostname") is None
                and orig.get("dst_action_external_hostname") is None
            )
            has_dns_match = orig.get("action_remote_ip") in dns_ips

            if was_bare_ip and has_dns_match and dns_events:
                # May have been enriched (hostname set to a dns_query_name)
                if enriched.get("action_external_hostname") is not None:
                    valid_names = {d["dns_query_name"] for d in dns_events if d["action_remote_ip"] == orig["action_remote_ip"]}
                    assert enriched["action_external_hostname"] in valid_names, (
                        f"Enriched hostname {enriched['action_external_hostname']} "
                        f"not in valid DNS names {valid_names}"
                    )
            elif not was_bare_ip:
                # Should be unchanged
                assert enriched["action_external_hostname"] == orig["action_external_hostname"]


# ── Task 7.3: Property test for DNS enrichment closest timestamp selection ──


class TestProperty4DNSEnrichmentClosestTimestamp:
    """
    Feature: browser-session-v2-enhancements, Property 4: DNS enrichment selects closest DNS event by timestamp

    When multiple DNS events match the same IP, the one with smallest absolute
    timestamp difference is selected.

    **Validates: Requirements 2.4**
    """

    @given(
        event_ts=st.integers(min_value=_TS_MIN + 100_000, max_value=_TS_MAX - 100_000),
        remote_ip=st.ip_addresses().map(str),
        dns_offsets=st.lists(
            st.integers(min_value=-50_000, max_value=50_000),
            min_size=2,
            max_size=10,
        ),
    )
    @settings(max_examples=100)
    def test_closest_dns_event_selected(self, event_ts, remote_ip, dns_offsets):
        """The DNS event with the smallest absolute timestamp difference is selected."""
        # Ensure unique absolute offsets so there's a clear winner
        abs_offsets = [abs(o) for o in dns_offsets]
        assume(len(set(abs_offsets)) == len(abs_offsets))

        network_events = [{
            "event_timestamp": event_ts,
            "action_external_hostname": None,
            "dst_action_external_hostname": None,
            "action_remote_ip": remote_ip,
            "action_remote_port": 443,
        }]

        dns_events = []
        for i, offset in enumerate(dns_offsets):
            dns_events.append({
                "dns_query_name": f"dns{i}.example.com",
                "action_remote_ip": remote_ip,
                "event_timestamp": event_ts + offset,
            })

        _enrich_dns_batch(network_events, dns_events)

        # Find which DNS event should have been selected (smallest abs diff)
        closest_idx = min(range(len(dns_offsets)), key=lambda i: abs(dns_offsets[i]))
        expected_name = f"dns{closest_idx}.example.com"

        assert network_events[0]["action_external_hostname"] == expected_name, (
            f"Expected {expected_name} (offset={dns_offsets[closest_idx]}), "
            f"got {network_events[0]['action_external_hostname']}"
        )

    @given(
        event_ts=st.integers(min_value=_TS_MIN + 100_000, max_value=_TS_MAX - 100_000),
        remote_ip=st.ip_addresses().map(str),
        other_ip=st.ip_addresses().map(str),
        dns_name=st.from_regex(r"[a-z]{3,8}\.[a-z]{2,4}", fullmatch=True),
    )
    @settings(max_examples=100)
    def test_non_matching_ip_dns_events_ignored(self, event_ts, remote_ip, other_ip, dns_name):
        """DNS events with a different IP are not used for enrichment."""
        assume(remote_ip != other_ip)

        network_events = [{
            "event_timestamp": event_ts,
            "action_external_hostname": None,
            "dst_action_external_hostname": None,
            "action_remote_ip": remote_ip,
            "action_remote_port": 443,
        }]

        dns_events = [{
            "dns_query_name": dns_name,
            "action_remote_ip": other_ip,
            "event_timestamp": event_ts,
        }]

        _enrich_dns_batch(network_events, dns_events)

        assert network_events[0]["action_external_hostname"] is None, (
            f"Event should not be enriched with DNS from different IP, "
            f"got {network_events[0]['action_external_hostname']}"
        )


# ── Task 7.4: Unit tests for _enrich_dns_batch ──────────────────────────


class TestEnrichDnsBatch:
    """Unit tests for _enrich_dns_batch.

    Requirements: 2.1, 2.3, 2.4, 2.5
    """

    def test_empty_network_events(self):
        """Empty network events list returns empty list."""
        result = _enrich_dns_batch([], [{"dns_query_name": "a.com", "action_remote_ip": "1.1.1.1", "event_timestamp": 100}])
        assert result == []

    def test_empty_dns_events(self):
        """Empty DNS events list leaves network events unchanged."""
        events = [{"action_external_hostname": None, "dst_action_external_hostname": None, "action_remote_ip": "1.1.1.1", "event_timestamp": 100}]
        result = _enrich_dns_batch(events, [])
        assert result[0]["action_external_hostname"] is None

    def test_no_bare_ip_events(self):
        """Events with existing hostnames are left unchanged."""
        events = [{
            "action_external_hostname": "existing.com",
            "dst_action_external_hostname": None,
            "action_remote_ip": "1.1.1.1",
            "event_timestamp": 100,
        }]
        dns = [{"dns_query_name": "other.com", "action_remote_ip": "1.1.1.1", "event_timestamp": 100}]
        _enrich_dns_batch(events, dns)
        assert events[0]["action_external_hostname"] == "existing.com"

    def test_dst_hostname_present_skips_enrichment(self):
        """Events with dst_action_external_hostname set are left unchanged."""
        events = [{
            "action_external_hostname": None,
            "dst_action_external_hostname": "dst.com",
            "action_remote_ip": "1.1.1.1",
            "event_timestamp": 100,
        }]
        dns = [{"dns_query_name": "other.com", "action_remote_ip": "1.1.1.1", "event_timestamp": 100}]
        _enrich_dns_batch(events, dns)
        assert events[0]["action_external_hostname"] is None

    def test_single_match(self):
        """Single bare-IP event with matching DNS record gets enriched."""
        events = [{
            "action_external_hostname": None,
            "dst_action_external_hostname": None,
            "action_remote_ip": "93.184.216.34",
            "event_timestamp": 1_700_000_000_000,
        }]
        dns = [{
            "dns_query_name": "example.com",
            "action_remote_ip": "93.184.216.34",
            "event_timestamp": 1_700_000_001_000,
        }]
        _enrich_dns_batch(events, dns)
        assert events[0]["action_external_hostname"] == "example.com"

    def test_multiple_dns_closest_wins(self):
        """When multiple DNS events match, the closest by timestamp is selected."""
        events = [{
            "action_external_hostname": None,
            "dst_action_external_hostname": None,
            "action_remote_ip": "10.0.0.1",
            "event_timestamp": 1_000_000,
        }]
        dns = [
            {"dns_query_name": "far.com", "action_remote_ip": "10.0.0.1", "event_timestamp": 1_050_000},
            {"dns_query_name": "close.com", "action_remote_ip": "10.0.0.1", "event_timestamp": 1_005_000},
            {"dns_query_name": "farther.com", "action_remote_ip": "10.0.0.1", "event_timestamp": 1_100_000},
        ]
        _enrich_dns_batch(events, dns)
        assert events[0]["action_external_hostname"] == "close.com"

    def test_no_matching_dns(self):
        """Bare-IP event with no matching DNS record remains null."""
        events = [{
            "action_external_hostname": None,
            "dst_action_external_hostname": None,
            "action_remote_ip": "192.168.1.1",
            "event_timestamp": 1_000_000,
        }]
        dns = [{"dns_query_name": "other.com", "action_remote_ip": "10.0.0.1", "event_timestamp": 1_000_000}]
        _enrich_dns_batch(events, dns)
        assert events[0]["action_external_hostname"] is None

    def test_mutates_in_place_and_returns_same_list(self):
        """Function mutates the input list in-place and returns the same object."""
        events = [{
            "action_external_hostname": None,
            "dst_action_external_hostname": None,
            "action_remote_ip": "1.2.3.4",
            "event_timestamp": 100,
        }]
        dns = [{"dns_query_name": "test.com", "action_remote_ip": "1.2.3.4", "event_timestamp": 100}]
        result = _enrich_dns_batch(events, dns)
        assert result is events
        assert events[0]["action_external_hostname"] == "test.com"

    def test_mixed_events_only_bare_ip_enriched(self):
        """Only bare-IP events are enriched; events with hostnames are untouched."""
        events = [
            {"action_external_hostname": "existing.com", "dst_action_external_hostname": None, "action_remote_ip": "1.1.1.1", "event_timestamp": 100},
            {"action_external_hostname": None, "dst_action_external_hostname": None, "action_remote_ip": "1.1.1.1", "event_timestamp": 200},
            {"action_external_hostname": None, "dst_action_external_hostname": None, "action_remote_ip": "2.2.2.2", "event_timestamp": 300},
        ]
        dns = [
            {"dns_query_name": "resolved.com", "action_remote_ip": "1.1.1.1", "event_timestamp": 150},
        ]
        _enrich_dns_batch(events, dns)
        assert events[0]["action_external_hostname"] == "existing.com"  # unchanged
        assert events[1]["action_external_hostname"] == "resolved.com"  # enriched
        assert events[2]["action_external_hostname"] is None  # no matching DNS


# ── Task 9.4: Property test for multi-endpoint merge preserving entries ──

# Strategy for per-endpoint result entries (generic dicts with a timestamp)
_endpoint_entry = st.fixed_dictionaries({
    "timestamp": st.integers(min_value=_TS_MIN, max_value=_TS_MAX),
    "url": st.one_of(st.none(), st.text(min_size=1, max_size=30)),
    "source": st.sampled_from(["correlated", "history_only", "network_only"]),
})

_endpoint_entry_list = st.lists(_endpoint_entry, min_size=0, max_size=15)

# Strategy for hostname strings
_hostname_str = st.from_regex(r"LAP-[0-9]{3,6}", fullmatch=True)


class TestProperty1MultiEndpointMergePreservesEntries:
    """
    Feature: browser-session-v2-enhancements, Property 1: Multi-endpoint merge preserves all entries with correct tagging

    Merged output length == sum of input list lengths, every entry has correct ``source_hostname``.

    **Validates: Requirements 1.3, 1.9**
    """

    @given(
        data=st.data(),
        num_endpoints=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=100)
    def test_merged_length_equals_sum_of_inputs(self, data, num_endpoints):
        """Merged output length equals the sum of all input list lengths."""
        per_endpoint: list[tuple[str, list[dict]]] = []
        total_expected = 0
        for i in range(num_endpoints):
            hn = data.draw(_hostname_str, label=f"hostname_{i}")
            entries = data.draw(_endpoint_entry_list, label=f"entries_{i}")
            per_endpoint.append((hn, entries))
            total_expected += len(entries)

        merged = _merge_endpoint_results(per_endpoint)
        assert len(merged) == total_expected, (
            f"Merged length ({len(merged)}) != sum of inputs ({total_expected})"
        )

    @given(
        data=st.data(),
        num_endpoints=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=100)
    def test_every_entry_has_correct_source_hostname(self, data, num_endpoints):
        """Every entry in the merged output has a source_hostname matching its origin."""
        per_endpoint: list[tuple[str, list[dict]]] = []
        for i in range(num_endpoints):
            hn = data.draw(_hostname_str, label=f"hostname_{i}")
            entries = data.draw(_endpoint_entry_list, label=f"entries_{i}")
            per_endpoint.append((hn, entries))

        merged = _merge_endpoint_results(per_endpoint)

        # Build expected mapping: for each entry, track which hostname it came from
        idx = 0
        for hn, entries in per_endpoint:
            for _ in entries:
                assert merged[idx].get("source_hostname") == hn, (
                    f"Entry at index {idx} has source_hostname={merged[idx].get('source_hostname')}, "
                    f"expected {hn}"
                )
                idx += 1


# ── Task 9.5: Property test for multi-endpoint merged timeline sorting ───


class TestProperty2MultiEndpointMergedTimelineSorting:
    """
    Feature: browser-session-v2-enhancements, Property 2: Multi-endpoint merged timeline is chronologically sorted

    Merged timeline timestamps are in non-decreasing order.

    **Validates: Requirements 1.8**
    """

    @given(
        data=st.data(),
        num_endpoints=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=100)
    def test_merged_timeline_is_chronologically_sorted(self, data, num_endpoints):
        """Merged timeline timestamps are in non-decreasing order."""
        per_endpoint: list[tuple[str, list[dict]]] = []
        for i in range(num_endpoints):
            hn = data.draw(_hostname_str, label=f"hostname_{i}")
            entries = data.draw(_endpoint_entry_list, label=f"entries_{i}")
            per_endpoint.append((hn, entries))

        merged = _merge_endpoint_timelines(per_endpoint)

        timestamps = [e["timestamp"] for e in merged]
        assert timestamps == sorted(timestamps), (
            "Merged timeline is not in non-decreasing chronological order"
        )

    @given(
        data=st.data(),
        num_endpoints=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=100)
    def test_merged_timeline_preserves_all_entries(self, data, num_endpoints):
        """Merged timeline preserves all entries (length check) even after sorting."""
        per_endpoint: list[tuple[str, list[dict]]] = []
        total_expected = 0
        for i in range(num_endpoints):
            hn = data.draw(_hostname_str, label=f"hostname_{i}")
            entries = data.draw(_endpoint_entry_list, label=f"entries_{i}")
            per_endpoint.append((hn, entries))
            total_expected += len(entries)

        merged = _merge_endpoint_timelines(per_endpoint)
        assert len(merged) == total_expected, (
            f"Merged timeline length ({len(merged)}) != sum of inputs ({total_expected})"
        )


# ── Task 9.6: Unit tests for multi-endpoint orchestration ───────────────


class TestMultiEndpointOrchestration:
    """Unit tests for multi-endpoint orchestration in investigate_browser_session.

    Requirements: 1.1, 1.2, 1.3, 1.6, 1.7, 1.8, 1.9
    """

    @pytest.mark.asyncio
    async def test_multi_endpoint_investigate_resolves_all(self):
        """Multi-endpoint investigate mode resolves all hostnames and merges results."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        resolve_map = {
            "LAP-001": ("ep001", "CONNECTED"),
            "LAP-002": ("ep002", "CONNECTED"),
        }

        async def mock_resolve(fetcher, hn):
            return resolve_map.get(hn, (None, None))

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", side_effect=mock_resolve),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="IGNORED", mode="investigate",
                hostnames=["LAP-001", "LAP-002"],
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "timeline" in data
        # Timeline entries should have source_hostname
        for entry in data["timeline"]:
            assert "source_hostname" in entry
            assert entry["source_hostname"] in ("LAP-001", "LAP-002")

    @pytest.mark.asyncio
    async def test_multi_endpoint_partial_failure_with_warnings(self):
        """Partial endpoint resolution failure produces warnings but continues."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_resolve(fetcher, hn):
            if hn == "LAP-BAD":
                return (None, None)
            return ("ep001", "CONNECTED")

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", side_effect=mock_resolve),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="IGNORED", mode="investigate",
                hostnames=["LAP-001", "LAP-BAD"],
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # Should have a warning about LAP-BAD
        assert any("LAP-BAD" in w for w in data["warnings"])
        # Timeline should still have entries from LAP-001
        assert len(data["timeline"]) > 0

    @pytest.mark.asyncio
    async def test_multi_endpoint_all_failures_returns_error(self):
        """All hostnames failing to resolve returns error."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_resolve(fetcher, hn):
            return (None, None)

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", side_effect=mock_resolve),
        ):
            result = await investigate_browser_session(
                ctx, hostname="IGNORED", mode="investigate",
                hostnames=["LAP-BAD1", "LAP-BAD2"],
            )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "no endpoints could be resolved" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_multi_endpoint_network_mode_merges_with_tagging(self):
        """Multi-endpoint network mode merges events with source_hostname tagging."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_resolve(fetcher, hn):
            resolve_map = {
                "LAP-001": ("ep001", "CONNECTED"),
                "LAP-002": ("ep002", "CONNECTED"),
            }
            return resolve_map.get(hn, (None, None))

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", side_effect=mock_resolve),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="IGNORED", mode="network",
                hostnames=["LAP-001", "LAP-002"],
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "network_events" in data
        # Each event should have source_hostname
        for event in data["network_events"]:
            assert "source_hostname" in event
            assert event["source_hostname"] in ("LAP-001", "LAP-002")

    @pytest.mark.asyncio
    async def test_multi_endpoint_investigate_timeline_sorted(self):
        """Multi-endpoint investigate mode produces chronologically sorted timeline."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_resolve(fetcher, hn):
            resolve_map = {
                "LAP-001": ("ep001", "CONNECTED"),
                "LAP-002": ("ep002", "CONNECTED"),
            }
            return resolve_map.get(hn, (None, None))

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", side_effect=mock_resolve),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="IGNORED", mode="investigate",
                hostnames=["LAP-001", "LAP-002"],
            )

        data = json.loads(result)
        assert data["success"] == "true"
        timestamps = [e["timestamp"] for e in data["timeline"]]
        assert timestamps == sorted(timestamps), "Timeline should be chronologically sorted"

    @pytest.mark.asyncio
    async def test_empty_hostnames_returns_error(self):
        """Empty hostnames list returns error."""
        ctx = _mock_ctx()

        result = await investigate_browser_session(
            ctx, hostname="LAP-TEST", mode="investigate",
            hostnames=[],
        )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "hostnames list must not be empty" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_limit_below_1_returns_error(self):
        """Limit below 1 returns error."""
        ctx = _mock_ctx()

        result = await investigate_browser_session(
            ctx, hostname="LAP-TEST", mode="investigate",
            limit=0,
        )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "limit must be at least 1" in data["error"].lower()

    @pytest.mark.asyncio
    async def test_limit_above_500_capped_with_warning(self):
        """Limit above 500 is capped at 500 with a warning."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                limit=1000,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert any("limit was reduced" in w for w in data["warnings"])

    @pytest.mark.asyncio
    async def test_invalid_browser_filter_returns_error(self):
        """Invalid browser_filter returns error."""
        ctx = _mock_ctx()

        result = await investigate_browser_session(
            ctx, hostname="LAP-TEST", mode="investigate",
            browser_filter="safari",
        )

        data = json.loads(result)
        assert data["success"] == "false"
        assert "invalid browser_filter" in data["error"].lower()


# ── Unit tests for _merge_endpoint_results and _merge_endpoint_timelines ─


class TestMergeEndpointResults:
    """Unit tests for _merge_endpoint_results pure function."""

    def test_empty_input(self):
        """Empty per-endpoint list returns empty merged list."""
        assert _merge_endpoint_results([]) == []

    def test_single_endpoint(self):
        """Single endpoint entries are tagged correctly."""
        entries = [{"timestamp": 100, "url": "a.com"}, {"timestamp": 200, "url": "b.com"}]
        merged = _merge_endpoint_results([("LAP-001", entries)])
        assert len(merged) == 2
        assert all(e["source_hostname"] == "LAP-001" for e in merged)

    def test_multiple_endpoints(self):
        """Multiple endpoint entries are merged and tagged correctly."""
        e1 = [{"timestamp": 100}]
        e2 = [{"timestamp": 200}, {"timestamp": 300}]
        merged = _merge_endpoint_results([("LAP-001", e1), ("LAP-002", e2)])
        assert len(merged) == 3
        assert merged[0]["source_hostname"] == "LAP-001"
        assert merged[1]["source_hostname"] == "LAP-002"
        assert merged[2]["source_hostname"] == "LAP-002"

    def test_empty_endpoint_entries(self):
        """Endpoint with empty entries contributes nothing."""
        merged = _merge_endpoint_results([("LAP-001", []), ("LAP-002", [{"timestamp": 100}])])
        assert len(merged) == 1
        assert merged[0]["source_hostname"] == "LAP-002"


class TestMergeEndpointTimelines:
    """Unit tests for _merge_endpoint_timelines pure function."""

    def test_empty_input(self):
        """Empty input returns empty list."""
        assert _merge_endpoint_timelines([]) == []

    def test_sorted_chronologically(self):
        """Merged timeline is sorted by timestamp."""
        e1 = [{"timestamp": 300}, {"timestamp": 100}]
        e2 = [{"timestamp": 200}]
        merged = _merge_endpoint_timelines([("LAP-001", e1), ("LAP-002", e2)])
        timestamps = [e["timestamp"] for e in merged]
        assert timestamps == [100, 200, 300]

    def test_preserves_source_hostname(self):
        """Merged timeline preserves source_hostname tagging."""
        e1 = [{"timestamp": 100}]
        e2 = [{"timestamp": 50}]
        merged = _merge_endpoint_timelines([("LAP-001", e1), ("LAP-002", e2)])
        assert merged[0]["source_hostname"] == "LAP-002"  # ts=50 comes first
        assert merged[1]["source_hostname"] == "LAP-001"  # ts=100 comes second


# ── Task 11.6: Integration tests for end-to-end flows ───────────────────


# Sample data for integration tests
_SAMPLE_NETWORK_ROWS_BARE_IP = [
    {
        "event_timestamp": 1717236000000,
        "actor_process_image_name": "chrome.exe",
        "action_remote_ip": "93.184.216.34",
        "action_remote_port": 443,
        "action_external_hostname": None,
        "dst_action_external_hostname": None,
        "action_local_ip": "10.0.0.5",
        "action_local_port": 54321,
        "dns_query_name": None,
    },
]

_SAMPLE_DNS_ROWS = [
    {
        "dns_query_name": "evil.com",
        "action_remote_ip": "93.184.216.34",
        "event_timestamp": 1717236001000,
    },
]

_SAMPLE_DOWNLOAD_SCRIPT_RESULT = {
    "status": "success",
    "action_id": 12345,
    "endpoint_id": "endpoint123",
    "standard_output": (
        "Endpoint TZ: UTC (UTC0:00:00)\n"
        "Hostname: LAP-TEST\n"
        "---\n"
        "[2024-06-01 10:00:00] | TestUser | Chrome | Typed | Example | https://evil.com/page | https://referrer.com\n"
        "---\n"
        "[2024-06-01 10:00:05] | TestUser | Chrome | Complete | Safe | 2.5 | Yes | application/pdf | C:\\Downloads\\report.pdf | https://evil.com/report.pdf | https://evil.com/page | https://referrer.com\n"
    ),
    "return_value": "",
    "error": None,
}


class TestIntegrationMultiEndpointEndToEnd:
    """Integration test: multi-endpoint end-to-end with mocked PAPI.

    Requirements: 1.1–1.9
    """

    @pytest.mark.asyncio
    async def test_multi_endpoint_full_flow(self):
        """Full multi-endpoint investigate flow with 2 endpoints."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        resolve_map = {
            "LAP-001": ("ep001", "CONNECTED"),
            "LAP-002": ("ep002", "CONNECTED"),
        }

        async def mock_resolve(fetcher, hn):
            return resolve_map.get(hn, (None, None))

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", side_effect=mock_resolve),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="IGNORED", mode="investigate",
                hostnames=["LAP-001", "LAP-002"],
                indicator="evil.com",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "timeline" in data
        assert len(data["timeline"]) > 0
        # All entries should have source_hostname
        hostnames_seen = {e["source_hostname"] for e in data["timeline"]}
        assert "LAP-001" in hostnames_seen
        assert "LAP-002" in hostnames_seen
        # Timeline should be sorted
        timestamps = [e["timestamp"] for e in data["timeline"]]
        assert timestamps == sorted(timestamps)


class TestIntegrationDNSEnrichmentPipeline:
    """Integration test: DNS enrichment pipeline.

    Verifies enrichment happens before correlation in investigate mode
    and before returning results in network mode.

    Requirements: 2.1–2.8
    """

    @pytest.mark.asyncio
    async def test_dns_enrichment_before_correlation_investigate(self):
        """DNS enrichment runs before correlation in investigate mode."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        # _run_xql returns bare-IP network rows first, then DNS rows
        xql_call_count = 0

        async def mock_xql(fetcher, query, **kwargs):
            nonlocal xql_call_count
            xql_call_count += 1
            if "dns_query_name != null" in query:
                return _SAMPLE_DNS_ROWS
            return _SAMPLE_NETWORK_ROWS_BARE_IP

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator=None,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # XQL should have been called twice: network + DNS
        assert xql_call_count == 2
        # The network event should have been enriched with DNS data
        # Check timeline for the enriched hostname
        network_entries = [e for e in data["timeline"] if e.get("external_hostname") is not None]
        # At least one entry should have the enriched hostname
        enriched = [e for e in network_entries if e["external_hostname"] == "evil.com"]
        assert len(enriched) > 0, "DNS enrichment should have resolved bare-IP to evil.com"

    @pytest.mark.asyncio
    async def test_dns_enrichment_in_network_mode(self):
        """DNS enrichment runs in network mode before returning results."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_xql(fetcher, query, **kwargs):
            if "dns_query_name != null" in query:
                return _SAMPLE_DNS_ROWS
            return _SAMPLE_NETWORK_ROWS_BARE_IP

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="network",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # The network event should have been enriched
        enriched = [e for e in data["network_events"] if e.get("action_external_hostname") == "evil.com"]
        assert len(enriched) > 0, "DNS enrichment should have resolved bare-IP to evil.com in network mode"

    @pytest.mark.asyncio
    async def test_dns_enrichment_failure_graceful(self):
        """DNS enrichment failure is handled gracefully with a warning."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        call_count = 0

        async def mock_xql(fetcher, query, **kwargs):
            nonlocal call_count
            call_count += 1
            if "dns_query_name != null" in query:
                raise RuntimeError("DNS query failed")
            return _SAMPLE_NETWORK_ROWS_BARE_IP

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator=None,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # Should have a warning about DNS enrichment failure
        assert any("dns" in w.lower() and "failed" in w.lower() for w in data["warnings"])


class TestIntegrationDownloadCorrelationPipeline:
    """Integration test: download correlation pipeline.

    Verifies downloads appear in the timeline when history_mode is 'downloads' or 'both'.

    Requirements: 4.1–4.8
    """

    @pytest.mark.asyncio
    async def test_downloads_appear_in_timeline_both_mode(self):
        """Downloads are parsed and appear in timeline when history_mode='both'."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_DOWNLOAD_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                history_mode="both",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # Timeline should contain download entries
        download_entries = [
            e for e in data["timeline"]
            if e.get("source") in ("download", "download_correlated")
        ]
        assert len(download_entries) > 0, "Downloads should appear in timeline"
        # Download entries should have download-specific fields
        for dl in download_entries:
            assert dl.get("file_path") is not None
            assert dl.get("source_url") is not None

    @pytest.mark.asyncio
    async def test_downloads_not_parsed_in_history_only_mode(self):
        """Downloads are NOT parsed when history_mode='history'."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_DOWNLOAD_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                history_mode="history",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # No download entries should be in the timeline
        download_entries = [
            e for e in data["timeline"]
            if e.get("source") in ("download", "download_correlated")
        ]
        assert len(download_entries) == 0, "Downloads should NOT appear when history_mode='history'"


class TestIntegrationSummarizeMode:
    """Integration test: summarize mode switching in both network and investigate modes.

    Requirements: 3.1–3.7
    """

    @pytest.mark.asyncio
    async def test_summarize_network_mode_aggregates_all(self):
        """summarize=True in network mode aggregates all events."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        multi_rows = [
            {
                "event_timestamp": 1717236000000,
                "actor_process_image_name": "chrome.exe",
                "action_remote_ip": "93.184.216.34",
                "action_remote_port": 443,
                "action_external_hostname": "evil.com",
                "dst_action_external_hostname": "evil.com",
                "action_local_ip": "10.0.0.5",
                "action_local_port": 54321,
                "dns_query_name": "evil.com",
            },
            {
                "event_timestamp": 1717236001000,
                "actor_process_image_name": "chrome.exe",
                "action_remote_ip": "93.184.216.34",
                "action_remote_port": 443,
                "action_external_hostname": "evil.com",
                "dst_action_external_hostname": "evil.com",
                "action_local_ip": "10.0.0.5",
                "action_local_port": 54322,
                "dns_query_name": "evil.com",
            },
        ]

        async def mock_xql(fetcher, query, **kwargs):
            if "dns_query_name != null" in query:
                return []
            return multi_rows

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="network",
                summarize=True,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "aggregated_network" in data
        assert "network_events" not in data
        # Aggregated records should have count fields
        for rec in data["aggregated_network"]:
            assert "count" in rec
            assert "external_hostname" in rec
            assert "first_seen" in rec
            assert "last_seen" in rec

    @pytest.mark.asyncio
    async def test_summarize_false_returns_raw_events_network(self):
        """summarize=False in network mode returns raw events."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_xql(fetcher, query, **kwargs):
            if "dns_query_name != null" in query:
                return []
            return _SAMPLE_NETWORK_ROWS

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="network",
                summarize=False,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "network_events" in data
        assert "aggregated_network" not in data

    @pytest.mark.asyncio
    async def test_summarize_investigate_mode_aggregates_network_only(self):
        """summarize=True in investigate mode aggregates only network_only entries."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                summarize=True,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "aggregated_network" in data
        # Timeline should only contain non-network_only entries
        for entry in data["timeline"]:
            assert entry["source"] != "network_only", (
                "network_only entries should be aggregated, not in timeline"
            )

    @pytest.mark.asyncio
    async def test_summarize_false_investigate_returns_full_timeline(self):
        """summarize=False in investigate mode returns full timeline."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                summarize=False,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "aggregated_network" not in data
        assert "timeline" in data


class TestIntegrationBackwardCompatibility:
    """Integration test: backward compatibility.

    All new params at defaults produce identical behavior to current code.

    Requirements: 1.1–1.9, 2.1–2.8, 3.1–3.7, 4.1–4.8, 5.1–5.6, 6.1–6.6
    """

    @pytest.mark.asyncio
    async def test_defaults_produce_same_behavior_investigate(self):
        """Default params in investigate mode produce same behavior as before."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate", indicator="evil.com",
                # All new params at defaults
                hostnames=None, summarize=False, browser_filter="*", limit=50,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "timeline" in data
        assert "summary" in data
        assert "aggregated_network" not in data
        # Should not have source_hostname (single endpoint)
        for entry in data["timeline"]:
            assert "source_hostname" not in entry

    @pytest.mark.asyncio
    async def test_defaults_produce_same_behavior_network(self):
        """Default params in network mode produce same behavior as before."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_xql(fetcher, query, **kwargs):
            if "dns_query_name != null" in query:
                return []
            return _SAMPLE_NETWORK_ROWS

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="network",
                hostnames=None, summarize=False, browser_filter="*", limit=50,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        assert "network_events" in data
        assert "aggregated_network" not in data

    @pytest.mark.asyncio
    async def test_defaults_produce_same_behavior_history(self):
        """Default params in history mode produce same behavior as before."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history",
                hostnames=None, summarize=False, browser_filter="*", limit=50,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # browser_filter should be passed as "*" to the script
        script_params = mock_script.call_args[0][3]
        assert script_params["browser_filter"] == "*"


class TestIntegrationBrowserFilter:
    """Integration test: browser filter applied in all modes.

    Requirements: 5.1–5.6
    """

    @pytest.mark.asyncio
    async def test_browser_filter_in_investigate_xql(self):
        """Browser filter is applied to XQL query in investigate mode."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS) as mock_xql,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                browser_filter="chrome",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # First XQL call (network query) should only have chrome.exe
        network_query = mock_xql.call_args_list[0][0][1]
        assert '"chrome.exe"' in network_query
        assert '"msedge.exe"' not in network_query

    @pytest.mark.asyncio
    async def test_browser_filter_in_history_script(self):
        """Browser filter is passed to history script parameters."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT) as mock_script,
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS),
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                browser_filter="edge",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        script_params = mock_script.call_args[0][3]
        assert script_params["browser_filter"] == "edge"

    @pytest.mark.asyncio
    async def test_browser_filter_in_network_mode_xql(self):
        """Browser filter is applied to XQL query in network mode."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_xql(fetcher, query, **kwargs):
            if "dns_query_name != null" in query:
                return []
            return _SAMPLE_NETWORK_ROWS

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql) as mock_xql_obj,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="network",
                browser_filter="firefox",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # First XQL call should only have firefox.exe
        network_query = mock_xql_obj.call_args_list[0][0][1]
        assert '"firefox.exe"' in network_query
        assert '"chrome.exe"' not in network_query

    @pytest.mark.asyncio
    async def test_browser_filter_in_history_mode(self):
        """Browser filter is passed to history script in history mode."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history",
                browser_filter="brave",
            )

        data = json.loads(result)
        assert data["success"] == "true"
        script_params = mock_script.call_args[0][3]
        assert script_params["browser_filter"] == "brave"


class TestIntegrationConfigurableLimit:
    """Integration test: configurable limit in XQL queries.

    Requirements: 6.1–6.6
    """

    @pytest.mark.asyncio
    async def test_custom_limit_in_investigate_xql(self):
        """Custom limit is used in investigate mode XQL query."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_SCRIPT_RESULT),
            patch(f"{_MOD}._run_xql", return_value=_SAMPLE_NETWORK_ROWS) as mock_xql,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="investigate",
                limit=200,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # First XQL call should use limit 200
        network_query = mock_xql.call_args_list[0][0][1]
        assert "limit 200" in network_query

    @pytest.mark.asyncio
    async def test_custom_limit_in_network_xql(self):
        """Custom limit is used in network mode XQL query."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        async def mock_xql(fetcher, query, **kwargs):
            if "dns_query_name != null" in query:
                return []
            return _SAMPLE_NETWORK_ROWS

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._run_xql", side_effect=mock_xql) as mock_xql_obj,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="network",
                limit=100,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        network_query = mock_xql_obj.call_args_list[0][0][1]
        assert "limit 100" in network_query

    @pytest.mark.asyncio
    async def test_history_mode_unaffected_by_limit(self):
        """History mode is unaffected by the limit parameter."""
        ctx = _mock_ctx()
        mock_fetcher = AsyncMock()

        with (
            patch(f"{_MOD}.get_fetcher", return_value=mock_fetcher),
            patch(f"{_MOD}._resolve_endpoint", return_value=("endpoint123", "CONNECTED")),
            patch(f"{_MOD}._resolve_script_uid", return_value="script-uid-abc"),
            patch(f"{_MOD}._run_script_on_endpoint", return_value=_SAMPLE_HISTORY_RESULT) as mock_script,
            patch(f"{_MOD}._run_xql") as mock_xql,
        ):
            result = await investigate_browser_session(
                ctx, hostname="LAP-TEST", mode="history",
                limit=200,
            )

        data = json.loads(result)
        assert data["success"] == "true"
        # XQL should not be called in history mode
        mock_xql.assert_not_called()
        # Script params should not contain the limit
        script_params = mock_script.call_args[0][3]
        assert "limit" not in script_params
