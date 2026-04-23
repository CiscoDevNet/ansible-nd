# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for nd_output.py

Tests the NDOutput class for formatting module output, including
verbosity-gated API call detail via format_with_verbosity().
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


# =============================================================================
# Helpers
# =============================================================================


def _register_task(
    results,
    path="/api/v1/test",
    verb=HttpVerbEnum.POST,
    payload=None,
    verbosity_level=3,
    operation_type=OperationType.CREATE,
    success=True,
    changed=True,
):
    """Register a single task in a Results instance with configurable fields."""
    results.action = operation_type.value
    results.operation_type = operation_type
    results.path_current = path
    results.verb_current = verb
    results.payload_current = payload
    results.verbosity_level_current = verbosity_level
    results.response_current = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    results.result_current = {"success": success, "changed": changed}
    results.diff_current = {"before": {}, "after": {"foo": "bar"}} if changed else {}
    results.register_api_call()


def _make_results_write_and_query():
    """
    Create a Results instance with two tasks:

    1. Write operation (CREATE) tagged at verbosity_level=2
    2. Query operation (QUERY) tagged at verbosity_level=3
    """
    r = Results()
    r.state = "merged"
    r.check_mode = False

    # Task 1: write (verbosity 2 — shown at -vv)
    _register_task(
        r,
        path="/api/v1/fabrics",
        verb=HttpVerbEnum.POST,
        payload={"name": "FAB1"},
        verbosity_level=2,
        operation_type=OperationType.CREATE,
    )

    # Task 2: query (verbosity 3 — shown at -vvv)
    _register_task(
        r,
        path="/api/v1/fabrics",
        verb=HttpVerbEnum.GET,
        payload=None,
        verbosity_level=3,
        operation_type=OperationType.QUERY,
        changed=False,
    )

    r.build_final_result()
    return r


# =============================================================================
# Test: NDOutput.__init__
# =============================================================================


class TestNDOutputInit:
    """Tests for NDOutput initialization."""

    def test_init_normal(self):
        """NDOutput initializes with output_level stored."""
        output = NDOutput("normal")
        assert output._output_level == "normal"
        assert output._changed is False
        assert output._logs == []
        assert output._extra == {}

    def test_init_debug(self):
        """NDOutput accepts debug output_level."""
        output = NDOutput("debug")
        assert output._output_level == "debug"

    def test_init_info(self):
        """NDOutput accepts info output_level."""
        output = NDOutput("info")
        assert output._output_level == "info"


# =============================================================================
# Test: NDOutput.format (base output, no verbosity)
# =============================================================================


class TestNDOutputFormat:
    """Tests for the base format() method."""

    def test_format_normal_base_keys(self):
        """Normal output_level includes output_level, changed, after, before, diff."""
        output = NDOutput("normal")
        result = output.format()
        assert result["output_level"] == "normal"
        assert result["changed"] is False
        assert "after" in result
        assert "before" in result
        assert "diff" in result

    def test_format_normal_excludes_proposed_and_logs(self):
        """Normal output_level does NOT include proposed or logs."""
        output = NDOutput("normal")
        result = output.format()
        assert "proposed" not in result
        assert "logs" not in result

    def test_format_info_includes_proposed(self):
        """Info output_level includes proposed but not logs."""
        output = NDOutput("info")
        result = output.format()
        assert "proposed" in result
        assert "logs" not in result

    def test_format_debug_includes_proposed_and_logs(self):
        """Debug output_level includes both proposed and logs."""
        output = NDOutput("debug")
        result = output.format()
        assert "proposed" in result
        assert "logs" in result

    def test_format_kwargs_merged(self):
        """Extra kwargs passed to format() are included in output."""
        output = NDOutput("normal")
        result = output.format(custom_key="custom_value")
        assert result["custom_key"] == "custom_value"

    def test_format_extra_from_assign(self):
        """Extra kwargs from assign() are included in output."""
        output = NDOutput("normal")
        output.assign(extra_field="extra_value")
        result = output.format()
        assert result["extra_field"] == "extra_value"

    def test_format_lists_as_defaults(self):
        """When no NDConfigCollection is assigned, lists are used as-is."""
        output = NDOutput("normal")
        result = output.format()
        assert result["after"] == []
        assert result["before"] == []
        assert result["diff"] == []


# =============================================================================
# Test: NDOutput.assign
# =============================================================================


class TestNDOutputAssign:
    """Tests for the assign() method."""

    def test_assign_logs(self):
        """assign() sets logs when a list is provided."""
        output = NDOutput("debug")
        output.assign(logs=["log1", "log2"])
        assert output._logs == ["log1", "log2"]

    def test_assign_logs_ignores_non_list(self):
        """assign() ignores logs when a non-list is provided."""
        output = NDOutput("debug")
        output.assign(logs="not_a_list")
        assert output._logs == []

    def test_assign_none_values_ignored(self):
        """assign() ignores None values for typed parameters."""
        output = NDOutput("normal")
        output.assign(after=None, before=None, diff=None, proposed=None, logs=None)
        assert output._after == []
        assert output._before == []

    def test_assign_extra_kwargs(self):
        """assign() stores extra kwargs in _extra."""
        output = NDOutput("normal")
        output.assign(custom="value1")
        output.assign(another="value2")
        assert output._extra["custom"] == "value1"
        assert output._extra["another"] == "value2"


# =============================================================================
# Test: NDOutput.format_with_verbosity — verbosity 0 and 1
# =============================================================================


class TestFormatWithVerbosityLevel0And1:
    """Tests for verbosity levels 0 and 1 (default / -v): no API detail."""

    def test_verbosity_0_no_api_keys(self):
        """Verbosity 0: output contains no api_* keys."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(0, results)
        assert "api_paths" not in result
        assert "api_verbs" not in result
        assert "api_response" not in result

    def test_verbosity_1_no_api_keys(self):
        """Verbosity 1 (-v): output contains no api_* keys."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(1, results)
        assert "api_paths" not in result
        assert "api_verbs" not in result

    def test_verbosity_0_preserves_base_format(self):
        """Verbosity 0 still includes all base format() keys."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(0, results)
        assert "output_level" in result
        assert "changed" in result
        assert "after" in result
        assert "before" in result
        assert "diff" in result


# =============================================================================
# Test: NDOutput.format_with_verbosity — verbosity 2 (-vv)
# =============================================================================


class TestFormatWithVerbosityLevel2:
    """Tests for verbosity level 2 (-vv): API call summary for writes."""

    def test_verbosity_2_includes_paths_and_verbs(self):
        """Verbosity 2 includes api_paths and api_verbs."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(2, results)
        assert "api_paths" in result
        assert "api_verbs" in result

    def test_verbosity_2_filters_to_writes_only(self):
        """Verbosity 2 shows only tasks tagged verbosity_level <= 2 (writes)."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(2, results)
        # Only the write task (POST, verbosity_level=2) should appear
        assert result["api_paths"] == ["/api/v1/fabrics"]
        assert result["api_verbs"] == ["POST"]

    def test_verbosity_2_excludes_full_detail(self):
        """Verbosity 2 does NOT include api_response, api_result, etc."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(2, results)
        assert "api_response" not in result
        assert "api_result" not in result
        assert "api_diff" not in result
        assert "api_metadata" not in result
        assert "api_payload" not in result

    def test_verbosity_2_propagates_changed_from_results(self):
        """Results changed=True propagates into output at verbosity 2."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(2, results)
        assert result["changed"] is True

    def test_verbosity_2_propagates_failed_from_results(self):
        """Results failed=True propagates into output at verbosity 2."""
        output = NDOutput("normal")
        r = Results()
        r.state = "merged"
        r.check_mode = False
        _register_task(r, verbosity_level=2, success=False, changed=False)
        r.build_final_result()
        result = output.format_with_verbosity(2, r)
        assert result.get("failed") is True


# =============================================================================
# Test: NDOutput.format_with_verbosity — verbosity 3+ (-vvv)
# =============================================================================


class TestFormatWithVerbosityLevel3:
    """Tests for verbosity level 3+ (-vvv): full controller detail."""

    def test_verbosity_3_includes_all_tasks(self):
        """Verbosity 3 shows both write (vl=2) and query (vl=3) tasks."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(3, results)
        assert len(result["api_paths"]) == 2
        assert result["api_paths"] == ["/api/v1/fabrics", "/api/v1/fabrics"]
        assert result["api_verbs"] == ["POST", "GET"]

    def test_verbosity_3_includes_full_detail_keys(self):
        """Verbosity 3 includes api_response, api_result, api_diff, api_metadata, api_payload."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(3, results)
        assert "api_response" in result
        assert "api_result" in result
        assert "api_diff" in result
        assert "api_metadata" in result
        assert "api_payload" in result

    def test_verbosity_3_detail_lists_match_task_count(self):
        """All detail lists at verbosity 3 have the same length as task count."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(3, results)
        for key in ("api_response", "api_result", "api_diff", "api_metadata", "api_payload"):
            assert len(result[key]) == 2, f"{key} should have 2 entries"

    def test_verbosity_3_payload_contains_correct_data(self):
        """api_payload reflects registered payloads (dict for write, None for query)."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(3, results)
        assert result["api_payload"][0] == {"name": "FAB1"}
        assert result["api_payload"][1] is None

    def test_verbosity_4_same_as_3(self):
        """Verbosity 4+ behaves identically to 3 (all tasks, full detail)."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result_3 = output.format_with_verbosity(3, results)
        result_4 = output.format_with_verbosity(4, results)
        assert result_3["api_paths"] == result_4["api_paths"]
        assert result_3["api_verbs"] == result_4["api_verbs"]
        assert result_3.get("api_response") == result_4.get("api_response")


# =============================================================================
# Test: NDOutput.format_with_verbosity — edge cases
# =============================================================================


class TestFormatWithVerbosityEdgeCases:
    """Edge case tests for format_with_verbosity."""

    def test_none_results_returns_base_format(self):
        """When results is None, returns base format() output without api_* keys."""
        output = NDOutput("normal")
        result = output.format_with_verbosity(3, None)
        assert "api_paths" not in result
        assert "changed" in result

    def test_empty_results_no_api_keys(self):
        """Results with no registered tasks produces no api_* keys."""
        output = NDOutput("normal")
        results = Results()
        results.build_final_result()
        result = output.format_with_verbosity(3, results)
        assert "api_paths" not in result

    def test_auto_builds_final_result(self):
        """format_with_verbosity auto-calls build_final_result() if not yet built."""
        output = NDOutput("normal")
        r = Results()
        r.state = "merged"
        r.check_mode = False
        _register_task(r, path="/api/v1/auto", verbosity_level=2)
        # Do NOT call r.build_final_result() — let format_with_verbosity do it
        result = output.format_with_verbosity(2, r)
        assert result["api_paths"] == ["/api/v1/auto"]

    def test_kwargs_forwarded_to_format(self):
        """Extra kwargs are forwarded to the base format() call."""
        output = NDOutput("normal")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(2, results, custom="val")
        assert result["custom"] == "val"

    def test_output_level_and_verbosity_independent(self):
        """output_level and verbosity are independent — debug output_level with verbosity 0."""
        output = NDOutput("debug")
        results = _make_results_write_and_query()
        result = output.format_with_verbosity(0, results)
        # Debug output_level features present
        assert "proposed" in result
        assert "logs" in result
        # But no api_* keys because verbosity < 2
        assert "api_paths" not in result

    def test_all_tasks_above_verbosity_threshold(self):
        """When all tasks have verbosity_level > requested, no api_* keys appear."""
        output = NDOutput("normal")
        r = Results()
        r.state = "merged"
        r.check_mode = False
        _register_task(r, verbosity_level=5)
        r.build_final_result()
        result = output.format_with_verbosity(2, r)
        assert "api_paths" not in result

    def test_multiple_write_tasks(self):
        """Multiple write tasks all appear at verbosity 2."""
        output = NDOutput("normal")
        r = Results()
        r.state = "merged"
        r.check_mode = False
        _register_task(r, path="/api/v1/a", verb=HttpVerbEnum.POST, verbosity_level=2)
        _register_task(r, path="/api/v1/b", verb=HttpVerbEnum.PUT, verbosity_level=2)
        _register_task(r, path="/api/v1/c", verb=HttpVerbEnum.DELETE, verbosity_level=2)
        r.build_final_result()
        result = output.format_with_verbosity(2, r)
        assert result["api_paths"] == ["/api/v1/a", "/api/v1/b", "/api/v1/c"]
        assert result["api_verbs"] == ["POST", "PUT", "DELETE"]

    def test_changed_false_not_overwritten(self):
        """If Results changed=False, output changed stays as-is from NDOutput."""
        output = NDOutput("normal")
        r = Results()
        r.state = "merged"
        r.check_mode = False
        _register_task(r, verbosity_level=2, changed=False, success=True)
        r.build_final_result()
        result = output.format_with_verbosity(2, r)
        assert result["changed"] is False
