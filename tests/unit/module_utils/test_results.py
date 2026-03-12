# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for results.py

Tests the Results class and its Pydantic models for collecting and aggregating
API call results.
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import (
    ApiCallResult,
    PendingApiCall,
    Results,
)

# =============================================================================
# Helper: register a task with all fields populated
# =============================================================================


def _register_task(results, path="/api/v1/test", verb=HttpVerbEnum.POST, payload=None, verbosity_level=3):
    """Register a single task with the given request-side fields."""
    results.path_current = path
    results.verb_current = verb
    results.payload_current = payload
    results.verbosity_level_current = verbosity_level
    results.action = "test_action"
    results.state = "merged"
    results.check_mode = False
    results.operation_type = OperationType.DELETE
    results.response_current = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    results.result_current = {"success": True, "changed": True}
    results.diff_current = {"before": {}, "after": {"foo": "bar"}}
    results.register_api_call()


# =============================================================================
# Test: PendingApiCall new fields
# =============================================================================


class TestPendingApiCallNewFields:
    """Tests for the new fields on PendingApiCall."""

    def test_defaults(self):
        """New fields have correct defaults."""
        pending = PendingApiCall()
        assert pending.path == ""
        assert pending.verb == HttpVerbEnum.GET
        assert pending.payload is None
        assert pending.verbosity_level == 3

    def test_explicit_values(self):
        """New fields accept explicit values."""
        pending = PendingApiCall(
            path="/api/v1/fabrics",
            verb=HttpVerbEnum.DELETE,
            payload={"name": "FABRIC_1"},
            verbosity_level=5,
        )
        assert pending.path == "/api/v1/fabrics"
        assert pending.verb == HttpVerbEnum.DELETE
        assert pending.payload == {"name": "FABRIC_1"}
        assert pending.verbosity_level == 5

    def test_verbosity_level_min_boundary(self):
        """verbosity_level rejects values below 1."""
        with pytest.raises(Exception):
            PendingApiCall(verbosity_level=0)

    def test_verbosity_level_max_boundary(self):
        """verbosity_level rejects values above 6."""
        with pytest.raises(Exception):
            PendingApiCall(verbosity_level=7)

    def test_verbosity_level_valid_boundaries(self):
        """verbosity_level accepts boundary values 1 and 6."""
        p1 = PendingApiCall(verbosity_level=1)
        p6 = PendingApiCall(verbosity_level=6)
        assert p1.verbosity_level == 1
        assert p6.verbosity_level == 6


# =============================================================================
# Test: ApiCallResult new fields
# =============================================================================


class TestApiCallResultNewFields:
    """Tests for the new fields on ApiCallResult."""

    @staticmethod
    def _make_result(**overrides):
        """Create an ApiCallResult with sensible defaults, allowing overrides."""
        defaults = {
            "sequence_number": 1,
            "path": "/api/v1/test",
            "verb": "POST",
            "payload": None,
            "verbosity_level": 3,
            "response": {"RETURN_CODE": 200},
            "result": {"success": True},
            "diff": {},
            "metadata": {"action": "test"},
            "changed": False,
            "failed": False,
        }
        defaults.update(overrides)
        return ApiCallResult(**defaults)

    def test_stores_request_fields(self):
        """ApiCallResult stores path, verb, payload, verbosity_level."""
        task = self._make_result(
            path="/api/v1/fabrics",
            verb="DELETE",
            payload={"name": "FAB1"},
            verbosity_level=5,
        )
        assert task.path == "/api/v1/fabrics"
        assert task.verb == "DELETE"
        assert task.payload == {"name": "FAB1"}
        assert task.verbosity_level == 5

    def test_verb_validator_coerces_enum(self):
        """field_validator coerces HttpVerbEnum to string."""
        task = self._make_result(verb=HttpVerbEnum.PUT)
        assert task.verb == "PUT"
        assert isinstance(task.verb, str)

    def test_verb_validator_passes_string(self):
        """field_validator passes plain strings through."""
        task = self._make_result(verb="GET")
        assert task.verb == "GET"

    def test_payload_none_allowed(self):
        """payload=None is valid (e.g. for GET requests)."""
        task = self._make_result(payload=None)
        assert task.payload is None

    def test_verbosity_level_rejects_out_of_range(self):
        """verbosity_level outside 1-6 raises ValidationError."""
        with pytest.raises(Exception):
            self._make_result(verbosity_level=0)
        with pytest.raises(Exception):
            self._make_result(verbosity_level=7)

    def test_frozen(self):
        """ApiCallResult is immutable."""
        task = self._make_result()
        with pytest.raises(Exception):
            task.path = "/new/path"


# =============================================================================
# Test: Results current-task properties (getters/setters)
# =============================================================================


class TestResultsCurrentProperties:
    """Tests for path_current, verb_current, payload_current, verbosity_level_current."""

    def test_path_current_get_set(self):
        """path_current getter/setter works."""
        r = Results()
        assert r.path_current == ""
        r.path_current = "/api/v1/foo"
        assert r.path_current == "/api/v1/foo"

    def test_path_current_type_error(self):
        """path_current setter rejects non-string."""
        r = Results()
        with pytest.raises(TypeError, match="value must be a string"):
            r.path_current = 123

    def test_verb_current_get_set(self):
        """verb_current getter/setter works."""
        r = Results()
        assert r.verb_current == HttpVerbEnum.GET
        r.verb_current = HttpVerbEnum.POST
        assert r.verb_current == HttpVerbEnum.POST

    def test_verb_current_type_error(self):
        """verb_current setter rejects non-HttpVerbEnum."""
        r = Results()
        with pytest.raises(TypeError, match="value must be an HttpVerbEnum"):
            r.verb_current = "POST"

    def test_payload_current_get_set(self):
        """payload_current getter/setter works with dict and None."""
        r = Results()
        assert r.payload_current is None
        r.payload_current = {"key": "val"}
        assert r.payload_current == {"key": "val"}
        r.payload_current = None
        assert r.payload_current is None

    def test_payload_current_type_error(self):
        """payload_current setter rejects non-dict/non-None."""
        r = Results()
        with pytest.raises(TypeError, match="value must be a dict or None"):
            r.payload_current = "not a dict"

    def test_verbosity_level_current_get_set(self):
        """verbosity_level_current getter/setter works."""
        r = Results()
        assert r.verbosity_level_current == 3
        r.verbosity_level_current = 5
        assert r.verbosity_level_current == 5

    def test_verbosity_level_current_type_error(self):
        """verbosity_level_current setter rejects non-int."""
        r = Results()
        with pytest.raises(TypeError, match="value must be an int"):
            r.verbosity_level_current = "high"

    def test_verbosity_level_current_type_error_bool(self):
        """verbosity_level_current setter rejects bool (isinstance(True, int) is True)."""
        r = Results()
        with pytest.raises(TypeError, match="value must be an int"):
            r.verbosity_level_current = True

    def test_verbosity_level_current_value_error_low(self):
        """verbosity_level_current setter rejects value < 1."""
        r = Results()
        with pytest.raises(ValueError, match="value must be between 1 and 6"):
            r.verbosity_level_current = 0

    def test_verbosity_level_current_value_error_high(self):
        """verbosity_level_current setter rejects value > 6."""
        r = Results()
        with pytest.raises(ValueError, match="value must be between 1 and 6"):
            r.verbosity_level_current = 7


# =============================================================================
# Test: register_api_call captures new fields
# =============================================================================


class TestRegisterApiCallNewFields:
    """Tests that register_api_call() captures the new request-side fields."""

    def test_captures_all_new_fields(self):
        """register_api_call stores path, verb, payload, verbosity_level on the task."""
        r = Results()
        payload = {"fabric": "FAB1"}
        _register_task(r, path="/api/v1/fabrics", verb=HttpVerbEnum.POST, payload=payload, verbosity_level=4)

        assert len(r._tasks) == 1
        task = r._tasks[0]
        assert task.path == "/api/v1/fabrics"
        assert task.verb == "POST"  # coerced from enum
        assert task.payload == {"fabric": "FAB1"}
        assert task.verbosity_level == 4

    def test_captures_none_payload(self):
        """register_api_call handles None payload correctly."""
        r = Results()
        _register_task(r, payload=None)
        assert r._tasks[0].payload is None

    def test_payload_is_deep_copied(self):
        """register_api_call deep-copies payload to prevent mutation."""
        r = Results()
        payload = {"nested": {"key": "original"}}
        _register_task(r, payload=payload)
        # Mutate original
        payload["nested"]["key"] = "mutated"
        # Registered copy should be unaffected
        assert r._tasks[0].payload["nested"]["key"] == "original"

    def test_defaults_when_not_set(self):
        """When new fields are not explicitly set, defaults are used."""
        r = Results()
        r.action = "test_action"
        r.state = "merged"
        r.check_mode = False
        r.operation_type = OperationType.QUERY
        r.response_current = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        r.result_current = {"success": True}
        r.diff_current = {}
        r.register_api_call()

        task = r._tasks[0]
        assert task.path == ""
        assert task.verb == "GET"
        assert task.payload is None
        assert task.verbosity_level == 3


# =============================================================================
# Test: aggregate properties (path, verb, payload, verbosity_level)
# =============================================================================


class TestAggregateProperties:
    """Tests for the aggregate list properties."""

    def test_aggregate_properties(self):
        """Aggregate properties return lists across all registered tasks."""
        r = Results()
        _register_task(r, path="/api/v1/a", verb=HttpVerbEnum.GET, payload=None, verbosity_level=1)
        _register_task(r, path="/api/v1/b", verb=HttpVerbEnum.POST, payload={"x": 1}, verbosity_level=5)

        assert r.path == ["/api/v1/a", "/api/v1/b"]
        assert r.verb == ["GET", "POST"]
        assert r.payload == [None, {"x": 1}]
        assert r.verbosity_level == [1, 5]

    def test_empty_when_no_tasks(self):
        """Aggregate properties return empty lists when no tasks registered."""
        r = Results()
        assert r.path == []
        assert r.verb == []
        assert r.payload == []
        assert r.verbosity_level == []


# =============================================================================
# Test: build_final_result includes new fields
# =============================================================================


class TestBuildFinalResultNewFields:
    """Tests that build_final_result() includes the new fields."""

    def test_final_result_includes_new_fields(self):
        """build_final_result populates path, verb, payload, verbosity_level."""
        r = Results()
        _register_task(r, path="/api/v1/fabrics", verb=HttpVerbEnum.DELETE, payload={"name": "F1"}, verbosity_level=2)
        _register_task(r, path="/api/v1/switches", verb=HttpVerbEnum.GET, payload=None, verbosity_level=4)

        r.build_final_result()
        result = r.final_result

        assert result["path"] == ["/api/v1/fabrics", "/api/v1/switches"]
        assert result["verb"] == ["DELETE", "GET"]
        assert result["payload"] == [{"name": "F1"}, None]
        assert result["verbosity_level"] == [2, 4]

    def test_final_result_empty_tasks(self):
        """build_final_result with no tasks produces empty lists for new fields."""
        r = Results()
        r.build_final_result()
        result = r.final_result

        assert result["path"] == []
        assert result["verb"] == []
        assert result["payload"] == []
        assert result["verbosity_level"] == []
