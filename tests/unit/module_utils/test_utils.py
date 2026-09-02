# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the pure diff and argument-spec pruning helpers in ``module_utils/utils.py``."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.utils import has_removals, issubset, prune_to_spec


class TestPruneToSpec:
    """Tests for prune_to_spec, which trims data to an argument spec's options."""

    def test_drops_keys_not_in_spec(self):
        """Keys absent from the spec (e.g. response-only fields) are removed."""
        data = {"name": "leaf1", "link_id": "UUID-123"}
        spec = {"name": {"type": "str"}}
        assert prune_to_spec(data, spec) == {"name": "leaf1"}

    def test_keeps_scalar_and_scalar_list_verbatim(self):
        """Scalars and lists of scalars pass through unchanged."""
        data = {"name": "leaf1", "interface_names": ["Eth1/1", "Eth1/2"]}
        spec = {"name": {"type": "str"}, "interface_names": {"type": "list", "elements": "str"}}
        assert prune_to_spec(data, spec) == data

    def test_recurses_into_modeled_dict(self):
        """A dict suboption with options is pruned recursively."""
        data = {"config_data": {"policy_type": "numbered", "server_only": "x"}}
        spec = {"config_data": {"type": "dict", "options": {"policy_type": {"type": "str"}}}}
        assert prune_to_spec(data, spec) == {"config_data": {"policy_type": "numbered"}}

    def test_recurses_into_list_of_modeled_dicts(self):
        """A list of dicts with options is pruned element by element."""
        data = {"links": [{"name": "a", "extra": 1}, {"name": "b", "extra": 2}]}
        spec = {"links": {"type": "list", "elements": "dict", "options": {"name": {"type": "str"}}}}
        assert prune_to_spec(data, spec) == {"links": [{"name": "a"}, {"name": "b"}]}

    def test_free_form_dict_left_untouched(self):
        """A dict suboption without options is free-form and preserved verbatim."""
        data = {"template_inputs": {"anyKey": 1, "nested": {"deep": True}}}
        spec = {"template_inputs": {"type": "dict"}}
        assert prune_to_spec(data, spec) == data

    def test_deeply_nested_recursion(self):
        """Recursion follows options through several levels."""
        data = {"config_data": {"network_os": {"policy": {"mtu": "9216", "server_only": "x"}}}}
        spec = {
            "config_data": {
                "type": "dict",
                "options": {
                    "network_os": {
                        "type": "dict",
                        "options": {"policy": {"type": "dict", "options": {"mtu": {"type": "str"}}}},
                    }
                },
            }
        }
        assert prune_to_spec(data, spec) == {"config_data": {"network_os": {"policy": {"mtu": "9216"}}}}

    def test_masks_no_log_keys(self):
        """no_log suboptions are masked so gathered never surfaces the real secret."""
        data = {"name": "leaf1", "password": "hunter2"}
        spec = {"name": {"type": "str"}, "password": {"type": "str", "no_log": True}}
        assert prune_to_spec(data, spec) == {"name": "leaf1", "password": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"}

    def test_masks_nested_no_log_keys(self):
        """no_log suboptions nested inside a modeled dict are also masked."""
        data = {"config_data": {"policy_type": "numbered", "password": "hunter2"}}
        spec = {
            "config_data": {
                "type": "dict",
                "options": {"policy_type": {"type": "str"}, "password": {"type": "str", "no_log": True}},
            }
        }
        expected = {"config_data": {"policy_type": "numbered", "password": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"}}
        assert prune_to_spec(data, spec) == expected

    def test_non_dict_data_returned_as_is(self):
        """Non-dict input is returned unchanged."""
        assert prune_to_spec("leaf1", {"name": {"type": "str"}}) == "leaf1"

    def test_mismatched_type_values_kept(self):
        """If data shape does not match the spec's declared type, value is kept as-is."""
        # spec says dict, but data has a scalar -> keep verbatim rather than crash
        data = {"config_data": "unexpected"}
        spec = {"config_data": {"type": "dict", "options": {"policy_type": {"type": "str"}}}}
        assert prune_to_spec(data, spec) == {"config_data": "unexpected"}


# pylint: disable=line-too-long

# --- issubset (001XX) ---


def test_utils_00100() -> None:
    """
    # Summary

    A dict whose keys/values all appear in the superset is a subset; extra superset keys are ignored.

    ## Test

    - `issubset` is called with a proposed dict that is a strict key-subset of the existing dict.
    - The result is `True` (extra existing keys are not examined -- the documented one-way behavior).

    ## Classes and Methods

    - utils.issubset()
    """
    assert issubset({"a": 1}, {"a": 1, "b": 2}) is True


def test_utils_00110() -> None:
    """
    # Summary

    A differing scalar value, or a key missing from the superset, is not a subset.

    ## Test

    - `issubset` is called with a value mismatch, then with a key absent from the superset.
    - Both results are `False`.

    ## Classes and Methods

    - utils.issubset()
    """
    assert issubset({"a": 1}, {"a": 2}) is False
    assert issubset({"a": 1}, {"b": 1}) is False


def test_utils_00120() -> None:
    """
    # Summary

    Nested dicts recurse, and `None` values on the subset side are skipped.

    ## Test

    - A nested dict subset matches a deeper superset.
    - A subset key with value `None` does not force a mismatch.

    ## Classes and Methods

    - utils.issubset()
    """
    assert issubset({"a": {"b": 1}}, {"a": {"b": 1, "c": 2}}) is True
    assert issubset({"a": {"b": 2}}, {"a": {"b": 1, "c": 2}}) is False
    assert issubset({"a": None}, {"b": 1}) is True


def test_utils_00130() -> None:
    """
    # Summary

    Lists require equal length and bidirectional element matches (order-independent full equality).

    ## Test

    - Equal lists in different order match.
    - A shorter proposed list, or an element whose dict dropped a key, does not match.

    ## Classes and Methods

    - utils.issubset()
    """
    assert issubset({"a": [1, 2]}, {"a": [2, 1]}) is True
    assert issubset({"a": [1]}, {"a": [1, 2]}) is False
    assert issubset({"a": [{"b": 1}]}, {"a": [{"b": 1, "c": 2}]}) is False


def test_utils_00140() -> None:
    """
    # Summary

    A type mismatch between subset and superset is never a subset.

    ## Test

    - A dict compared against a list, and an int against a str, both return `False`.

    ## Classes and Methods

    - utils.issubset()
    """
    assert issubset({"a": 1}, [{"a": 1}]) is False
    assert issubset(1, "1") is False


# --- has_removals (002XX) ---


def test_utils_00200() -> None:
    """
    # Summary

    A key present on the existing side but absent from the proposed side is a removal.

    ## Test

    - `has_removals` is called with an existing dict carrying one extra non-empty key.
    - The result is `True`.

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": 1, "b": 2}, {"a": 1}) is True


def test_utils_00210() -> None:
    """
    # Summary

    Identical key sets have no removals; value differences are NOT removals (they are the forward pass's job).

    ## Test

    - Same keys with equal values: `False`.
    - Same keys with differing scalar values: still `False` -- `has_removals` only reports missing keys.

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": 1}, {"a": 1}) is False
    assert has_removals({"a": 1}, {"a": 2}) is False


def test_utils_00220() -> None:
    """
    # Summary

    Empty values (`None`, `""`, `[]`, `{}`) on the existing side are normalized to absent and never count as removals.

    ## Test

    - Existing keys whose values are `None`, `""`, `[]`, and `{}` are all missing from proposed.
    - The result is `False` for each (ND echoes empty markers for never-configured fields).

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": None}, {}) is False
    assert has_removals({"a": ""}, {}) is False
    assert has_removals({"a": []}, {}) is False
    assert has_removals({"a": {}}, {}) is False


def test_utils_00230() -> None:
    """
    # Summary

    Removals are detected recursively inside nested dicts present on both sides.

    ## Test

    - A nested dict on both sides where the existing nested dict carries one extra non-empty key: `True`.
    - The same shape with the extra nested key empty-valued: `False`.

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": {"b": 1, "c": 2}}, {"a": {"b": 1}}) is True
    assert has_removals({"a": {"b": 1, "c": ""}}, {"a": {"b": 1}}) is False


def test_utils_00240() -> None:
    """
    # Summary

    A non-empty nested dict absent entirely from the proposed side is a removal.

    ## Test

    - Existing carries a nested dict with real content; proposed lacks the key.
    - The result is `True`.

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": {"b": 1}}, {}) is True


def test_utils_00250() -> None:
    """
    # Summary

    A nested dict whose members are all empty-valued normalizes to absent as a whole.

    ## Test

    - Existing carries a nested dict containing only empty values; proposed lacks the key.
    - The result is `False` (nothing user-visible would be removed).

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": {"b": "", "c": None}}, {}) is False


def test_utils_00260() -> None:
    """
    # Summary

    Keys present on both sides with list or scalar values are not recursed; list content is the forward pass's job.

    ## Test

    - A non-empty list present on existing and absent from proposed: `True` (removal).
    - The same list present on both sides but with differing content: `False` (not a removal).

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": [1, 2]}, {}) is True
    assert has_removals({"a": [1, 2]}, {"a": [1]}) is False


def test_utils_00270() -> None:
    """
    # Summary

    Non-dict top-level input never reports removals.

    ## Test

    - Scalars, lists, and `None` as the existing side all return `False`.

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals("a", "b") is False
    assert has_removals([1], []) is False
    assert has_removals(None, {"a": 1}) is False


def test_utils_00280() -> None:
    """
    # Summary

    A dict existing side compared against a non-dict proposed side reports no removals (type conflicts are the forward pass's job).

    ## Test

    - Existing is a dict, proposed is a scalar.
    - The result is `False` -- the forward `issubset` type check already classifies this as changed.

    ## Classes and Methods

    - utils.has_removals()
    """
    assert has_removals({"a": 1}, "not-a-dict") is False
