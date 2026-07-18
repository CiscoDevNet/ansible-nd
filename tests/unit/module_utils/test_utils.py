# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for module_utils/utils.py helpers.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.utils import prune_to_spec


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
