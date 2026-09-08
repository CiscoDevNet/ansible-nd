# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `nd_interface_ethernet_access` module-level helpers.

Covers `validate_within_item_duplicates`, `validate_across_item_duplicates`, and the integrated
`expand_config` flatten step. Live ND interaction is exercised by the integration target.
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long

from __future__ import absolute_import, division, print_function

from typing import Any

import pytest
import yaml
from ansible_collections.cisco.nd.plugins.modules import nd_interface_ethernet_access
from ansible_collections.cisco.nd.plugins.modules.nd_interface_ethernet_access import (
    expand_config,
    validate_across_item_duplicates,
    validate_interface_names,
    validate_within_item_duplicates,
)

# --- validate_within_item_duplicates ---


def test_validate_within_item_duplicates_00000_no_duplicates():
    """
    # Summary

    Verify that distinct interface names within a single item produce no error.

    ## Test

    - Single item with two distinct interface names is accepted

    ## Classes and Methods

    - validate_within_item_duplicates()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1", "Ethernet1/2"]}]
    validate_within_item_duplicates(config)


def test_validate_within_item_duplicates_00100_exact_duplicate_raises():
    """
    # Summary

    Verify that the same interface name listed twice in one item raises ValueError with the
    offending name, switch, and item index in the message.

    ## Test

    - Single item with duplicate interface names raises ValueError

    ## Classes and Methods

    - validate_within_item_duplicates()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1", "Ethernet1/1"]}]
    with pytest.raises(ValueError, match=r"Duplicate interface 'Ethernet1/1' in interface_names for switch '1.1.1.1' \(config item 0\)"):
        validate_within_item_duplicates(config)


def test_validate_within_item_duplicates_00101_case_insensitive_raises():
    """
    # Summary

    Verify duplicate detection is case-insensitive within a single item.

    ## Test

    - Single item with `Ethernet1/1` and `ethernet1/1` raises ValueError

    ## Classes and Methods

    - validate_within_item_duplicates()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1", "ethernet1/1"]}]
    with pytest.raises(ValueError, match=r"Duplicate interface 'ethernet1/1'"):
        validate_within_item_duplicates(config)


def test_validate_within_item_duplicates_00102_reports_correct_item_index():
    """
    # Summary

    Verify the error identifies the offending item index (not 0) when the duplicate occurs in a
    later config item.

    ## Test

    - Two clean items followed by a third item with a duplicate raises with index 2

    ## Classes and Methods

    - validate_within_item_duplicates()
    """
    config = [
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1"]},
        {"switch_ip": "2.2.2.2", "interface_names": ["Ethernet1/1"]},
        {"switch_ip": "3.3.3.3", "interface_names": ["Ethernet1/5", "Ethernet1/5"]},
    ]
    with pytest.raises(ValueError, match=r"\(config item 2\)"):
        validate_within_item_duplicates(config)


# --- validate_across_item_duplicates ---


def test_validate_across_item_duplicates_00000_no_duplicates():
    """
    # Summary

    Verify that distinct `(switch_ip, interface_name)` pairs across items produce no error.

    ## Test

    - Multiple items with no overlapping pairs are accepted

    ## Classes and Methods

    - validate_across_item_duplicates()
    """
    config = [
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1", "Ethernet1/2"]},
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/3"]},
        {"switch_ip": "2.2.2.2", "interface_names": ["Ethernet1/1"]},
    ]
    validate_across_item_duplicates(config)


def test_validate_across_item_duplicates_00100_duplicate_pair_raises_with_both_indices():
    """
    # Summary

    Verify that the same `(switch_ip, interface_name)` pair appearing in two items raises ValueError
    with both offending item indices in the message.

    ## Test

    - Pair `(1.1.1.1, Ethernet1/1)` appears in items 0 and 2 raises ValueError naming both indices

    ## Classes and Methods

    - validate_across_item_duplicates()
    """
    config = [
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1"]},
        {"switch_ip": "2.2.2.2", "interface_names": ["Ethernet1/1"]},
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1"]},
    ]
    with pytest.raises(ValueError, match=r"Interface 'Ethernet1/1' on switch '1.1.1.1' is specified in multiple config items \(0 and 2\)"):
        validate_across_item_duplicates(config)


def test_validate_across_item_duplicates_00101_case_insensitive():
    """
    # Summary

    Verify across-item duplicate detection is case-insensitive.

    ## Test

    - Item 0 lists `Ethernet1/1`, Item 1 lists `ethernet1/1` on the same switch raises ValueError

    ## Classes and Methods

    - validate_across_item_duplicates()
    """
    config = [
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1"]},
        {"switch_ip": "1.1.1.1", "interface_names": ["ethernet1/1"]},
    ]
    with pytest.raises(ValueError, match=r"\(0 and 1\)"):
        validate_across_item_duplicates(config)


def test_validate_across_item_duplicates_00102_same_interface_different_switches_ok():
    """
    # Summary

    Verify the same interface name on different switches is not a duplicate.

    ## Test

    - `Ethernet1/1` on switch A and `Ethernet1/1` on switch B in separate items is accepted

    ## Classes and Methods

    - validate_across_item_duplicates()
    """
    config = [
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1"]},
        {"switch_ip": "2.2.2.2", "interface_names": ["Ethernet1/1"]},
    ]
    validate_across_item_duplicates(config)


# --- expand_config ---


def test_expand_config_00000_flattens_to_one_record_per_interface():
    """
    # Summary

    Verify `expand_config` produces one flat record per interface name, sharing `switch_ip` and
    `config_data` from the source group.

    ## Test

    - Two interfaces in one item produce two flat records with `interface_name` set

    ## Classes and Methods

    - expand_config()
    """
    config = [
        {
            "switch_ip": "1.1.1.1",
            "interface_names": ["Ethernet1/1", "Ethernet1/2"],
            "config_data": {"network_os": {"policy": {"access_vlan": 100}}},
        }
    ]
    result = expand_config(config)
    assert len(result) == 2
    assert {item["interface_name"] for item in result} == {"Ethernet1/1", "Ethernet1/2"}
    assert all(item["switch_ip"] == "1.1.1.1" for item in result)
    assert all("interface_names" not in item for item in result)
    assert all(item["config_data"]["network_os"]["policy"]["access_vlan"] == 100 for item in result)


def test_expand_config_00001_split_configs_on_same_switch():
    """
    # Summary

    Verify `expand_config` correctly handles two items on the same switch with different configs,
    producing distinct flat records that preserve each item's `config_data`.

    ## Test

    - Two items, same switch, different `access_vlan` produces records that retain each VLAN

    ## Classes and Methods

    - expand_config()
    """
    config = [
        {
            "switch_ip": "1.1.1.1",
            "interface_names": ["Ethernet1/1"],
            "config_data": {"network_os": {"policy": {"access_vlan": 100}}},
        },
        {
            "switch_ip": "1.1.1.1",
            "interface_names": ["Ethernet1/2"],
            "config_data": {"network_os": {"policy": {"access_vlan": 200}}},
        },
    ]
    result = expand_config(config)
    assert len(result) == 2
    by_name = {item["interface_name"]: item for item in result}
    assert by_name["Ethernet1/1"]["config_data"]["network_os"]["policy"]["access_vlan"] == 100
    assert by_name["Ethernet1/2"]["config_data"]["network_os"]["policy"]["access_vlan"] == 200


def test_expand_config_00100_within_item_duplicate_raises():
    """
    # Summary

    Verify `expand_config` raises ValueError when a within-item duplicate is detected.

    ## Test

    - Single item with duplicate interface names raises before flattening

    ## Classes and Methods

    - expand_config()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1", "Ethernet1/1"]}]
    with pytest.raises(ValueError, match=r"Duplicate interface 'Ethernet1/1'"):
        expand_config(config)


def test_expand_config_00101_across_item_duplicate_raises():
    """
    # Summary

    Verify `expand_config` raises ValueError when an across-item duplicate is detected.

    ## Test

    - Two items sharing `(switch_ip, interface_name)` raises before flattening

    ## Classes and Methods

    - expand_config()
    """
    config = [
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1"]},
        {"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1"]},
    ]
    with pytest.raises(ValueError, match=r"is specified in multiple config items"):
        expand_config(config)


def test_expand_config_00200_empty_input_returns_empty_list():
    """
    # Summary

    Verify `expand_config` returns an empty list when given an empty config list.

    ## Test

    - Empty input produces empty output

    ## Classes and Methods

    - expand_config()
    """
    assert expand_config([]) == []


# --- validate_interface_names ---


def test_validate_interface_names_00000_all_strings():
    """
    # Summary

    Verify `validate_interface_names` accepts a list of well-formed non-empty strings without raising.

    ## Test

    - Every entry is a non-empty string -> no error

    ## Classes and Methods

    - validate_interface_names()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1", "Ethernet1/2"]}]
    validate_interface_names(config)


@pytest.mark.parametrize(
    "interface_names,offender,expected_match",
    [
        ([None], "null", r"interface_names\[0\] for switch '1.1.1.1' \(config item 0\) is null"),
        (["Ethernet1/1", None], "null", r"interface_names\[1\] for switch '1.1.1.1' \(config item 0\) is null"),
        ([""], "empty", r"interface_names\[0\] for switch '1.1.1.1' \(config item 0\) is empty"),
        (["Ethernet1/1", ""], "empty", r"interface_names\[1\] for switch '1.1.1.1' \(config item 0\) is empty"),
        ([5], "non_string", r"interface_names\[0\] for switch '1.1.1.1' \(config item 0\) is not a string \(got int\)"),
        (["Ethernet1/1", 5], "non_string", r"interface_names\[1\] for switch '1.1.1.1' \(config item 0\) is not a string \(got int\)"),
    ],
    ids=["null_only", "null_after_valid", "empty_only", "empty_after_valid", "non_string_only", "non_string_after_valid"],
)
def test_validate_interface_names_00100_rejects_null_empty_or_non_string(interface_names, offender, expected_match):
    """
    # Summary

    Verify `validate_interface_names` raises `ValueError` for any `None`, empty-string, or non-string entry,
    naming the offending index and switch so the user can locate it in their playbook.

    ## Test

    - A null, empty-string, or non-string entry raises ValueError before the duplicate-check or expansion paths run

    ## Classes and Methods

    - validate_interface_names()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": interface_names}]
    with pytest.raises(ValueError, match=expected_match):
        validate_interface_names(config)


def test_validate_interface_names_00101_null_list_is_treated_as_empty():
    """
    # Summary

    Verify a whole-list `interface_names: ~` (yielding `None`) is treated as empty and does not raise,
    consistent with the duplicate validators and `expand_config`.

    ## Test

    - `interface_names: None` -> no error (caller's empty-list semantics)

    ## Classes and Methods

    - validate_interface_names()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": None}]
    validate_interface_names(config)


def test_expand_config_00102_null_entry_raises_value_error_via_expand():
    """
    # Summary

    Verify `expand_config` surfaces the null-entry case as `ValueError` (not `AttributeError`) so the
    surrounding `except ValueError` in `main()` produces a friendly fail_json instead of a traceback.

    ## Test

    - `interface_names: [Ethernet1/1, null]` raises ValueError naming the null entry

    ## Classes and Methods

    - expand_config()
    - validate_interface_names()
    """
    config = [{"switch_ip": "1.1.1.1", "interface_names": ["Ethernet1/1", None]}]
    with pytest.raises(ValueError, match=r"interface_names\[1\].*is null"):
        expand_config(config)


# --- config_actions.deploy default ---


class _ArgumentSpecCaptured(Exception):
    """
    # Summary

    Raised by the `AnsibleModule` stand-in to abort `main()` immediately after the `argument_spec` has been built, carrying the spec.

    ## Raises

    None
    """


def _capture_argument_spec(**kwargs: Any) -> None:
    """
    # Summary

    Stand in for `AnsibleModule` inside `main()`: raise `_ArgumentSpecCaptured` with the `argument_spec` keyword argument.

    ## Raises

    ### _ArgumentSpecCaptured

    - Always, carrying `kwargs["argument_spec"]`
    """
    raise _ArgumentSpecCaptured(kwargs["argument_spec"])


def test_nd_interface_ethernet_access_00200_deploy_default_matches_documentation(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify `config_actions.deploy` defaults to `False` in both the DOCUMENTATION and the runtime `argument_spec`.

    ## Test

    - DOCUMENTATION declares `options.config_actions.suboptions.deploy.default` as `false`
    - `main()` builds an `argument_spec` whose `config_actions.options.deploy.default` is `False`

    ## Classes and Methods

    - nd_interface_ethernet_access.main()
    """
    documentation = yaml.safe_load(nd_interface_ethernet_access.DOCUMENTATION)
    assert documentation["options"]["config_actions"]["suboptions"]["deploy"]["default"] is False

    monkeypatch.setattr(nd_interface_ethernet_access, "AnsibleModule", _capture_argument_spec)
    with pytest.raises(_ArgumentSpecCaptured) as exc_info:
        nd_interface_ethernet_access.main()
    argument_spec = exc_info.value.args[0]
    assert argument_spec["config_actions"]["options"]["deploy"]["default"] is False
