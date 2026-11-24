# Copyright: (c) 2026, Cisco Systems, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Explicit resources bind member preparation without a separate public option."""

from copy import deepcopy

import pytest
import yaml

from ansible_collections.cisco.nd.plugins.module_utils import interface_workflow_contract as contract
from ansible_collections.cisco.nd.plugins.modules import nd_interfaces_workflow as workflow_module

REMOVED_OPTION = "missing_member_preparation_switch_ids"
ORDINARY_REQUEST_SHA256 = "6b92889fc63b7c17f578a03154b043683b71ca596332f54f801d4f48b1ee6d2c"


def _params():
    return {
        "fabric_name": "fabric-1",
        "resources": [{"type": "port_channel_trunk_host", "state": "merged", "config": []}],
        "config_actions": {"deploy": False},
        "verify": {"enabled": True},
    }


@pytest.mark.parametrize("options", [None, {}, {"contract_version": 1, "desired_equality": False, "member_batching": "disabled"}])
def test_ordinary_requests_preserve_existing_options_and_pinned_digest(options):
    params = _params()
    if options is not None:
        params["execution_options"] = deepcopy(options)

    assert contract.workflow_options(params) == {"contract_version": 1, "desired_equality": False, "member_batching": "disabled"}
    assert contract.request_sha256(params) == ORDINARY_REQUEST_SHA256
    assert REMOVED_OPTION not in contract.workflow_contract(params)["requested_options"]


def test_explicit_ethernet_resources_are_bound_to_the_request_without_new_options():
    params = _params()
    params["resources"].append(
        {
            "type": "ethernet_trunk_host",
            "state": "merged",
            "config": [
                {
                    "switch_ip": "192.0.2.1",
                    "interface_names": ["Ethernet1/42"],
                    "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "trunkHost"}}},
                }
            ],
        }
    )
    before = deepcopy(params)
    receipt = contract.workflow_contract(params)
    changed_port = deepcopy(params)
    changed_port["resources"][1]["config"][0]["interface_names"] = ["Ethernet1/43"]
    changed_policy = deepcopy(params)
    changed_policy["resources"][1]["config"][0]["config_data"]["network_os"]["policy"]["policy_type"] = "accessHost"

    assert contract.request_projection(params)["resources"] == params["resources"]
    assert receipt["request_sha256"] == contract.request_sha256(params)
    assert len({receipt["request_sha256"], contract.request_sha256(changed_port), contract.request_sha256(changed_policy), ORDINARY_REQUEST_SHA256}) == 4
    assert receipt["requested_options"] == contract.workflow_options(_params())
    assert params == before


def test_explicit_preparation_capability_is_advertised_without_old_opt_in_capability():
    capabilities = contract.EXECUTION_CONTRACT_CAPABILITIES

    assert "explicit_member_preparation_v1" in capabilities
    assert "explicit_member_preparation_v1" in contract.workflow_contract(_params())["capabilities"]
    assert "missing_member_preparation_v1" not in capabilities


def test_public_argspec_and_documentation_do_not_expose_a_switch_id_option():
    argspec = workflow_module.interface_workflow_argument_spec()
    documentation = yaml.safe_load(workflow_module.DOCUMENTATION)

    assert REMOVED_OPTION not in argspec["execution_options"]["options"]
    assert REMOVED_OPTION not in documentation["options"]["execution_options"]["suboptions"]
    assert "Explicit NX-OS Ethernet" in workflow_module.DOCUMENTATION


def test_documented_missing_member_example_supplies_both_explicit_resources():
    example = yaml.safe_load(workflow_module.EXAMPLES)[0]["cisco.nd.nd_interfaces_workflow"]

    assert [resource["type"] for resource in example["resources"]] == ["ethernet_trunk_host", "port_channel_trunk_host"]
    assert example["config_actions"] == {"deploy": False}
    assert example["verify"] == {"enabled": True}
    assert REMOVED_OPTION not in example.get("execution_options", {})
