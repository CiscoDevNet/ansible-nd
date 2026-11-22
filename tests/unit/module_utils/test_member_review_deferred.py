# Copyright: (c) 2026, Cisco Systems, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Public workflow regressions for explicit proofs beside deferred membership."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import INTERFACE_FAMILY_ADAPTERS
from ansible_collections.cisco.nd.tests.unit.module_utils import member_review_fakes
from ansible_collections.cisco.nd.tests.unit.module_utils import test_interface_preparation_observation as observation_fixtures


class ReadOnlyController(member_review_fakes.Controller):
    """Serve real workflow observations and reject every configuration write."""

    def __init__(self, inventory, *, paired=False):
        super().__init__(paired=paired)
        self.rows.update(deepcopy(inventory))

    def send_request(self, verb, path, body=None):
        assert verb == "GET", "Deferred observation must never dispatch configuration"
        assert body is None
        return super().send_request(verb, path, body)


def _retirement_request(family):
    plan, snapshot = observation_fixtures._explicit_member_fixture(family)
    resources = [{"type": row.resource_type, "state": row.state, "config": row.proposed.to_ansible_config()} for row in plan.resources]
    for resource in resources:
        if resource["type"].startswith("ethernet_"):
            for item in resource["config"]:
                item["interface_names"] = [item.pop("interface_name")]
    for resource in resources:
        for item in resource["config"]:
            item["switch_ip"] = {"10.0.0.1": "192.0.2.1", "10.0.0.2": "192.0.2.2"}[item["switch_ip"]]
    config = {
        "switch_ip": "192.0.2.1",
        "interface_name": "port-channel20",
        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "trunkPoHost", "ports": ["Ethernet1/40"]}}},
    }
    resources.append({"type": "port_channel_trunk_host", "state": "replaced", "config": [config]})
    current = deepcopy(config)
    current["config_data"]["network_os"]["policy"]["ports"].append("Ethernet1/41")
    adapter = INTERFACE_FAMILY_ADAPTERS["port_channel_trunk_host"]
    parent = adapter.model_class.from_config(current, context={"state": "replaced"}).to_payload()
    parent.update(switchId="S1", operData={"portChannelId": -1})
    snapshot._interfaces_by_switch["S1"]["port-channel20"] = parent
    for name in ("Ethernet1/40", "Ethernet1/41"):
        snapshot._interfaces_by_switch["S1"][name.casefold()] = {
            "switchId": "S1",
            "interfaceName": name,
            "interfaceType": "ethernet",
            "configData": {"mode": "trunk", "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": "poMember", "portChannelId": "20"}}},
            "operData": {"portChannelId": -1},
        }
    controller = ReadOnlyController(snapshot._interfaces_by_switch, paired=family.startswith("vpc_"))
    params = {
        "fabric_name": "fab",
        "resources": resources,
        "config_actions": {"deploy": False},
        "verify": {"enabled": True},
        "execution_options": {"preparation_only": True, "defer_ready_membership": True},
    }
    return params, controller


@pytest.mark.parametrize("family", ["port_channel_access", "port_channel_trunk_host", "vpc_access", "vpc_trunk_host"])
def test_public_workflow_keeps_explicit_member_proof_with_independent_deferred_retirement(monkeypatch, family):
    params, controller = _retirement_request(family)
    before = deepcopy(controller.rows)

    outcome = member_review_fakes.run_module(monkeypatch, params, controller)

    assert outcome.failed is False, outcome.result.get("msg", outcome.result)
    result = outcome.result
    proof = result["preparation_observation"]
    assert proof["observed"] and proof["complete"] and proof["all_ready"], proof
    assert proof["all_satisfied"] is False
    assert result["changed"] is False
    assert result["execution"]["status"] == "no_change"
    assert result["write_receipt"]["no_mutation_attempted"] is True
    assert result["write_receipt"]["mutation_attempts"] == 0
    members = result["member_verifications"]
    assert members["observed"] and members["complete"]
    expected_owners = {
        ("S1", "Ethernet1/1", "S1", "vpc10" if family.startswith("vpc_") else "port-channel10", 10),
        *(([("S2", "Ethernet1/2", "S2", "vpc10", 20)]) if family.startswith("vpc_") else []),
    }
    assert {
        (row["switch_id"], row["interface_name"], row["owner_switch_id"], row["parent_interface_name"], row["configured_port_channel_id"])
        for row in members["members"]
    } == expected_owners
    assert all(row["parent_resource_index"] == 0 and row["pair_validated"] is family.startswith("vpc_") for row in members["members"])
    explicit = [target for group in proof["resources"] if group["type"].startswith("ethernet_") for target in group["targets"]]
    assert all(target["satisfied"] is True and target["aggregate_member"]["parent_resource_index"] == 0 for target in explicit)
    retirement = proof["resources"][-1]["targets"][0]
    assert retirement["ready"] is True and retirement["satisfied"] is False
    assert retirement["disposition"] == "deferred_membership"
    assert retirement["members"] == ["Ethernet1/40", "Ethernet1/41"]
    assert retirement["desired_members"] == ["Ethernet1/40"]
    assert controller.rows == before
    assert controller.writes == []


def test_public_workflow_still_rejects_fresh_preparation_with_deferred_retirement(monkeypatch):
    params, controller = _retirement_request("port_channel_trunk_host")
    params["resources"] = [
        {
            "type": "ethernet_trunk_host",
            "state": "merged",
            "config": [
                {"switch_ip": "192.0.2.1", "interface_names": ["Ethernet1/30"], "config_data": {"network_os": {"policy": {"policy_type": "trunkHost"}}}}
            ],
        },
        {
            "type": "port_channel_trunk_host",
            "state": "merged",
            "config": [
                {
                    "switch_ip": "192.0.2.1",
                    "interface_name": "port-channel30",
                    "config_data": {"network_os": {"policy": {"policy_type": "trunkPoHost", "ports": ["Ethernet1/30"]}}},
                }
            ],
        },
        params["resources"][-1],
    ]

    outcome = member_review_fakes.run_module(monkeypatch, params, controller)

    assert outcome.failed is True
    assert "Deferred membership cannot share explicit member preparation work" in outcome.result["msg"]
    assert outcome.result["write_receipt"]["no_mutation_attempted"] is True
    assert controller.writes == []
