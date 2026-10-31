# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Replay actual ND default echoes through the real Network CRUD planner."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import NetworkBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlanner
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _fixture():
    return json.loads((Path(__file__).parent / "fixtures/network_defaults_c16b.json").read_text())


def _plan(fixture, explicit_multicast=True):
    wanted = deepcopy(fixture["desired_config"])
    if explicit_multicast:
        groups = {row["networkName"]: row["l2Data"]["fabricData"]["multicastGroup"] for row in fixture["network_definitions"]}
        for row in wanted:
            row["multicast_group_address"] = groups[row["network_name"]]
    strategy = StandaloneNetworkStrategy(fabric_name="nac-msd-fabric1", fabric_data={"managementType": "vxlanIbgp"})
    args = {"fabric_name": strategy.fabric_name, "state": "staged", "config": wanted}
    coordinator = NetworkWorkflowCoordinator(SimpleNamespace(params=args, check_mode=True), strategy=strategy)
    parsed = coordinator._parse_config(wanted, strategy.config_model_cls, "staged")
    orchestrator = NDNetworkOrchestrator(rest_send=RestSend({"state": "staged", "config": parsed, "check_mode": True}), strategy=strategy)
    before = NDConfigCollection.from_api_response(orchestrator._normalize_query_network_items(fixture["network_definitions"]), NetworkBaseModel)
    proposed = NDConfigCollection.from_ansible_config(orchestrator.prepare_config_data(parsed), NetworkBaseModel, context={"state": "replaced"})
    return NDStatePlanner.plan(state="replaced", before=before, proposed=proposed), before, proposed


def test_actual_eight_definitions_with_explicit_allocations_need_no_definition_puts():
    plan, _before, _proposed = _plan(_fixture())
    assert len(plan.updates) == len(plan.creates) == len(plan.deletes) == 0


def test_one_real_definition_edit_requires_exactly_one_put():
    fixture = _fixture()
    fixture["desired_config"][0]["gateway_ipv4_address"] = "172.29.191.254/24"
    plan, _before, _proposed = _plan(fixture)
    assert [row.network_name for row in plan.updates] == [fixture["desired_config"][0]["network_name"]]


def test_unproven_omitted_multicast_allocation_keeps_conservative_updates():
    plan, _before, _proposed = _plan(_fixture(), explicit_multicast=False)
    assert len(plan.updates) == 7  # Preserved MyNetwork already declares its group.


@pytest.mark.parametrize(
    "path,value",
    [
        (("displayName",), "custom-display"),
        (("vlanNetworkType",), "privatePrimary"),
        (("l2Data", "rtAuto"), True),
        (("l2Data", "xConnect"), True),
        (("l3Data", "fabricData", "gatewayOnBorder"), True),
        (("l3Data", "fabricData", "igmpVersion"), 3),
        (("l3Data", "fabricData", "ipv6Trm"), True),
    ],
)
def test_omitted_non_default_values_still_require_reset(path, value):
    fixture = _fixture()
    row = fixture["network_definitions"][0]
    parent = row
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    plan, _before, _proposed = _plan(fixture)
    assert [row.network_name for row in plan.updates] == [fixture["network_definitions"][0]["networkName"]]


def test_custom_multicast_inside_the_same_pool_is_not_exempted():
    fixture = _fixture()
    fixture["network_definitions"][0]["l2Data"]["fabricData"]["multicastGroup"] = "239.1.1.17"
    plan, _before, _proposed = _plan(fixture, explicit_multicast=False)
    assert fixture["network_definitions"][0]["networkName"] in [row.network_name for row in plan.updates]


def test_custom_explicit_multicast_group_is_not_replaced_by_a_global_default():
    fixture = _fixture()
    for row in fixture["network_definitions"]:
        row["l2Data"]["fabricData"]["multicastGroup"] = "239.77.1.23"
    plan, _before, _proposed = _plan(fixture)
    assert not plan.changed


@pytest.mark.parametrize("field", ["network_id", "vlan_id"])
def test_omitted_dynamic_ids_are_not_silently_ignored(field):
    fixture = _fixture()
    for row in fixture["desired_config"]:
        row.pop(field, None)
    plan, _before, _proposed = _plan(fixture)
    assert plan.changed
