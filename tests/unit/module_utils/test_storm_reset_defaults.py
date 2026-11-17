# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Disabled storm thresholds must clear through replacement, never zero sentinels."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceOrchestrator
from ansible_collections.cisco.nd.tests.unit.module_utils.test_interface_workflow_planner import _planner

CAPTURE = json.loads((Path(__file__).parent / "fixtures/fixture_data/storm_reset_20b_raw.json").read_text())["records"]
FIELDS = sorted(InterfaceDefaultConfig.STORM_THRESHOLD_FIELDS)


def _plan(row, switch_ip):
    planner, recorder = _planner(switches={switch_ip: row["switchId"]}, responses=[{"interfaces": [deepcopy(row)]}])
    resources = [{"type": "ethernet_trunk_host", "state": "deleted", "config": [{"switch_ip": switch_ip, "interface_names": [row["interfaceName"]]}]}]
    return planner.plan(resources), recorder


def _unused():
    return deepcopy(next(record for record in CAPTURE if record["row"]["interfaceName"] == "Ethernet1/60"))


def test_factory_reset_payloads_never_inject_zero_storm_thresholds():
    for payload in (
        InterfaceDefaultConfig.to_normalize_payload([("Ethernet1/46", "S1")]),
        InterfaceDefaultConfig.to_normalize_payload([("Ethernet1/46", "S1")], omit_description=True),
        InterfaceDefaultConfig.to_reset_payload("Ethernet1/46", "S1"),
    ):
        policy = payload["configData"]["networkOS"]["policy"]
        assert not InterfaceDefaultConfig.STORM_THRESHOLD_FIELDS.intersection(policy)
        assert policy.get("stormControl", False) is False


def test_live_fixture_contains_exactly_the_three_failed_ports_and_four_unused_controls():
    affected = {
        (record["row"]["switchId"], record["row"]["interfaceName"])
        for record in CAPTURE
        if InterfaceDefaultConfig.STORM_THRESHOLD_FIELDS.intersection(record["row"]["configData"]["networkOS"]["policy"])
    }
    assert affected == {("99TRB2TMZYJ", "Ethernet1/46"), ("9FF8AWWMKLN", "Ethernet1/43"), ("9FF8AWWMKLN", "Ethernet1/44")}
    assert sum(record["row"]["interfaceName"] == "Ethernet1/60" for record in CAPTURE) == 4


@pytest.mark.parametrize("record", CAPTURE, ids=lambda record: record["switch_ip"] + ":" + record["row"]["interfaceName"])
def test_real_captures_select_only_three_bad_resets_and_leave_unused_controls_noop(record):
    row = deepcopy(record["row"])
    before = deepcopy(row)
    policy = row["configData"]["networkOS"]["policy"]
    has_rates = bool(InterfaceDefaultConfig.STORM_THRESHOLD_FIELDS.intersection(policy))
    assert EthernetBaseOrchestrator._is_absent_delete_reset_target(row) is not has_rates
    assert EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(row) is not has_rates
    plan, recorder = _plan(row, record["switch_ip"])
    assert plan.mutation_count == int(has_rates)
    assert len(recorder.calls) == 1
    assert row == before
    if has_rates:
        assert policy["stormControl"] is False
        assert all(policy[field] == 0 for field in FIELDS)
        resource = plan.resources[0]
        resource.orchestrator.delete(next(iter(resource.operations.deletes)), existing_data=row)
        assert resource.orchestrator.pending_resets == ((row["interfaceName"], row["switchId"]),)
        assert resource.orchestrator.pending_normalizes == ()


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("nonzero", [False, True])
def test_zero_and_nonzero_percentage_or_pps_rates_require_replacement(field, nonzero):
    record = _unused()
    row = record["row"]
    policy = row["configData"]["networkOS"]["policy"]
    policy["stormControl"] = False
    policy[field] = (4200 if nonzero else 0) if field.endswith("Pps") else (42.5 if nonzero else 0.0)
    assert EthernetBaseOrchestrator._has_unresettable_fields(row) is True
    assert EthernetBaseOrchestrator._is_absent_delete_reset_target(row) is False
    assert EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(row) is False
    plan, _recorder = _plan(row, record["switch_ip"])
    assert plan.mutation_count == 1
    resource = plan.resources[0]
    resource.orchestrator.delete(next(iter(resource.operations.deletes)), existing_data=row)
    assert resource.orchestrator.pending_resets == ((row["interfaceName"], row["switchId"]),)
    assert resource.orchestrator.pending_normalizes == ()


@pytest.mark.parametrize("field", FIELDS)
def test_null_threshold_is_still_absent_and_does_not_force_a_reset(field):
    record = _unused()
    row = record["row"]
    row["configData"]["networkOS"]["policy"][field] = None
    assert EthernetBaseOrchestrator._has_unresettable_fields(row) is False
    assert EthernetBaseOrchestrator._is_absent_delete_reset_target(row) is True
    assert EthernetTrunkHostInterfaceOrchestrator._is_unconfigured_default(row) is True
    assert _plan(row, record["switch_ip"])[0].mutation_count == 0


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(
    "field,value",
    [
        ("storm_control_broadcast_level", 0.0),
        ("storm_control_broadcast_level", 42.5),
        ("storm_control_broadcast_level_pps", 0),
        ("storm_control_broadcast_level_pps", 4200),
    ],
)
def test_ordinary_explicit_storm_configuration_is_preserved(enabled, field, value):
    config = {
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/1",
        "config_data": {"network_os": {"policy": {"storm_control": enabled, field: value}}},
    }
    model = EthernetTrunkHostInterfaceModel.from_config(config)
    policy = model.to_payload()["configData"]["networkOS"]["policy"]
    assert policy["stormControl"] is enabled
    alias = "stormControlBroadcastLevelPps" if field.endswith("pps") else "stormControlBroadcastLevel"
    assert policy[alias] == value
