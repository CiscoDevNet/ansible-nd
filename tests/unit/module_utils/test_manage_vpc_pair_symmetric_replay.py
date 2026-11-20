# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""An intended vPC pair can be returned with either chassis first."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import (
    _is_update_needed,
    _normalize_pair_identity_for_compare,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import actions as vpc_actions
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.resources import VpcPairStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_model import VpcPairModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput


def _machine(state, virtual, controller_pair=None):
    machine = object.__new__(VpcPairStateMachine)
    machine.module = SimpleNamespace(params={"state": state, "config_actions": {"save": False, "deploy": False}}, check_mode=False)
    machine.model_class = VpcPairModel
    observed = controller_pair or {"switchId": "9FF8AWWMKLN", "peerSwitchId": "88054YPFFFF", "useVirtualPeerLink": virtual}
    machine.existing = NDConfigCollection.from_api_response([deepcopy(observed)], VpcPairModel)
    machine.before = machine.existing.copy()
    machine.sent = NDConfigCollection(VpcPairModel)
    machine.model_orchestrator = MagicMock()
    machine.logs = []
    machine.output = NDOutput("debug", state)
    return machine


def _observed_details(kind):
    if kind == "custom":
        return {"type": "custom", "templateName": "existing_vpc_template", "templateConfig": {"peer1Port": "Ethernet1/11", "peer2Port": "Ethernet1/12"}}
    return {
        "type": "default",
        "domainId": 42,
        "switchPoId": 500,
        "peerSwitchPoId": 501,
        "switchMemberInterfaces": ["Ethernet1/11"],
        "peerSwitchMemberInterfaces": ["Ethernet1/12"],
        "adminState": True,
        "allowedVlans": "all",
    }


def _tor_machine(monkeypatch, state, details_kind, *, reverse, virtual=False):
    first, second = ("9KRB7M5WM1T", "90I6166RVLT") if reverse else ("90I6166RVLT", "9KRB7M5WM1T")
    observed = {
        "switchId": first,
        "peerSwitchId": second,
        "useVirtualPeerLink": virtual,
        "vpcPairDetails": _observed_details(details_kind),
    }
    machine = _machine(state, virtual, observed)
    machine.module.params["fabric_name"] = "example-fabric"
    machine.fabric_type = "vxlanIbgp"
    # A genuine merged update still strips generated details on VXLAN fabrics.
    # Keep that existing path local; unchanged replays must not reach it.
    nd_factory = MagicMock(return_value=SimpleNamespace())
    monkeypatch.setattr(vpc_actions, "NDModuleV2", nd_factory)
    return machine, nd_factory


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("virtual", [False, True])
def test_reversed_controller_pair_is_noop_with_actual_models_and_output(state, virtual):
    machine = _machine(state, virtual)
    config = [{"switch_id": "88054YPFFFF", "peer_switch_id": "9FF8AWWMKLN", "use_virtual_peer_link": virtual}]
    original = machine.existing.to_ansible_config()

    machine.manage_state(state, config)
    machine.add_logs_and_outputs()

    machine.model_orchestrator.create.assert_not_called()
    machine.model_orchestrator.update.assert_not_called()
    machine.model_orchestrator.delete.assert_not_called()
    machine.model_orchestrator.query_all.assert_not_called()
    assert list(machine.sent) == []
    assert machine.result["changed"] is False
    assert machine.result["updated"] == []
    assert machine.result["diff"] == []
    assert machine.result["before"] == machine.result["after"] == original
    assert [entry["status"] for entry in machine.logs] == ["no_change"]
    assert config[0]["switch_id"] == "88054YPFFFF"


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("reverse", [False, True], ids=["same-order", "reversed-order"])
@pytest.mark.parametrize("details_kind", ["default", "custom"])
def test_unrequested_controller_details_do_not_update_existing_tor_pair(monkeypatch, state, reverse, details_kind):
    """A ToR pair already carrying Leaf-ToR associations must remain untouched."""
    machine, nd_factory = _tor_machine(monkeypatch, state, details_kind, reverse=reverse)
    config = [{"switch_id": "90I6166RVLT", "peer_switch_id": "9KRB7M5WM1T", "use_virtual_peer_link": False, "vpc_pair_details": None}]
    original_config = deepcopy(config)
    original = machine.existing.to_ansible_config()

    machine.manage_state(state, config)

    machine.model_orchestrator.update.assert_not_called()
    machine.model_orchestrator.create.assert_not_called()
    machine.model_orchestrator.delete.assert_not_called()
    nd_factory.assert_not_called()
    machine.add_logs_and_outputs()

    machine.model_orchestrator.query_all.assert_not_called()
    assert list(machine.sent) == []
    assert machine.result["changed"] is False
    assert machine.result["updated"] == []
    assert machine.result["diff"] == []
    assert machine.result["before"] == machine.result["after"] == original
    assert [entry["status"] for entry in machine.logs] == ["no_change"]
    assert config == original_config


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("details_kind", ["default", "custom"])
def test_observed_details_do_not_hide_requested_mode_change(monkeypatch, state, details_kind):
    machine, _nd_factory = _tor_machine(monkeypatch, state, details_kind, reverse=True, virtual=True)

    machine.manage_state(state, [{"switch_id": "90I6166RVLT", "peer_switch_id": "9KRB7M5WM1T", "use_virtual_peer_link": False}])

    machine.model_orchestrator.update.assert_called_once()
    machine.model_orchestrator.create.assert_not_called()
    machine.model_orchestrator.delete.assert_not_called()
    assert machine.proposed_config == {"switchId": "90I6166RVLT", "peerSwitchId": "9KRB7M5WM1T", "useVirtualPeerLink": False}
    assert [entry["status"] for entry in machine.logs] == ["updated"]


@pytest.mark.parametrize("details_kind", ["default", "custom"])
def test_observed_only_details_preserve_wire_orientation_and_values(details_kind):
    want = {"switchId": "90I6166RVLT", "peerSwitchId": "9KRB7M5WM1T", "useVirtualPeerLink": False}
    have = {
        "switchId": "9KRB7M5WM1T",
        "peerSwitchId": "90I6166RVLT",
        "useVirtualPeerLink": False,
        "vpcPairDetails": _observed_details(details_kind),
    }
    original = deepcopy((want, have))

    normalized_want, normalized_have = _normalize_pair_identity_for_compare(want, have)

    assert normalized_want["switchId"] == normalized_have["switchId"] == "90I6166RVLT"
    assert normalized_want["peerSwitchId"] == normalized_have["peerSwitchId"] == "9KRB7M5WM1T"
    assert normalized_want["useVirtualPeerLink"] is normalized_have["useVirtualPeerLink"] is False
    assert "vpcPairDetails" not in normalized_want
    assert normalized_have["vpcPairDetails"] == original[1]["vpcPairDetails"]
    assert (want, have) == original


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_reversed_pair_mode_change_still_dispatches_update(state):
    machine = _machine(state, virtual=True)

    machine.manage_state(state, [{"switch_id": "88054YPFFFF", "peer_switch_id": "9FF8AWWMKLN", "use_virtual_peer_link": False}])

    machine.model_orchestrator.update.assert_called_once()
    assert machine.proposed_config == {"switchId": "88054YPFFFF", "peerSwitchId": "9FF8AWWMKLN", "useVirtualPeerLink": False}
    assert [entry["status"] for entry in machine.logs] == ["updated"]


def test_merged_reversed_pair_with_omitted_mode_preserves_observed_virtual_mode():
    machine = _machine("merged", virtual=True)

    machine.manage_state("merged", [{"switch_id": "88054YPFFFF", "peer_switch_id": "9FF8AWWMKLN"}])
    machine.add_logs_and_outputs()

    machine.model_orchestrator.update.assert_not_called()
    assert machine.result["changed"] is False
    assert next(iter(machine.existing)).use_virtual_peer_link is True


def test_action_comparison_is_symmetric_without_mutating_wire_data():
    want = {"switchId": "88054YPFFFF", "peerSwitchId": "9FF8AWWMKLN", "useVirtualPeerLink": True}
    have = {"switchId": "9FF8AWWMKLN", "peerSwitchId": "88054YPFFFF", "useVirtualPeerLink": True}
    original = deepcopy((want, have))

    assert _is_update_needed(want, have) is False
    assert (want, have) == original
    assert VpcPairModel.from_config(have).to_payload() == have


def test_unknown_mode_is_not_invented_by_identity_normalization():
    want = {"switchId": "88054YPFFFF", "peerSwitchId": "9FF8AWWMKLN", "useVirtualPeerLink": False}
    have = {"switchId": "9FF8AWWMKLN", "peerSwitchId": "88054YPFFFF"}

    _normalized_want, normalized_have = _normalize_pair_identity_for_compare(want, have)

    assert "useVirtualPeerLink" not in normalized_have
    assert _is_update_needed(want, have) is True


def test_different_pair_is_not_equal_after_identity_normalization():
    want = {"switchId": "SWITCH-A", "peerSwitchId": "SWITCH-B", "useVirtualPeerLink": True}
    have = {"switchId": "SWITCH-C", "peerSwitchId": "SWITCH-A", "useVirtualPeerLink": True}

    assert _is_update_needed(want, have) is True


@pytest.mark.parametrize("details", [{"type": "default", "switchPoId": 11, "peerSwitchPoId": 22}, {"type": "custom", "templateConfig": {"peer": "opaque"}}])
@pytest.mark.parametrize("observed_details", [False, True])
def test_peer_specific_template_details_keep_orientation_sensitive_comparison(details, observed_details):
    want = {"switchId": "88054YPFFFF", "peerSwitchId": "9FF8AWWMKLN", "vpcPairDetails": details}
    have = {"switchId": "9FF8AWWMKLN", "peerSwitchId": "88054YPFFFF"}
    if observed_details:
        have["vpcPairDetails"] = deepcopy(details)

    normalized_want, normalized_have = _normalize_pair_identity_for_compare(want, have)

    assert _is_update_needed(want, have) is True
    assert normalized_want["switchId"] == "88054YPFFFF"
    assert normalized_have["switchId"] == "9FF8AWWMKLN"
