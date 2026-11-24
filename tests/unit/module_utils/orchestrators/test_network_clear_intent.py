# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Explicit VXLAN clears remain intent until the final Manage payload boundary."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import NetworkConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import NetworkBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


@pytest.mark.parametrize("field,wire", [("gateway_ipv4_address", "gatewayIpv4Address"), ("gateway_ipv6_address", "gatewayIpv6Address")])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_gateway_clear_survives_validation_and_repeats_after_omitted_readback(field, wire, state):
    raw = {"network_name": "BLUE", "network_mode": "layer3", "vrf_name": "TENANT", field: ""}
    parsed = NetworkConfigModel.from_config(raw, context={"state": state}).to_config(exclude_unset=True)
    assert parsed[field] == ""
    strategy = StandaloneNetworkStrategy("FAB", {"managementType": "vxlanIbgp"})
    orchestrator = NDNetworkOrchestrator(rest_send=RestSend({"state": state}), strategy=strategy)
    proposed = NetworkBaseModel.from_config(orchestrator.prepare_config_data([parsed])[0])
    saved = {
        "fabricName": "FAB",
        "networkName": "BLUE",
        "networkType": "vxlanIbgp",
        "networkMode": "layer3",
        "vrfName": "TENANT",
        "l3Data": {"gatewayIpv4Address": "198.18.1.1/24", "gatewayIpv6Address": "2001:db8:1::1/64"},
    }
    current = NetworkBaseModel.from_response(saved)
    assert not current.get_diff(proposed, exclude_unset=state == "merged")
    effective = current.model_copy(deep=True).merge(proposed) if state == "merged" else proposed
    assert effective.l3_data.to_payload()[wire] == ""
    payload = orchestrator._create_or_update_payload(effective)
    assert wire not in payload["l3Data"]
    if state == "merged":
        sibling = "gatewayIpv6Address" if wire == "gatewayIpv4Address" else "gatewayIpv4Address"
        assert payload["l3Data"][sibling] == saved["l3Data"][sibling]
    readback = NetworkBaseModel.from_response(deepcopy(payload))
    assert readback.get_diff(proposed, exclude_unset=state == "merged")


@pytest.mark.parametrize("network_type", ["vxlan", "vxlanIbgp", "vxlanEbgp", "vxlanCampus", "aimlVxlanIbgp", "aimlVxlanEbgp"])
@pytest.mark.parametrize("section,field", [("l2Data", "vlanName"), ("l3Data", "vlanInterfaceDescription")])
def test_empty_text_and_omitted_readback_are_comparison_equivalent_without_payload_defaults(network_type, section, field):
    current = NetworkBaseModel.from_response({"networkName": "BLUE", "networkType": network_type, "networkMode": "layer3"})
    proposed = NetworkBaseModel.from_config({"networkName": "BLUE", "networkType": network_type, "network_mode": "layer3", section: {field: ""}})
    assert current.get_diff(proposed, exclude_unset=True)
    assert field not in current.to_payload().get(section, {})
