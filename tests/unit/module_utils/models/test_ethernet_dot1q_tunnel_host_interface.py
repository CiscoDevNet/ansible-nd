# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit coverage for the NX-OS dot1q-tunnel Ethernet host policy contract."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceModel,
    EthernetDot1qTunnelHostPolicyModel,
)

WIRE_FIELDS = frozenset(
    {
        "accessVlan",
        "adminState",
        "bandwidth",
        "bpduFilter",
        "bpduGuard",
        "cdp",
        "debounceLinkupTimer",
        "debounceTimer",
        "description",
        "duplexMode",
        "errorDetectionAcl",
        "extraConfig",
        "fec",
        "inheritBandwidth",
        "linkType",
        "mtu",
        "negotiateAuto",
        "netflow",
        "netflowMonitor",
        "netflowSampler",
        "orphanPort",
        "pfc",
        "portTypeEdgeTrunk",
        "qos",
        "qosPolicy",
        "queuingPolicy",
        "speed",
        "stormControl",
        "stormControlAction",
        "stormControlBroadcastLevel",
        "stormControlBroadcastLevelPps",
        "stormControlMulticastLevel",
        "stormControlMulticastLevelPps",
        "stormControlUnicastLevel",
        "stormControlUnicastLevelPps",
    }
)


def test_policy_exposes_exactly_the_35_dot1q_template_properties() -> None:
    """Do not inherit access-only monitor or omit any dot1q property."""
    aliases = {field.alias for field in EthernetDot1qTunnelHostPolicyModel.model_fields.values()}
    assert aliases == WIRE_FIELDS | {"policyType"}
    assert len(WIRE_FIELDS) == 35
    assert "monitor" not in aliases


def test_policy_injects_discriminator_and_rejects_wrong_or_unknown_fields() -> None:
    """Host policy defaults on input, but member/foreign fields fail before writes."""
    policy = EthernetDot1qTunnelHostPolicyModel.from_config({"access_vlan": 150})
    assert policy.to_payload() == {"accessVlan": 150, "policyType": "dot1qTunnelHost"}
    with pytest.raises(ValidationError):
        EthernetDot1qTunnelHostPolicyModel.from_config({"policy_type": "accessHost"})
    with pytest.raises(ValidationError):
        EthernetDot1qTunnelHostPolicyModel.from_config({"monitor": True})
    with pytest.raises(ValidationError):
        EthernetDot1qTunnelHostPolicyModel.from_config({"ptp": False})


@pytest.mark.parametrize("vlan", [0, 4095])
def test_access_vlan_range_is_enforced(vlan: int) -> None:
    with pytest.raises(ValidationError):
        EthernetDot1qTunnelHostPolicyModel.from_config({"access_vlan": vlan})


def test_wire_discriminators_and_canonical_name() -> None:
    """A normal Ansible config serializes to the ND dot1q tunnel host shape."""
    model = EthernetDot1qTunnelHostInterfaceModel.from_config(
        {
            "switch_ip": "192.0.2.11",
            "interface_name": "e1/40",
            "config_data": {
                "network_os": {"network_os_type": "nx-os", "policy": {"access_vlan": 150, "speed": "1Gb"}},
            },
        }
    )
    assert model.interface_name == "Ethernet1/40"
    assert model.to_payload() == {
        "interfaceName": "Ethernet1/40",
        "interfaceType": "ethernet",
        "configData": {
            "mode": "dot1qTunnel",
            "networkOS": {"networkOSType": "nx-os", "policy": {"accessVlan": 150, "policyType": "dot1qTunnelHost", "speed": "1Gb"}},
        },
    }


def test_ios_xe_and_wrong_mode_are_rejected() -> None:
    base = {"switch_ip": "192.0.2.11", "interface_name": "Ethernet1/40"}
    with pytest.raises(ValidationError):
        EthernetDot1qTunnelHostInterfaceModel.from_config(
            {**base, "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"access_vlan": 150}}}}
        )
    with pytest.raises(ValidationError):
        EthernetDot1qTunnelHostInterfaceModel.from_config({**base, "config_data": {"mode": "trunk", "network_os": {"policy": {"access_vlan": 150}}}})


def test_identifier_only_delete_model_has_no_policy() -> None:
    model = EthernetDot1qTunnelHostInterfaceModel.from_config({"switch_ip": "192.0.2.11", "interface_name": "Ethernet1/40"})
    assert model.policy_type is None
    assert "configData" not in model.to_payload()


def test_response_only_ptp_echo_is_not_user_writable_or_replayed() -> None:
    """Historical ND GETs contain ptp=false, which is absent from the template."""
    response = {
        "switchIp": "192.0.2.11",
        "interfaceName": "Ethernet1/40",
        "interfaceType": "ethernet",
        "configData": {
            "mode": "dot1qTunnel",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": "dot1qTunnelHost", "accessVlan": 150, "bpduFilter": "enable", "ptp": False},
            },
        },
    }
    model = EthernetDot1qTunnelHostInterfaceModel.from_response(response)
    assert model.config_data.network_os.policy.bpdu_filter == "enable"
    assert "ptp" not in model.to_payload()["configData"]["networkOS"]["policy"]
    assert "bpduFilter" not in model.config_data.network_os.policy.to_reverse_diff_dict()


def test_nondefault_bpdu_filter_remains_in_reverse_diff() -> None:
    policy = EthernetDot1qTunnelHostPolicyModel.from_response({"policyType": "dot1qTunnelHost", "bpduFilter": "disable"})
    assert policy.to_reverse_diff_dict()["bpduFilter"] == "disable"


def test_storm_control_same_class_mutex_is_reused() -> None:
    with pytest.raises(ValidationError, match="broadcast"):
        EthernetDot1qTunnelHostPolicyModel.from_config({"storm_control_broadcast_level": 1.0, "storm_control_broadcast_level_pps": 1000})


def test_storm_control_units_are_exclusive_across_the_interface() -> None:
    with pytest.raises(ValidationError, match="across the interface"):
        EthernetDot1qTunnelHostPolicyModel.from_config({"storm_control_broadcast_level": 10.0, "storm_control_multicast_level_pps": 1000})


def test_storm_control_zero_is_a_clearing_sentinel() -> None:
    policy = EthernetDot1qTunnelHostPolicyModel.from_config({"storm_control_broadcast_level": 0.0, "storm_control_multicast_level_pps": 1000})
    assert policy.storm_control_multicast_level_pps == 1000


def test_storm_control_mixed_nd_echo_can_be_read_but_not_replayed() -> None:
    echoed = EthernetDot1qTunnelHostPolicyModel.from_response(
        {"policyType": "dot1qTunnelHost", "stormControlBroadcastLevel": 10.0, "stormControlMulticastLevelPps": 1000}
    )
    assert echoed.storm_control_broadcast_level == 10.0
    with pytest.raises(ValidationError, match="across the interface"):
        EthernetDot1qTunnelHostPolicyModel.from_config(echoed.model_dump(exclude_none=True))


def test_mixed_nd_echo_gives_actionable_merged_preflight_error() -> None:
    echoed = EthernetDot1qTunnelHostPolicyModel.from_response(
        {"policyType": "dot1qTunnelHost", "stormControlBroadcastLevel": 10.0, "stormControlMulticastLevelPps": 1000}
    )
    proposed = EthernetDot1qTunnelHostPolicyModel.from_config({"description": "unrelated edit"})
    with pytest.raises(ValueError, match="Use state: replaced with one consistent threshold unit"):
        echoed.merge(proposed)
    assert echoed.description is None
    assert echoed.storm_control_broadcast_level == 10.0
    assert echoed.storm_control_multicast_level_pps == 1000


@pytest.mark.parametrize(
    "old_class,new_class",
    [(old, new) for old in ("broadcast", "multicast", "unicast") for new in ("broadcast", "multicast", "unicast") if old != new],
)
@pytest.mark.parametrize("old_pps", [False, True])
def test_storm_merge_validates_the_complete_unit_transition(old_class: str, new_class: str, old_pps: bool) -> None:
    old_suffix = "Pps" if old_pps else ""
    old_attr = f"storm_control_{old_class}_level" + ("_pps" if old_pps else "")
    new_attr = f"storm_control_{new_class}_level" + ("" if old_pps else "_pps")
    existing = EthernetDot1qTunnelHostPolicyModel.from_response(
        {"policyType": "dot1qTunnelHost", f"stormControl{old_class.title()}Level{old_suffix}": 1000 if old_pps else 10.0}
    )
    proposed = EthernetDot1qTunnelHostPolicyModel.from_config({old_attr: 0, new_attr: 10.0 if old_pps else 1000})

    result = existing.merge(proposed)

    assert result is existing
    assert getattr(existing, old_attr) == 0
    assert getattr(existing, new_attr) == (10.0 if old_pps else 1000)
    assert not existing.has_mixed_storm_units()


def test_invalid_complete_storm_merge_does_not_mutate_the_existing_policy() -> None:
    existing = EthernetDot1qTunnelHostPolicyModel.from_response({"policyType": "dot1qTunnelHost", "description": "before", "stormControlUnicastLevel": 10.0})
    original = existing.model_dump()
    original_fields = set(existing.model_fields_set)
    proposed = EthernetDot1qTunnelHostPolicyModel.from_config({"description": "must not apply", "storm_control_broadcast_level_pps": 1000})

    with pytest.raises(ValueError, match="percentage and PPS"):
        existing.merge(proposed)

    assert existing.model_dump() == original
    assert existing.model_fields_set == original_fields
    # An error must not leave the model-local validation suspension enabled.
    with pytest.raises(ValidationError, match="across the interface"):
        EthernetDot1qTunnelHostPolicyModel.from_config({"storm_control_broadcast_level": 10.0, "storm_control_unicast_level_pps": 1000})
    existing.merge(EthernetDot1qTunnelHostPolicyModel.from_config({"description": "later valid edit"}))
    assert existing.description == "later valid edit"


def test_same_class_storm_merge_retains_inherited_counterpart_clearing() -> None:
    existing = EthernetDot1qTunnelHostPolicyModel.from_response({"policyType": "dot1qTunnelHost", "stormControlBroadcastLevel": 10.0})
    existing.merge(EthernetDot1qTunnelHostPolicyModel.from_config({"storm_control_broadcast_level_pps": 1000}))
    assert existing.storm_control_broadcast_level is None
    assert existing.storm_control_broadcast_level_pps == 1000


def test_empty_description_clear_diff_is_idempotent_after_controller_omits_it() -> None:
    identity = {"switch_ip": "192.0.2.11", "interface_name": "Ethernet1/40"}
    proposed = EthernetDot1qTunnelHostInterfaceModel.from_config({**identity, "config_data": {"network_os": {"policy": {"description": ""}}}})
    existing = EthernetDot1qTunnelHostInterfaceModel.from_response(
        {
            "switchIp": "192.0.2.11",
            "interfaceName": "Ethernet1/40",
            "interfaceType": "ethernet",
            "configData": {"mode": "dot1qTunnel", "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": "dot1qTunnelHost", "description": "old"}}},
        }
    )
    assert existing.get_diff(proposed, exclude_unset=True) is False
    assert proposed.to_payload()["configData"]["networkOS"]["policy"]["description"] == ""
    existing.config_data.network_os.policy.description = None
    assert existing.get_diff(proposed, exclude_unset=True) is True


def test_grouped_argument_spec_is_nx_os_only() -> None:
    spec = EthernetDot1qTunnelHostInterfaceModel.get_argument_spec()
    options = spec["config"]["options"]
    assert options["interface_names"]["required"] is True
    os_options = options["config_data"]["options"]["network_os"]["options"]
    assert os_options["network_os_type"]["choices"] == ["nx-os"]
    assert os_options["policy"]["options"]["policy_type"]["choices"] == ["dot1qTunnelHost"]
