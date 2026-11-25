# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Native link additions against ND 4.2.1/4.3.1 Manage contracts.

Expected aliases, required fields, release availability and bounds were taken
from immutable Manage API 1.1.411 and 1.2.224 schemas, not model metadata.
"""

from __future__ import annotations

import copy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from pydantic import ValidationError

ADDITIONAL_POLICIES = (
    "ipfmNumbered",
    "ospfVrfLite",
    "csrMultisiteUnderlay",
    "csrEvpnMultisiteOverlay",
    "csrBgpOverIpsec",
    "vxlanAciMultisiteUnderlay",
    "vxlanAciEvpnOverlay",
    "routedFabric",
    "multisiteUnderlayInterFabricGroup",
    "serviceTrunk",
    "servicePoTrunk",
    "serviceVpcTrunk",
)
ONLY_431 = {"multisiteUnderlayInterFabricGroup", "serviceTrunk", "servicePoTrunk", "serviceVpcTrunk"}

MINIMAL_INPUTS = {
    "ipfmNumbered": {"interface_vrf": "media", "src_ip": "192.0.2.1", "dst_ip": "192.0.2.2"},
    "ospfVrfLite": {},
    "csrMultisiteUnderlay": {"src_ip_address_mask": "192.0.2.1/30", "dst_ip": "192.0.2.2"},
    "csrEvpnMultisiteOverlay": {},
    "csrBgpOverIpsec": {
        "ip_sec_shared_key": "TEST-IPSEC-KEY",
        "on_prem_device_ip_bgp_peering": "192.0.2.1",
        "cloud_csr_ip_bgp_peering": "192.0.2.2",
        "on_prem_device_tunnel_ip": "198.51.100.1",
        "cloud_csr_tunnel_ip": "198.51.100.2",
        "on_prem_device_remote_domain": "on-prem.example",
        "on_prem_device_fqdn": "router.on-prem.example",
        "cloud_csr_remote_domain": "cloud.example",
        "cloud_csr_fqdn": "router.cloud.example",
    },
    "vxlanAciMultisiteUnderlay": {"src_ebgp_asn": "65001", "dst_ebgp_asn": "65002"},
    "vxlanAciEvpnOverlay": {"src_ebgp_asn": "65001", "dst_ebgp_asn": "65002", "src_ip_address": "192.0.2.1", "dst_ip_address": "192.0.2.2"},
    "routedFabric": {"src_ebgp_asn": "65001", "dst_ebgp_asn": "65002"},
    "multisiteUnderlayInterFabricGroup": {"src_ebgp_asn": "65001", "dst_ebgp_asn": "65002"},
    "serviceTrunk": {},
    "servicePoTrunk": {},
    "serviceVpcTrunk": {},
}

# Schema-required fields without documented defaults must not be synthesized.
REQUIRED_WITHOUT_DEFAULT = {
    "ipfmNumbered": ("interface_vrf", "src_ip", "dst_ip"),
    "csrMultisiteUnderlay": ("src_ip_address_mask", "dst_ip"),
    "csrBgpOverIpsec": tuple(MINIMAL_INPUTS["csrBgpOverIpsec"]),
    "vxlanAciMultisiteUnderlay": ("src_ebgp_asn", "dst_ebgp_asn"),
    "vxlanAciEvpnOverlay": ("src_ebgp_asn", "dst_ebgp_asn", "src_ip_address", "dst_ip_address"),
    "routedFabric": ("src_ebgp_asn", "dst_ebgp_asn"),
    "multisiteUnderlayInterFabricGroup": ("src_ebgp_asn", "dst_ebgp_asn"),
}


def config(policy_type, inputs=None):
    return {
        "src_fabric_name": "fabric-a",
        "dst_fabric_name": "fabric-b",
        "src_switch_name": "leaf-a",
        "dst_switch_name": "leaf-b",
        "src_switch_id": "SERIAL-A",
        "dst_switch_id": "SERIAL-B",
        "src_interface_name": "Ethernet1/1",
        "dst_interface_name": "Ethernet1/2",
        "config_data": {"policy_type": policy_type, "template_inputs": copy.deepcopy(MINIMAL_INPUTS[policy_type] if inputs is None else inputs)},
    }


def link(policy_type, inputs=None, state="merged"):
    return NDLinkModel.from_config(config(policy_type, inputs), context={"state": state})


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
def test_each_addition_has_a_native_write_and_response_model(policy_type):
    model = link(policy_type)
    payload = model.to_payload(controller_version="4.3.1")
    assert payload["configData"]["policyType"] == policy_type
    assert "policy_type_marker" not in repr(payload)
    response = NDLinkModel.from_response({**payload, "linkId": "LINK-TEST"})
    assert response.is_unsupported_policy is False
    assert response.config_data.policy_type == policy_type


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("spelling", ["template_inputs", "templateInputs"])
def test_write_state_validation_cannot_be_bypassed_by_omitting_or_nulling_inputs(policy_type, state, spelling):
    raw = config(policy_type)
    raw["config_data"].pop("template_inputs")
    raw["config_data"][spelling] = None
    if policy_type in REQUIRED_WITHOUT_DEFAULT:
        with pytest.raises(ValidationError):
            NDLinkModel.from_config(raw, context={"state": state})
    else:
        model = NDLinkModel.from_config(raw, context={"state": state})
        assert model.is_unsupported_policy is False
        assert model.to_payload(controller_version="4.3.1")["configData"]["policyType"] == policy_type


@pytest.mark.parametrize("policy_type,missing", [(policy, field) for policy, fields in REQUIRED_WITHOUT_DEFAULT.items() for field in fields])
def test_every_required_input_without_a_default_is_validated(policy_type, missing):
    inputs = copy.deepcopy(MINIMAL_INPUTS[policy_type])
    inputs.pop(missing)
    with pytest.raises(ValidationError):
        link(policy_type, inputs)


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
def test_identifier_only_delete_does_not_require_policy_inputs(policy_type):
    raw = config(policy_type)
    raw.pop("config_data")
    deleted = NDLinkModel.from_config(raw, context={"state": "deleted"})
    assert deleted.config_data is None


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
def test_unknown_template_input_rejected_for_each_native_policy(policy_type):
    with pytest.raises(ValidationError):
        link(policy_type, {**MINIMAL_INPUTS[policy_type], "not_a_manage_property": True})


@pytest.mark.parametrize(
    "policy_type,python_key,wire_key,value",
    [
        ("ipfmNumbered", "bandwidth_capacity_percentage", "bandwidthCapacityPercentage", 75),
        ("ospfVrfLite", "auto_gen_config_peer", "autoGenConfigPeer", True),
        ("csrMultisiteUnderlay", "src_ip_address_mask", "srcIpAddressMask", "192.0.2.5/30"),
        ("csrEvpnMultisiteOverlay", "ebgp_multihop", "ebgpMultihop", 10),
        ("csrBgpOverIpsec", "cloud_csr_fqdn", "cloudCsrFqdn", "changed.cloud.example"),
        ("vxlanAciMultisiteUnderlay", "src_ebgp_asn", "srcEbgpAsn", "65100"),
        ("vxlanAciEvpnOverlay", "route_server_routing_tag", "routeServerRoutingTag", "1234"),
        ("routedFabric", "default_route_configuration", "defaultRouteConfiguration", True),
        ("multisiteUnderlayInterFabricGroup", "dci_tracking_direction", "dciTrackingDirection", "destination"),
        ("serviceTrunk", "allowed_vlans", "allowedVlans", "100-110"),
        ("servicePoTrunk", "lacp_port_priority", "lacpPortPriority", 42),
    ],
)
def test_python_names_and_api_aliases_generate_the_same_payload(policy_type, python_key, wire_key, value):
    python_model = link(policy_type, {**MINIMAL_INPUTS[policy_type], python_key: value})
    alias_inputs = {key: item for key, item in MINIMAL_INPUTS[policy_type].items() if key != python_key}
    alias_model = link(policy_type, {**alias_inputs, wire_key: value})
    assert python_model.to_payload(controller_version="4.3.1") == alias_model.to_payload(controller_version="4.3.1")
    assert python_model.to_payload(controller_version="4.3.1")["configData"]["templateInputs"][wire_key] == value


@pytest.mark.parametrize(
    "policy_type,field,value",
    [
        ("ipfmNumbered", "bandwidth_capacity_percentage", 101),
        ("ipfmNumbered", "mtu", 575),
        ("ospfVrfLite", "src_kme_server_port_number", 65536),
        ("ospfVrfLite", "src_qkd_profile_name", "x" * 64),
        ("csrMultisiteUnderlay", "src_interface_description", "x" * 255),
        ("csrEvpnMultisiteOverlay", "ebgp_multihop", 1),
        ("csrBgpOverIpsec", "loopback_id", -1),
        ("csrBgpOverIpsec", "tunnel_id", 2147483648),
        ("vxlanAciMultisiteUnderlay", "speed", "invalid-speed"),
        ("vxlanAciEvpnOverlay", "ebgp_multihop", 256),
        ("routedFabric", "ebgp_maximum_paths", 0),
        ("multisiteUnderlayInterFabricGroup", "dci_tracking_direction", "both"),
        ("multisiteUnderlayInterFabricGroup", "ebgp_auth_key_encryption_type", "plain"),
        ("serviceTrunk", "native_vlan", 4095),
        ("serviceTrunk", "mtu", "9216"),
        ("serviceTrunk", "description", "bad\u2603"),
        ("serviceTrunk", "description", ""),
        ("servicePoTrunk", "lacp_port_priority", 0),
        ("servicePoTrunk", "port_channel_mode", "invalid"),
    ],
)
def test_schema_bounds_and_choices_reject_invalid_user_values(policy_type, field, value):
    with pytest.raises(ValidationError):
        link(policy_type, {**MINIMAL_INPUTS[policy_type], field: value})


@pytest.mark.parametrize(
    "policy_type,expected_defaults",
    [
        ("ipfmNumbered", {"mtu": 9216, "interfaceAdminState": True, "bandwidthCapacityPercentage": 5}),
        ("ospfVrfLite", {"linkMtu": 9216, "templateConfigGenPeer": "Ext_VRF_Lite_Jython", "inheritTtagFabricSetting": True}),
        ("csrMultisiteUnderlay", {"enableEbgpPassword": False}),
        ("csrEvpnMultisiteOverlay", {"ebgpMultihop": 5, "enableEbgpPassword": False}),
        ("csrBgpOverIpsec", {"loopbackId": 0, "tunnelId": 0}),
        ("vxlanAciEvpnOverlay", {"ebgpMultihop": 5, "redistributeRouteServer": False}),
        ("routedFabric", {"ebgpMaximumPaths": 64, "linkMtu": 9216, "defaultRouteConfiguration": False}),
        ("multisiteUnderlayInterFabricGroup", {"dciTrackingDirection": "source", "enableEbgpPassword": False, "ebgpMaximumPaths": 64}),
        ("serviceTrunk", {"adminState": True, "allowedVlans": "none", "bpduGuard": "default", "mtu": "jumbo", "portTypeEdgeTrunk": True}),
        ("servicePoTrunk", {"portChannelMode": "active", "lacpRate": "normal", "lacpPortPriority": 32768}),
    ],
)
def test_documented_defaults_survive_final_payload_serialization(policy_type, expected_defaults):
    payload_inputs = link(policy_type).to_payload(controller_version="4.3.1")["configData"]["templateInputs"]
    assert {key: payload_inputs[key] for key in expected_defaults} == expected_defaults


@pytest.mark.parametrize("policy_type", ["serviceTrunk", "servicePoTrunk"])
def test_optional_constrained_service_fields_do_not_become_invalid_typed_empties(policy_type):
    inputs = link(policy_type).to_payload(controller_version="4.3.1")["configData"]["templateInputs"]
    assert "nativeVlan" not in inputs
    assert "speed" not in inputs
    assert "description" not in inputs


def test_service_vpc_is_discriminator_only_in_both_input_spellings():
    for spelling in ("template_inputs", "templateInputs"):
        raw = config("serviceVpcTrunk")
        raw["config_data"] = {"policy_type": "serviceVpcTrunk", spelling: {}}
        model = NDLinkModel.from_config(raw, context={"state": "merged"})
        assert model.to_payload(controller_version="4.3.1")["configData"] == {"policyType": "serviceVpcTrunk"}


@pytest.mark.parametrize("release", ["4.2.1", "4.3.1"])
@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
def test_release_availability_matches_bundled_manage_contracts(policy_type, release):
    model = link(policy_type)
    if release == "4.2.1" and policy_type in ONLY_431:
        with pytest.raises(ValueError):
            model.to_payload(controller_version=release)
    else:
        assert model.to_payload(controller_version=release)["configData"]["policyType"] == policy_type


@pytest.mark.parametrize("policy_type", sorted(ONLY_431))
def test_release_specific_policy_cannot_be_sent_when_controller_version_is_unknown(policy_type):
    with pytest.raises(ValueError):
        link(policy_type).to_payload()


@pytest.mark.parametrize(
    "policy_type,field,value,valid_release,invalid_release",
    [
        ("vxlanAciMultisiteUnderlay", "src_interface_config", "logging event port link-status", "4.2.1", "4.3.1"),
        ("vxlanAciMultisiteUnderlay", "speed", "100Gb", "4.3.1", "4.2.1"),
        ("vxlanAciEvpnOverlay", "macsec", True, "4.2.1", "4.3.1"),
        ("vxlanAciEvpnOverlay", "ebgp_multihop", 10, "4.3.1", "4.2.1"),
    ],
)
def test_explicit_release_specific_fields_are_gated_before_sending(policy_type, field, value, valid_release, invalid_release):
    model = link(policy_type, {**MINIMAL_INPUTS[policy_type], field: value})
    model.to_payload(controller_version=valid_release)
    with pytest.raises(ValueError):
        model.to_payload(controller_version=invalid_release)
    with pytest.raises(ValueError):
        model.to_payload()


@pytest.mark.parametrize(
    "policy_type,python_key,wire_key,release",
    [
        ("csrMultisiteUnderlay", "ebgp_neighbor_password", "ebgpNeighborPassword", "4.3.1"),
        ("csrEvpnMultisiteOverlay", "ebgp_neighbor_password", "ebgpNeighborPassword", "4.3.1"),
        ("csrBgpOverIpsec", "ip_sec_shared_key", "ipSecSharedKey", "4.3.1"),
        ("ospfVrfLite", "macsec_primary_key_string", "macsecPrimaryKeyString", "4.3.1"),
        ("ospfVrfLite", "macsec_fallback_key_string", "macsecFallbackKeyString", "4.3.1"),
        ("vxlanAciEvpnOverlay", "macsec_primary_key_string", "macsecPrimaryKeyString", "4.2.1"),
        ("multisiteUnderlayInterFabricGroup", "ebgp_password", "ebgpPassword", "4.3.1"),
    ],
)
def test_new_secret_fields_are_registered_masked_and_excluded_from_diff(policy_type, python_key, wire_key, release):
    secret = "TEST-ROTATED-KEY"
    for key in (python_key, wire_key):
        secret_inputs = {name: value for name, value in MINIMAL_INPUTS[policy_type].items() if name != python_key}
        raw = config(policy_type, {**secret_inputs, key: secret})
        assert secret in NDLinkModel.collect_secret_values(raw)
        model = NDLinkModel.from_config(raw, context={"state": "merged"})
        assert model.to_payload(controller_version=release)["configData"]["templateInputs"][wire_key] == secret
        assert model.to_config()["config_data"]["template_inputs"][python_key] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        assert wire_key not in model.to_diff_dict()["configData"]["templateInputs"]
        assert python_key not in model.to_gathered_config()["config_data"]["template_inputs"]


@pytest.mark.parametrize("policy_type", ADDITIONAL_POLICIES)
def test_controller_echo_with_payload_defaults_round_trips_through_gathered(policy_type):
    original = link(policy_type)
    existing = NDLinkModel.from_response({**original.to_payload(controller_version="4.3.1"), "linkId": "LINK-TEST"})
    gathered = existing.to_gathered_config()
    if policy_type == "csrBgpOverIpsec":
        assert "ip_sec_shared_key" not in gathered["config_data"]["template_inputs"]
        # The API requires this write-only key: a reusable write must resupply it.
        gathered["config_data"]["template_inputs"]["ip_sec_shared_key"] = "TEST-REPLAY-KEY"
    replay = NDLinkModel.from_config(gathered, context={"state": "merged"})
    assert replay.to_payload(controller_version="4.3.1")["configData"]["policyType"] == policy_type
    if policy_type != "csrBgpOverIpsec":
        assert existing.get_diff(replay, exclude_unset=True) is True


def test_argspec_adds_twelve_choices_and_keeps_sonic_excluded():
    choices = NDLinkModel.get_argument_spec()["config"]["options"]["config_data"]["options"]["policy_type"]["choices"]
    assert len(choices) == len(set(choices)) == 26
    assert set(ADDITIONAL_POLICIES) <= set(choices)
    assert not {"sonicNumbered", "sonicRoutedFabric"} & set(choices)
