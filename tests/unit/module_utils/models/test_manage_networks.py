# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for ND Manage network Pydantic models."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_actions_models import (
    MulticastIpResponseModel,
    NetworkRemoveRequestModel,
    NetworkStretchPayloadModel,
    NetworkSwitchesListModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NetworkConfigModel,
    NetworkInterfaceConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_attachment_models import (
    AccessInterfaceModel,
    NetworkAttachDetachPayloadModel,
    NetworkAttachmentDetailModel,
    NetworkAttachmentInterfaceModel,
    NetworkAttachmentModel,
    NetworkAttachmentQueryResponseModel,
    NetworkAttachmentValidateInterfaceModel,
    NetworkAttachmentValidateInterfacesPayloadModel,
    SingleMappingModel,
    TrunkInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import (
    AimlRoutedNetworkModel,
    AimlVxlanEbgpNetworkModel,
    AimlVxlanIbgpNetworkModel,
    ClassicLanEnhancedNetworkModel,
    ClassicOrRoutedL2DataModel,
    ClassicOrRoutedL3DataModel,
    CustomNetworkModel,
    DefaultL2DataModel,
    DefaultL2FabricDataModel,
    DefaultL3DataModel,
    NetworkBaseModel,
    NetworkCreateRequestModel,
    NetworkListResponseModel,
    NetworkPreInformationResponseModel,
    RoutedNetworkModel,
    VxlanCampusNetworkModel,
    VxlanEbgpNetworkModel,
    VxlanIbgpNetworkModel,
    VxlanL3FabricDataModel,
    VxlanNetworkModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.validators import (
    NetworkValidators,
)


@pytest.mark.parametrize(
    "model_cls,l2_cls,l3_cls",
    [
        (VxlanNetworkModel, DefaultL2DataModel, DefaultL3DataModel),
        (VxlanIbgpNetworkModel, DefaultL2DataModel, DefaultL3DataModel),
        (VxlanEbgpNetworkModel, DefaultL2DataModel, DefaultL3DataModel),
        (VxlanCampusNetworkModel, DefaultL2DataModel, DefaultL3DataModel),
        (AimlVxlanIbgpNetworkModel, DefaultL2DataModel, DefaultL3DataModel),
        (AimlVxlanEbgpNetworkModel, DefaultL2DataModel, DefaultL3DataModel),
        (RoutedNetworkModel, ClassicOrRoutedL2DataModel, ClassicOrRoutedL3DataModel),
        (AimlRoutedNetworkModel, ClassicOrRoutedL2DataModel, ClassicOrRoutedL3DataModel),
        (ClassicLanEnhancedNetworkModel, ClassicOrRoutedL2DataModel, ClassicOrRoutedL3DataModel),
    ],
)
def test_network_factories_select_matching_typed_models(model_cls, l2_cls, l3_cls):
    """Verify configuration and controller rows select the same concrete nested schemas."""
    network_type = model_cls.model_fields["network_type"].default.value
    proposed = NetworkBaseModel.from_config({"network_name": "USERS", "network_type": network_type, "l2_data": {}, "l3_data": {}}, context={"state": "merged"})
    existing = NetworkBaseModel.from_response({"networkName": "USERS", "networkType": network_type, "l2Data": {}, "l3Data": {}})
    for model in (proposed, existing):
        assert isinstance(model, model_cls)
        assert isinstance(model.l2_data, l2_cls)
        assert isinstance(model.l3_data, l3_cls)
        assert not model.l2_data.model_fields_set
        assert not model.l3_data.model_fields_set
    assert existing.get_diff(proposed, exclude_unset=True)


def test_vxlan_nested_models_apply_defaults_without_manufacturing_explicit_fields():
    """Verify natural nested conversion preserves model defaults separately from supplied values."""
    model = VxlanIbgpNetworkModel(networkName="USERS", l2Data={"fabricData": {}}, l3Data={"fabricData": {}})
    assert isinstance(model.l2_data.fabric_data, DefaultL2FabricDataModel)
    assert isinstance(model.l3_data.fabric_data, VxlanL3FabricDataModel)
    assert model.l3_data.mtu == 9216
    assert model.l3_data.arp_suppression is False
    assert model.l3_data.fabric_data.netflow is False
    assert model.to_payload(exclude_unset=True) == {"networkName": "USERS", "l2Data": {"fabricData": {}}, "l3Data": {"fabricData": {}}}


def test_vxlan_factory_nested_merge_preserves_omissions_and_explicit_clears():
    """Verify typed nested merging retains omitted data and sends explicit false and empty lists."""
    existing = NetworkBaseModel.from_response(
        {
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "l3Data": {"mtu": 9000, "arpSuppression": True, "fabricData": {"netflow": True, "dhcpServers": [{"serverAddress": "192.0.2.10"}]}},
        }
    )
    proposed = NetworkBaseModel.from_config(
        {"network_name": "USERS", "network_type": "vxlanIbgp", "l3_data": {"arp_suppression": False, "fabric_data": {"dhcp_servers": []}}}
    )
    payload = existing.merge(proposed).to_payload()
    assert payload["l3Data"]["mtu"] == 9000
    assert payload["l3Data"]["arpSuppression"] is False
    assert payload["l3Data"]["fabricData"]["netflow"] is True
    assert payload["l3Data"]["fabricData"]["dhcpServers"] == []


@pytest.mark.parametrize("factory", [NetworkBaseModel.from_config, NetworkBaseModel.from_response])
def test_known_network_schema_cannot_fall_back_to_unvalidated_nested_dictionary(factory):
    """Verify invalid known-type nested configuration is rejected instead of accepted as a raw dictionary."""
    with pytest.raises(ValidationError):
        factory({"networkType": "vxlanIbgp", "l3Data": {"mtu": 99999}})


def test_custom_network_factories_preserve_raw_nested_configuration():
    """Verify custom template data remains untyped and is not populated with VXLAN defaults."""
    data = {"networkName": "CUSTOM", "networkType": "userDefined", "l2Data": {}, "l3Data": {"customSetting": {"enabled": False}}}
    for factory in (NetworkBaseModel.from_config, NetworkBaseModel.from_response):
        model = factory(data)
        assert isinstance(model, CustomNetworkModel)
        assert model.to_payload()["l2Data"] == {}
        assert model.to_payload()["l3Data"] == data["l3Data"]


@pytest.mark.parametrize("layer", ["layer3", "layer2WithVrf"])
@pytest.mark.parametrize("collection", ["dhcp", "ipv4", "ipv6"])
@pytest.mark.parametrize("readback", ["missing", "null", "empty"])
@pytest.mark.parametrize("exclude_unset", [False, True])
def test_vxlan_empty_collection_matches_absent_null_or_empty_readback(layer, collection, readback, exclude_unset):
    """Verify cleared collection equivalence without changing public output or write payloads."""
    l3_data = {"mtu": 9216, "arpSuppression": False, "fabricData": {"netflow": False}}
    field = {"dhcp": "dhcpServers", "ipv4": "secondaryGatewayIpv4Collection", "ipv6": "secondaryGatewayIpv6Collection"}[collection]
    if readback != "missing":
        target = l3_data["fabricData"] if collection == "dhcp" else l3_data
        target[field] = None if readback == "null" else []
    existing = NetworkBaseModel.from_response({"networkName": "USERS", "networkType": "vxlanIbgp", "networkMode": layer, "l3Data": l3_data})
    desired_l3 = {"fabricData": {field: []}} if collection == "dhcp" else {field: [], "fabricData": {}}
    proposed = NetworkBaseModel.from_config({"networkName": "USERS", "networkType": "vxlanIbgp", "layer": layer, "l3Data": desired_l3})
    payload_before = existing.to_payload()
    config_before = existing.to_config()
    assert existing.get_diff(proposed, exclude_unset=exclude_unset)
    assert existing.to_payload() == payload_before
    assert existing.to_config() == config_before
    desired_payload = proposed.to_payload(exclude_unset=True)["l3Data"]
    assert (desired_payload["fabricData"] if collection == "dhcp" else desired_payload)[field] == []


@pytest.mark.parametrize("collection", ["dhcp", "ipv4", "ipv6"])
@pytest.mark.parametrize("exclude_unset", [False, True])
def test_vxlan_nonempty_collection_still_requires_explicit_clear(collection, exclude_unset):
    """Verify equivalence never hides a real nonempty-to-empty change."""
    field, values = {
        "dhcp": ("dhcpServers", [{"serverAddress": "192.0.2.10"}]),
        "ipv4": ("secondaryGatewayIpv4Collection", ["192.0.2.1/24"]),
        "ipv6": ("secondaryGatewayIpv6Collection", ["2001:db8::1/64"]),
    }[collection]
    current_l3 = {"fabricData": {field: values}} if collection == "dhcp" else {field: values}
    desired_l3 = {"fabricData": {field: []}} if collection == "dhcp" else {field: []}
    existing = NetworkBaseModel.from_response({"networkName": "USERS", "networkType": "vxlanIbgp", "l3Data": current_l3})
    proposed = NetworkBaseModel.from_config({"networkName": "USERS", "networkType": "vxlanIbgp", "l3Data": desired_l3})
    assert not existing.get_diff(proposed, exclude_unset=exclude_unset)
    merged_l3 = existing.merge(proposed).to_payload()["l3Data"]
    assert (merged_l3["fabricData"] if collection == "dhcp" else merged_l3)[field] == []


@pytest.mark.parametrize("collection", ["dhcp", "ipv4", "ipv6"])
@pytest.mark.parametrize("explicit_null", [False, True])
def test_vxlan_omitted_or_null_merged_collection_preserves_existing_entries(collection, explicit_null):
    """Verify comparison normalization does not introduce clearing intent for sparse omitted or None input."""
    field, alias, values = {
        "dhcp": ("dhcp_servers", "dhcpServers", [{"serverAddress": "192.0.2.10"}]),
        "ipv4": ("secondary_gateway_ipv4_collection", "secondaryGatewayIpv4Collection", ["192.0.2.1/24"]),
        "ipv6": ("secondary_gateway_ipv6_collection", "secondaryGatewayIpv6Collection", ["2001:db8::1/64"]),
    }[collection]
    current_l3 = {"fabricData": {alias: values}} if collection == "dhcp" else {alias: values}
    input_value = {field: None} if explicit_null else {}
    desired_l3 = {"fabric_data": input_value} if collection == "dhcp" else input_value
    existing = NetworkBaseModel.from_response({"networkName": "USERS", "networkType": "vxlanIbgp", "l3Data": current_l3})
    proposed = NetworkBaseModel.from_config({"network_name": "USERS", "network_type": "vxlanIbgp", "l3_data": desired_l3})
    proposed_l3 = proposed.to_diff_dict(exclude_unset=True)["l3Data"]
    assert alias not in (proposed_l3["fabricData"] if collection == "dhcp" else proposed_l3)
    assert existing.get_diff(proposed, exclude_unset=True)
    merged_l3 = existing.merge(proposed).to_payload()["l3Data"]
    assert (merged_l3["fabricData"] if collection == "dhcp" else merged_l3)[alias] == values


def test_vxlan_collection_equivalence_handles_absent_nested_blocks_only_in_comparison():
    """Verify a missing L3 or fabric block represents no entries without manufacturing payload fields."""
    existing = NetworkBaseModel.from_response({"networkName": "USERS", "networkType": "vxlanIbgp"})
    proposed = NetworkBaseModel.from_config({"networkName": "USERS", "networkType": "vxlanIbgp", "l3Data": {"fabricData": {"dhcpServers": []}}})
    assert existing.get_diff(proposed, exclude_unset=True)
    assert "l3Data" not in existing.to_payload()


def test_custom_network_comparison_does_not_apply_vxlan_collection_equivalence():
    """Verify raw custom schemas retain their own absent-versus-empty semantics."""
    existing = NetworkBaseModel.from_response({"networkName": "CUSTOM", "networkType": "userDefined", "l3Data": {}})
    proposed = NetworkBaseModel.from_config({"networkName": "CUSTOM", "networkType": "userDefined", "l3Data": {"dhcpServers": []}})
    assert not existing.get_diff(proposed, exclude_unset=True)


@pytest.mark.parametrize("network_type", ["vxlan", "vxlanIbgp", "vxlanEbgp", "vxlanCampus", "aimlVxlanIbgp", "aimlVxlanEbgp"])
@pytest.mark.parametrize("exclude_unset", [False, True])
def test_layer2_vxlan_comparison_excludes_l3_only_without_changing_diagnostics(network_type, exclude_unset):
    existing = NetworkBaseModel.from_response(
        {"networkName": "USERS", "networkType": network_type, "networkMode": "layer2", "l3Data": {"fabricData": {"igmpVersion": 3}}}
    )
    proposed = NetworkBaseModel.from_config({"networkName": "USERS", "networkType": network_type, "layer": "layer2"})
    assert "l3Data" in existing.to_payload()
    assert "l3_data" in existing.to_config()
    expected = None if exclude_unset else {"fabricData": {"netflow": False}}
    assert existing.to_diff_dict(exclude_unset=exclude_unset).get("l3Data") == expected
    assert proposed.to_diff_dict(exclude_unset=exclude_unset).get("l3Data") == expected
    assert existing.get_diff(proposed, exclude_unset=exclude_unset)


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("layer", ["layer3", "layer2WithVrf"])
def test_x_connect_rejects_routed_capable_modes(state, layer):
    """Reject cross-connect only when the effective definition is not plain Layer 2."""
    with pytest.raises(ValidationError, match="x_connect is only valid for layer2 networks"):
        NetworkConfigModel.from_config({"network_name": "USERS", "layer": layer, "vrf_name": "T", "x_connect": True}, context={"state": state})
    with pytest.raises(ValidationError, match="x_connect is only valid for layer2 networks"):
        NetworkConfigModel.from_config(
            {"network_name": "USERS", "x_connect": True}, context={"state": state, "existing_layer": layer, "existing_vrf_name": "T"}
        )
    valid = NetworkConfigModel.from_config({"network_name": "USERS", "layer": layer, "vrf_name": "T", "x_connect": False}, context={"state": state})
    assert valid.x_connect is False


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged", "deleted", "gathered"])
def test_layer2_x_connect_and_read_only_selectors_remain_valid(state):
    """Keep valid Layer-2 writes and read/delete selectors independent of creation restrictions."""
    layer = "layer3" if state in ("deleted", "gathered") else "layer2"
    model = NetworkConfigModel.from_config({"network_name": "USERS", "layer": layer, "x_connect": True}, context={"state": state})
    assert model.x_connect is True


@pytest.mark.parametrize("exclude_unset", [False, True])
def test_layer2_netflow_comparison_preserves_explicit_enable_and_disable(exclude_unset):
    """Keep genuine NetFlow changes actionable while suppressing unrelated L3 readback."""
    existing = NetworkBaseModel.from_response(
        {"networkName": "USERS", "networkType": "vxlanIbgp", "networkMode": "layer2", "l3Data": {"mtu": 9000, "fabricData": {"netflow": True}}}
    )
    disabled = NetworkBaseModel.from_config(
        {"networkName": "USERS", "networkType": "vxlanIbgp", "layer": "layer2", "l3Data": {"fabricData": {"netflow": False}}}
    )
    assert not existing.get_diff(disabled, exclude_unset=exclude_unset)
    assert existing.merge(disabled).l3_data.to_layer2_payload() == {"fabricData": {"netflow": False}}
    assert existing.merge(disabled).get_diff(disabled, exclude_unset=exclude_unset)
    absent = NetworkBaseModel.from_response({"networkName": "USERS", "networkType": "vxlanIbgp", "networkMode": "layer2"})
    assert absent.get_diff(disabled, exclude_unset=exclude_unset)


@pytest.mark.parametrize("layer", ["layer3", "layer2WithVrf"])
@pytest.mark.parametrize("exclude_unset", [False, True])
def test_routed_capable_vxlan_modes_retain_gathered_l3_and_detect_updates(layer, exclude_unset):
    existing = NetworkBaseModel.from_response(
        {
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "networkMode": layer,
            "vrfName": "T",
            "l3Data": {"gatewayIpv4Address": "192.0.2.1/24", "mtu": 9000, "fabricData": {"ipv4Trm": True, "igmpVersion": 3}},
        }
    )
    gathered = existing.to_gathered_config()
    assert gathered["gateway_ipv4_address"] == "192.0.2.1/24"
    assert gathered["mtu"] == 9000
    assert gathered["igmp_version"] == 3
    NetworkConfigModel.from_config(gathered)
    proposed = NetworkBaseModel.from_config({"networkName": "USERS", "networkType": "vxlanIbgp", "layer": layer, "l3Data": {"mtu": 9100}})
    assert not existing.get_diff(proposed, exclude_unset=exclude_unset)
    assert existing.merge(proposed).to_payload()["l3Data"]["mtu"] == 9100


def test_layer2_custom_network_retains_its_own_l3_comparison_and_gathered_semantics():
    existing = CustomNetworkModel.from_response({"networkName": "CUSTOM", "networkMode": "layer2", "l3Data": {"mtu": 9000, "customSetting": True}})
    proposed = CustomNetworkModel.from_config({"network_name": "CUSTOM", "layer": "layer2", "l3_data": {"mtu": 9100}})
    assert existing.to_gathered_config()["mtu"] == 9000
    assert "l3Data" in existing.to_diff_dict()
    assert not existing.get_diff(proposed, exclude_unset=True)


def test_manage_network_validators_00010() -> None:
    """Verify network validators accept valid schema values."""
    assert NetworkValidators.validate_network_name("net1") == "net1"
    assert NetworkValidators.validate_vlan_id(2) == 2
    assert NetworkValidators.validate_network_id(16777214) == 16777214
    assert NetworkValidators.validate_cidrv4("192.0.2.1/24") == "192.0.2.1/24"
    assert NetworkValidators.validate_cidrv6("2001:db8::1/64") == "2001:db8::1/64"
    assert NetworkValidators.validate_multicast_ipv4("239.1.1.2") == "239.1.1.2"


def test_manage_network_validators_00020() -> None:
    """Verify network validators reject invalid schema values."""
    with pytest.raises(ValueError):
        NetworkValidators.validate_network_name("n" * 129)
    with pytest.raises(ValueError):
        NetworkValidators.validate_vlan_id(1)
    with pytest.raises(ValueError):
        NetworkValidators.validate_network_id(16777215)
    with pytest.raises(ValueError):
        NetworkValidators.validate_cidrv4("2001:db8::1/64")
    with pytest.raises(ValueError):
        NetworkValidators.validate_multicast_ipv4("192.0.2.1")


def test_manage_network_data_models_00100() -> None:
    """Verify VXLAN network aliasing and payload serialization."""
    model = VxlanNetworkModel(
        fabricName="fab1",
        networkName="net1",
        vrfName="vrf1",
        vlanId=3000,
        layer="layer3",
        l2Data=DefaultL2DataModel(vlanName="VLAN3000"),
        l3Data=DefaultL3DataModel(
            gatewayIpv4Address="192.0.2.1/24",
            gatewayIpv6Address="2001:db8::1/64",
            secondaryGatewayIpv4Collection=["192.0.2.2/24"],
            fabricData={
                "netflow": True,
                "l2NetflowMonitor": "L2_MON",
                "l3NetflowMonitor": "L3_MON",
            },
        ),
    )

    payload = model.to_payload()

    assert payload["networkType"] == "vxlan"
    assert payload["networkName"] == "net1"
    assert payload["networkMode"] == "layer3"
    assert "layer" not in payload
    assert payload["l2Data"]["vlanName"] == "VLAN3000"
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    assert payload["l3Data"]["mtu"] == 9216
    assert payload["l3Data"]["fabricData"]["l2NetflowMonitor"] == "L2_MON"
    assert payload["l3Data"]["fabricData"]["l3NetflowMonitor"] == "L3_MON"


def test_manage_network_data_models_00105() -> None:
    """Verify API defaults and nested L2 fabricData properties."""
    model = DefaultL2DataModel(
        vlanName="VLAN3000",
        fabricData={
            "multicastGroup": "239.1.1.2",
            "dsVni": 50000,
        },
    )

    payload = model.to_payload()

    assert payload["fabricData"]["multicastGroup"] == "239.1.1.2"
    assert payload["fabricData"]["dsVni"] == 50000


def test_manage_network_data_models_00110() -> None:
    """Verify create/list/pre-info wrapper models."""
    network = VxlanNetworkModel(fabricName="fab1", networkName="net1", vrfName="vrf1")
    create = NetworkCreateRequestModel(networks=[network])
    listed = NetworkListResponseModel.model_validate({"networks": [network.to_payload()]}, by_alias=True)
    pre_info = NetworkPreInformationResponseModel.model_validate(
        {"multicastIp": "239.1.1.2", "l2Vni": 30000, "networkPrefix": "Network_", "vlanId": 3000},
        by_alias=True,
    )

    assert create.to_payload()["networks"][0]["networkName"] == "net1"
    assert listed.networks[0].network_name == "net1"
    assert pre_info.multicast_ip == "239.1.1.2"


def test_manage_network_data_models_00120() -> None:
    """Verify invalid network model values are rejected."""
    with pytest.raises(ValidationError):
        VxlanNetworkModel(fabricName="fab1", networkName="n" * 129, vrfName="vrf1")
    with pytest.raises(ValidationError):
        VxlanNetworkModel(fabricName="fab1", networkName="net1", vrfName="v" * 33)
    with pytest.raises(ValidationError):
        DefaultL3DataModel(gatewayIpv4Address="2001:db8::1/64")
    with pytest.raises(ValidationError):
        NetworkPreInformationResponseModel(multicastIp="192.0.2.1")


def test_manage_network_action_models_00200() -> None:
    """Verify network action request and response models."""
    switches = NetworkSwitchesListModel(networkNames=["net1"], switchIds=["FDO123"])
    remove = NetworkRemoveRequestModel(networkNames=["net1"])
    stretch = NetworkStretchPayloadModel.model_validate(
        {"attachments": [{"networkName": "net1", "stretch": "allBgwList"}]},
        by_alias=True,
    )
    multicast = MulticastIpResponseModel.model_validate({"multicastIp": "239.1.1.2"}, by_alias=True)

    assert switches.to_payload() == {"networkNames": ["net1"], "switchIds": ["FDO123"]}
    assert remove.to_payload() == {"networkNames": ["net1"]}
    assert stretch.attachments[0].network_name == "net1"
    assert multicast.multicast_ip == "239.1.1.2"


def test_manage_network_attachment_models_00300() -> None:
    """Verify network attachment payload and query response models."""
    access = AccessInterfaceModel(interfaceRange="Ethernet1/1")
    trunk = TrunkInterfaceModel(
        interfaceRange="Ethernet1/2",
        nativeVlan=True,
        mapping=SingleMappingModel(customerVlan=300),
    )
    attachment = NetworkAttachmentModel(
        networkName="net1",
        switchId="FDO123",
        vlanId=3000,
        attach=True,
        interfaces=[access, trunk],
    )
    payload = NetworkAttachDetachPayloadModel(attachments=[attachment]).to_payload()
    query = NetworkAttachmentQueryResponseModel.model_validate(
        {
            "attachments": [
                {
                    "networkName": "net1",
                    "switchId": "FDO123",
                    "vlanId": 3000,
                    "status": "pending",
                    "attach": True,
                    "networkId": 30000,
                }
            ]
        },
        by_alias=True,
    )

    assert payload["attachments"][0]["networkName"] == "net1"
    assert payload["attachments"][0]["interfaces"][0]["mode"] == "access"
    assert query.attachments[0].network_id == 30000
    assert isinstance(query.attachments[0], NetworkAttachmentDetailModel)


def test_manage_network_attachment_models_00310() -> None:
    """Verify invalid attachment values are rejected."""
    with pytest.raises(ValidationError):
        SingleMappingModel(customerVlan=1)
    with pytest.raises(ValidationError):
        NetworkAttachmentInterfaceModel(mode="trunk")
    with pytest.raises(ValidationError):
        NetworkAttachmentModel(networkName="net1", vlanId=1, attach=True)


def test_manage_network_attachment_config_models_00315() -> None:
    """Verify playbook interface config enforces trunk mapping bindings."""
    with pytest.raises(ValidationError, match="native_vlan cannot be true when mapping_type=single"):
        NetworkInterfaceConfigModel(
            mode="trunk",
            interface_range="Ethernet1/1",
            native_vlan=True,
            mapping_type="single",
            customer_vlan=300,
        )
    with pytest.raises(ValidationError, match="native_vlan can only be used when mode=trunk"):
        NetworkInterfaceConfigModel(
            mode="access",
            interface_range="Ethernet1/1",
            native_vlan=True,
        )
    with pytest.raises(ValidationError, match="mapping_type can only be used when mode=trunk"):
        NetworkInterfaceConfigModel(
            mode="access",
            interface_range="Ethernet1/1",
            mapping_type="single",
            customer_vlan=300,
        )
    with pytest.raises(ValidationError, match="customer_vlan can only be used when mapping_type=single"):
        NetworkInterfaceConfigModel(
            mode="trunk",
            interface_range="Ethernet1/1",
            customer_vlan=300,
        )
    with pytest.raises(ValidationError, match="customer_vlan can only be used when mapping_type=single"):
        NetworkInterfaceConfigModel(
            mode="trunk",
            interface_range="Ethernet1/1",
            mapping_type="none",
            customer_vlan=300,
        )
    with pytest.raises(ValidationError, match="mode must be one of"):
        NetworkInterfaceConfigModel(
            mode="host",
            interface_range="Ethernet1/1",
            interface_group_name="ifgrp1",
        )
    with pytest.raises(ValidationError, match="interface_group_name can only be used when mode is access or trunk"):
        NetworkInterfaceConfigModel(
            mode="pvlan_host",
            interface_range="Ethernet1/1",
            interface_group_name="ifgrp1",
        )

    native_only = NetworkInterfaceConfigModel(
        mode="trunk",
        interface_range="Ethernet1/1",
        native_vlan=True,
    )
    mapping_only = NetworkInterfaceConfigModel(
        mode="trunk",
        interface_range="Ethernet1/2",
        mapping_type="single",
        customer_vlan=300,
    )
    access_group = NetworkInterfaceConfigModel(
        mode="access",
        interface_range="Ethernet1/3",
        interface_group_name="ifgrp1",
    )

    assert native_only.native_vlan is True
    assert mapping_only.mapping_type == "single"
    assert mapping_only.customer_vlan == 300
    assert access_group.interface_group_name == "ifgrp1"


def test_manage_network_attachment_config_models_00316() -> None:
    """Verify vlan_network_type controls valid attachment interface modes."""
    with pytest.raises(ValidationError, match="mode=pvlan_host is not valid for vlan_network_type=normal"):
        NetworkConfigModel(
            network_name="net1",
            layer="layer2",
            attach=[{"ip_address": "192.0.2.10", "interfaces": [{"mode": "pvlan_host", "interface_range": "Ethernet1/1"}]}],
        )
    with pytest.raises(ValidationError, match="mode=pvlan_host is not valid for vlan_network_type=privatePrimary"):
        NetworkConfigModel(
            network_name="net1",
            layer="layer2",
            vlan_network_type="primary",
            attach=[{"ip_address": "192.0.2.10", "interfaces": [{"mode": "pvlan_host", "interface_range": "Ethernet1/1"}]}],
        )
    with pytest.raises(ValidationError, match="mode=trunk is not valid for vlan_network_type=privateSecondaryCommunity"):
        NetworkConfigModel(
            network_name="net1",
            layer="layer2",
            vlan_network_type="community",
            primary_network_id=30000,
            attach=[{"ip_address": "192.0.2.10", "interfaces": [{"mode": "trunk", "interface_range": "Ethernet1/1"}]}],
        )

    private_primary = NetworkConfigModel(
        network_name="net1",
        layer="layer2",
        vlan_network_type="primary",
        attach=[{"ip_address": "192.0.2.10", "interfaces": [{"mode": "promiscuous", "interface_range": "Ethernet1/1"}]}],
    )
    private_secondary = NetworkConfigModel(
        network_name="net2",
        layer="layer2",
        vlan_network_type="isolated",
        primary_network_id=30000,
        attach=[{"ip_address": "192.0.2.10", "interfaces": [{"mode": "pvlan_host", "interface_range": "Ethernet1/2"}]}],
    )
    secondary_trunk = NetworkConfigModel(
        network_name="net3",
        layer="layer2",
        vlan_network_type="community",
        primary_network_id=30000,
        attach=[{"ip_address": "192.0.2.10", "interfaces": [{"mode": "trunk_secondary", "interface_range": "Ethernet1/3"}]}],
    )

    assert private_primary.vlan_network_type == "privatePrimary"
    assert private_secondary.vlan_network_type == "privateSecondaryIsolated"
    assert private_secondary.primary_network_id == 30000
    assert secondary_trunk.attach[0].interfaces[0].mode == "trunk_secondary"


def test_manage_network_config_models_00318() -> None:
    """Verify omitted layer is validated using the same effective layer as payload construction."""
    with pytest.raises(ValidationError, match="vrf_name is required for layer3 and layer2WithVrf networks"):
        NetworkConfigModel.from_config(
            {
                "network_name": "net_no_vrf",
                "network_id": 30001,
                "vlan_id": 101,
            }
        )

    implicit_l3 = NetworkConfigModel.from_config(
        {
            "network_name": "net_with_vrf",
            "network_id": 30002,
            "vlan_id": 102,
            "vrf_name": "VRF_BLUE",
        }
    )
    explicit_l2 = NetworkConfigModel.from_config(
        {
            "network_name": "net_l2",
            "network_id": 30003,
            "vlan_id": 103,
            "layer": "layer2",
        }
    )
    attachment_only = NetworkConfigModel.from_config(
        {
            "network_name": "net_attach_only",
            "attach": [{"ip_address": "192.0.2.10"}],
        }
    )
    secondary_pvlan = NetworkConfigModel.from_config(
        {
            "network_name": "pvlan_community",
            "vlan_network_type": "community",
            "primary_network_id": 30000,
            "network_id": 30004,
        }
    )

    assert implicit_l3.layer == "layer3"
    assert explicit_l2.layer == "layer2"
    assert attachment_only.layer is None
    assert secondary_pvlan.layer == "layer2"


def test_manage_network_attachment_models_00320() -> None:
    """Verify interface validation payload accepts controller probe VLAN."""
    attachment = NetworkAttachmentValidateInterfaceModel(
        networkName="net1",
        switchId="FDO123",
        vlanId=-1,
        attach=True,
        interfaces=[TrunkInterfaceModel(interfaceRange="Ethernet1/3")],
    )
    payload = NetworkAttachmentValidateInterfacesPayloadModel(attachments=[attachment]).to_payload()

    assert payload == {
        "attachments": [
            {
                "networkName": "net1",
                "switchId": "FDO123",
                "vlanId": -1,
                "interfaces": [
                    {
                        "mode": "trunk",
                        "interfaceRange": "Ethernet1/3",
                        "nativeVlan": False,
                    }
                ],
                "attach": True,
            }
        ]
    }
