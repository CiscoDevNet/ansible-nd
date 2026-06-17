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
    NetworkBulkDeleteRequestModel,
    NetworkStretchPayloadModel,
    NetworkSwitchesListModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_attachment_models import (
    AccessInterfaceModel,
    NetworkAttachDetachPayloadModel,
    NetworkAttachmentDetailModel,
    NetworkAttachmentModel,
    NetworkAttachmentQueryResponseModel,
    SingleMappingModel,
    TrunkInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import (
    DefaultL2DataModel,
    DefaultL3DataModel,
    NetworkCreateRequestModel,
    NetworkListResponseModel,
    NetworkPreInformationResponseModel,
    VxlanNetworkModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.validators import (
    NetworkValidators,
)


def test_manage_network_validators_00010() -> None:
    """Verify network validators accept valid schema values."""
    assert NetworkValidators.validate_network_name("net1") == "net1"
    assert NetworkValidators.validate_tenant_name("tenant_1") == "tenant_1"
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
        NetworkValidators.validate_tenant_name("bad tenant")
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
        tenantName="tenant1",
        l2Data=DefaultL2DataModel(vlanName="VLAN3000"),
        l3Data=DefaultL3DataModel(
            gatewayIpv4Address="192.0.2.1/24",
            gatewayIpv6Address="2001:db8::1/64",
            secondaryGatewayIpv4Collection=["192.0.2.2/24"],
        ),
    )

    payload = model.to_payload()

    assert payload["networkType"] == "vxlan"
    assert payload["networkName"] == "net1"
    assert payload["l2Data"]["vlanName"] == "VLAN3000"
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    assert payload["l3Data"]["mtu"] == 9216


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

    assert payload["fabricData"]["enableIr"] is False
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
    remove = NetworkBulkDeleteRequestModel(networkNames=["net1"])
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
        NetworkAttachmentModel(networkName="net1", vlanId=1, attach=True)
