# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for Routed and AI/ML Routed fabric models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import FabricTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_routed import (
    FabricRoutedModel,
    RoutedManagementModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_routed import (
    AimlRoutedManagementModel,
    FabricAiRoutedModel,
)


def test_manage_fabric_routed_00010() -> None:
    """
    # Summary

    Verify the Routed fabric model applies the routed type discriminator and
    propagates the fabric name and site_id defaults.
    """
    model = FabricRoutedModel(
        fabric_name="routed_fabric",
        management={"type": "routed", "bgp_asn": "65001"},
    )

    assert model._fabric_type == FabricTypeEnum.ROUTED
    assert model.management is not None
    assert model.management.type == FabricTypeEnum.ROUTED
    assert model.management.evpn is False
    assert model.management.name == "routed_fabric"
    assert model.management.site_id == "65001"
    assert model.telemetry_collection is False


def test_manage_fabric_routed_00020() -> None:
    """
    # Summary

    Verify the AI Routed fabric model inherits the routed base behavior and
    forces aiml_qos to True.
    """
    model = FabricAiRoutedModel(
        fabric_name="ai_routed_fabric",
        management={"type": "aimlRouted", "bgp_asn": "65002"},
    )

    assert model._fabric_type == FabricTypeEnum.AIML_ROUTED
    assert model.management is not None
    assert model.management.type == "aimlRouted"
    assert model.management.evpn is False
    assert model.management.name == "ai_routed_fabric"
    assert model.management.site_id == "65002"
    assert model.management.aiml_qos is True
    assert model.management.nxapi_http is True
    assert model.telemetry_collection is False


def test_manage_fabric_routed_00030() -> None:
    """
    # Summary

    Verify aiml_qos is not exposed in the AI Routed model argument spec.
    """
    spec = FabricAiRoutedModel.get_argument_spec()

    def contains_option(node: dict, key: str) -> bool:
        if not isinstance(node, dict):
            return False
        options = node.get("options")
        if isinstance(options, dict):
            if key in options:
                return True
            for child in options.values():
                if isinstance(child, dict) and contains_option(child, key):
                    return True
        elements = node.get("elements")
        if isinstance(elements, dict) and contains_option(elements, key):
            return True
        return False

    assert contains_option(spec, "aiml_qos") is False
    assert contains_option(spec, "nxapi_http") is False
    for fixed_option in (
        "evpn",
        "auto_configure_ebgp_evpn_peering",
        "tenant_dhcp",
        "next_generation_oam",
        "per_vrf_loopback_auto_provision",
        "per_vrf_loopback_auto_provision_ipv6",
    ):
        assert contains_option(FabricRoutedModel.get_argument_spec(), fixed_option) is False
        assert contains_option(FabricAiRoutedModel.get_argument_spec(), fixed_option) is False


def test_manage_fabric_routed_00040() -> None:
    """
    # Summary

    Verify aiml_qos is locked to True on the AI Routed model and cannot be
    overridden to a non-True value, including via a wire payload.
    """
    with pytest.raises(ValidationError):
        FabricAiRoutedModel(
            fabric_name="ai_routed_fabric",
            management={"type": "aimlRouted", "bgp_asn": "65002", "aiml_qos": False},
        )

    with pytest.raises(ValidationError):
        FabricAiRoutedModel(
            fabric_name="ai_routed_fabric",
            management={"type": "aimlRouted", "bgp_asn": "65002", "aimlQos": False},
        )


@pytest.mark.parametrize(
    "model_class,fabric_type",
    ((FabricRoutedModel, "routed"), (FabricAiRoutedModel, "aimlRouted")),
)
@pytest.mark.parametrize(
    "field",
    (
        "evpn",
        "auto_configure_ebgp_evpn_peering",
        "tenant_dhcp",
        "next_generation_oam",
        "per_vrf_loopback_auto_provision",
        "per_vrf_loopback_auto_provision_ipv6",
    ),
)
def test_manage_fabric_routed_00045(model_class, fabric_type, field) -> None:
    """Verify Routed-only false invariants cannot be enabled through config."""
    with pytest.raises(ValidationError):
        model_class.from_config(
            {
                "fabric_name": "routed_fabric",
                "management": {
                    "type": fabric_type,
                    "bgp_asn": "65001",
                    field: True,
                },
            }
        )


def test_manage_fabric_routed_00050() -> None:
    """Verify Routed inherits the complete current eBGP management contract."""
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
        VxlanEbgpManagementModel,
    )

    assert issubclass(RoutedManagementModel, VxlanEbgpManagementModel)
    assert set(RoutedManagementModel.model_fields) == set(VxlanEbgpManagementModel.model_fields)
    assert "bgpAsnRange" in RoutedManagementModel.replacement_preserve_fields
    assert "anycastGatewayMac" in RoutedManagementModel.replacement_preserve_fields
    assert "fabricPlatformType" in RoutedManagementModel.replacement_preserve_fields
    assert "fabricPlatformType" in RoutedManagementModel.config_exclude_fields
    assert RoutedManagementModel.empty_string_means_unset is True

    management = RoutedManagementModel(bgp_asn="65001")
    assert management.evpn is False
    assert management.auto_configure_ebgp_evpn_peering is False
    assert management.assign_ipv4_to_loopback0 is False
    assert management.network_template == "Routed_Network_Universal"
    assert management.network_extension_template == "Routed_Network_Universal"
    assert management.tenant_dhcp is False
    assert management.next_generation_oam is False
    assert management.per_vrf_loopback_auto_provision is False
    assert management.per_vrf_loopback_auto_provision_ipv6 is False


@pytest.mark.parametrize(
    "model_class,fabric_type",
    ((FabricRoutedModel, "routed"), (FabricAiRoutedModel, "aimlRouted")),
)
def test_manage_fabric_routed_00060(model_class, fabric_type) -> None:
    """Verify both Routed families inherit eBGP secret masking and no-log metadata."""
    model = model_class.from_config(
        {
            "fabric_name": "routed_fabric",
            "management": {
                "type": fabric_type,
                "bgp_asn": "65001",
                "bgp_authentication_key": "ROUTED_SECRET",
            },
        }
    )

    assert model.to_payload()["management"]["bgpAuthenticationKey"] == "ROUTED_SECRET"
    assert model.to_config()["management"]["bgp_authentication_key"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    management_spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]
    assert management_spec["bgp_authentication_key"]["no_log"] is True


@pytest.mark.parametrize(
    "model_class,fabric_type,aiml_qos,nxapi_http",
    (
        (FabricRoutedModel, "routed", False, False),
        (FabricAiRoutedModel, "aimlRouted", True, True),
    ),
)
def test_manage_fabric_routed_00070(model_class, fabric_type, aiml_qos, nxapi_http) -> None:
    """Verify both routed models accept and normalize the live ND Routed defaults."""
    model = model_class.from_response(
        {
            "name": "routed_fabric",
            "category": "fabric",
            "management": {
                "type": fabric_type,
                "bgpAsn": "65001",
                "evpn": False,
                "aimlQos": aiml_qos,
                "networkTemplate": "Routed_Network_Universal",
                "networkExtensionTemplate": "Routed_Network_Universal",
                "nextGenerationOAM": False,
                "tenantDhcp": False,
                "nxapiHttp": nxapi_http,
                "anycastGatewayMac": "2020.0000.00bb",
                "fabricPlatformType": "nx-os",
            },
        }
    )

    assert model.management is not None
    assert model.management.evpn is False
    assert model.management.network_template == "Routed_Network_Universal"
    assert model.management.network_extension_template == "Routed_Network_Universal"
    assert model.management.next_generation_oam is False
    assert model.management.tenant_dhcp is False
    assert model.management.nxapi_http is nxapi_http
    assert "fabricPlatformType" not in model.to_config()["management"]

    proposed = model_class.from_config(
        {
            "fabric_name": "routed_fabric",
            "management": {"type": fabric_type, "bgp_asn": "65001"},
        }
    )
    prepared = proposed.prepare_for_replacement(model)
    assert prepared.management.anycast_gateway_mac == "2020.0000.00bb"
    assert prepared.to_payload()["management"]["anycastGatewayMac"] == "2020.0000.00bb"
    assert prepared.to_payload()["management"]["fabricPlatformType"] == "nx-os"


def test_manage_fabric_routed_00080() -> None:
    """Verify NX-API HTTP drift remains visible for standard Routed fabrics."""
    existing = FabricRoutedModel.from_response(
        {
            "name": "routed_fabric",
            "category": "fabric",
            "management": {
                "type": "routed",
                "bgpAsn": "65001",
                "evpn": False,
                "nxapiHttp": True,
            },
        }
    )
    proposed = FabricRoutedModel.from_config(
        {
            "fabric_name": "routed_fabric",
            "management": {
                "type": "routed",
                "bgp_asn": "65001",
                "nxapi_http": False,
            },
        }
    )

    assert existing.get_diff(proposed, exclude_unset=True) is False


def test_manage_fabric_routed_00090() -> None:
    """Verify AI Routed keeps NX-API HTTP enabled as enforced by ND."""
    assert AimlRoutedManagementModel(bgp_asn="65001").nxapi_http is True

    with pytest.raises(ValidationError):
        FabricAiRoutedModel.from_config(
            {
                "fabric_name": "ai_routed_fabric",
                "management": {
                    "type": "aimlRouted",
                    "bgp_asn": "65001",
                    "nxapi_http": False,
                },
            }
        )
