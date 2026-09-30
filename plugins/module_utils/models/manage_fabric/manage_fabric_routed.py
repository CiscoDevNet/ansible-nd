# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for Routed fabric management through Nexus Dashboard."""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import FabricTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
    VxlanEbgpManagementModel,
)


class RoutedManagementModel(VxlanEbgpManagementModel):
    """Routed fabric management configuration.

    Nexus Dashboard composes Routed fabrics from the eBGP management property
    set. Inheriting that contract keeps validation, secret handling,
    replacement preservation, and release-specific omission behavior aligned;
    the declarations below apply Routed-specific invariants and defaults.
    """

    # ND 4.3 adds a Routed-only platform selector. The module does not expose
    # platform conversion, so full replacement retains the controller value
    # and normalized Ansible output omits it.
    replacement_preserve_fields: ClassVar[set[str]] = VxlanEbgpManagementModel.replacement_preserve_fields | {"fabricPlatformType"}
    config_exclude_fields: ClassVar[set[str]] = VxlanEbgpManagementModel.config_exclude_fields | {"fabricPlatformType"}

    type: Literal[FabricTypeEnum.ROUTED] = Field(
        description="Type of the fabric",
        default=FabricTypeEnum.ROUTED,
    )

    # Routed fabrics use the eBGP underlay property set but do not enable the
    # EVPN/VXLAN overlay. The shared OpenAPI component's eBGP default is not
    # fabric-specific; live Routed behavior reports this value as false.
    evpn: Literal[False] = Field(
        description="EVPN/VXLAN overlay is disabled for Routed fabrics",
        default=False,
        frozen=True,
    )

    auto_configure_ebgp_evpn_peering: Literal[False] = Field(
        alias="autoConfigureEbgpEvpnPeering",
        description="eBGP EVPN overlay peering is disabled for Routed fabrics",
        default=False,
        frozen=True,
    )
    assign_ipv4_to_loopback0: bool = Field(
        alias="assignIpv4ToLoopback0",
        description=(
            "In an IPv6 routed fabric, assign an IPv4 address used for the BGP Router ID "
            "to the routing loopback interface"
        ),
        default=False,
    )
    network_template: str = Field(
        alias="networkTemplate",
        description="Default Routed network template for leaf switches",
        default="Routed_Network_Universal",
    )
    network_extension_template: str = Field(
        alias="networkExtensionTemplate",
        description="Default Routed network template for border switches",
        default="Routed_Network_Universal",
    )
    tenant_dhcp: Literal[False] = Field(
        alias="tenantDhcp",
        description="Tenant DHCP is disabled for Routed fabrics",
        default=False,
        frozen=True,
    )
    next_generation_oam: Literal[False] = Field(
        alias="nextGenerationOAM",
        description="Next Generation OAM is disabled for Routed fabrics",
        default=False,
        frozen=True,
    )


class FabricRoutedModel(FabricEbgpModel):
    """Complete model for Routed fabric lifecycle management."""

    _fabric_type: ClassVar[FabricTypeEnum] = FabricTypeEnum.ROUTED

    management: RoutedManagementModel | None = Field(
        description="Routed management configuration",
        default=None,
    )
