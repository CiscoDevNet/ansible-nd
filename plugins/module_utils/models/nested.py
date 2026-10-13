# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared nested (identifier-less) Pydantic fragments: the `NDNestedModel` base and nested models reused across several feature models.
"""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import CustomerVlanIdList, VlanId


class NDNestedModel(NDBaseModel):
    """
    Base for nested models without identifiers.
    """

    # NOTE: model_config, ClassVar, and Fields can be overwritten here if needed

    identifiers: ClassVar[list[str]] = []


class VlanMappingEntryModel(NDNestedModel):
    """
    # Summary

    A single VLAN mapping entry for a trunk-like interface (ethernet trunkHost, port-channel trunkPoHost, vPC trunkVpcHost). Maps to one
    element of the `configData.networkOS.policy.vlanMappingEntries` list in the ND API. Entries translate customer VLAN ids to a provider
    VLAN id, optionally using selective dot1q-tunnel mode.

    Shared by every trunk model that supports VLAN mapping (issue #347) so a field, bound, or alias edit lives in one place.

    ## Raises

    None
    """

    customer_inner_vlan_id: VlanId | None = Field(
        default=None, alias="customerInnerVlanId", description="Inner customer VLAN id (selective dot1q-tunnel only)"
    )
    customer_vlan_id: CustomerVlanIdList = Field(
        default=None,
        alias="customerVlanId",
        description="Customer VLAN id list; each entry is a VLAN id or range string in 1..4094 (e.g. ['100', '200-300'])",
    )
    dot1q_tunnel: bool | None = Field(default=None, alias="dot1qTunnel", description="Use selective dot1q-tunnel mode for this entry")
    provider_vlan_id: VlanId | None = Field(default=None, alias="providerVlanId", description="Provider VLAN id")
