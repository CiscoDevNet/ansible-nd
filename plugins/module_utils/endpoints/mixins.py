# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Reusable mixin classes for endpoint models.

This module provides mixin classes that can be composed to add common
fields to endpoint models without duplication.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import BooleanStringEnum


class ClusterNameMixin(BaseModel):
    """Mixin for endpoints that require cluster_name parameter."""

    cluster_name: str | None = Field(default=None, min_length=1, description="Cluster name")


class FabricNameMixin(BaseModel):
    """Mixin for endpoints that require fabric_name parameter."""

    fabric_name: str | None = Field(default=None, min_length=1, max_length=64, description="Fabric name")


class FilterMixin(BaseModel):
    """Mixin for endpoints that require a Lucene filter expression."""

    filter: str | None = Field(default=None, min_length=1, description="Lucene filter expression")


class ForceShowRunMixin(BaseModel):
    """Mixin for endpoints that require force_show_run parameter."""

    force_show_run: BooleanStringEnum = Field(default=BooleanStringEnum.FALSE, description="Force show running config")


class HealthCategoryMixin(BaseModel):
    """Mixin for endpoints that require health_category parameter."""

    health_category: str | None = Field(default=None, min_length=1, description="Health category")


class InclAllMsdSwitchesMixin(BaseModel):
    """Mixin for endpoints that require incl_all_msd_switches parameter."""

    incl_all_msd_switches: BooleanStringEnum = Field(default=BooleanStringEnum.FALSE, description="Include all MSD switches")


class InterfaceNameMixin(BaseModel):
    """Mixin for endpoints that require interface_name parameter."""

    interface_name: str | None = Field(default=None, min_length=1, description="Interface name")


class LinkUuidMixin(BaseModel):
    """Mixin for endpoints that require link_uuid parameter."""

    link_uuid: str | None = Field(default=None, min_length=1, description="Link UUID")


class LoginIdMixin(BaseModel):
    """Mixin for endpoints that require login_id parameter."""

    login_id: str | None = Field(default=None, min_length=1, description="Login ID")


class MaxMixin(BaseModel):
    """Mixin for endpoints that require a max results parameter."""

    max: int | None = Field(default=None, ge=1, description="Maximum number of results")


class NetworkNameMixin(BaseModel):
    """Mixin for endpoints that require network_name parameter."""

    network_name: str | None = Field(default=None, min_length=1, max_length=64, description="Network name")


class OffsetMixin(BaseModel):
    """Mixin for endpoints that require a pagination offset parameter."""

    offset: int | None = Field(default=None, ge=0, description="Pagination offset")


class NodeNameMixin(BaseModel):
    """Mixin for endpoints that require node_name parameter."""

    node_name: str | None = Field(default=None, min_length=1, description="Node name")


class SwitchSerialNumberMixin(BaseModel):
    """Mixin for endpoints that require switch_sn parameter."""

    switch_sn: str | None = Field(default=None, min_length=1, description="Switch serial number")


class TicketIdMixin(BaseModel):
    """Mixin for endpoints that require ticket_id parameter."""

    ticket_id: str | None = Field(default=None, min_length=1, description="Change control ticket ID")


class FilterMixin(BaseModel):
    """Mixin for endpoints that accept a Lucene filter expression."""

    filter: Optional[str] = Field(default=None, min_length=1, description="Lucene filter expression")


class MaxMixin(BaseModel):
    """Mixin for endpoints that accept a max results parameter."""

    max: Optional[int] = Field(default=None, ge=1, description="Maximum number of results")


class OffsetMixin(BaseModel):
    """Mixin for endpoints that accept a pagination offset parameter."""

    offset: Optional[int] = Field(default=None, ge=0, description="Pagination offset")


class TicketIdMixin(BaseModel):
    """Mixin for endpoints that accept a change-control ticket ID."""

    ticket_id: Optional[str] = Field(default=None, min_length=1, description="Change control ticket ID")


class UpdateGroupNameMixin(BaseModel):
    """Mixin for endpoints that require update_group_name parameter."""

    update_group_name: str | None = Field(default=None, min_length=1, description="Update group name")


class VrfNameMixin(BaseModel):
    """Mixin for endpoints that require vrf_name parameter."""

    vrf_name: str | None = Field(default=None, min_length=1, max_length=64, description="VRF name")


class SwitchIdMixin(BaseModel):
    """Mixin for endpoints that require switch_id parameter."""

    switch_id: str | None = Field(default=None, min_length=1, description="Switch serial number")


class PeerSwitchIdMixin(BaseModel):
    """Mixin for endpoints that require peer_switch_id parameter."""

    peer_switch_id: str | None = Field(default=None, min_length=1, description="Peer switch serial number")


class UseVirtualPeerLinkMixin(BaseModel):
    """Mixin for endpoints that require use_virtual_peer_link parameter."""

    use_virtual_peer_link: bool | None = Field(
        default=False,
        description="Indicates whether a virtual peer link is present",
    )


class FromClusterMixin(BaseModel):
    """Mixin for endpoints that support fromCluster query parameter."""

    from_cluster: str | None = Field(default=None, description="Optional cluster name")


class ComponentTypeMixin(BaseModel):
    """Mixin for endpoints that require componentType query parameter."""

    component_type: str | None = Field(default=None, description="Component type for filtering response")


class ViewMixin(BaseModel):
    """Mixin for endpoints that support view parameter."""

    view: str | None = Field(default=None, description="Optional view type for filtering results")
