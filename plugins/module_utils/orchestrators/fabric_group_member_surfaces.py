# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Surface definitions for fabric group membership.

Nexus Dashboard exposes fabric group membership through two APIs that are not
interchangeable:

- **Manage** (``/api/v1/manage``) owns single-cluster fabric groups.
- **OneManage** (``/api/v1/oneManage/manage``) owns multi-cluster fabric groups, and is
  reachable only from a session authenticated through the multi-cluster login domain.

They differ in more than the URL prefix: the request body shape, whether ``clusterName``
is part of a member's identity, and which endpoints back config save/deploy. Each surface
collects those differences in one place so the orchestrator holds a single resolved
surface instead of branching on a flag at every call site.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsGet,
    EpManageFabricsMembersAddPost,
    EpManageFabricsMembersGet,
    EpManageFabricsMembersRemovePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import EpFabricConfigSavePost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
    FabricDeployQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switchactions import EpManageFabricsSwitchActionsDeployPost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import EpManageFabricsSwitchesGet
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics import (
    EpOneManageFabricsConfigSavePost,
    EpOneManageFabricsDeployPost,
    EpOneManageFabricsFabricNameGet,
    EpOneManageFabricsMembersAddPost,
    EpOneManageFabricsMembersGet,
    EpOneManageFabricsMembersRemovePost,
    EpOneManageFabricsSwitchActionsDeployPost,
    EpOneManageFabricsSwitchesGet,
)


class FabricGroupMemberSurface:
    """One ND API surface's endpoints and member request shape."""

    name: ClassVar[str]

    # Whether a member's identity includes the cluster that hosts it. This drives both the
    # request body and the validation of user config, because the two surfaces disagree:
    # OneManage rejects a member without ``clusterName``, while Manage accepts one and
    # silently drops it -- which would leave the module unable to match its own members.
    identifies_members_by_cluster: ClassVar[bool]

    fabric_get_endpoint: ClassVar[type[NDEndpointBaseModel]]
    members_get_endpoint: ClassVar[type[NDEndpointBaseModel]]
    members_add_endpoint: ClassVar[type[NDEndpointBaseModel]]
    members_remove_endpoint: ClassVar[type[NDEndpointBaseModel]]
    config_save_endpoint: ClassVar[type[NDEndpointBaseModel]]
    switches_endpoint: ClassVar[type[NDEndpointBaseModel]]
    switch_deploy_endpoint: ClassVar[type[NDEndpointBaseModel]]

    @classmethod
    def member_body(cls, member_payload: dict[str, Any]) -> dict[str, Any]:
        """Wrap a single serialized member in the envelope this surface accepts."""
        raise NotImplementedError

    @classmethod
    def deploy_global_endpoint(cls, fabric_name: str) -> NDEndpointBaseModel:
        """Return the fabric-wide deploy endpoint for this surface."""
        raise NotImplementedError


class ManageSurface(FabricGroupMemberSurface):
    """Single-cluster fabric groups, served by ``/api/v1/manage``."""

    name = "Manage"
    identifies_members_by_cluster = False

    fabric_get_endpoint = EpManageFabricsGet
    members_get_endpoint = EpManageFabricsMembersGet
    members_add_endpoint = EpManageFabricsMembersAddPost
    members_remove_endpoint = EpManageFabricsMembersRemovePost
    config_save_endpoint = EpFabricConfigSavePost
    switches_endpoint = EpManageFabricsSwitchesGet
    switch_deploy_endpoint = EpManageFabricsSwitchActionsDeployPost

    @classmethod
    def member_body(cls, member_payload: dict[str, Any]) -> dict[str, Any]:
        """Return ``{"members": [<member>]}``.

        The Manage OpenAPI schema types ``members`` as an array, but the implementation
        accepts exactly one element: a two-member request is answered with
        "Only one member fabric can be added at a time".
        """
        return {"members": [member_payload]}

    @classmethod
    def deploy_global_endpoint(cls, fabric_name: str) -> NDEndpointBaseModel:
        """Deploy the whole group, including member-fabric switches.

        The Manage deploy API defaults ``inclAllFabricGroupsSwitches`` to ``false``, which
        would leave a fabric group's member fabrics undeployed, so a ``global`` deploy must
        set it explicitly.
        """
        return EpFabricDeployPost(fabric_name=fabric_name, endpoint_params=FabricDeployQueryParams(incl_all_fabric_groups_switches=True))


class OneManageSurface(FabricGroupMemberSurface):
    """Multi-cluster fabric groups, served by ``/api/v1/oneManage/manage``."""

    name = "OneManage"
    identifies_members_by_cluster = True

    fabric_get_endpoint = EpOneManageFabricsFabricNameGet
    members_get_endpoint = EpOneManageFabricsMembersGet
    members_add_endpoint = EpOneManageFabricsMembersAddPost
    members_remove_endpoint = EpOneManageFabricsMembersRemovePost
    config_save_endpoint = EpOneManageFabricsConfigSavePost
    switches_endpoint = EpOneManageFabricsSwitchesGet
    switch_deploy_endpoint = EpOneManageFabricsSwitchActionsDeployPost

    @classmethod
    def member_body(cls, member_payload: dict[str, Any]) -> dict[str, Any]:
        """Return the member object unwrapped.

        OneManage expects a flat ``{"clusterName": ..., "name": ...}``; the Manage
        ``{"members": [...]}`` envelope is rejected with HTTP 500.
        """
        return member_payload

    @classmethod
    def deploy_global_endpoint(cls, fabric_name: str) -> NDEndpointBaseModel:
        return EpOneManageFabricsDeployPost(fabric_name=fabric_name)
