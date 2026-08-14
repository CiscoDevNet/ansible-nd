# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type, ClassVar, List, Optional
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions_mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_group_members import (
    EpManageFabricGroupMembersGet,
    EpManageFabricGroupMembersAddPost,
    EpManageFabricGroupMembersRemovePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics import (
    EpOneManageFabricsFabricNameGet,
    EpOneManageFabricsMembersGet,
    EpOneManageFabricsMembersAddPost,
    EpOneManageFabricsMembersRemovePost,
    EpOneManageFabricsConfigSavePost,
    EpOneManageFabricsDeployPost,
    EpOneManageFabricsSwitchesGet,
    EpOneManageFabricsSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switchactions import (
    EpManageFabricsSwitchActionsDeployPost,
)


class ManageFabricGroupMembersOrchestrator(ConfigActionsMixin, NDBaseOrchestrator[FabricGroupMemberModel]):
    model_class: ClassVar[Type[NDBaseModel]] = FabricGroupMemberModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True

    create_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersAddPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersAddPost
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersRemovePost
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersGet
    create_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageFabricGroupMembersAddPost
    delete_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageFabricGroupMembersRemovePost

    # OneManage (multi-cluster fabric group) endpoint variants, selected at runtime when the parent
    # fabric_name is detected to be a multi-cluster fabric group.
    onemanage_fabric_get_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsFabricNameGet
    onemanage_query_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsMembersGet
    onemanage_add_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsMembersAddPost
    onemanage_remove_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsMembersRemovePost

    # Cached result of the multi-cluster probe (None until first resolved).
    _multicluster: Optional[bool] = None

    @property
    def fabric_name(self) -> str:
        """Return the parent fabric group name from module params (populated by NDStateMachine)."""
        return self.rest_send.params.get("fabric_name")

    @property
    def is_multicluster(self) -> bool:
        """
        Return True when the parent fabric_name is a OneManage multi-cluster fabric group.

        Detection mirrors the VRF/Network resolver: a plain fabric group is unknown to OneManage
        (the probe GET 404s), whereas a multi-cluster fabric group is reported by OneManage with
        category 'multiClusterFabricGroup'. Probed once and cached for the orchestrator's lifetime.
        """
        if self._multicluster is None:
            self._multicluster = self._detect_multicluster()
        return self._multicluster

    def _detect_multicluster(self) -> bool:
        """Probe the OneManage fabric GET endpoint; a 'multiClusterFabricGroup' category means MCFG."""
        try:
            api_endpoint = self.onemanage_fabric_get_endpoint(fabric_name=self.fabric_name)
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            return isinstance(result, dict) and result.get("category") == "multiClusterFabricGroup"
        except Exception:
            # A probe failure must not mask the Manage path; default to the fabric-group surface.
            return False

    def _query_endpoint(self) -> NDEndpointBaseModel:
        """Return the members GET endpoint for the resolved surface, with fabric_name set."""
        endpoint_cls = self.onemanage_query_endpoint if self.is_multicluster else self.query_all_endpoint
        api_endpoint = endpoint_cls()
        api_endpoint.fabric_name = self.fabric_name
        return api_endpoint

    def _add_endpoint(self) -> NDEndpointBaseModel:
        """Return the addMembers POST endpoint for the resolved surface, with fabric_name set."""
        endpoint_cls = self.onemanage_add_endpoint if self.is_multicluster else self.create_bulk_endpoint
        api_endpoint = endpoint_cls()
        api_endpoint.fabric_name = self.fabric_name
        return api_endpoint

    def _remove_endpoint(self) -> NDEndpointBaseModel:
        """Return the removeMembers POST endpoint for the resolved surface, with fabric_name set."""
        endpoint_cls = self.onemanage_remove_endpoint if self.is_multicluster else self.delete_bulk_endpoint
        api_endpoint = endpoint_cls()
        api_endpoint.fabric_name = self.fabric_name
        return api_endpoint

    # --- ConfigActionsMixin hook overrides ---
    # Route save/deploy to the OneManage surface for a multi-cluster fabric group; otherwise the
    # mixin's Manage defaults apply. The OneManage endpoints mirror Manage 1:1 (same bodies), so
    # the mixin's save/switch-filter/deploy logic is reused unchanged.
    def _config_save_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        endpoint_cls = EpOneManageFabricsConfigSavePost if self.is_multicluster else EpFabricConfigSavePost
        return endpoint_cls(fabric_name=fabric_name)

    def _deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        endpoint_cls = EpOneManageFabricsDeployPost if self.is_multicluster else EpFabricDeployPost
        return endpoint_cls(fabric_name=fabric_name)

    def _switches_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        endpoint_cls = EpOneManageFabricsSwitchesGet if self.is_multicluster else EpManageFabricsSwitchesGet
        return endpoint_cls(fabric_name=fabric_name)

    def _switch_deploy_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        endpoint_cls = EpOneManageFabricsSwitchActionsDeployPost if self.is_multicluster else EpManageFabricsSwitchActionsDeployPost
        return endpoint_cls(fabric_name=fabric_name)

    def create(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """Add a single member via the bulk add endpoint."""
        try:
            return self.create_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Add member failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """Membership has no in-place update; re-adding a member is idempotent."""
        try:
            return self.create_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Update member failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """Remove a single member via the bulk remove endpoint."""
        try:
            return self.delete_bulk([model_instance])
        except Exception as e:
            raise Exception(f"Remove member failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """
        Query a specific member of the fabric group by scanning the full members list.
        """
        try:
            for member in self.query_all():
                if member.get("name") == model_instance.member_name:
                    return member
            return None
        except Exception as e:
            raise Exception(f"Query member failed for {model_instance.member_name}: {e}") from e

    def query_all(self, model_instance: Optional[FabricGroupMemberModel] = None, **kwargs) -> ResponseType:
        """
        Query all members of the fabric group.

        The GET .../members response wraps the members in a 'fabrics' array on both the Manage
        (fabric group) and OneManage (multi-cluster fabric group) surfaces.
        """
        try:
            api_endpoint = self._query_endpoint()
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            if isinstance(result, dict):
                return result.get("fabrics", []) or []
            return result or []
        except Exception as e:
            raise Exception(f"Query all members failed: {e}") from e

    def create_bulk(self, model_instances: List[FabricGroupMemberModel], **kwargs) -> ResponseType:
        """
        Add members to the fabric group in a single API call.

        Builds the payload from each model. For a multi-cluster fabric group the per-member
        clusterName is included when supplied; for a plain fabric group only name is sent.
        """
        try:
            api_endpoint = self._add_endpoint()
            payload = {"members": [instance.to_payload() for instance in model_instances]}
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        except Exception as e:
            names = [instance.member_name for instance in model_instances]
            raise Exception(f"Add members failed for {names}: {e}") from e

    def delete_bulk(self, model_instances: List[FabricGroupMemberModel], **kwargs) -> ResponseType:
        """
        Remove members from the fabric group in a single API call.

        Builds the payload from each model. For a multi-cluster fabric group the per-member
        clusterName is included when supplied; for a plain fabric group only name is sent.
        """
        try:
            api_endpoint = self._remove_endpoint()
            payload = {"members": [instance.to_payload() for instance in model_instances]}
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        except Exception as e:
            names = [instance.member_name for instance in model_instances]
            raise Exception(f"Remove members failed for {names}: {e}") from e
