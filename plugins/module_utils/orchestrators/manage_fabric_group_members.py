# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type, ClassVar, List, Optional
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsMembersGet,
    EpManageFabricsMembersAddPost,
    EpManageFabricsMembersRemovePost,
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
    FabricDeployQueryParams,
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

    create_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsMembersAddPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsMembersAddPost
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsMembersRemovePost
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsMembersGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsMembersGet
    create_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageFabricsMembersAddPost
    delete_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = EpManageFabricsMembersRemovePost

    # OneManage (multi-cluster fabric group) endpoint variants, selected at runtime when the parent
    # fabric_name is detected to be a multi-cluster fabric group.
    onemanage_fabric_get_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsFabricNameGet
    onemanage_query_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsMembersGet
    onemanage_add_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsMembersAddPost
    onemanage_remove_endpoint: ClassVar[Type[NDEndpointBaseModel]] = EpOneManageFabricsMembersRemovePost

    # Probe replies that mean "this fabric is not a multi-cluster fabric group" rather than an error.
    # 404 is retained defensively; ND 4.2.1 and 4.3.1 both answer 400 (see _detect_multicluster).
    NOT_MULTICLUSTER_RETURN_CODES: ClassVar[frozenset] = frozenset({400, 404})

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

        A multi-cluster fabric group is reported by OneManage with category
        'multiClusterFabricGroup'. Probed once and cached for the orchestrator's lifetime.
        """
        if self._multicluster is None:
            self._multicluster = self._detect_multicluster()
        return self._multicluster

    def _detect_multicluster(self) -> bool:
        """Probe the OneManage fabric GET endpoint; a 'multiClusterFabricGroup' category means MCFG.

        Manage cannot answer this: it reports 404 for a multi-cluster fabric group, so the
        OneManage surface is the only one that can identify one.

        ND signals "not a multi-cluster fabric group" with 400 rather than 404, in two forms
        observed on 4.2.1 and 4.3.1: "Multi-cluster environment must be configured before using
        this feature" from a single-cluster controller, which rejects the whole OneManage surface
        before resolving the name, and "fabric not found" from a multi-cluster controller for a
        fabric that is not an MCFG. Any other failure propagates rather than being reclassified,
        which would silently redirect the run's writes to the wrong API surface.

        The probe deliberately bypasses ``_request`` so that its expected 400 is not recorded with
        ``Results``: an internal capability check is not an operation the user asked for, and
        registering the failure makes ``format_with_verbosity`` report a successful run as failed
        at ``-vv`` and above.
        """
        api_endpoint = self.onemanage_fabric_get_endpoint(fabric_name=self.fabric_name)
        self.rest_send.path = api_endpoint.path
        self.rest_send.verb = api_endpoint.verb
        self.rest_send.commit()
        if self.rest_send.return_code in self.NOT_MULTICLUSTER_RETURN_CODES:
            return False
        if not self.rest_send.success:
            raise Exception(f"Multi-cluster detection failed {self.rest_send.error_summary}")
        result = self.rest_send.response_current.get("DATA", {})
        return isinstance(result, dict) and result.get("category") == "multiClusterFabricGroup"

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
    def config_save_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        endpoint_cls = EpOneManageFabricsConfigSavePost if self.is_multicluster else EpFabricConfigSavePost
        return endpoint_cls(fabric_name=fabric_name)

    def deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        """Deploy the whole group, including member-fabric switches.

        The Manage deploy API defaults ``inclAllFabricGroupsSwitches`` to ``false``, which leaves a
        fabric group's member fabrics undeployed, so a ``global`` deploy must set it explicitly.
        """
        if self.is_multicluster:
            return EpOneManageFabricsDeployPost(fabric_name=fabric_name)
        return EpFabricDeployPost(fabric_name=fabric_name, endpoint_params=FabricDeployQueryParams(incl_all_fabric_groups_switches=True))

    def switches_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        endpoint_cls = EpOneManageFabricsSwitchesGet if self.is_multicluster else EpManageFabricsSwitchesGet
        return endpoint_cls(fabric_name=fabric_name)

    def switch_deploy_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
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

    def _send_members(
        self,
        api_endpoint: NDEndpointBaseModel,
        model_instances: List[FabricGroupMemberModel],
        operation_type: OperationType,
    ) -> ResponseType:
        """Send a membership change as one request per member, in the shape the surface accepts.

        Both surfaces reject multi-member bodies -- ND 4.2.1 answers a two-member Manage request
        with "Only one member fabric can be added at a time" -- so membership always fans out even
        though the Manage schema types ``members`` as an array. Only the envelope differs: Manage
        wants a one-element ``fabricGroupMemberUpdateRequest`` (``{"members": [{...}]}``) and
        OneManage wants a flat ``multiClusterFabricGroupMemberUpdate``
        (``{"clusterName": ..., "name": ...}``).

        The fan-out is not atomic: a failure on the Nth member leaves the preceding members
        applied and raises, matching the rest of the collection's fail-fast behaviour. The
        accepted work stays visible because each request is registered with Results as it runs.
        """
        responses: List[ResponseType] = []
        for instance in model_instances:
            payload = instance.to_payload() if self.is_multicluster else {"members": [instance.to_payload()]}
            responses.append(self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload, operation_type=operation_type))
        return responses

    def create_bulk(self, model_instances: List[FabricGroupMemberModel], **kwargs) -> ResponseType:
        """Add members to the fabric group using the resolved surface's request shape."""
        try:
            return self._send_members(self._add_endpoint(), model_instances, OperationType.UPDATE)
        except Exception as e:
            names = [instance.member_name for instance in model_instances]
            raise Exception(f"Add members failed for {names}: {e}") from e

    def delete_bulk(self, model_instances: List[FabricGroupMemberModel], **kwargs) -> ResponseType:
        """Remove members from the fabric group using the resolved surface's request shape."""
        try:
            return self._send_members(self._remove_endpoint(), model_instances, OperationType.DELETE)
        except Exception as e:
            names = [instance.member_name for instance in model_instances]
            raise Exception(f"Remove members failed for {names}: {e}") from e
