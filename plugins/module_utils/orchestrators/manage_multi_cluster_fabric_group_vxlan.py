# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics import (
    EpOneManageFabricsConfigSavePost,
    EpOneManageFabricsDelete,
    EpOneManageFabricsDeployPost,
    EpOneManageFabricsFabricNameGet,
    EpOneManageFabricsListGet,
    EpOneManageFabricsPost,
    EpOneManageFabricsPut,
    EpOneManageFabricsSwitchActionsDeployPost,
    EpOneManageFabricsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_multi_cluster_fabric_group_vxlan import (
    MultiClusterFabricGroupVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions_mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class ManageMultiClusterFabricGroupVxlanOrchestrator(ConfigActionsMixin, NDBaseOrchestrator):
    """Orchestrator for OneManage multi-cluster VXLAN Fabric Groups (MCFG).

    Mirrors ``ManageFabricGroupVxlanOrchestrator`` but targets the OneManage
    surface: CRUD is routed to the ``EpOneManageFabrics*`` endpoints and the
    config save/deploy hooks are overridden to the OneManage action endpoints.
    """

    model_class: ClassVar[type[NDBaseModel]] = MultiClusterFabricGroupVxlanModel

    create_endpoint: type[NDEndpointBaseModel] = EpOneManageFabricsPost
    update_endpoint: type[NDEndpointBaseModel] = EpOneManageFabricsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpOneManageFabricsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpOneManageFabricsFabricNameGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpOneManageFabricsListGet

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """
        Custom query_all action to extract 'fabrics' from response, filtered to
        only multi-cluster fabric groups (category=multiClusterFabricGroup).
        """
        try:
            api_endpoint = self.query_all_endpoint()
            api_endpoint.category = "multiClusterFabricGroup"
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            fabrics = result.get("fabrics", []) or []
            return [f for f in fabrics if f.get("category") == "multiClusterFabricGroup"]
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    # --- ConfigActionsMixin hook overrides ---
    # MCFG is OneManage-only, so save/deploy always target the OneManage surface. The OneManage
    # endpoints mirror Manage 1:1 (same bodies), so the mixin's save/switch-filter/deploy logic
    # is reused unchanged.
    def _config_save_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return EpOneManageFabricsConfigSavePost(fabric_name=fabric_name)

    def _deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return EpOneManageFabricsDeployPost(fabric_name=fabric_name)

    def _switches_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return EpOneManageFabricsSwitchesGet(fabric_name=fabric_name)

    def _switch_deploy_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        return EpOneManageFabricsSwitchActionsDeployPost(fabric_name=fabric_name)
