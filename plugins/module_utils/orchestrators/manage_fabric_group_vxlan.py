# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsDelete,
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
    FabricDeployQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.enums import (
    FabricGroupTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    FabricGroupVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import (
    ConfigActionsMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric.collection_query import (
    ManageFabricCollectionQueryMixin,
)


class ManageFabricGroupVxlanOrchestrator(ManageFabricCollectionQueryMixin, ConfigActionsMixin, NDBaseOrchestrator):
    model_class: ClassVar[type[NDBaseModel]] = FabricGroupVxlanModel
    fabric_inventory_category: ClassVar[str] = "fabricGroup"
    fabric_inventory_management_type: ClassVar[str] = FabricGroupTypeEnum.VXLAN.value

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageFabricsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageFabricsListGet

    def deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        """Deploy the entire fabric group, including member-fabric switches.

        The Manage deploy API defaults ``inclAllFabricGroupsSwitches`` to ``false``,
        which does not deploy pending changes to a fabric group's member fabrics.
        A fabric group ``global`` deploy must reach every member switch, so this
        override sets the flag to ``true``.
        """
        return EpFabricDeployPost(
            fabric_name=fabric_name,
            endpoint_params=FabricDeployQueryParams(incl_all_fabric_groups_switches=True),
        )
