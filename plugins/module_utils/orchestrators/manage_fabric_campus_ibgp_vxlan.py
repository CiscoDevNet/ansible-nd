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
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric.collection_query import (
    ManageFabricCollectionQueryMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_campus_validation import (
    ManageCampusFabricValidationMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_dhcp_validation import (
    ManageFabricDhcpValidationMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import (
    ConfigActionsMixin,
)


class ManageCampusIbgpVxlanFabricOrchestrator(
    ManageCampusFabricValidationMixin,
    ManageFabricDhcpValidationMixin,
    ManageFabricCollectionQueryMixin,
    ConfigActionsMixin,
    NDBaseOrchestrator,
):
    model_class: ClassVar[type[NDBaseModel]] = FabricCampusIbgpVxlanModel
    fabric_inventory_category: ClassVar[str] = "fabric"
    fabric_inventory_management_type: ClassVar[str] = "vxlanCampus"

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageFabricsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageFabricsListGet
