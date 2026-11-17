# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

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
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import GatheredLuceneSpec
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric.collection_query import (
    ManageFabricCollectionQueryMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    ManageFabricBgpValidationMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_dhcp_validation import (
    ManageFabricDhcpValidationMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import (
    ConfigActionsMixin,
)


class ManageEbgpFabricOrchestrator(
    ManageFabricBgpValidationMixin,
    ManageFabricDhcpValidationMixin,
    ManageFabricCollectionQueryMixin,
    ConfigActionsMixin,
    NDBaseOrchestrator,
):
    model_class: ClassVar[type[NDBaseModel]] = FabricEbgpModel
    fabric_inventory_category: ClassVar[str] = "fabric"
    fabric_inventory_management_type: ClassVar[str] = "vxlanEbgp"
    supports_gathered_server_filtering: ClassVar[bool] = True
    gathered_lucene_spec: ClassVar[GatheredLuceneSpec] = GatheredLuceneSpec(
        base_terms=(("type", "vxlanEbgp"),),
        field_map={
            ("fabric_name",): "name",
            ("license_tier",): "licenseTier",
            ("security_domain",): "securityDomain",
            ("alert_suspend",): "alertSuspend",
            ("telemetry_collection",): "telemetryCollection",
        },
    )

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageFabricsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageFabricsListGet
