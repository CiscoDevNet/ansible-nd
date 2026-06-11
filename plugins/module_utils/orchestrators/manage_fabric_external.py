# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsDelete,
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class ManageExternalFabricOrchestrator(NDBaseOrchestrator):
    model_class: type[NDBaseModel] = FabricExternalConnectivityModel

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageFabricsPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageFabricsDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageFabricsListGet

    def query_all(self) -> ResponseType:
        """
        Custom query_all action to extract 'fabrics' from response,
        filtered to only externalConnectivity fabric types.
        """
        try:
            api_endpoint = self.query_all_endpoint()
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            fabrics = result.get("fabrics", []) or []
            return [f for f in fabrics if f.get("management", {}).get("type") == "externalConnectivity"]
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
