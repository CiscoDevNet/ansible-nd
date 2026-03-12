# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Type
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_fabric.manage_fabric_ibgp import FabricModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
    EpManageFabricsDelete,
)


class ManageFabricOrchestrator(NDBaseOrchestrator):
    model_class: Type[NDBaseModel] = FabricModel

    create_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageFabricsListGet

    def query_all(self) -> ResponseType:
        """
        Custom query_all action to extract 'fabrics' from response.
        """
        try:
            result = self.sender.query_obj(self.query_all_endpoint.base_path)
            return result.get("fabrics", []) or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
