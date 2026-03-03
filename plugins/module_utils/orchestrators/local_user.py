# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Type
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.local_user import LocalUserModel
<<<<<<< HEAD
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.aaa_local_users import (
    EpInfraAaaLocalUsersPost,
    EpInfraAaaLocalUsersPut,
    EpInfraAaaLocalUsersDelete,
    EpInfraAaaLocalUsersGet,
=======
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDBaseSmartEndpoint
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra_aaa_local_users import (
    V1InfraAaaLocalUsersPost,
    V1InfraAaaLocalUsersPut,
    V1InfraAaaLocalUsersDelete,
    V1InfraAaaLocalUsersGet,
>>>>>>> 8d72e06 ([ignore] Restructure api_endpoints folder into endpoints -> v1. Fix some sanity issues.)
)


class LocalUserOrchestrator(NDBaseOrchestrator):
    model_class: Type[NDBaseModel] = LocalUserModel

<<<<<<< HEAD
    create_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersPost
    update_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersGet
=======
    create_endpoint: Type[NDBaseSmartEndpoint] = V1InfraAaaLocalUsersPost
    update_endpoint: Type[NDBaseSmartEndpoint] = V1InfraAaaLocalUsersPut
    delete_endpoint: Type[NDBaseSmartEndpoint] = V1InfraAaaLocalUsersDelete
    query_one_endpoint: Type[NDBaseSmartEndpoint] = V1InfraAaaLocalUsersGet
    query_all_endpoint: Type[NDBaseSmartEndpoint] = V1InfraAaaLocalUsersGet
>>>>>>> 8d72e06 ([ignore] Restructure api_endpoints folder into endpoints -> v1. Fix some sanity issues.)

    def query_all(self) -> ResponseType:
        """
        Custom query_all action to extract 'localusers' from response.
        """
        try:
            api_endpoint = self.query_all_endpoint()
            result = self.sender.query_obj(api_endpoint.path)
            return result.get("localusers", []) or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
