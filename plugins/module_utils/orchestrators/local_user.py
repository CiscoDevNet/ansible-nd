# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.local_user.local_user import LocalUserModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.infra_aaa_local_users import (
    EpInfraAaaLocalUsersPost,
    EpInfraAaaLocalUsersPut,
    EpInfraAaaLocalUsersDelete,
    EpInfraAaaLocalUsersGet,
)


class LocalUserOrchestrator(NDBaseOrchestrator):
    model_class: Type[NDBaseModel] = LocalUserModel

    create_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersPost
    update_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpInfraAaaLocalUsersGet

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