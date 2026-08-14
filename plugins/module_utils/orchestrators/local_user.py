# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import ClassVar
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.aaa_local_users import (
    EpInfraAaaLocalUsersDelete,
    EpInfraAaaLocalUsersGet,
    EpInfraAaaLocalUsersPost,
    EpInfraAaaLocalUsersPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.local_user.local_user import LocalUserModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class LocalUserOrchestrator(NDBaseOrchestrator[LocalUserModel]):
    model_class: ClassVar[type[NDBaseModel]] = LocalUserModel

    create_endpoint: type[NDEndpointBaseModel] = EpInfraAaaLocalUsersPost
    update_endpoint: type[NDEndpointBaseModel] = EpInfraAaaLocalUsersPut
    delete_endpoint: type[NDEndpointBaseModel] = EpInfraAaaLocalUsersDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpInfraAaaLocalUsersGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpInfraAaaLocalUsersGet

    def query_all(self) -> ResponseType:
        """
        Custom query_all action to extract 'localusers' from response.
        """
        try:
            api_endpoint = self.query_all_endpoint()
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            return result.get("localusers", []) or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
