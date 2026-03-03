# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Dict, List, Any, Union, Type
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.local_user import LocalUserModel
from ansible_collections.cisco.nd.plugins.module_utils.api_endpoints.base import NDBaseSmartEndpoint
from ansible_collections.cisco.nd.plugins.module_utils.api_endpoints.local_user import (
    EpApiV1InfraAaaLocalUsersPost,
    EpApiV1InfraAaaLocalUsersPut,
    EpApiV1InfraAaaLocalUsersDelete,
    EpApiV1InfraAaaLocalUsersGet,
)


ResponseType = Union[List[Dict[str, Any]], Dict[str, Any], None]


class LocalUserOrchestrator(NDBaseOrchestrator):
    model_class: Type[NDBaseModel] = LocalUserModel

    create_endpoint: Type[NDBaseSmartEndpoint] = EpApiV1InfraAaaLocalUsersPost
    update_endpoint: Type[NDBaseSmartEndpoint] = EpApiV1InfraAaaLocalUsersPut
    delete_endpoint: Type[NDBaseSmartEndpoint] = EpApiV1InfraAaaLocalUsersDelete
    query_one_endpoint: Type[NDBaseSmartEndpoint] = EpApiV1InfraAaaLocalUsersGet
    query_all_endpoint: Type[NDBaseSmartEndpoint] = EpApiV1InfraAaaLocalUsersGet

    def query_all(self):
        """
        Custom query_all action to extract 'localusers' from response.
        """
        try:
            result = self.sender.query_obj(self.query_all_endpoint.base_path)
            return result.get("localusers", []) or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
