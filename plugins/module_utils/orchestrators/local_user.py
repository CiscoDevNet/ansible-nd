# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Type
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.local_user import LocalUserModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDBaseEndpoint
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra_aaa_local_users import (
    V1InfraAaaLocalUsersPost,
    V1InfraAaaLocalUsersPut,
    V1InfraAaaLocalUsersDelete,
    V1InfraAaaLocalUsersGet,
)


class LocalUserOrchestrator(NDBaseOrchestrator):
    model_class: Type[NDBaseModel] = LocalUserModel

    create_endpoint: Type[NDBaseEndpoint] = V1InfraAaaLocalUsersPost
    update_endpoint: Type[NDBaseEndpoint] = V1InfraAaaLocalUsersPut
    delete_endpoint: Type[NDBaseEndpoint] = V1InfraAaaLocalUsersDelete
    query_one_endpoint: Type[NDBaseEndpoint] = V1InfraAaaLocalUsersGet
    query_all_endpoint: Type[NDBaseEndpoint] = V1InfraAaaLocalUsersGet

    def query_all(self) -> ResponseType:
        """
        Custom query_all action to extract 'localusers' from response.
        """
        try:
            result = self.sender.query_obj(self.query_all_endpoint.base_path)
            return result.get("localusers", []) or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
