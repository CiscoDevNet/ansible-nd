# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from .base import NDBaseOrchestrator
from ..models.local_user import LocalUserModel
from typing import Dict, List, Any, Union, Type
from ..api_endpoints.local_user import (
    EpApiV1InfraAaaLocalUsersPost,
    EpApiV1InfraAaaLocalUsersPut,
    EpApiV1InfraAaaLocalUsersDelete,
    EpApiV1InfraAaaLocalUsersGet,
)


ResponseType = Union[List[Dict[str, Any]], Dict[str, Any], None]

class LocalUserOrchestrator(NDBaseOrchestrator):

    model_class = Type[LocalUserModel]

    post_endpoint = EpApiV1InfraAaaLocalUsersPost()
    put_endpoint = EpApiV1InfraAaaLocalUsersPut()
    delete_endpoint = EpApiV1InfraAaaLocalUsersDelete()
    get_endpoint = EpApiV1InfraAaaLocalUsersGet()

    def query_all(self):
        """
        Custom query_all action to extract 'localusers' from response.
        """
        try:
            result = self.module.query_obj(self.get_endpoint.base_path)
            return result.get("localusers", []) or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
    