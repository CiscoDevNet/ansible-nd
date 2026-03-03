# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict
from typing import ClassVar, Type, Optional
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
<<<<<<< HEAD
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
=======
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDBaseSmartEndpoint
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.types import ResponseType
>>>>>>> 8d72e06 ([ignore] Restructure api_endpoints folder into endpoints -> v1. Fix some sanity issues.)


class NDBaseOrchestrator(BaseModel):
    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    model_class: ClassVar[Type[NDBaseModel]] = Type[NDBaseModel]

    # NOTE: if not defined by subclasses, return an error as they are required
    create_endpoint: Type[NDEndpointBaseModel]
    update_endpoint: Type[NDEndpointBaseModel]
    delete_endpoint: Type[NDEndpointBaseModel]
    query_one_endpoint: Type[NDEndpointBaseModel]
    query_all_endpoint: Type[NDEndpointBaseModel]

    # NOTE: Module Field is always required
    sender: NDModule

    # NOTE: Generic CRUD API operations for simple endpoints with single identifier (e.g. "api/v1/infra/aaa/LocalUsers/{loginID}")
    def create(self, model_instance: NDBaseModel, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.create_endpoint()
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: NDBaseModel, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.update_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: NDBaseModel, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.delete_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: NDBaseModel, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.query_one_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: Optional[NDBaseModel] = None, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.query_all_endpoint()
            result = self.sender.query_obj(api_endpoint.path)
            return result or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
