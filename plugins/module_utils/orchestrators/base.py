# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ..models.base import NDBaseModel
from ..nd import NDModule
from ..api_endpoints.base import NDBaseSmartEndpoint
from typing import Dict, List, Any, Union, ClassVar, Type, Optional
from pydantic import BaseModel, ConfigDict


ResponseType = Union[List[Dict[str, Any]], Dict[str, Any], None]


# TODO: Revisit naming them "Orchestrator"
class NDBaseOrchestrator(BaseModel):

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    model_class: ClassVar[Type[NDBaseModel]] = Type[NDBaseModel]

    # NOTE: if not defined by subclasses, return an error as they are required
    create_endpoint: Type[NDBaseSmartEndpoint]
    update_endpoint: Type[NDBaseSmartEndpoint]
    delete_endpoint: Type[NDBaseSmartEndpoint]
    query_one_endpoint: Type[NDBaseSmartEndpoint]
    query_all_endpoint: Type[NDBaseSmartEndpoint]

    # NOTE: Module Field is always required
    # TODO: Replace it with future sender (low priority)
    sender: NDModule

    # NOTE: Generic CRUD API operations for simple endpoints with single identifier (e.g. "api/v1/infra/aaa/LocalUsers/{loginID}")
    # TODO: Explore new ways to make them even more general -> e.g., create a general API operation function (low priority)
    # TODO: Revisit Deserialization
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

    # TODO: Revisit the straegy around the query_all (see local_user's case)
    def query_all(self, model_instance: Optional[NDBaseModel] = None, **kwargs) -> ResponseType:
        try:
            result = self.sender.query_obj(self.query_all_endpoint.path)
            return result or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
