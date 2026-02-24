# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ..models.base import NDBaseModel
from ..nd import NDModule
from ..api_endpoints.base import NDBaseSmartEndpoint
from typing import Dict, List, Any, Union, ClassVar, Type
from pydantic import BaseModel


ResponseType = Union[List[Dict[str, Any]], Dict[str, Any], None]


# TODO: Revisit naming them "Orchestrator"
class NDBaseOrchestrator(BaseModel):

    model_class: ClassVar[Type[NDBaseModel]] = Type[NDBaseModel]

    # NOTE: if not defined by subclasses, return an error as they are required
    # TODO: change name from http method to crud (e.g. post -> create)
    post_endpoint: Type[NDBaseSmartEndpoint]
    put_endpoint: Type[NDBaseSmartEndpoint]
    delete_endpoint: Type[NDBaseSmartEndpoint]
    get_endpoint: Type[NDBaseSmartEndpoint]

    # NOTE: Module Field is always required
    # TODO: Replace it with future sender
    module: NDModule

    # NOTE: Generic CRUD API operations for simple endpoints with single identifier (e.g. "api/v1/infra/aaa/LocalUsers/{loginID}")
    # TODO: Explore new ways to make them even more general
    # TODO: Revisit Deserialization
    def create(self, model_instance: NDBaseModel) -> ResponseType:
        if self.module.check_mode:
            return model_instance.to_payload()
        
        try:
            api_endpoint = self.post_endpoint()
            return self.module.request(path=api_endpoint.path, method=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    # TODO: Make the same changes as create() with local api_endpoint variable
    def update(self, model_instance: NDBaseModel) -> ResponseType:
        if self.module.check_mode:
            return model_instance.to_payload()
        
        try:
            self.put_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.module.request(path=self.put_endpoint.path, method=self.put_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise Exception(f"Update failed for {self.current_identifier}: {e}") from e

    def delete(self, model_instance: NDBaseModel) -> ResponseType:
        if self.module.check_mode:
            return model_instance.to_payload()
        
        try:
            self.delete_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.module.request(path=self.delete_endpoint.path, method=self.delete_endpoint.verb)
        except Exception as e:
            raise Exception(f"Delete failed for {self.current_identifier}: {e}") from e

    def query_one(self, model_instance: NDBaseModel) -> ResponseType:
        try:
            self.get_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.module.request(path=self.get_endpoint.path, method=self.get_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {self.current_identifier}: {e}") from e

    # TODO: Revisit the straegy around the query_all (see local_user's case)
    def query_all(self, model_instance: NDBaseModel, **kwargs) -> ResponseType:
        try:
            result = self.module.query_obj(self.get_endpoint.path)
            return result or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e