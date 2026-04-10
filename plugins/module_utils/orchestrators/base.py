# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from functools import wraps
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, model_validator
from typing import ClassVar, Type, Optional, Generic, TypeVar, List
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

ModelType = TypeVar("ModelType", bound=NDBaseModel)


def requires_bulk_support(flag_name: str):
    """Decorator that restricts method access based on a ClassVar boolean flag."""

    def decorator(method):
        @wraps(method)
        def wrapper(self, *args, **kwargs):
            if not getattr(self, flag_name, False):
                raise AttributeError(f"'{method.__name__}' is not available when '{flag_name}' is disabled on '{self.__class__.__name__}'.")
            return method(self, *args, **kwargs)

        return wrapper

    return decorator


class NDBaseOrchestrator(BaseModel, Generic[ModelType]):
    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    model_class: ClassVar[Type[NDBaseModel]] = NDBaseModel
    supports_bulk_create: ClassVar[bool] = False
    supports_bulk_delete: ClassVar[bool] = False

    # NOTE: if not defined by subclasses, return an error as they are required
    create_endpoint: Type[NDEndpointBaseModel]
    update_endpoint: Type[NDEndpointBaseModel]
    delete_endpoint: Type[NDEndpointBaseModel]
    query_one_endpoint: Type[NDEndpointBaseModel]
    query_all_endpoint: Type[NDEndpointBaseModel]

    # NOTE: Conditionally required
    create_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = None
    delete_bulk_endpoint: Optional[Type[NDEndpointBaseModel]] = None

    # NOTE: Module Field is always required
    sender: NDModule

    # NOTE: Generic CRUD API operations for simple endpoints with single identifier (e.g. "api/v1/infra/aaa/LocalUsers/{loginID}")
    def create(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.create_endpoint()
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.update_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=model_instance.to_payload())
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.delete_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: ModelType, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.query_one_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: Optional[ModelType] = None, **kwargs) -> ResponseType:
        try:
            api_endpoint = self.query_all_endpoint()
            result = self.sender.query_obj(api_endpoint.path)
            return result or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    @model_validator(mode="after")
    def validate_bulk_endpoints(self):
        if self.supports_bulk_create and self.create_bulk_endpoint is None:
            raise ValueError(f"'{self.__class__.__name__}' has 'supports_bulk_create=True' but 'create_bulk_endpoint' is not defined.")
        if self.supports_bulk_delete and self.delete_bulk_endpoint is None:
            raise ValueError(f"'{self.__class__.__name__}' has 'supports_bulk_delete=True' but 'delete_bulk_endpoint' is not defined.")
        return self

    @requires_bulk_support("supports_bulk_create")
    def create_bulk(self, model_instances: List[ModelType], **kwargs) -> ResponseType:
        raise NotImplementedError

    @requires_bulk_support("supports_bulk_delete")
    def delete_bulk(self, model_instances: List[ModelType], **kwargs) -> ResponseType:
        raise NotImplementedError
