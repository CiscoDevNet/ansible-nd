# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type, ClassVar
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_group_members import (
    EpManageFabricGroupMembersGet,
    EpManageFabricGroupMembersAddPost,
    EpManageFabricGroupMembersRemovePost,
)


class ManageFabricGroupMembersOrchestrator(NDBaseOrchestrator[FabricGroupMemberModel]):
    model_class: ClassVar[Type[NDBaseModel]] = FabricGroupMemberModel

    create_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersAddPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersAddPost
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersRemovePost
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageFabricGroupMembersGet

    def _get_fabric_group_name(self) -> str:
        """Extract fabric_name from module params."""
        return self.sender.params.get("fabric_name")

    def create(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """
        Add a member to the fabric group.

        Wraps the member name in the required API payload format:
        {"members": [{"name": "..."}]}
        """
        try:
            api_endpoint = self.create_endpoint()
            api_endpoint.fabric_name = self._get_fabric_group_name()
            payload = {"members": [{"name": model_instance.name}]}
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)
        except Exception as e:
            raise Exception(f"Add member failed for {model_instance.name}: {e}") from e

    def update(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """
        Update is not applicable for fabric group members.
        Members are either present or absent — redirect to create (add).
        """
        return self.create(model_instance, **kwargs)

    def delete(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """
        Remove a member from the fabric group.

        Wraps the member name in the required API payload format:
        {"members": [{"name": "..."}]}
        """
        try:
            api_endpoint = self.delete_endpoint()
            api_endpoint.fabric_name = self._get_fabric_group_name()
            payload = {"members": [{"name": model_instance.name}]}
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=payload)
        except Exception as e:
            raise Exception(f"Remove member failed for {model_instance.name}: {e}") from e

    def query_one(self, model_instance: FabricGroupMemberModel, **kwargs) -> ResponseType:
        """
        Query a specific member of the fabric group by checking the full members list.
        """
        try:
            all_members = self.query_all()
            for member in all_members:
                if member.get("name") == model_instance.name:
                    return member
            return None
        except Exception as e:
            raise Exception(f"Query member failed for {model_instance.name}: {e}") from e

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """
        Query all members of the fabric group.

        Extracts 'fabrics' from the API response.
        """
        try:
            api_endpoint = self.query_all_endpoint()
            api_endpoint.fabric_name = self._get_fabric_group_name()
            result = self.sender.query_obj(api_endpoint.path)
            return result.get("fabrics", []) or []
        except Exception as e:
            raise Exception(f"Query all members failed: {e}") from e
