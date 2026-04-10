# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type, ClassVar, List
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import ManageTorModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_tor import (
    EpManageTorAssociatePost,
    EpManageTorDisassociatePost,
    EpManageTorAssociationsGet,
)


class ManageTorOrchestrator(NDBaseOrchestrator[ManageTorModel]):
    """
    Orchestrator for access/ToR switch associations.

    This API uses a non-standard pattern:
    - Associate: POST array of switch pairs with resources
    - Disassociate: POST array of switch pair IDs
    - List: GET returns associations array

    There is no individual GET, PUT, or DELETE. All write operations
    accept arrays and return 207 Multi-Status.
    """

    model_class: ClassVar[Type[NDBaseModel]] = ManageTorModel

    # Associate endpoint used for both create and update
    create_endpoint: Type[NDEndpointBaseModel] = EpManageTorAssociatePost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageTorAssociatePost
    # Disassociate endpoint used for delete
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageTorDisassociatePost
    # List endpoint used for both query_one and query_all
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageTorAssociationsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageTorAssociationsGet

    # Bulk operation support
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    create_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageTorAssociatePost
    delete_bulk_endpoint: Type[NDEndpointBaseModel] = EpManageTorDisassociatePost

    def _get_fabric_name(self) -> str:
        """Extract fabric_name from module parameters."""
        return self.sender.params.get("fabric_name", "")

    def create_bulk(self, model_instances: List[ManageTorModel], **kwargs) -> ResponseType:
        """Associate multiple access/ToR switch pairs in a single API call."""
        try:
            api_endpoint = self.create_bulk_endpoint()
            api_endpoint.fabric_name = model_instances[0].fabric_name
            data = [instance.to_payload() for instance in model_instances]
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=data)
        except Exception as e:
            raise Exception(f"Bulk associate failed: {e}") from e

    def update(self, model_instance: ManageTorModel, **kwargs) -> ResponseType:
        """Re-associate an access/ToR switch pair (same as create for this API)."""
        try:
            api_endpoint = self.update_endpoint()
            api_endpoint.fabric_name = model_instance.fabric_name
            data = [model_instance.to_payload()]
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=data)
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete_bulk(self, model_instances: List[ManageTorModel], **kwargs) -> ResponseType:
        """Disassociate multiple access/ToR switch pairs in a single API call."""
        try:
            api_endpoint = self.delete_bulk_endpoint()
            api_endpoint.fabric_name = model_instances[0].fabric_name
            data = []
            for instance in model_instances:
                disassociate_payload = {
                    "accessOrTorSwitchId": instance.access_or_tor_switch_id,
                    "aggregationOrLeafSwitchId": instance.aggregation_or_leaf_switch_id,
                }
                if instance.access_or_tor_peer_switch_id is not None:
                    disassociate_payload["accessOrTorPeerSwitchId"] = instance.access_or_tor_peer_switch_id
                if instance.aggregation_or_leaf_peer_switch_id is not None:
                    disassociate_payload["aggregationOrLeafPeerSwitchId"] = instance.aggregation_or_leaf_peer_switch_id
                data.append(disassociate_payload)
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb, data=data)
        except Exception as e:
            raise Exception(f"Bulk disassociate failed: {e}") from e

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """
        List all access/ToR associations for the fabric.

        Extracts fabric_name from module parameters and injects it into
        each returned association so the model can be constructed properly.
        """
        try:
            fabric_name = self._get_fabric_name()
            api_endpoint = self.query_all_endpoint()
            api_endpoint.fabric_name = fabric_name
            result = self.sender.query_obj(api_endpoint.path)
            associations = result.get("associations", []) or []
            # Inject fabric_name into each association for model construction
            for assoc in associations:
                assoc["fabricName"] = fabric_name
            return associations
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
