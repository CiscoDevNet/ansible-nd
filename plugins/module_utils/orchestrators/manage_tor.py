# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type, ClassVar, List
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions_mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import ManageTorModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_tor import (
    EpManageTorAssociatePost,
    EpManageTorDisassociatePost,
    EpManageTorAssociationsGet,
)

# ND returns HTTP 207 with a ``DATA.associations[]`` array whose items carry a
# per-item ``status`` (``success``/``failed``). These literals mark a failed item.
_ASSOCIATE_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})

# A failed item whose message reports a port-channel id defaulted to 0 (the user
# omitted the PO id, so ND fell back to 0) is benign -- the association intent is
# still recorded. The switch UUID and the bracketed id vary between messages, so
# match only these stable fragments (lowercased). A genuinely bad id -- e.g.
# ``Id [5000] is not within the range of 1 and 4096`` -- will not match and still
# raises.
_BENIGN_ASSOCIATE_MESSAGE_FRAGMENTS = ("id [0]", "is not within the range of 1 and 4096")


class ManageTorOrchestrator(ConfigActionsMixin, NDBaseOrchestrator[ManageTorModel]):
    """
    Orchestrator for access/ToR switch associations.

    This API uses a non-standard pattern:
    - Associate: POST array of switch pairs with resources
    - Disassociate: POST array of switch pair IDs
    - List: GET returns associations array

    There is no individual GET, PUT, or DELETE. All write operations
    accept arrays and return 207 Multi-Status.

    ``ConfigActionsMixin`` adds fabric config save/deploy so that
    associate/disassociate changes can be pushed to the switches after the
    intent is written.
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

    @staticmethod
    def _raise_on_associate_failures(response: ResponseType, prefix: str) -> None:
        """
        Surface a genuine per-item 207 failure from an associate/disassociate body.

        ND wraps per-item outcomes in ``DATA.associations[]`` with a per-item
        ``status``. The response arrives as a 2xx (207) success from the shared
        REST layer, so the per-item outcomes must be inspected here. A ``failed``
        item whose ``message`` reports a port-channel id defaulted to 0 (the id
        was omitted) is treated as success -- ND still records the association
        intent. Any other failed item is raised so the module reports it.
        """
        if not isinstance(response, dict):
            return
        associations = response.get("associations")
        if not isinstance(associations, list):
            return
        real_failures = []
        for item in associations:
            if not isinstance(item, dict):
                continue
            if str(item.get("status") or "").strip().lower() not in _ASSOCIATE_FAILURE_STATUSES:
                continue
            message = str(item.get("message") or "").lower()
            if all(fragment in message for fragment in _BENIGN_ASSOCIATE_MESSAGE_FRAGMENTS):
                continue
            real_failures.append(item)
        if real_failures:
            raise Exception(f"{prefix}: {real_failures}")

    def create_bulk(self, model_instances: List[ManageTorModel], **kwargs) -> ResponseType:
        """Associate multiple access/ToR switch pairs in a single API call."""
        try:
            api_endpoint = self.create_bulk_endpoint()
            api_endpoint.fabric_name = model_instances[0].fabric_name
            data = [instance.to_payload() for instance in model_instances]
            response = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=data, operation_type=OperationType.CREATE)
        except Exception as e:
            raise Exception(f"Bulk associate failed: {e}") from e
        self._raise_on_associate_failures(response, "Bulk associate failed")
        return response

    def update(self, model_instance: ManageTorModel, **kwargs) -> ResponseType:
        """Re-associate an access/ToR switch pair (same as create for this API)."""
        try:
            api_endpoint = self.update_endpoint()
            api_endpoint.fabric_name = model_instance.fabric_name
            data = [model_instance.to_payload()]
            response = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=data, operation_type=OperationType.UPDATE)
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e
        self._raise_on_associate_failures(response, f"Update failed for {model_instance.get_identifier_value()}")
        return response

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
            response = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=data, operation_type=OperationType.DELETE)
        except Exception as e:
            raise Exception(f"Bulk disassociate failed: {e}") from e
        self._raise_on_associate_failures(response, "Bulk disassociate failed")
        return response

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """
        List every configured access/ToR association in the fabric in one call.

        A single fabric-wide GET with ``includeCandidates=false`` and no
        ``aggregationOrLeafSwitchId`` returns all existing associations across
        every leaf. ``includeCandidates`` must be sent explicitly -- the ND API
        returns HTTP 400 when the query string is omitted entirely.

        Each vPC pairing is returned once as a self-contained entry carrying
        both member switch IDs inline (``accessOrTorPeerSwitchId`` /
        ``aggregationOrLeafPeerSwitchId``), so no per-leaf sweep or client-side
        de-duplication is needed. ``fabricName`` is injected into each
        association so the model can be constructed from the response.
        """
        try:
            fabric_name = self.rest_send.params.get("fabric_name", "")

            api_endpoint = self.query_all_endpoint()
            api_endpoint.fabric_name = fabric_name
            api_endpoint.endpoint_params.aggregation_or_leaf_switch_id = None
            api_endpoint.endpoint_params.include_candidates = False

            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            associations: List[dict] = (result or {}).get("associations", []) or []
            for assoc in associations:
                assoc["fabricName"] = fabric_name
            return associations
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
