# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Dict, Optional, Tuple, Type, ClassVar, List
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import ManageTorModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_tor import (
    EpManageTorAssociatePost,
    EpManageTorDisassociatePost,
    EpManageTorReserveResourcesPost,
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

# Model fields (snake_case) carrying the port-channel / VPC resource IDs that ND
# 4.2.x requires on associate. When the user supplies none of them we ask ND to
# allocate them via reserveResources before associating.
_RESOURCE_FIELDS = (
    "access_or_tor_port_channel_id",
    "aggregation_or_leaf_port_channel_id",
    "access_or_tor_peer_port_channel_id",
    "aggregation_or_leaf_peer_port_channel_id",
    "access_or_tor_vpc_id",
    "aggregation_or_leaf_vpc_id",
)

# Controllers below this (major, minor) require the caller to reserve the
# port-channel / VPC IDs before associate; ND 4.3+ allocates them implicitly.
_RESOURCE_RESERVATION_MAX_VERSION = (4, 3)

# API spellings of the resource IDs, used to scope what is merged back out of an
# ``includeCandidates=true`` response.
_RESOURCE_ALIASES = frozenset(
    {
        "accessOrTorPortChannelId",
        "aggregationOrLeafPortChannelId",
        "accessOrTorPeerPortChannelId",
        "aggregationOrLeafPeerPortChannelId",
        "accessOrTorVpcId",
        "aggregationOrLeafVpcId",
    }
)


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

    @staticmethod
    def _parse_major_minor(version: Optional[str]) -> Optional[Tuple[int, int]]:
        """Return ``(major, minor)`` from a build version like ``"4.2.1.10"``, or ``None``."""
        if not version:
            return None
        parts = str(version).split(".")
        try:
            return (int(parts[0]), int(parts[1]))
        except (IndexError, ValueError):
            return None

    def _requires_manual_resource_reservation(self) -> bool:
        """
        True when the controller needs the caller to reserve resource IDs.

        ND 4.2.x rejects an associate that omits the port-channel / VPC IDs, so
        we pre-allocate them via reserveResources. ND 4.3+ allocates implicitly.
        When the version cannot be determined, default to reserving (the current
        GA is 4.2.x and the extra call is harmless on 4.3).
        """
        parsed = self._parse_major_minor(self.rest_send.controller_version)
        if parsed is None:
            return True
        return parsed < _RESOURCE_RESERVATION_MAX_VERSION

    def _reserve_resources(self, model_instance: ManageTorModel) -> Dict[str, int]:
        """Ask ND to allocate the port-channel / VPC IDs for a prospective association."""
        api_endpoint = EpManageTorReserveResourcesPost()
        api_endpoint.fabric_name = model_instance.fabric_name
        body: Dict[str, str] = {
            "accessOrTorSwitchId": model_instance.access_or_tor_switch_id,
            "aggregationOrLeafSwitchId": model_instance.aggregation_or_leaf_switch_id,
        }
        if model_instance.access_or_tor_peer_switch_id is not None:
            body["accessOrTorPeerSwitchId"] = model_instance.access_or_tor_peer_switch_id
        if model_instance.aggregation_or_leaf_peer_switch_id is not None:
            body["aggregationOrLeafPeerSwitchId"] = model_instance.aggregation_or_leaf_peer_switch_id
        response = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=body, operation_type=OperationType.CREATE)
        resources = response.get("resources") if isinstance(response, dict) else None
        return resources if isinstance(resources, dict) else {}

    def _build_associate_payload(self, model_instance: ManageTorModel, reserve: bool) -> Dict:
        """
        Build one associate payload, reserving resource IDs first when required.

        Reservation runs only when ``reserve`` is set (controller needs it and
        not check mode) and the user supplied none of the resource IDs -- an
        explicit ID is always honoured as-is.
        """
        payload = model_instance.to_payload()
        user_omitted_resources = all(getattr(model_instance, name) is None for name in _RESOURCE_FIELDS)
        if reserve and user_omitted_resources:
            reserved = self._reserve_resources(model_instance)
            if reserved:
                payload["resources"] = {**payload.get("resources", {}), **reserved}
        return payload

    def create_bulk(self, model_instances: List[ManageTorModel], **kwargs) -> ResponseType:
        """Associate multiple access/ToR switch pairs in a single API call."""
        try:
            api_endpoint = self.create_bulk_endpoint()
            api_endpoint.fabric_name = model_instances[0].fabric_name
            reserve = self._requires_manual_resource_reservation() and not self.rest_send.check_mode
            data = [self._build_associate_payload(instance, reserve) for instance in model_instances]
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
            reserve = self._requires_manual_resource_reservation() and not self.rest_send.check_mode
            data = [self._build_associate_payload(model_instance, reserve)]
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
        List every configured access/ToR association in the fabric, with resources.

        Phase 1 is a single fabric-wide GET (``includeCandidates=false``, no leaf
        filter) returning every existing association across every leaf. This is the
        authoritative membership list: each vPC pairing arrives once as a
        self-contained entry carrying both member switch IDs inline, so no per-leaf
        sweep or client-side de-duplication is needed. ``includeCandidates`` must be
        sent explicitly -- the ND API returns HTTP 400 when the query string is
        omitted entirely.

        Phase 2 backfills the port-channel / VPC IDs, which phase 1 never returns.
        It is skipped for ``deleted``, which matches on identity alone.

        ``fabricName`` is injected into each association so the model can be
        constructed from the response.
        """
        try:
            fabric_name = self.rest_send.params.get("fabric_name", "")

            api_endpoint = self.query_all_endpoint()
            api_endpoint.fabric_name = fabric_name
            api_endpoint.endpoint_params.aggregation_or_leaf_switch_id = None
            api_endpoint.endpoint_params.aggregation_or_leaf_peer_switch_id = None
            api_endpoint.endpoint_params.include_candidates = False

            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            associations: List[dict] = (result or {}).get("associations", []) or []

            if self.rest_send.params.get("state") != "deleted":
                self._enrich_with_resources(fabric_name, associations)

            for assoc in associations:
                assoc["fabricName"] = fabric_name
            return associations
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    @staticmethod
    def _association_key(association: dict) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
        """
        Order-independent identity for an association, mirroring
        ``ManageTorModel.get_identifier_value()``.

        ND treats each vPC pair as unordered and may report a different
        primary/peer than was submitted, so both sides are sorted.
        """
        access = tuple(sorted(v for v in (association.get("accessOrTorSwitchId"), association.get("accessOrTorPeerSwitchId")) if v))
        aggregation = tuple(sorted(v for v in (association.get("aggregationOrLeafSwitchId"), association.get("aggregationOrLeafPeerSwitchId")) if v))
        return (access, aggregation)

    def _enrich_with_resources(self, fabric_name: str, associations: List[dict]) -> None:
        """
        Merge the port-channel / VPC IDs into each association, in place.

        ND returns ``resources`` only from an ``includeCandidates=true`` query scoped
        to the association's full aggregation side (both leaf IDs for a vPC pair), so
        associations are grouped by that scope and one call is issued per distinct
        scope rather than one per association.
        """
        by_scope: Dict[Tuple[Optional[str], Optional[str]], List[dict]] = {}
        for association in associations:
            scope = (association.get("aggregationOrLeafSwitchId"), association.get("aggregationOrLeafPeerSwitchId"))
            by_scope.setdefault(scope, []).append(association)

        for (leaf_id, peer_id), scoped in by_scope.items():
            if not leaf_id:
                continue
            targets = {self._association_key(item): item for item in scoped}
            for row in self._query_scope_resources(fabric_name, leaf_id, peer_id):
                # A scoped query also returns candidate rows for ToRs paired elsewhere,
                # carrying proposed (not configured) allocations. Matching against the
                # phase-1 membership list drops them without parsing ``remarks``.
                target = targets.get(self._association_key(row))
                if target is None:
                    continue
                resources = row.get("resources") or {}
                target["resources"] = {key: value for key, value in resources.items() if key in _RESOURCE_ALIASES}

    def _query_scope_resources(self, fabric_name: str, leaf_id: str, peer_id: Optional[str]) -> List[dict]:
        """Return the associations ND reports for one aggregation scope, with resources."""
        api_endpoint = self.query_all_endpoint()
        api_endpoint.fabric_name = fabric_name
        api_endpoint.endpoint_params.aggregation_or_leaf_switch_id = leaf_id
        api_endpoint.endpoint_params.aggregation_or_leaf_peer_switch_id = peer_id
        api_endpoint.endpoint_params.include_candidates = True

        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
        return (result or {}).get("associations", []) or []
