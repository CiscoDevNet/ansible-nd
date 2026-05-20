# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Fabric update group orchestrator for Nexus Dashboard.

Implements CRUD operations for fabric update groups via the ND Manage Fabric Software Management API.
Fabric name is supplied by the module's top-level `fabric_name` option and propagated to every endpoint
instance prior to path generation; per-config identifier is `update_group_name`.

`update_group_switches` and `installation_order_devices` accept either switch IP addresses or switch
serial numbers (switchIds). IPs are resolved to switchIds via `FabricContext` before being sent on the
wire; switchIds in GET responses are converted back to IPs so playbook authors see consistent IP-based
output even though the wire stores serials.

POST is bulk-only: the wire shape is `{"updateGroups": [...]}`, returning HTTP 207 with per-item
`status` ("success" or "error"). `create()` wraps a single payload in the bulk shape and inspects
the per-item status before returning. `create_bulk()` sends N groups in a single POST.

PUT, DELETE, and per-name GET take the single update group as a flat dict / path-only.
"""

from __future__ import annotations

from typing import Any, ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.fabric_update_group import (
    EpFabricUpdateGroupDelete,
    EpFabricUpdateGroupGet,
    EpFabricUpdateGroupListGet,
    EpFabricUpdateGroupPost,
    EpFabricUpdateGroupPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_update_group.fabric_update_group import FabricUpdateGroupModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# Wire payload keys whose list-valued contents are switch identifiers (IP or switchId)
_SWITCH_LIST_PAYLOAD_KEYS = ("updateGroupSwitches", "installationOrderDevices")


class FabricUpdateGroupOrchestrator(NDBaseOrchestrator[FabricUpdateGroupModel]):
    """
    # Summary

    Orchestrator for fabric update group CRUD on Nexus Dashboard.

    Reads `fabric_name` from module params and applies it to every endpoint instance before path
    generation. Resolves switch IPs to switchIds (and back) via `FabricContext` so users can specify
    either form in `update_group_switches` / `installation_order_devices`. POST is bulk-only - single
    create calls are wrapped in `{"updateGroups": [payload]}`.

    ## Raises

    ### RuntimeError

    - Via `create` if the create API request fails or any per-item status is "error".
    - Via `update` if the update API request fails.
    - Via `delete` if the delete API request fails.
    - Via `query_one` if the query API request fails.
    - Via `query_all` if the query API request fails.
    - Via `_resolve_switch_id` if the user-provided switch IP cannot be matched in the fabric.
    """

    model_class: ClassVar[Type[NDBaseModel]] = FabricUpdateGroupModel
    supports_bulk_create: ClassVar[bool] = True

    create_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupPost
    update_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpFabricUpdateGroupPost

    _fabric_context: FabricContext | None = None

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return `fabric_name` from module params.

        ## Raises

        None
        """
        return self.rest_send.params.get("fabric_name")

    @property
    def fabric_context(self) -> FabricContext:
        """
        # Summary

        Return a lazily-initialized `FabricContext` for this orchestrator's fabric. Used to resolve
        switch IPs to switchIds (and back).

        ## Raises

        None
        """
        if self._fabric_context is None:
            self._fabric_context = FabricContext(rest_send=self.rest_send, fabric_name=self.fabric_name)
        return self._fabric_context

    def _configure_endpoint(self, api_endpoint):
        """
        # Summary

        Set `fabric_name` on an endpoint instance before path generation.

        ## Raises

        None
        """
        api_endpoint.fabric_name = self.fabric_name
        return api_endpoint

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        """
        # Summary

        Heuristic: a string with a dot is an IP address; anything else is treated as a switch serial
        number (switchIds in the field, e.g. `FDO12345ABC`, never contain dots).

        ## Raises

        None
        """
        return isinstance(value, str) and "." in value

    def _resolve_switch_id(self, value: str) -> str:
        """
        # Summary

        Resolve a user-supplied switch identifier to a switchId. IP addresses are looked up via
        `FabricContext`; switchId strings are returned unchanged.

        ## Raises

        ### RuntimeError

        - If the value looks like an IP but no switch with that `fabricManagementIp` exists in the fabric.
        """
        if self._looks_like_ip(value):
            return self.fabric_context.get_switch_id(value)
        return value

    def _resolve_switches_in_payload(self, payload: dict) -> dict:
        """
        # Summary

        Replace IP entries in `updateGroupSwitches` and `installationOrderDevices` with the matching
        switchIds before sending. Mutates the payload dict in place and returns it.

        ## Raises

        ### RuntimeError

        - If any IP in either list cannot be resolved in the fabric (propagated from `_resolve_switch_id`).
        """
        for key in _SWITCH_LIST_PAYLOAD_KEYS:
            values = payload.get(key)
            if isinstance(values, list):
                payload[key] = [self._resolve_switch_id(v) for v in values]
        return payload

    def _denormalize_switches_in_response(self, item: Any) -> Any:
        """
        # Summary

        For a single GET response dict, replace switchIds in `updateGroupSwitches` and
        `installationOrderDevices` with their matching IPs so the user sees consistent IP-based output.

        Denormalization is best-effort: if the switch map cannot be loaded (e.g. the inventory call
        fails), the response is returned unmodified rather than raising — switchIds shown to the user
        are still correct, just not user-friendlier IPs. Per-switchId lookups that miss the map (stale
        serials) are also passed through unchanged.

        ## Raises

        None
        """
        if not isinstance(item, dict):
            return item
        if not any(isinstance(item.get(key), list) for key in _SWITCH_LIST_PAYLOAD_KEYS):
            return item
        try:
            switch_map_by_id = self.fabric_context.switch_map_by_id
        except Exception:  # pylint: disable=broad-except
            return item
        for key in _SWITCH_LIST_PAYLOAD_KEYS:
            values = item.get(key)
            if isinstance(values, list):
                item[key] = [switch_map_by_id.get(v, v) for v in values]
        return item

    @staticmethod
    def _raise_on_207_item_errors(result: Any, expected_names: list[str]) -> None:
        """
        # Summary

        Inspect a POST 207 response of shape `{"updateGroups": [{"updateGroupName": "X", "status": "...", "message": "..."}]}`
        and raise `RuntimeError` if any item reports `status != "success"`.

        ## Raises

        ### RuntimeError

        - If any item in the response reports a non-success status.
        """
        if not isinstance(result, dict):
            return
        items = result.get("updateGroups")
        if not isinstance(items, list):
            return
        failures = [item for item in items if isinstance(item, dict) and item.get("status") and item.get("status") != "success"]
        if failures:
            details = ", ".join(f"{item.get('updateGroupName')}: {item.get('status')} - {item.get('message')}" for item in failures)
            raise RuntimeError(f"Per-item failures in bulk create response: {details}")

    def create(self, model_instance: FabricUpdateGroupModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a single fabric update group. Resolves any IPs in `update_group_switches` /
        `installation_order_devices` to switchIds, wraps the payload in the bulk `{"updateGroups": [...]}`
        shape required by the ND POST endpoint, and inspects per-item status in the 207 response.

        ## Raises

        ### RuntimeError

        - If a switch IP cannot be resolved, the POST request fails, or any per-item status is not "success".
        """
        try:
            api_endpoint = self._configure_endpoint(self.create_endpoint())
            payload = self._resolve_switches_in_payload(model_instance.to_payload())
            body = {"updateGroups": [payload]}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=body)
            self._raise_on_207_item_errors(result, [model_instance.update_group_name])
            return result
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def create_bulk(self, model_instances: list[FabricUpdateGroupModel], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple fabric update groups in a single POST. Resolves switch IPs to switchIds on each
        payload before sending. The wire endpoint accepts a list of groups under the `updateGroups` key
        and returns per-item status in a 207 response.

        ## Raises

        ### RuntimeError

        - If a switch IP cannot be resolved, the POST request fails, or any per-item status is not "success".
        """
        try:
            api_endpoint = self._configure_endpoint(self.create_bulk_endpoint())  # pyright: ignore[reportOptionalCall]
            payloads = [self._resolve_switches_in_payload(m.to_payload()) for m in model_instances]
            body = {"updateGroups": payloads}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=body)
            self._raise_on_207_item_errors(result, [m.update_group_name for m in model_instances])
            return result
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def update(self, model_instance: FabricUpdateGroupModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update a single fabric update group by name. Resolves any IPs in `update_group_switches` /
        `installation_order_devices` to switchIds before sending. PUT body is the flat group dict
        (no `updateGroups` wrapper).

        ## Raises

        ### RuntimeError

        - If a switch IP cannot be resolved or the PUT request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.update_endpoint())
            api_endpoint.set_identifiers(model_instance.update_group_name)
            payload = self._resolve_switches_in_payload(model_instance.to_payload())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: FabricUpdateGroupModel, **kwargs) -> ResponseType:
        """
        # Summary

        Delete a single fabric update group by name.

        ## Raises

        ### RuntimeError

        - If the DELETE request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.delete_endpoint())
            api_endpoint.set_identifiers(model_instance.update_group_name)
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        except Exception as e:
            raise RuntimeError(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_one(self, model_instance: FabricUpdateGroupModel, **kwargs) -> ResponseType:
        """
        # Summary

        Query a single fabric update group by name. Returns the flat group dict (not wrapped) with
        switchIds converted back to their fabric management IPs for user-friendly output.

        ## Raises

        ### RuntimeError

        - If the GET request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.query_one_endpoint())
            api_endpoint.set_identifiers(model_instance.update_group_name)
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb)
            return self._denormalize_switches_in_response(result)
        except Exception as e:
            raise RuntimeError(f"Query failed for {model_instance.get_identifier_value()}: {e}") from e

    def query_all(self, model_instance: FabricUpdateGroupModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Query all user-managed fabric update groups in the configured fabric. Extracts the list from the
        `updateGroups` key in the response, drops the ND-managed default group, and converts switchIds
        back to IPs in each remaining item.

        ## Raises

        ### RuntimeError

        - If the GET request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.query_all_endpoint())
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, not_found_ok=True)
            items: list = []
            if isinstance(result, dict):
                items = result.get("updateGroups", []) or []
            # ND returns a system-managed default update group named "None" (the literal string) that
            # holds switches not assigned to any user-defined group. It is intentional ND behavior, not
            # an API discrepancy. Users cannot create or delete it, so it must never appear in module
            # output: `state: overridden` would try to delete a group ND manages, and a future
            # `state: gathered` would emit an unusable playbook task for it. The `updateGroup` schema
            # carries no system/default flag, so the only discriminator is the name. Drop it here.
            items = [g for g in items if isinstance(g, dict) and g.get("updateGroupName") not in (None, "", "None")]
            return [self._denormalize_switches_in_response(item) for item in items]
        except Exception as e:
            raise RuntimeError(f"Query all failed: {e}") from e
