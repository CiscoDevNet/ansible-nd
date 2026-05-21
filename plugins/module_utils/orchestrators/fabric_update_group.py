# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Fabric update group orchestrator for Nexus Dashboard.

Drives fabric update group lifecycle via the ND Manage Fabric Software Management API. The write
path uses the switch-centric "action" API, which is ghost-safe by construction: `attachGroup`
requires at least one switch, and `detachGroup` auto-deletes a group server-side once its last
switch is removed.

- `create` / `create_bulk` create groups and assign switches via `attachGroup`, then apply group
  settings via `PUT /updateGroups/{name}` (the action API carries membership only).
- `update` reconciles membership - `attachGroup` for added switches, `detachGroup` for removed
  switches - then applies settings via PUT.
- `delete` detaches every switch via `detachGroup`; ND deletes the emptied group. If the group is
  a zero-switch ghost that the single GET cannot read, `delete` falls back to the group-centric
  `DELETE /updateGroups/{name}` to free the reserved name.
- `query_one` / `query_all` read via the group-centric GET endpoints.

Fabric name is supplied by the module's top-level `fabric_name` option and propagated to every
endpoint instance prior to path generation; per-config identifier is `update_group_name`.

`update_group_switches` and `installation_order_devices` accept either switch IP addresses or
switch serial numbers (switchIds). IPs are resolved to switchIds via `FabricContext` before being
sent on the wire; switchIds in GET responses are converted back to IPs so playbook authors see
consistent IP-based output even though the wire stores serials.

`attachGroup` and `detachGroup` return HTTP 207 with per-item `status`. Any status other than
`success` fails the task. ND returns `attachGroup` `status: warning` when it declines to apply a
change pending confirmation (and leaves nothing attached); setting the `force_created` option makes
ND apply the change and return `success` instead.
"""

from __future__ import annotations

from typing import Any, ClassVar, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.fabric_update_group import (
    EpFabricUpdateGroupDelete,
    EpFabricUpdateGroupGet,
    EpFabricUpdateGroupListGet,
    EpFabricUpdateGroupPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.software_update_plan_actions import (
    EpFabricSoftwareUpdatePlanAttachGroup,
    EpFabricSoftwareUpdatePlanDetachGroup,
    EpFabricSoftwareUpdatePlanPropose,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_update_group.fabric_update_group import FabricUpdateGroupModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# Wire payload keys whose list-valued contents are switch identifiers (IP or switchId)
_SWITCH_LIST_PAYLOAD_KEYS = ("updateGroupSwitches", "installationOrderDevices")

# Wire payload keys that identify a group / its membership rather than its settings
_NON_SETTINGS_PAYLOAD_KEYS = ("updateGroupName", "updateGroupSwitches")


class FabricUpdateGroupOrchestrator(NDBaseOrchestrator[FabricUpdateGroupModel]):
    """
    # Summary

    Orchestrator for fabric update group lifecycle on Nexus Dashboard.

    Reads `fabric_name` from module params and applies it to every endpoint instance before path
    generation. Resolves switch IPs to switchIds (and back) via `FabricContext`. The write path
    uses the switch-centric `attachGroup` / `detachGroup` action endpoints for membership and
    `PUT /updateGroups/{name}` for group settings.

    ## Raises

    ### RuntimeError

    - Via `create` / `create_bulk` if a request fails or any per-item `attachGroup` status is not `success`.
    - Via `update` if a request fails or `update_group_switches` resolves to an empty set.
    - Via `delete` if a request fails or any per-item `detachGroup` status is not `success`.
    - Via `query_one` / `query_all` if the query API request fails.
    - Via `propose` if the auto-assign request fails.
    - Via `_resolve_switch_id` if the user-provided switch IP cannot be matched in the fabric.
    """

    model_class: ClassVar[Type[NDBaseModel]] = FabricUpdateGroupModel
    supports_bulk_create: ClassVar[bool] = True

    create_endpoint: Type[NDEndpointBaseModel] = EpFabricSoftwareUpdatePlanAttachGroup
    update_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpFabricUpdateGroupListGet
    create_bulk_endpoint: Type[NDEndpointBaseModel] | None = EpFabricSoftwareUpdatePlanAttachGroup
    detach_group_endpoint: Type[NDEndpointBaseModel] = EpFabricSoftwareUpdatePlanDetachGroup
    propose_endpoint: Type[NDEndpointBaseModel] = EpFabricSoftwareUpdatePlanPropose

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
        fails), the response is returned unmodified rather than raising - switchIds shown to the user
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
    def _raise_on_207_action_errors(result: Any, response_key: str, message_key: str) -> None:
        """
        # Summary

        Inspect a 207 action response of shape `{response_key: [{updateGroupName, status, ...}]}` and
        raise `RuntimeError` if any item reports a non-`success` status. A `status: warning` means ND
        declined to apply the change (it left nothing attached) - so, like `failed`, it fails the
        task. The user opts past warnings by setting `force_created`, which makes ND apply the change
        and return `success`; `force_created` therefore governs the request, never response handling.

        ## Raises

        ### RuntimeError

        - If any item in the response reports a status other than `success`.
        """
        if not isinstance(result, dict):
            return
        items = result.get(response_key)
        if not isinstance(items, list):
            return
        failures = [item for item in items if isinstance(item, dict) and item.get("status") not in (None, "success")]
        if failures:
            details = ", ".join(f"{item.get('updateGroupName')}: {item.get('status')} - {item.get(message_key)}" for item in failures)
            raise RuntimeError(f"Per-item failures in {response_key} response: {details}")

    @staticmethod
    def _model_has_settings(model_instance: FabricUpdateGroupModel) -> bool:
        """
        # Summary

        Return True if the model carries any group setting (i.e. any payload key beyond the group
        name and its switch membership). When False, no settings PUT is needed.

        ## Raises

        None
        """
        return any(key not in _NON_SETTINGS_PAYLOAD_KEYS for key in model_instance.to_payload())

    def _attach_item(self, model_instance: FabricUpdateGroupModel, switch_ids: list[str] | None = None) -> dict:
        """
        # Summary

        Build a single `attachUpdateGroups` item. When `switch_ids` is None the model's
        `update_group_switches` are resolved (IP -> switchId); otherwise the provided already-resolved
        list is used verbatim.

        ## Raises

        ### RuntimeError

        - If a switch IP cannot be resolved (propagated from `_resolve_switch_id`).
        """
        if switch_ids is None:
            switch_ids = [self._resolve_switch_id(s) for s in (model_instance.update_group_switches or [])]
        return {
            "updateGroupName": model_instance.update_group_name,
            "switchIds": switch_ids,
            "forceCreated": model_instance.force_created,
        }

    def _attach(self, attach_items: list[dict]) -> ResponseType:
        """
        # Summary

        POST `attachGroup` with the supplied `attachUpdateGroups` items and inspect the 207 response.

        ## Raises

        ### RuntimeError

        - If the request fails or any per-item status is not `success`.
        """
        api_endpoint = self._configure_endpoint(self.create_endpoint())
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data={"attachUpdateGroups": attach_items})
        self._raise_on_207_action_errors(result, "attachUpdateGroups", "warningMessage")
        return result

    def _detach(self, detach_items: list[dict]) -> ResponseType:
        """
        # Summary

        POST `detachGroup` with the supplied `detachUpdateGroups` items and inspect the 207 response.

        ## Raises

        ### RuntimeError

        - If the request fails or any per-item status is not `success`.
        """
        api_endpoint = self._configure_endpoint(self.detach_group_endpoint())
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data={"detachUpdateGroups": detach_items})
        self._raise_on_207_action_errors(result, "detachUpdateGroups", "message")
        return result

    def _get_group_raw(self, update_group_name: str) -> dict:
        """
        # Summary

        GET a single update group and return its raw wire dict.

        ## Raises

        ### Exception

        - If the GET request fails (propagated from `_request`).
        """
        api_endpoint = self._configure_endpoint(self.query_one_endpoint())
        api_endpoint.set_identifiers(update_group_name)
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        return result if isinstance(result, dict) else {}

    def _get_group_raw_or_none(self, update_group_name: str) -> dict | None:
        """
        # Summary

        GET a single update group, returning None if the group cannot be read (e.g. a zero-switch
        ghost group, which ND returns HTTP 400 for).

        ## Raises

        None
        """
        try:
            return self._get_group_raw(update_group_name)
        except Exception:  # pylint: disable=broad-except
            return None

    def _delete_group(self, update_group_name: str) -> None:
        """
        # Summary

        Issue the group-centric `DELETE /updateGroups/{name}`. Used as a fallback to free the name of
        a zero-switch ghost group that `detachGroup` cannot act on.

        ## Raises

        ### Exception

        - If the DELETE request fails (propagated from `_request`).
        """
        api_endpoint = self._configure_endpoint(self.delete_endpoint())
        api_endpoint.set_identifiers(update_group_name)
        self._request(path=api_endpoint.path, verb=api_endpoint.verb)

    def _apply_settings(self, model_instance: FabricUpdateGroupModel, current_raw: dict | None = None) -> None:
        """
        # Summary

        Apply group settings via `PUT /updateGroups/{name}`. The action API carries membership only,
        so settings are PUT separately. PUT is a full replace requiring all of `updateGroupName`,
        `execution`, `contingency`, `analysis`, `isMaintenance`, `isDisruptiveUpdate`, and
        `updateGroupSwitches`; the body is built by overlaying the user's explicitly-set fields onto a
        GET of the current group, so every required field is present and `updateGroupSwitches` echoes
        the group's actual membership (PUT moves no switches). Skipped entirely when the model carries
        no settings.

        ## Raises

        ### RuntimeError

        - If a switch IP cannot be resolved, or the GET / PUT request fails.
        """
        if not self._model_has_settings(model_instance):
            return
        if current_raw is None:
            current_raw = self._get_group_raw(model_instance.update_group_name)
        merged = FabricUpdateGroupModel.from_response(current_raw)
        merged.merge(model_instance)
        api_endpoint = self._configure_endpoint(self.update_endpoint())
        api_endpoint.set_identifiers(model_instance.update_group_name)
        payload = self._resolve_switches_in_payload(merged.to_payload())
        self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

    def create(self, model_instance: FabricUpdateGroupModel, **kwargs) -> ResponseType:
        """
        # Summary

        Create a fabric update group: `attachGroup` creates the group and assigns its switches, then
        any group settings are applied via PUT.

        ## Raises

        ### RuntimeError

        - If a switch IP cannot be resolved, a request fails, or `attachGroup` reports a non-success status.
        """
        try:
            self._attach([self._attach_item(model_instance)])
            self._apply_settings(model_instance)
            return {}
        except Exception as e:
            raise RuntimeError(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def create_bulk(self, model_instances: list[FabricUpdateGroupModel], **kwargs) -> ResponseType:
        """
        # Summary

        Create multiple fabric update groups: a single `attachGroup` POST assigns switches for all
        groups, then group settings are applied per group via PUT.

        ## Raises

        ### RuntimeError

        - If a switch IP cannot be resolved, a request fails, or `attachGroup` reports a non-success status.
        """
        try:
            attach_items = [self._attach_item(m) for m in model_instances]
            self._attach(attach_items)
            for model_instance in model_instances:
                self._apply_settings(model_instance)
            return {}
        except Exception as e:
            raise RuntimeError(f"Bulk create failed: {e}") from e

    def update(self, model_instance: FabricUpdateGroupModel, **kwargs) -> ResponseType:
        """
        # Summary

        Update a fabric update group: reconcile membership against the current wire state
        (`attachGroup` for added switches, `detachGroup` for removed switches), then apply settings
        via PUT.

        ## Raises

        ### RuntimeError

        - If `update_group_switches` resolves to an empty set (an empty update group is not permitted -
          use `state: deleted`), a switch IP cannot be resolved, a request fails, or an action
          endpoint reports a non-success status.
        """
        try:
            update_group_name = model_instance.update_group_name
            current_raw = self._get_group_raw(update_group_name)
            current_ids = list(current_raw.get("updateGroupSwitches") or [])
            desired_ids = [self._resolve_switch_id(s) for s in (model_instance.update_group_switches or [])]
            if not desired_ids:
                raise RuntimeError("update_group_switches must be non-empty; an empty update group is not permitted (use state: deleted)")
            to_add = [s for s in desired_ids if s not in current_ids]
            to_remove = [s for s in current_ids if s not in desired_ids]
            if to_add:
                self._attach([self._attach_item(model_instance, switch_ids=to_add)])
            if to_remove:
                self._detach([{"updateGroupName": update_group_name, "switchIds": to_remove}])
            self._apply_settings(model_instance, current_raw=current_raw)
            return {}
        except Exception as e:
            raise RuntimeError(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: FabricUpdateGroupModel, **kwargs) -> ResponseType:
        """
        # Summary

        Delete a fabric update group by detaching every switch via `detachGroup` (ND deletes the
        emptied group). If the group cannot be read by the single GET (a zero-switch ghost group),
        fall back to the group-centric `DELETE /updateGroups/{name}` to free the reserved name.

        ## Raises

        ### RuntimeError

        - If a request fails or `detachGroup` reports a non-success status.
        """
        try:
            update_group_name = model_instance.update_group_name
            current_raw = self._get_group_raw_or_none(update_group_name)
            switch_ids = list(current_raw.get("updateGroupSwitches") or []) if current_raw else []
            if switch_ids:
                self._detach([{"updateGroupName": update_group_name, "switchIds": switch_ids}])
            else:
                self._delete_group(update_group_name)
            return {}
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

    def propose(self, algorithm: str) -> ResponseType:
        """
        # Summary

        Auto-assign update groups fabric-wide via the `propose` action endpoint. ND generates the
        update groups itself from `algorithm` (`roleBased` or `evenOdd`) and applies the result
        immediately; the action returns HTTP 200 with the resulting plan.

        ## Raises

        ### RuntimeError

        - If the request fails.
        """
        try:
            api_endpoint = self._configure_endpoint(self.propose_endpoint())
            return self._request(path=api_endpoint.path, verb=api_endpoint.verb, data={"algorithm": algorithm})
        except Exception as e:
            raise RuntimeError(f"Auto-assign (propose) failed for fabric '{self.fabric_name}': {e}") from e
