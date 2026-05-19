# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Maintenance mode orchestrator for Nexus Dashboard.

Wraps `POST /api/v1/manage/fabrics/{fabric_name}/switchActions/changeSystemMode` — a switch *action*
endpoint that sets the system mode (`normal` or `maintenance`) for a batch of switches in one call.

The endpoint is action-shaped (not CRUD), so the orchestrator adapts it to fit `NDStateMachine`'s
CRUD-shaped driver:

- The Ansible-facing `config` is a dict, wrapped into a 1-item list by `nd_maintenance_mode.main()`
  so the state machine sees a singleton collection.
- `query_all()` fans out per-switch GETs to read the current `intendedSystemMode` and returns a
  single snapshot dict that becomes `output.before`. It also hard-fails the entire operation if any
  requested switch is currently in `migration` mode (a stuck/failed deployment state that the user
  must clear in the ND UI before the module can operate).
- `update()` is the real action method: resolves IPs to serials, filters to only the switches whose
  current intent differs from the desired mode, sets query params from the model, and POSTs.
- `create()` aliases `update()`. `delete()` is not supported (state `deleted` is not advertised).

Uses `FabricContext` for fabric existence / freeze / locality pre-checks and switch IP-to-serial
resolution.
"""

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageFabricsSwitchActionsChangeSystemModePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import EpManageSwitchesGet
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.maintenance_mode.maintenance_mode import MaintenanceModeModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

_MIGRATION_REMEDIATION = (
    "Switch(es) are in 'migration' mode: {ips}. Please remediate any deployment errors in "
    "Nexus Dashboard and run 'Recalculate and Deploy' before attempting to change modes to normal "
    "or maintenance."
)


class MaintenanceModeOrchestrator(NDBaseInterfaceOrchestrator[MaintenanceModeModel]):
    """
    # Summary

    Orchestrator for the `changeSystemMode` switch action.

    Builds a snapshot of per-switch `intendedSystemMode` in `query_all()` (which `NDStateMachine`
    calls during init), then `update()` POSTs the desired mode for only the switches whose current
    intent differs from the request. The 207 response body is inspected per-item; any `status:
    failed` entry triggers a `RuntimeError` with an aggregate message naming the failing switches
    by IP.

    Inherits from `NDBaseInterfaceOrchestrator` for `FabricContext` plumbing, switch IP resolution,
    and pre-flight validation. The deploy/remove queuing methods on that base are unused here.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist, is not local, or is in deployment-freeze mode.
    - Via `_resolve_switch_id` if a user-supplied `switch_ip` is not found in the fabric.
    - Via `query_all` if any switch is currently in `migration` mode.
    - Via `update` if the POST changeSystemMode request fails or the 207 body contains per-switch failures.

    ### NotImplementedError

    - Via `delete` — state `deleted` is not supported for switch maintenance mode.
    """

    model_class: ClassVar[type[NDBaseModel]] = MaintenanceModeModel
    supports_bulk_create: ClassVar[bool] = False
    supports_bulk_delete: ClassVar[bool] = False

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsSwitchActionsChangeSystemModePost
    update_endpoint: type[NDEndpointBaseModel] = EpManageFabricsSwitchActionsChangeSystemModePost
    delete_endpoint: type[NDEndpointBaseModel] = NDEndpointBaseModel  # unused; delete() raises NotImplementedError
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageSwitchesGet  # unused; query_one() delegates to query_all()
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageSwitchesGet  # used per-switch in query_all() fan-out

    # ------------------------------------------------------------------ #
    # CRUD method overrides (action-shaped semantics)
    # ------------------------------------------------------------------ #

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Build a snapshot of the user's requested switches by fanning out per-switch GETs and reading
        `additionalData.intendedSystemMode`. If any switch is currently in `migration` mode, hard-fail
        with a remediation message before returning. This runs unconditionally during `NDStateMachine`
        init, so the migration check fires even in `check_mode`.

        Returns a 1-element list (the singleton snapshot) so `NDConfigCollection.from_api_response`
        builds exactly one `MaintenanceModeModel`.

        ## Raises

        ### RuntimeError

        - If any switch is currently in `migration` mode.
        - If the fabric pre-flight check fails.
        - If a `switch_ip` is not found in the fabric.
        - If a per-switch GET fails.
        """
        try:
            self.validate_prerequisites()
            user_switches = self._user_switches()
            if not user_switches:
                # Empty config (e.g. during argspec failure cases) — return an empty snapshot.
                return [{"switches": [], "switch_modes": {}}]

            switch_modes: dict[str, str] = {}
            migration_ips: list[str] = []

            for entry in user_switches:
                switch_ip = entry.get("switch_ip")
                if not switch_ip:
                    continue
                intended, discovered = self._fetch_switch_modes(switch_ip)
                if discovered == "migration":
                    migration_ips.append(switch_ip)
                if intended is not None:
                    switch_modes[switch_ip] = intended

            if migration_ips:
                raise RuntimeError(_MIGRATION_REMEDIATION.format(ips=migration_ips))

            snapshot = {
                "switches": [{"switch_ip": entry.get("switch_ip")} for entry in user_switches if entry.get("switch_ip")],
                "switch_modes": switch_modes,
            }
            return [snapshot]
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"query_all failed: {e}") from e

    def query_one(self, model_instance: MaintenanceModeModel, **kwargs) -> ResponseType:
        """
        # Summary

        Delegate to `query_all`. `nd_maintenance_mode` is a singleton operation; there is no
        meaningful "query one" distinct from "query all" for this module.

        ## Raises

        - Whatever `query_all` raises.
        """
        return self.query_all(model_instance=model_instance, **kwargs)

    def create(self, model_instance: MaintenanceModeModel, **kwargs) -> ResponseType:
        """
        # Summary

        Alias to `update`. `NDStateMachine` only routes to `create` when the existing collection is
        empty, which cannot happen for this singleton (the snapshot is always non-empty).

        ## Raises

        - Whatever `update` raises.
        """
        return self.update(model_instance, **kwargs)

    def update(self, model_instance: MaintenanceModeModel, **kwargs) -> ResponseType:
        """
        # Summary

        Apply the requested system mode to the switches that currently differ.

        Resolves `switch_ip` to `switchId` for every entry, reads the snapshot from `query_all` to
        determine which switches actually need to change, sets the endpoint query params from the
        model, and POSTs. The 207 response body is parsed; any `status: failed` items raise a
        `RuntimeError` with switch IPs included.

        ## Raises

        ### RuntimeError

        - If the POST request fails outright.
        - If the 207 response body contains one or more per-switch failures.
        """
        try:
            self.validate_prerequisites()
            if model_instance.mode is None or not model_instance.switches:
                return {}

            # Re-read the live snapshot so we only POST switches whose intent actually needs to change.
            snapshot_response = self.query_all()
            snapshot_modes: dict[str, str] = {}
            if snapshot_response and isinstance(snapshot_response, list):
                snapshot_modes = (snapshot_response[0] or {}).get("switch_modes", {}) or {}

            target_ips: list[str] = []
            target_switch_ids: list[str] = []
            for switch in model_instance.switches:
                if snapshot_modes.get(switch.switch_ip) == model_instance.mode:
                    continue
                target_ips.append(switch.switch_ip)
                target_switch_ids.append(self._resolve_switch_id(switch.switch_ip))

            if not target_switch_ids:
                # Every requested switch already has matching intent — nothing to do.
                return {}

            api_endpoint = EpManageFabricsSwitchActionsChangeSystemModePost()
            api_endpoint.fabric_name = self.fabric_name
            api_endpoint.endpoint_params.deploy = model_instance.deploy
            api_endpoint.endpoint_params.blocking = model_instance.blocking
            api_endpoint.endpoint_params.ticket_id = model_instance.ticket_id

            payload = {"mode": model_instance.mode, "switchIds": target_switch_ids}
            result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, data=payload)

            self._raise_on_207_failures(result, target_ips, target_switch_ids)
            return result
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"changeSystemMode failed: {e}") from e

    def delete(self, model_instance: MaintenanceModeModel, **kwargs) -> ResponseType:
        """
        # Summary

        Not supported. Maintenance mode is a binary switch attribute, not a managed resource. Users
        who want to take a switch out of maintenance set `mode: normal` under `state: merged`.

        ## Raises

        ### NotImplementedError

        - Always.
        """
        raise NotImplementedError("state 'deleted' is not supported by nd_maintenance_mode. Use 'state: merged' with 'mode: normal' to restore a switch.")

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _fetch_switch_modes(self, switch_ip: str) -> tuple[str | None, str | None]:
        """
        # Summary

        GET a single switch and return its `(intendedSystemMode, discoveredSystemMode)` pair from
        `additionalData`. Returns `(None, None)` if the response is malformed.

        ## Raises

        ### RuntimeError

        - Via `_resolve_switch_id` if the IP is not in the fabric.
        - Via `_request` if the GET fails.
        """
        switch_id = self._resolve_switch_id(switch_ip)
        api_endpoint = EpManageSwitchesGet()
        api_endpoint.fabric_name = self.fabric_name
        api_endpoint.switch_id = switch_id
        response = self._request(path=api_endpoint.path, verb=api_endpoint.verb)
        if not isinstance(response, dict):
            return None, None
        # Read `intendedSystemMode` for idempotency rather than the aggregator `systemMode`, because
        # `systemMode` returns "inconsistent" when intent != discovered (e.g. after a no-deploy POST).
        # Comparing against the aggregator would re-POST on every playbook run that left intent != discovered.
        additional = response.get("additionalData") or {}
        return additional.get("intendedSystemMode"), additional.get("discoveredSystemMode")

    def _user_switches(self) -> list[dict[str, Any]]:
        """
        # Summary

        Return the list of `{switch_ip: ...}` dicts the user supplied in `config.switches`, after the
        `main()` wrap that puts the original `config` dict inside a 1-item list.

        ## Raises

        None
        """
        config_list = self.rest_send.params.get("config") or []
        if not isinstance(config_list, list) or not config_list:
            return []
        first = config_list[0]
        if not isinstance(first, dict):
            return []
        switches = first.get("switches") or []
        return [s for s in switches if isinstance(s, dict)]

    def _raise_on_207_failures(self, result: Any, target_ips: list[str], target_switch_ids: list[str]) -> None:
        """
        # Summary

        Inspect the 207 multi-status response body. If any item has `status` other than `success`,
        raise `RuntimeError` with the failing switches translated back to their IPs.

        ## Raises

        ### RuntimeError

        - If the response body contains one or more per-switch failures.
        """
        if not isinstance(result, dict):
            return
        items = result.get("items")
        if not isinstance(items, list) or not items:
            return
        ip_by_id = dict(zip(target_switch_ids, target_ips))
        failures: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            status = (item.get("status") or "").lower()
            if status == "success":
                continue
            switch_id = item.get("switchId") or "?"
            ip = ip_by_id.get(switch_id, switch_id)
            message = item.get("message") or "unknown error"
            failures.append(f"{ip}: {message}")
        if failures:
            raise RuntimeError(f"changeSystemMode reported per-switch failures: {'; '.join(failures)}")
