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
- `query_all()` issues **one** bulk GET of the fabric's switches and reads each row's
  `additionalData.intendedSystemMode`/`discoveredSystemMode`. It builds a snapshot dict that
  becomes `output.before` and caches both the per-IP mode map and the per-IP switchId map on the
  orchestrator instance. It hard-fails if any requested switch is currently in `migration` mode
  (a stuck/failed deployment state that the user must clear in the ND UI before the module can
  operate).
- `update()` reads the cached maps to filter to switches whose intent differs from the desired
  mode, sets query params from the model, and POSTs. It does not re-query.
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
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import EpManageSwitchesListGet
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.maintenance_mode.maintenance_mode import MaintenanceModeModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

_MIGRATION_REMEDIATION = (
    "Switch(es) are in 'migration' mode: {ips}. Please remediate any deployment errors in "
    "Nexus Dashboard and run 'Recalculate and Deploy' before attempting to change modes to normal "
    "or maintenance."
)

# Explicit denylist of 207 per-item status values that count as a failure. Anything else --
# `success`, missing, empty, or future progress/info tokens like `pending` or `warning` -- is
# tolerated. ND's switchAction APIs occasionally include informational rows; treating "not
# success" as failure would surface those as spurious errors.
_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})


class MaintenanceModeOrchestrator(NDBaseInterfaceOrchestrator[MaintenanceModeModel]):
    """
    # Summary

    Orchestrator for the `changeSystemMode` switch action.

    Builds a snapshot of per-switch `intendedSystemMode` in `query_all()` via a single bulk GET
    of the fabric's switches (which `NDStateMachine` calls during init), then `update()` POSTs the
    desired mode for only the switches whose current intent differs from the request, reusing the
    IP→switchId map captured by `query_all()`. The 207 response body is inspected per-item; any
    `status: failed` entry triggers a `RuntimeError` with an aggregate message naming the failing
    switches by IP.

    Inherits from `NDBaseInterfaceOrchestrator` for `FabricContext` plumbing and pre-flight
    validation. The deploy/remove queuing methods on that base are unused here. The IP→switchId
    resolution provided by `FabricContext.get_switch_id` is intentionally bypassed: this
    orchestrator parses the same bulk switches GET it issues for mode reads, so calling
    `FabricContext` would trigger a second list GET.

    ## Raises

    ### RuntimeError

    - Via `validate_prerequisites` if the fabric does not exist, is not local, or is in deployment-freeze mode
      for a state that mutates configuration.
    - Via `query_all` if a user-supplied `switch_ip` is not found in the fabric.
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
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageSwitchesListGet  # unused; query_one() delegates to query_all()
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageSwitchesListGet  # bulk fabric switches GET

    # Snapshot of switch_ip -> intendedSystemMode captured by query_all() and reused by update().
    # NDStateMachine invokes query_all() during init and the same orchestrator instance is reused for
    # update(), so caching here avoids a second per-switch GET fan-out per module run.
    _snapshot_modes: dict[str, str] | None = None
    # Companion cache of switch_ip -> switchId for the user-supplied switches, parsed from the same
    # bulk list-GET, so update() does not need to fall back to FabricContext (which would issue a
    # second list GET).
    _snapshot_switch_ids: dict[str, str] | None = None

    # ------------------------------------------------------------------ #
    # CRUD method overrides (action-shaped semantics)
    # ------------------------------------------------------------------ #

    def query_all(self, model_instance: NDBaseModel | None = None, **kwargs) -> ResponseType:
        """
        # Summary

        Build a snapshot of the user's requested switches with **one** bulk GET of the fabric's
        switches (`/api/v1/manage/fabrics/{fabric_name}/switches`). Each row's `additionalData`
        carries `intendedSystemMode` and `discoveredSystemMode`, so a single round-trip replaces
        the per-switch GET fan-out and avoids touching `FabricContext.get_switch_id` (which would
        issue its own list GET).

        If any user-supplied `switch_ip` is not present in the fabric, hard-fail with a
        FabricContext-style message. If any user switch is in `migration` mode, hard-fail with
        the remediation message before returning. This runs unconditionally during `NDStateMachine`
        init, so the migration check fires even in `check_mode`.

        Returns a 1-element list (the singleton snapshot) so `NDConfigCollection.from_api_response`
        builds exactly one `MaintenanceModeModel`.

        ## Raises

        ### RuntimeError

        - If the fabric pre-flight check fails.
        - If any user `switch_ip` is not found in the fabric.
        - If any user switch is currently in `migration` mode.
        - If the bulk switches GET fails.
        """
        try:
            self.validate_prerequisites()
            user_switches = self._user_switches()
            if not user_switches:
                # Empty config (e.g. during argspec failure cases) — return an empty snapshot.
                self._snapshot_modes = {}
                self._snapshot_switch_ids = {}
                return [{"switches": [], "switch_modes": {}}]

            wanted_ips = [entry["switch_ip"] for entry in user_switches if entry.get("switch_ip")]
            wanted_ip_set = set(wanted_ips)

            list_endpoint = EpManageSwitchesListGet()
            list_endpoint.fabric_name = self.fabric_name
            response = self._request(path=list_endpoint.path, verb=list_endpoint.verb)
            rows = response.get("switches") if isinstance(response, dict) else []
            # `_parse_switch_rows` is typed `list[Any]`; guard the container shape at the boundary so
            # a malformed `switches` value (string, dict, scalar) does not iterate character-by-
            # character or TypeError inside the helper.
            if not isinstance(rows, list):
                rows = []

            switch_ids, switch_modes, migration_ips = self._parse_switch_rows(rows, wanted_ip_set)

            missing = [ip for ip in wanted_ips if ip not in switch_ids]
            if missing:
                # Match the FabricContext error shape so existing tests/messages stay consistent.
                raise RuntimeError(f"No switch found with fabricManagementIp '{missing[0]}' in fabric '{self.fabric_name}'.")

            if migration_ips:
                raise RuntimeError(_MIGRATION_REMEDIATION.format(ips=migration_ips))

            # Cache for update() so we don't re-issue the bulk GET (or fall back to FabricContext).
            self._snapshot_modes = switch_modes
            self._snapshot_switch_ids = switch_ids

            snapshot = {
                "switches": [{"switch_ip": ip} for ip in wanted_ips],
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

        Reads the snapshot cached by `query_all()` (populated during `NDStateMachine` init) to decide
        which switches need to change, resolves `switch_ip` to `switchId` for those, sets the endpoint
        query params from the model, and POSTs. The 207 response body is parsed; any `status: failed`
        items raise a `RuntimeError` with switch IPs included.

        If the cache is empty (defensive path for callers that invoke `update()` without going through
        `query_all()` first), `query_all()` is called once to populate it.

        ## Raises

        ### RuntimeError

        - If the POST request fails outright.
        - If the 207 response body contains one or more per-switch failures.
        """
        try:
            if model_instance.mode is None or not model_instance.switches:
                return {}

            if self._snapshot_modes is None:
                # Defensive: caller skipped query_all (e.g. direct orchestrator use outside NDStateMachine).
                self.query_all()
            snapshot_modes = self._snapshot_modes or {}
            snapshot_switch_ids = self._snapshot_switch_ids or {}

            target_ips: list[str] = []
            target_switch_ids: list[str] = []
            for switch in model_instance.switches:
                if snapshot_modes.get(switch.switch_ip) == model_instance.mode:
                    continue
                target_ips.append(switch.switch_ip)
                # Read from the cached map (built by query_all); never fall back to FabricContext,
                # which would issue a second list GET on its first switch_map access.
                target_switch_ids.append(snapshot_switch_ids[switch.switch_ip])

            if not target_switch_ids:
                # Every requested switch already has matching intent — nothing to do.
                return {}

            api_endpoint = EpManageFabricsSwitchActionsChangeSystemModePost()
            api_endpoint.fabric_name = self.fabric_name
            # Only push truthy deploy/blocking onto the endpoint params: the model defaults are
            # False, and the endpoint serializes via `exclude_none=True` (not `exclude_defaults`),
            # so assigning False would emit `?deploy=false&blocking=false` on every request.
            if model_instance.deploy:
                api_endpoint.endpoint_params.deploy = True
            if model_instance.blocking:
                api_endpoint.endpoint_params.blocking = True
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

    @staticmethod
    def _parse_switch_rows(rows: list[Any], wanted_ip_set: set[str]) -> tuple[dict[str, str], dict[str, str], list[str]]:
        """
        # Summary

        Walk one bulk `/switches` response, keep only rows whose `fabricManagementIp` is in
        `wanted_ip_set`, and return `(switch_ids, switch_modes, migration_ips)`:

        - `switch_ids`: IP → switchId for every wanted row that carries both.
        - `switch_modes`: IP → `additionalData.intendedSystemMode` (when present and non-null).
        - `migration_ips`: wanted IPs whose `additionalData.discoveredSystemMode` is `"migration"`.

        ## Raises

        None
        """
        switch_ids: dict[str, str] = {}
        switch_modes: dict[str, str] = {}
        migration_ips: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = row.get("fabricManagementIp")
            switch_id = row.get("switchId")
            if not ip or not switch_id or ip not in wanted_ip_set:
                continue
            switch_ids[ip] = switch_id
            additional = row.get("additionalData") or {}
            intended = additional.get("intendedSystemMode")
            if additional.get("discoveredSystemMode") == "migration":
                migration_ips.append(ip)
            if intended is not None:
                switch_modes[ip] = intended
        return switch_ids, switch_modes, migration_ips

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
            if status not in _FAILURE_STATUSES:
                continue
            switch_id = item.get("switchId") or "?"
            ip = ip_by_id.get(switch_id, switch_id)
            message = item.get("message") or "unknown error"
            failures.append(f"{ip}: {message}")
        if failures:
            raise RuntimeError(f"changeSystemMode reported per-switch failures: {'; '.join(failures)}")
