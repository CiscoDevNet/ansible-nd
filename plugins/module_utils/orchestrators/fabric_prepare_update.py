# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Orchestrator for the fabric "prepare update" (stage) action on Nexus Dashboard.

The ND 4.2 GUI "Prepare" step is the `softwareUpdatePlan/actions/stage` action: ND copies each
update group's configured image to the member switches, runs `show install all impact`, and
generates pre-reports. The action is asynchronous - the POST returns HTTP 202 with an empty body
and progress is observed by polling `softwareUpdatePlan/summary`.

This orchestrator is intentionally *not* an `NDBaseOrchestrator` subclass: there is no CRUD
resource here, so the base's five required create/update/delete/query endpoint fields do not
apply. It is a standalone Pydantic model that drives `RestSend` directly via a private `_request`
helper adapted from `NDBaseOrchestrator._request`.

Responsibilities:

- `preflight_role_check` - fail before staging if an update group spans more than one switch role
  (ND will not prepare a mixed-role group).
- `status_snapshot` - per-group / per-switch stage-validate status, used for module `before` /
  `after` output and for the idempotency decision.
- `stage` - POST the stage action for the named update groups.
- `wait_for_completion` - poll the summary until every target switch has staged and validated, or
  raise on a per-switch failure or timeout.
"""

from __future__ import annotations

import time
from typing import Any, cast

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.software_update_plan_actions import EpFabricSoftwareUpdatePlanStage
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.software_update_plan_summary import EpFabricSoftwareUpdatePlanSummary
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_prepare_update.software_update_plan_summary import (
    SoftwareUpdatePlanSummaryModel,
    SwitchStageStatusModel,
    UpdateGroupStatusModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results

# Per-switch staged / validated statuses that count as terminal-OK for a prepare operation.
# `skipped` is terminal-OK: ND skips staging a switch whose image is already in place.
_TERMINAL_OK: frozenset[str] = frozenset({"success", "skipped"})

# Per-switch staged / validated status that counts as a terminal failure.
_FAILED_STATUS: str = "failed"

# Consecutive `get_summary()` failures tolerated while polling before `wait_for_completion` gives
# up. A staging poll runs for many minutes, so a single transient transport error (a token
# refresh, a brief controller hiccup) is expected; only a sustained run of failures is fatal.
_MAX_CONSECUTIVE_POLL_FAILURES: int = 3


def _switch_is_prepared(switch: SwitchStageStatusModel) -> bool:
    """
    # Summary

    Return True if `switch` has reached a terminal-OK state for both the stage and validate phases.

    ## Raises

    None
    """
    return switch.image_staged_status in _TERMINAL_OK and switch.image_validated_status in _TERMINAL_OK


def _switch_has_failed(switch: SwitchStageStatusModel) -> bool:
    """
    # Summary

    Return True if `switch` reports a terminal failure for either the stage or validate phase.

    ## Raises

    None
    """
    return _FAILED_STATUS in (switch.image_staged_status, switch.image_validated_status)


class FabricPrepareUpdateOrchestrator(BaseModel):
    """
    # Summary

    Orchestrator for the fabric "prepare update" (stage) action on Nexus Dashboard.

    Reads `fabric_name` from module params and drives the `softwareUpdatePlan/actions/stage` and
    `softwareUpdatePlan/summary` endpoints via an injected `RestSend`.

    ## Raises

    ### RuntimeError

    - Via `_request` if a REST request fails.
    - Via `preflight_role_check` if an update group is missing or spans more than one switch role.
    - Via `status_snapshot` / `wait_for_completion` if an update group is missing from the summary.
    - Via `stage` if the stage action request fails.
    - Via `wait_for_completion` if a switch reports a staging failure or the wait times out.
    """

    model_config = ConfigDict(
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        arbitrary_types_allowed=True,
    )

    rest_send: RestSend
    results: Results | None = None

    @property
    def fabric_name(self) -> str:
        """
        # Summary

        Return `fabric_name` from module params.

        ## Raises

        None
        """
        return self.rest_send.params.get("fabric_name")

    def _register_api_call(self, path: str, verb: HttpVerbEnum, operation_type: OperationType, payload: dict[str, Any] | None = None) -> None:
        """
        # Summary

        Register the most recent REST call with `Results` for verbosity-gated observability. No-op
        when no `Results` instance is attached.

        ## Raises

        None
        """
        if self.results is None:
            return
        self.results.action = operation_type.value
        self.results.operation_type = operation_type
        self.results.path_current = path
        self.results.verb_current = verb
        self.results.payload_current = payload
        self.results.response_current = self.rest_send.response_current
        self.results.result_current = self.rest_send.result_current
        self.results.diff_current = {}
        # Write actions are shown at -vv (verbosity 2); reads at -vvv (verbosity 3).
        self.results.verbosity_level_current = 3 if operation_type == OperationType.QUERY else 2
        self.results.register_api_call()

    def _request(self, path: str, verb: HttpVerbEnum, data: dict[str, Any] | None = None, operation_type: OperationType = OperationType.QUERY) -> ResponseType:
        """
        # Summary

        Send a REST request via `RestSend`, register it with `Results`, and return the response
        `DATA`.

        ## Raises

        ### RuntimeError

        - If the controller returns a non-success result.
        """
        self.rest_send.path = path
        self.rest_send.verb = verb
        if data is not None:
            self.rest_send.payload = data
        self.rest_send.commit()

        # Register before the success check so failed calls are also captured for troubleshooting.
        self._register_api_call(path, verb, operation_type, self.rest_send.committed_payload)

        if not self.rest_send.success:
            raise RuntimeError(f"Request failed: {self.rest_send.error_summary}")

        return self.rest_send.response_current.get("DATA", {})

    def get_summary(self) -> SoftwareUpdatePlanSummaryModel:
        """
        # Summary

        GET the fabric's software update plan summary and parse it into a
        `SoftwareUpdatePlanSummaryModel`.

        ## Raises

        ### RuntimeError

        - If the summary GET request fails.
        """
        api_endpoint = EpFabricSoftwareUpdatePlanSummary()
        api_endpoint.fabric_name = self.fabric_name
        result = self._request(path=api_endpoint.path, verb=api_endpoint.verb, operation_type=OperationType.QUERY)
        # NDBaseModel.from_response is annotated to return the base type; narrow it to the concrete model.
        return cast(SoftwareUpdatePlanSummaryModel, SoftwareUpdatePlanSummaryModel.from_response(result if isinstance(result, dict) else {}))

    def _resolve_groups(self, summary: SoftwareUpdatePlanSummaryModel, update_group_names: list[str]) -> list[UpdateGroupStatusModel]:
        """
        # Summary

        Return the `UpdateGroupStatusModel` for each requested name, in request order, raising if
        any requested update group is absent from the summary.

        ## Raises

        ### RuntimeError

        - If one or more requested update groups are not present in the software update plan.
        """
        groups_by_name = {g.update_group_name: g for g in (summary.update_groups or [])}
        resolved: list[UpdateGroupStatusModel] = []
        missing: list[str] = []
        for name in update_group_names:
            group = groups_by_name.get(name)
            if group is None:
                missing.append(name)
            else:
                resolved.append(group)
        if missing:
            available = sorted(n for n in groups_by_name if n)
            raise RuntimeError(
                f"Update group(s) {missing} not found in the software update plan for fabric '{self.fabric_name}'. "
                f"Available update groups: {available or 'none'}. Create them first with cisco.nd.nd_fabric_update_group."
            )
        return resolved

    def preflight_role_check(self, update_group_names: list[str]) -> None:
        """
        # Summary

        Fail before staging if any requested update group spans more than one switch role. Nexus
        Dashboard will not prepare a mixed-role update group (for example, leaf + spine together),
        because simultaneous reloads across roles can disrupt fabric functionality.

        ## Raises

        ### RuntimeError

        - If a requested update group is missing from the summary.
        - If a requested update group contains switches of more than one role.
        """
        summary = self.get_summary()
        for group in self._resolve_groups(summary, update_group_names):
            roles = sorted({s.switch_role for s in (group.update_group_switches or []) if s.switch_role})
            if len(roles) > 1:
                raise RuntimeError(
                    f"Update group '{group.update_group_name}' contains a mix of switch roles ({', '.join(roles)}); "
                    f"Nexus Dashboard will not prepare a mixed-role update group. Split the switches into "
                    f"single-role update groups with cisco.nd.nd_fabric_update_group."
                )

    @staticmethod
    def _group_to_snapshot(group: UpdateGroupStatusModel) -> dict[str, Any]:
        """
        # Summary

        Build a stable, user-facing status dict for one update group. Member switches are sorted by
        name so `before` / `after` output is deterministic.

        ## Raises

        None
        """
        switches = sorted(group.update_group_switches or [], key=lambda s: (s.switch_name or s.switch_id or ""))
        return {
            "update_group_name": group.update_group_name,
            "update_group_status": group.update_group_status,
            "stage_validate_percentage": group.stage_validate_percentage,
            "switches": [
                {
                    "switch_name": s.switch_name,
                    "switch_id": s.switch_id,
                    "switch_role": s.switch_role,
                    "switch_management_ip": s.switch_management_ip,
                    "selected_version": s.selected_version,
                    "image_staged_status": s.image_staged_status,
                    "image_validated_status": s.image_validated_status,
                    "switch_stage_validate_percentage": s.switch_stage_validate_percentage,
                }
                for s in switches
            ],
        }

    def status_snapshot(self, update_group_names: list[str]) -> list[dict[str, Any]]:
        """
        # Summary

        Return the current stage-validate status of each requested update group as a list of plain
        dicts (one per group, in request order). Used for the module's `before` / `after` output
        and as the input to the idempotency decision.

        ## Raises

        ### RuntimeError

        - If a requested update group is missing from the summary.
        """
        summary = self.get_summary()
        return [self._group_to_snapshot(group) for group in self._resolve_groups(summary, update_group_names)]

    @staticmethod
    def snapshot_fully_prepared(snapshot: list[dict[str, Any]]) -> bool:
        """
        # Summary

        Return True if every switch in `snapshot` is already staged and validated. ND resets a
        switch's `imageStagedStatus` to `none` whenever the update group's configured image
        changes, so a `success` status already means "staged for the currently-configured image" -
        no separate version comparison is needed.

        Returns False for an empty snapshot (nothing to confirm prepared).

        ## Raises

        None
        """
        switches = [sw for group in snapshot for sw in group.get("switches", [])]
        if not switches:
            return False
        return all(sw.get("image_staged_status") in _TERMINAL_OK and sw.get("image_validated_status") in _TERMINAL_OK for sw in switches)

    def stage(self, update_group_names: list[str]) -> ResponseType:
        """
        # Summary

        POST the `softwareUpdatePlan/actions/stage` action for the named update groups. The action
        is asynchronous: ND returns HTTP 202 with an empty body.

        ## Raises

        ### RuntimeError

        - If the stage action request fails.
        """
        api_endpoint = EpFabricSoftwareUpdatePlanStage()
        api_endpoint.fabric_name = self.fabric_name
        try:
            return self._request(
                path=api_endpoint.path,
                verb=api_endpoint.verb,
                data={"updateGroupNames": list(update_group_names)},
                operation_type=OperationType.UPDATE,
            )
        except Exception as e:
            raise RuntimeError(f"Failed to stage update group(s) {update_group_names} in fabric '{self.fabric_name}': {e}") from e

    @staticmethod
    def _format_switch_statuses(switches: list[SwitchStageStatusModel]) -> str:
        """
        # Summary

        Render a compact, human-readable per-switch staged / validated status line for error and
        timeout messages.

        ## Raises

        None
        """
        return "; ".join(f"{s.switch_name or s.switch_id}=[staged:{s.image_staged_status}, validated:{s.image_validated_status}]" for s in switches)

    def wait_for_completion(self, update_group_names: list[str], timeout: int, interval: int) -> None:
        """
        # Summary

        Poll the software update plan summary until every switch in the requested update groups has
        staged and validated. Returns when staging is complete.

        A staging poll runs for many minutes, so a single transient transport error (a token
        refresh, a brief controller hiccup) is tolerated: a failed poll is retried, and only
        `_MAX_CONSECUTIVE_POLL_FAILURES` failures in a row abort the wait. A successful poll resets
        the failure count.

        ## Raises

        ### RuntimeError

        - If a requested update group is missing from the summary.
        - If any switch reports a staging or validation failure.
        - If the summary poll fails more than `_MAX_CONSECUTIVE_POLL_FAILURES` times in a row.
        - If staging does not complete within `timeout` seconds.
        """
        deadline = time.monotonic() + max(timeout, 0)
        consecutive_failures = 0
        while True:
            try:
                summary = self.get_summary()
            except Exception as e:  # pylint: disable=broad-except
                # A long poll will occasionally hit a transient transport error; retry it rather
                # than aborting the whole prepare. Only a sustained run of failures is fatal.
                consecutive_failures += 1
                if consecutive_failures > _MAX_CONSECUTIVE_POLL_FAILURES:
                    raise RuntimeError(
                        f"Polling staging status for update group(s) {update_group_names} in fabric "
                        f"'{self.fabric_name}' failed {consecutive_failures} times in a row: {e}"
                    ) from e
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"Timed out after {timeout}s waiting for staging of update group(s) {update_group_names} "
                        f"in fabric '{self.fabric_name}' to complete; last poll error: {e}"
                    ) from e
                time.sleep(interval)
                continue
            consecutive_failures = 0

            groups = self._resolve_groups(summary, update_group_names)
            switches = [sw for group in groups for sw in (group.update_group_switches or [])]

            failed = [sw for sw in switches if _switch_has_failed(sw)]
            if failed:
                raise RuntimeError(
                    f"Staging failed for update group(s) {update_group_names} in fabric '{self.fabric_name}': " f"{self._format_switch_statuses(failed)}"
                )

            if switches and all(_switch_is_prepared(sw) for sw in switches):
                return

            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"Timed out after {timeout}s waiting for staging of update group(s) {update_group_names} in "
                    f"fabric '{self.fabric_name}' to complete. Current status: {self._format_switch_statuses(switches)}"
                )

            time.sleep(interval)
