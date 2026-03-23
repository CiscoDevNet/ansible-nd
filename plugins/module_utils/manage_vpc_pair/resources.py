# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

import json
from typing import Any, Callable, Dict, List, Optional

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vpc_pair import (
    VpcPairOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_manage_vpc_pair_exceptions import (
    VpcPairResourceError,
)

"""
State-machine resource service for nd_manage_vpc_pair.

Note:
- This file does not define endpoint paths directly.
- Runtime endpoint path usage is centralized in `vpc_pair_runtime_endpoints.py`.
"""


RunStateHandler = Callable[[Any], Dict[str, Any]]
DeployHandler = Callable[[Any, str, Dict[str, Any]], Dict[str, Any]]
NeedsDeployHandler = Callable[[Dict[str, Any], Any], bool]


class VpcPairStateMachine(NDStateMachine):
    """NDStateMachine adapter with state handling for nd_manage_vpc_pair."""

    def __init__(self, module: AnsibleModule):
        super().__init__(module=module, model_orchestrator=VpcPairOrchestrator)
        self.model_orchestrator.bind_state_machine(self)
        self.current_identifier = None
        self.existing_config: Dict[str, Any] = {}
        self.proposed_config: Dict[str, Any] = {}
        self.logs: List[Dict[str, Any]] = []
        self.result: Dict[str, Any] = {}

    def format_log(
        self,
        identifier: Any,
        status: str,
        before_data: Optional[Any] = None,
        after_data: Optional[Any] = None,
        sent_payload_data: Optional[Any] = None,
    ) -> None:
        """Collect operation log entries expected by nd_manage_vpc_pair flows."""
        log_entry: Dict[str, Any] = {"identifier": identifier, "status": status}
        if before_data is not None:
            log_entry["before"] = before_data
        if after_data is not None:
            log_entry["after"] = after_data
        if sent_payload_data is not None:
            log_entry["sent_payload"] = sent_payload_data
        self.logs.append(log_entry)

    def add_logs_and_outputs(self) -> None:
        """
        Build final result payload compatible with nd_manage_vpc_pair runtime.
        """
        self._refresh_after_state()
        self.output.assign(
            after=getattr(self, "existing", None),
            before=getattr(self, "before", None),
            proposed=getattr(self, "proposed", None),
            logs=self.logs,
        )

        formatted = self.output.format()
        formatted.setdefault("current", formatted.get("after", []))
        formatted.setdefault("response", [])
        formatted.setdefault("result", [])
        class_diff = self._build_class_diff()
        changed_by_class_diff = bool(
            class_diff["created"] or class_diff["deleted"] or class_diff["updated"]
        )
        formatted["changed"] = bool(formatted.get("changed")) or changed_by_class_diff
        formatted["created"] = class_diff["created"]
        formatted["deleted"] = class_diff["deleted"]
        formatted["updated"] = class_diff["updated"]
        formatted["class_diff"] = class_diff
        if self.logs and "logs" not in formatted:
            formatted["logs"] = self.logs
        self.result = formatted

    def _refresh_after_state(self) -> None:
        """
        Optionally refresh the final "after" state from controller query.

        Enabled by default for write states to better reflect live controller
        state. Can be disabled for performance-sensitive runs.
        """
        state = self.module.params.get("state")
        if state not in ("merged", "replaced", "overridden", "deleted"):
            return
        if self.module.check_mode:
            return
        if self.module.params.get("suppress_verification", False):
            return
        if not self.module.params.get("refresh_after_apply", True):
            return

        refresh_timeout = self.module.params.get("refresh_after_timeout")
        had_original_timeout = "query_timeout" in self.module.params
        original_timeout = self.module.params.get("query_timeout")

        try:
            if refresh_timeout is not None:
                self.module.params["query_timeout"] = refresh_timeout
            response_data = self.model_orchestrator.query_all()
            self.existing = NDConfigCollection.from_api_response(
                response_data=response_data,
                model_class=self.model_class,
            )
        except Exception as exc:
            self.module.warn(
                f"Failed to refresh final after-state from controller query: {exc}"
            )
        finally:
            if refresh_timeout is not None:
                if had_original_timeout:
                    self.module.params["query_timeout"] = original_timeout
                else:
                    self.module.params.pop("query_timeout", None)

    @staticmethod
    def _identifier_to_key(identifier: Any) -> str:
        """
        Build a stable key for de-duplicating identifiers in class diff output.
        """
        try:
            return json.dumps(identifier, sort_keys=True, default=str)
        except Exception:
            return str(identifier)

    @staticmethod
    def _extract_changed_properties(log_entry: Dict[str, Any]) -> List[str]:
        """
        Best-effort changed-property extraction for update operations.
        """
        before = log_entry.get("before")
        after = log_entry.get("after")
        sent_payload = log_entry.get("sent_payload")

        changed = []
        if isinstance(before, dict) and isinstance(after, dict):
            all_keys = set(before.keys()) | set(after.keys())
            changed = [key for key in all_keys if before.get(key) != after.get(key)]

        if not changed and isinstance(sent_payload, dict):
            changed = list(sent_payload.keys())

        return sorted(set(changed))

    def _build_class_diff(self) -> Dict[str, List[Any]]:
        """
        Build class-level diff with created/deleted/updated entries.
        """
        created: List[Any] = []
        deleted: List[Any] = []
        updated: List[Dict[str, Any]] = []

        created_seen = set()
        deleted_seen = set()
        updated_map: Dict[str, Dict[str, Any]] = {}

        for log_entry in self.logs:
            status = log_entry.get("status")
            identifier = log_entry.get("identifier")
            key = self._identifier_to_key(identifier)

            if status == "created":
                if key not in created_seen:
                    created_seen.add(key)
                    created.append(identifier)
            elif status == "deleted":
                if key not in deleted_seen:
                    deleted_seen.add(key)
                    deleted.append(identifier)
            elif status == "updated":
                changed_props = self._extract_changed_properties(log_entry)
                entry = updated_map.get(key)
                if entry is None:
                    entry = {"identifier": identifier}
                    if changed_props:
                        entry["changed_properties"] = changed_props
                    updated_map[key] = entry
                elif changed_props:
                    merged = set(entry.get("changed_properties", [])) | set(changed_props)
                    entry["changed_properties"] = sorted(merged)

        updated.extend(updated_map.values())
        return {"created": created, "deleted": deleted, "updated": updated}

    def manage_state(
        self,
        state: str,
        new_configs: List[Dict[str, Any]],
        unwanted_keys: Optional[List] = None,
        override_exceptions: Optional[List] = None,
    ) -> None:
        unwanted_keys = unwanted_keys or []
        override_exceptions = override_exceptions or []

        self.state = state
        if hasattr(self, "params") and isinstance(getattr(self, "params"), dict):
            self.params["state"] = state
        else:
            self.module.params["state"] = state
        self.ansible_config = new_configs or []

        try:
            self.proposed = NDConfigCollection.from_ansible_config(
                data=self.ansible_config,
                model_class=self.model_class,
            )
            self.previous = self.existing.copy()
        except Exception as e:
            if isinstance(e, VpcPairResourceError):
                raise
            error_details = {"error": str(e)}
            if hasattr(e, "errors"):
                error_details["validation_errors"] = e.errors()
            raise VpcPairResourceError(
                msg=f"Failed to prepare configurations: {e}",
                **error_details,
            )

        if state in ["merged", "replaced", "overridden"]:
            self._manage_create_update_state(state, unwanted_keys)
            if state == "overridden":
                self._manage_override_deletions(override_exceptions)
        elif state == "deleted":
            self._manage_delete_state()
        else:
            raise VpcPairResourceError(msg=f"Invalid state: {state}")

    def _manage_create_update_state(self, state: str, unwanted_keys: List) -> None:
        for proposed_item in self.proposed:
            identifier = proposed_item.get_identifier_value()
            try:
                self.current_identifier = identifier

                existing_item = self.existing.get(identifier)
                self.existing_config = (
                    existing_item.model_dump(by_alias=True, exclude_none=True)
                    if existing_item
                    else {}
                )

                try:
                    diff_status = self.existing.get_diff_config(
                        proposed_item, unwanted_keys=unwanted_keys
                    )
                except TypeError:
                    diff_status = self.existing.get_diff_config(proposed_item)

                if diff_status == "no_diff":
                    self.format_log(
                        identifier=identifier,
                        status="no_change",
                        after_data=self.existing_config,
                    )
                    continue

                if state == "merged" and existing_item:
                    final_item = self.existing.merge(proposed_item)
                else:
                    if existing_item:
                        self.existing.replace(proposed_item)
                    else:
                        self.existing.add(proposed_item)
                    final_item = proposed_item

                self.proposed_config = final_item.to_payload()

                if diff_status == "changed":
                    response = self.model_orchestrator.update(final_item)
                    operation_status = "updated"
                else:
                    response = self.model_orchestrator.create(final_item)
                    operation_status = "created"

                self.sent.add(final_item)
                if not self.module.check_mode:
                    sent_payload = self.proposed_config
                else:
                    sent_payload = None

                self.format_log(
                    identifier=identifier,
                    status=operation_status,
                    after_data=(
                        response
                        if not self.module.check_mode
                        else final_item.model_dump(by_alias=True, exclude_none=True)
                    ),
                    sent_payload_data=sent_payload,
                )
            except VpcPairResourceError as e:
                # Preserve detailed context from vPC handlers instead of losing
                # it in generic state-machine wrapping layers.
                error_msg = f"Failed to process {identifier}: {e.msg}"
                self.format_log(
                    identifier=identifier,
                    status="no_change",
                    after_data=self.existing_config,
                )
                if not self.module.params.get("ignore_errors", False):
                    error_details = dict(getattr(e, "details", {}) or {})
                    error_details.setdefault("identifier", str(identifier))
                    error_details.setdefault("error", str(e))
                    raise VpcPairResourceError(msg=error_msg, **error_details)
            except Exception as e:
                error_msg = f"Failed to process {identifier}: {e}"
                self.format_log(
                    identifier=identifier,
                    status="no_change",
                    after_data=self.existing_config,
                )
                if not self.module.params.get("ignore_errors", False):
                    raise VpcPairResourceError(
                        msg=error_msg,
                        identifier=str(identifier),
                        error=str(e),
                    )

    def _manage_override_deletions(self, override_exceptions: List) -> None:
        diff_identifiers = self.previous.get_diff_identifiers(self.proposed)
        for identifier in diff_identifiers:
            if identifier in override_exceptions:
                continue

            try:
                self.current_identifier = identifier
                existing_item = self.existing.get(identifier)
                if not existing_item:
                    continue
                self.existing_config = existing_item.model_dump(
                    by_alias=True, exclude_none=True
                )
                delete_changed = self.model_orchestrator.delete(existing_item)
                self.existing.delete(identifier)
                self.format_log(
                    identifier=identifier,
                    status="deleted" if delete_changed is not False else "no_change",
                    after_data={},
                )
            except VpcPairResourceError as e:
                error_msg = f"Failed to delete {identifier}: {e.msg}"
                if not self.module.params.get("ignore_errors", False):
                    error_details = dict(getattr(e, "details", {}) or {})
                    error_details.setdefault("identifier", str(identifier))
                    error_details.setdefault("error", str(e))
                    raise VpcPairResourceError(msg=error_msg, **error_details)
            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"
                if not self.module.params.get("ignore_errors", False):
                    raise VpcPairResourceError(
                        msg=error_msg,
                        identifier=str(identifier),
                        error=str(e),
                    )

    def _manage_delete_state(self) -> None:
        for proposed_item in self.proposed:
            identifier = proposed_item.get_identifier_value()
            try:
                self.current_identifier = identifier
                existing_item = self.existing.get(identifier)
                if not existing_item:
                    self.format_log(identifier=identifier, status="no_change", after_data={})
                    continue

                self.existing_config = existing_item.model_dump(
                    by_alias=True, exclude_none=True
                )
                delete_changed = self.model_orchestrator.delete(existing_item)
                self.existing.delete(identifier)
                self.format_log(
                    identifier=identifier,
                    status="deleted" if delete_changed is not False else "no_change",
                    after_data={},
                )
            except VpcPairResourceError as e:
                error_msg = f"Failed to delete {identifier}: {e.msg}"
                if not self.module.params.get("ignore_errors", False):
                    error_details = dict(getattr(e, "details", {}) or {})
                    error_details.setdefault("identifier", str(identifier))
                    error_details.setdefault("error", str(e))
                    raise VpcPairResourceError(msg=error_msg, **error_details)
            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"
                if not self.module.params.get("ignore_errors", False):
                    raise VpcPairResourceError(
                        msg=error_msg,
                        identifier=str(identifier),
                        error=str(e),
                    )


class VpcPairResourceService:
    """
    Runtime service for nd_manage_vpc_pair execution flow.

    Orchestrates state management and optional deployment while keeping module
    entrypoint thin.
    """

    def __init__(
        self,
        module: AnsibleModule,
        run_state_handler: RunStateHandler,
        deploy_handler: DeployHandler,
        needs_deployment_handler: NeedsDeployHandler,
    ):
        self.module = module
        self.run_state_handler = run_state_handler
        self.deploy_handler = deploy_handler
        self.needs_deployment_handler = needs_deployment_handler

    def execute(self, fabric_name: str) -> Dict[str, Any]:
        nd_manage_vpc_pair = VpcPairStateMachine(module=self.module)
        result = self.run_state_handler(nd_manage_vpc_pair)

        if "_ip_to_sn_mapping" in self.module.params:
            result["ip_to_sn_mapping"] = self.module.params["_ip_to_sn_mapping"]

        deploy = self.module.params.get("deploy", False)
        if deploy and not self.module.check_mode:
            deploy_result = self.deploy_handler(nd_manage_vpc_pair, fabric_name, result)
            result["deployment"] = deploy_result
            result["deployment_needed"] = deploy_result.get(
                "deployment_needed",
                self.needs_deployment_handler(result, nd_manage_vpc_pair),
            )

        return result
