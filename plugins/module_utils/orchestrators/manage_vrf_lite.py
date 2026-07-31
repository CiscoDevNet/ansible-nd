# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions import (
    _ensure_vrf_exists,
    _post_attachment_payload,
    build_attach_payload_for_entry,
    build_detach_payload_for_entry,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    append_runtime_warning,
    get_config_actions,
    get_runtime_warnings,
    get_verify_settings,
    request_with_rest_send,
    _raise_vrf_lite_error,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.deploy import (
    _is_non_fatal_config_save_error,
    _needs_deployment,
    _target_vrfs_for_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.config_transform import (
    config_vrf_names,
    explode_playbook_to_entries,
    group_attachment_entries_to_vrfs,
    replacement_scope_vrfs,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    query_vrf_lite_state,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation import (
    validate_vrf_lite_write_guardrails,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_attachment_entry import (
    VrfLiteAttachmentEntry,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)

logger = logging.getLogger("nd.ManageVrfLiteOrchestrator")


class ManageVrfLiteOrchestrator(NDBaseOrchestrator):
    """Attachment-level VRF Lite adapter for the generic ND state machine."""

    model_class: ClassVar[type[NDBaseModel]] = VrfLiteAttachmentEntry
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    track_deletes_in_sent: ClassVar[bool] = True

    create_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    update_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    delete_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    create_bulk_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet
    delete_bulk_endpoint: type[NDEndpointBaseModel] = EpManageFabricsGet

    @staticmethod
    def prepare_module_params(module: Any, module_config: Any, normalized_config: list[dict[str, Any]] | None = None) -> None:
        """Normalize module params while preserving nested playbook config."""
        state = module_config.state
        if normalized_config is None:
            normalized_config = module_config.to_runtime_config()
        config_actions = get_config_actions(module.params)
        verify_settings = get_verify_settings(module.params)

        if state == "gathered":
            raw_module_args = ManageVrfLiteOrchestrator._get_raw_module_args()
            raw_config_actions = raw_module_args.get("config_actions")
            if isinstance(raw_config_actions, dict):
                normalized_actions = module.params.get("config_actions") or {}
                save_requested = "save" in raw_config_actions and normalized_actions.get("save") is True
                deploy_requested = "deploy" in raw_config_actions and normalized_actions.get("deploy") is True
                if save_requested or deploy_requested:
                    module.fail_json(
                        msg="config_actions.save/config_actions.deploy are not allowed with 'gathered' state. " "Gathered workflows are strictly read-only."
                    )

            config_actions = {
                "save": False,
                "deploy": False,
                "type": config_actions.get("type", "switch"),
            }

        if config_actions.get("deploy") and not config_actions.get("save"):
            module.fail_json(msg="Invalid config_actions: config_actions.deploy=true requires config_actions.save=true")

        module.params["config"] = normalized_config
        module.params["_vrf_lite_nested_config"] = list(normalized_config)
        module.params["config_actions"] = config_actions
        module.params["verify"] = verify_settings

        if state == "gathered":
            module.params["_gather_filter_config"] = list(normalized_config)
            module.params["config"] = []
        else:
            module.params["_gather_filter_config"] = []

        if state == "deleted" and not normalized_config:
            module.fail_json(msg="Config parameter is required for state 'deleted'. Specify one or more vrf_name entries in config.")

        module.params["_changed_vrfs"] = []
        module.params["_vrf_lite_requested_state"] = state
        module.params["_not_in_sync_vrfs"] = []
        module.params["_ip_to_sn_mapping"] = {}
        module.params["_sn_to_ip_mapping"] = {}
        module.params["_vrf_lite_vrf_vlan_map"] = {}
        module.params["_have"] = []
        module.params["_have_loaded"] = False
        module.params["_raw_vrf_attachment_map"] = {}
        module.params["_fabric_switch_inventory"] = {}
        module.params["_vrf_lite_support_cache"] = {}
        module.params["_vrf_lite_prototype_cache"] = {}
        module.params["_vrf_lite_switch_detail_cache"] = {}
        module.params["_warnings"] = list(module.params.get("_warnings")) if isinstance(module.params.get("_warnings"), list) else []

    @staticmethod
    def _get_raw_module_args() -> dict[str, Any]:
        """Best-effort extraction of raw user-provided args before defaults."""
        try:
            from ansible.module_utils import basic as ansible_basic

            raw_payload = getattr(ansible_basic, "_ANSIBLE_ARGS", None)
            if raw_payload is None:
                return {}

            if isinstance(raw_payload, (bytes, bytearray)):
                decoded = raw_payload.decode("utf-8")
            elif isinstance(raw_payload, str):
                decoded = raw_payload
            else:
                return {}

            parsed = json.loads(decoded)
            module_args = parsed.get("ANSIBLE_MODULE_ARGS")
            return module_args if isinstance(module_args, dict) else {}
        except Exception:
            return {}

    def _module(self) -> Any:
        return self.rest_send.sender.ansible_module

    def _public_scope_vrfs(self) -> list[str]:
        module = self._module()
        state = module.params.get("_vrf_lite_requested_state") or module.params.get("state", "merged")
        if state == "gathered":
            config = module.params.get("_gather_filter_config") or []
        else:
            config = module.params.get("_vrf_lite_nested_config") or module.params.get("config") or []
        return replacement_scope_vrfs(config)

    def _prepare_state_machine_config(self, current_entries: list[dict[str, Any]]) -> None:
        """Prepare flat attachment rows before the generic state machine builds proposed."""
        module = self._module()
        state = module.params.get("_vrf_lite_requested_state") or module.params.get("state", "merged")
        if state == "gathered":
            return
        config = module.params.get("_vrf_lite_nested_config") or module.params.get("config") or []
        module.params["config"] = explode_playbook_to_entries(config=config, module=module, state=state, current_entries=current_entries)

    def query_all(self, **kwargs: Any) -> list[dict[str, Any]]:
        current = self._query_current_state(flat=True)
        logger.debug("query_all: loaded %d current VRF Lite attachment row(s)", len(current))
        self._prepare_state_machine_config(current)
        return current

    def create(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        return self.create_bulk([model_instance], **kwargs)

    def update(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        return self._post_attach_entries([model_instance])

    def delete(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        return self.delete_bulk([model_instance], **kwargs)

    def create_bulk(self, model_instances: list[Any], **kwargs: Any) -> dict[str, Any]:
        return self._post_attach_entries(model_instances)

    def delete_bulk(self, model_instances: list[Any], **kwargs: Any) -> dict[str, Any]:
        return self._post_detach_entries(model_instances)

    def _validate_attach_entries(self, entries: list[Any]) -> None:
        module = self._module()
        seen_vrfs = set()
        for entry in entries:
            if entry.vrf_name not in seen_vrfs:
                _ensure_vrf_exists(module, self.rest_send, entry.vrf_name)
                seen_vrfs.add(entry.vrf_name)
            validate_vrf_lite_write_guardrails(module=module, model_instance=entry, rest_send=self.rest_send)

    def preflight_validate_check_mode(self, proposed_entries: list[Any]) -> None:
        """Run the non-mutating attach preflight during a check-mode run.

        The generic state machine skips all write methods in check mode
        (``_execute_operation`` only calls the operation ``if not check_mode``),
        so the VRF-existence and switch role/support guardrails inside
        ``_post_attach_entries`` are never reached. Without this, check mode
        would approve a plan that references a nonexistent VRF or an
        unsupported switch and then fail on the real run. This reuses the same
        read-only ``_validate_attach_entries`` guardrails so check mode rejects
        the same inputs the execution path would.
        """
        module = self._module()
        if not module.check_mode:
            return
        state = module.params.get("_vrf_lite_requested_state") or module.params.get("state", "merged")
        if state not in ("merged", "replaced", "overridden"):
            return
        attach_entries = [entry for entry in proposed_entries if getattr(entry, "switch_ip", None)]
        if attach_entries:
            self._validate_attach_entries(attach_entries)

    def _post_grouped_rows(self, rows_by_vrf: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        module = self._module()
        responses = []
        for vrf_name in sorted(rows_by_vrf):
            rows = rows_by_vrf[vrf_name]
            if not rows:
                continue
            logger.debug("_post_grouped_rows: posting %d attachment row(s) for VRF %s", len(rows), vrf_name)
            responses.append(
                {
                    "vrf_name": vrf_name,
                    "response": _post_attachment_payload(module, self.rest_send, module.params.get("fabric_name"), vrf_name, rows),
                }
            )
        return {"response": responses}

    def _post_attach_entries(self, entries: list[Any]) -> dict[str, Any]:
        if not entries:
            return {}
        module = self._module()
        if module.check_mode:
            logger.debug("_post_attach_entries: check_mode, planning %d attach entry(ies)", len(entries))
            return {"planned": [entry.to_config() for entry in entries]}

        logger.info("_post_attach_entries: attaching %d entry(ies) across VRF(s) %s", len(entries), sorted({entry.vrf_name for entry in entries}))
        self._validate_attach_entries(entries)
        rows_by_vrf: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entry in entries:
            rows_by_vrf[entry.vrf_name].append(build_attach_payload_for_entry(module, self.rest_send, entry))
        return self._post_grouped_rows(rows_by_vrf)

    def _post_detach_entries(self, entries: list[Any]) -> dict[str, Any]:
        # _validate_attach_entries is intentionally skipped here: detach entries only
        # reference attachments already confirmed present in current state by the state
        # machine before calling delete_bulk.  VRF-existence and role-guardrail checks
        # are not needed for a clear/detach operation.
        if not entries:
            return {}
        module = self._module()
        if module.check_mode:
            logger.debug("_post_detach_entries: check_mode, planning %d detach entry(ies)", len(entries))
            return {"planned": [entry.to_config() for entry in entries]}

        logger.info("_post_detach_entries: detaching %d entry(ies) across VRF(s) %s", len(entries), sorted({entry.vrf_name for entry in entries}))
        rows_by_vrf: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for entry in entries:
            rows_by_vrf[entry.vrf_name].append(build_detach_payload_for_entry(module, entry))
        return self._post_grouped_rows(rows_by_vrf)

    def gather(self) -> dict[str, Any]:
        flat_gathered = self._query_current_state(flat=True)
        gathered = group_attachment_entries_to_vrfs(flat_gathered, module=self._module(), include_vrfs=self._public_scope_vrfs())
        logger.info("gather: returning %d VRF(s) with VRF Lite attachments", len(gathered))
        output = {
            "output_level": self._module().params.get("output_level", "normal"),
            "changed": False,
            "before": gathered,
            "after": gathered,
            "current": gathered,
            "diff": [],
            "response": [],
            "result": [],
            "gathered": gathered,
        }
        return self.inject_runtime_metadata(output)

    def deploy_pending(self, result: dict[str, Any]) -> dict[str, Any] | None:
        module = self._module()
        config_actions = get_config_actions(module.params)

        if not config_actions.get("save", False) and not config_actions.get("deploy", False):
            logger.debug("deploy_pending: save/deploy both disabled, skipping config actions")
            return None

        logger.info(
            "deploy_pending: executing config actions (save=%s, deploy=%s, type=%s)",
            config_actions.get("save"),
            config_actions.get("deploy"),
            config_actions.get("type"),
        )
        return self._execute_config_actions(result)

    def refresh_verified_state(self, result: dict[str, Any]) -> dict[str, Any]:
        module = self._module()
        verify_settings = get_verify_settings(module.params)
        if not verify_settings.get("enabled", True):
            return result
        if module.check_mode or not result.get("changed"):
            return result

        logger.debug("refresh_verified_state: re-querying fabric to verify post-deploy state")
        # Per-switch details may have been cached during preflight.  They are
        # authoritative only until a write occurs; retain immutable prototype
        # metadata but force attachment details to be read again for verify.
        module.params["_vrf_lite_switch_detail_cache"] = {}
        refreshed = self._query_current_state(flat=True)
        result["after"] = group_attachment_entries_to_vrfs(refreshed, module=module, include_vrfs=self._public_scope_vrfs())
        result["current"] = result["after"]
        return result

    def format_public_output(self, result: dict[str, Any]) -> dict[str, Any]:
        module = self._module()
        state = module.params.get("state", "merged")
        scoped_empty_keys = {"before", "after", "current", "gathered"}
        include_vrfs = self._public_scope_vrfs() if state in ("deleted", "replaced", "overridden", "gathered") else []
        for key in ("before", "after", "current", "proposed", "diff", "gathered"):
            value = result.get(key)
            if not isinstance(value, list):
                continue
            has_flat_entries = any(isinstance(item, VrfLiteAttachmentEntry) or (isinstance(item, dict) and "switch_ip" in item) for item in value)
            should_preserve_empty_scope = not value and include_vrfs and key in scoped_empty_keys
            if has_flat_entries or should_preserve_empty_scope:
                result[key] = group_attachment_entries_to_vrfs(value, module=module, include_vrfs=include_vrfs)
        result.setdefault("current", result.get("after", []))
        return result

    def _query_current_state(self, flat: bool = True) -> list[dict[str, Any]]:
        module = self._module()
        fabric_name = module.params.get("fabric_name")
        state = module.params.get("state", "merged")

        if not fabric_name:
            raise ValueError("fabric_name must be set")

        if state == "gathered":
            if module.params.get("_have_loaded") and isinstance(module.params.get("_have"), list):
                have = module.params["_have"]
                return have if flat else group_attachment_entries_to_vrfs(have, module=module, include_vrfs=self._public_scope_vrfs())
            config = module.params.get("_gather_filter_config") or []
        else:
            config = module.params.get("_vrf_lite_nested_config") or module.params.get("config") or []

        # For overridden, query the full fabric so VRFs absent from config can be removed.
        requested_state = module.params.get("_vrf_lite_requested_state") or state
        filter_vrfs = None if requested_state == "overridden" else set(config_vrf_names(config))
        try:
            have = query_vrf_lite_state(
                module=module,
                rest_send=self.rest_send,
                fabric_name=fabric_name,
                filter_vrfs=(filter_vrfs if filter_vrfs else None),
                flat=True,
            )
        except NDModuleError as error:
            logger.error("Failed to query VRF Lite state for fabric %s: %s", fabric_name, error.msg)
            error_dict = error.to_dict()
            if "msg" in error_dict:
                error_dict["api_error_msg"] = error_dict.pop("msg")
            _raise_vrf_lite_error(msg="Failed to query VRF Lite state: {0}".format(error.msg), fabric=fabric_name, **error_dict)
        except VrfLiteResourceError:
            raise
        except Exception as error:
            _raise_vrf_lite_error(
                msg="Failed to query VRF Lite state: {0}".format(str(error)),
                fabric=fabric_name,
                exception_type=type(error).__name__,
            )

        module.params["_have"] = have
        module.params["_have_loaded"] = True
        logger.debug("_query_current_state: queried %d attachment row(s) for fabric %s", len(have), fabric_name)
        return have if flat else group_attachment_entries_to_vrfs(have, module=module, include_vrfs=self._public_scope_vrfs())

    def _execute_config_actions(self, result: dict[str, Any]) -> dict[str, Any]:
        module = self._module()
        fabric_name = module.params.get("fabric_name")
        config_actions = get_config_actions(module.params)
        save_enabled = config_actions.get("save", True)
        deploy_enabled = config_actions.get("deploy", True)

        if deploy_enabled and not save_enabled:
            _raise_vrf_lite_error(msg="Invalid config_actions: deploy=true requires save=true")

        if not save_enabled and not deploy_enabled:
            return {
                "msg": "Config actions disabled (save=false, deploy=false), skipping config save/deploy",
                "deployment_needed": False,
                "changed": False,
                "config_actions": config_actions,
                "response": [],
            }

        deployment_needed = _needs_deployment(result, module)
        if not deployment_needed:
            logger.info("_execute_config_actions: no changes or out-of-sync attachments, skipping save/deploy")
            return {
                "msg": "No changes or out-of-sync VRF Lite attachments detected, skipping config actions",
                "deployment_needed": False,
                "changed": False,
                "config_actions": config_actions,
                "response": [],
            }

        requested_deploy_vrfs = set(_target_vrfs_for_deploy(module))
        changed_vrfs = set(module.params.get("_changed_vrfs") or [])

        # Removed attachments (replaced/overridden/deleted) are absent from the retained
        # config, so _target_vrfs_for_deploy cannot see them.  Recover the removed
        # (vrf, switch) pairs from the state-machine operation journal (_deploy_targets,
        # which includes detaches) so a remove-all still deploys and every removed switch
        # is in scope.  Building the scope from config alone would leave the detach
        # undeployed on those switches while the module still reports success.  Removals
        # never carry deploy: false, so they always stay in scope.
        ip_to_sn = module.params.get("_ip_to_sn_mapping") or {}
        deploy_targets = module.params.get("_deploy_targets") or []
        config_pairs = {
            (str(item.get("vrf_name")), str(item.get("switch_ip")))
            for item in module.params.get("config") or []
            if isinstance(item, dict) and item.get("vrf_name") and item.get("switch_ip")
        }
        removed_pairs = {
            (str(target.get("vrf_name")), str(target.get("switch_ip")))
            for target in deploy_targets
            if isinstance(target, dict) and target.get("vrf_name") and target.get("switch_ip")
        } - config_pairs
        removed_vrfs = {vrf_name for vrf_name, _switch_id in removed_pairs}

        # Deploy VRFs that changed and are either deploy-enabled in the retained config
        # or had an attachment removed this run.
        target_vrfs = sorted(changed_vrfs & (requested_deploy_vrfs | removed_vrfs))
        logger.info("_execute_config_actions: save=%s deploy=%s target_vrfs=%s", save_enabled, deploy_enabled, target_vrfs)

        planned_actions = []
        if save_enabled:
            planned_actions.append("POST {0}".format(VrfLiteEndpoints.config_save(fabric_name)))
        target_switch_ids = sorted(
            {
                ip_to_sn.get(str(item.get("switch_ip")), str(item.get("switch_ip")))
                for item in module.params.get("config") or []
                if isinstance(item, dict) and item.get("vrf_name") in target_vrfs and item.get("switch_ip")
            }
            | {ip_to_sn.get(switch_id, switch_id) for vrf_name, switch_id in removed_pairs if vrf_name in target_vrfs}
        )

        if deploy_enabled and target_vrfs:
            deploy_action = "POST {0} vrfNames={1}".format(VrfLiteEndpoints.vrf_deployments(fabric_name), ",".join(target_vrfs))
            # type=switch scopes the deploy to only the affected switches; type=global omits
            # switchIds so the controller performs a fabric-wide deploy of the changed VRFs.
            if config_actions.get("type") == "switch" and target_switch_ids:
                deploy_action += " switchIds={0}".format(",".join(target_switch_ids))
            planned_actions.append(deploy_action)

        if module.check_mode:
            return {
                "msg": "CHECK MODE: Would run VRF Lite save/deploy actions",
                "deployment_needed": True,
                "changed": True,
                "config_actions": config_actions,
                "target_vrfs": target_vrfs,
                "planned_actions": planned_actions,
                "response": [],
            }

        responses = []
        changed = bool(module.params.get("_changed_vrfs"))

        if save_enabled:
            # config save is a fabric-wide trigger with no request body; the deploy scope
            # (switch vs global) is applied to the VRF deploy call below, not to config save.
            save_payload = {}
            try:
                save_resp = request_with_rest_send(module, self.rest_send, VrfLiteEndpoints.config_save(fabric_name), HttpVerbEnum.POST, save_payload)
                logger.debug("config_save POST succeeded for fabric %s", fabric_name)
                responses.append(
                    {
                        "operation": "config_save",
                        "path": VrfLiteEndpoints.config_save(fabric_name),
                        "payload": save_payload,
                        "response": save_resp,
                        "success": True,
                    }
                )
            except NDModuleError as error:
                if deploy_enabled and _is_non_fatal_config_save_error(error):
                    logger.warning("config_save returned known non-fatal error: %s; continuing with deploy", error.msg)
                    append_runtime_warning(
                        module.params,
                        "Config save returned a known non-fatal platform error: {0}. Continuing with deploy.".format(error.msg),
                    )
                    responses.append(
                        {
                            "operation": "config_save",
                            "path": VrfLiteEndpoints.config_save(fabric_name),
                            "payload": save_payload,
                            "response": error.to_dict(),
                            "success": False,
                            "non_fatal": True,
                        }
                    )
                else:
                    error_dict = error.to_dict()
                    if "msg" in error_dict:
                        error_dict["api_error_msg"] = error_dict.pop("msg")
                    _raise_vrf_lite_error(msg="Config save failed: {0}".format(error.msg), **error_dict)

        if deploy_enabled and target_vrfs:
            deploy_payload = {"vrfNames": target_vrfs}
            # type=switch scopes the deploy to only the affected switches; type=global omits
            # switchIds so the controller performs a fabric-wide deploy of the changed VRFs.
            if config_actions.get("type") == "switch" and target_switch_ids:
                deploy_payload["switchIds"] = target_switch_ids
            try:
                deploy_resp = request_with_rest_send(module, self.rest_send, VrfLiteEndpoints.vrf_deployments(fabric_name), HttpVerbEnum.POST, deploy_payload)
                logger.info("vrf_deploy POST succeeded for VRF(s) %s", target_vrfs)
                responses.append(
                    {
                        "operation": "vrf_deploy",
                        "path": VrfLiteEndpoints.vrf_deployments(fabric_name),
                        "payload": deploy_payload,
                        "response": deploy_resp,
                        "success": True,
                    }
                )
            except NDModuleError as error:
                error_dict = error.to_dict()
                if "msg" in error_dict:
                    error_dict["api_error_msg"] = error_dict.pop("msg")
                _raise_vrf_lite_error(msg="VRF deploy failed: {0}".format(error.msg), **error_dict)

        return {
            "msg": "VRF Lite config actions completed",
            "deployment_needed": True,
            "changed": changed,
            "config_actions": config_actions,
            "target_vrfs": target_vrfs,
            "planned_actions": planned_actions,
            "response": responses,
        }

    def inject_runtime_metadata(self, payload: dict[str, Any]) -> dict[str, Any]:
        module = self._module()
        warnings = get_runtime_warnings(module.params)
        if warnings:
            payload["warnings"] = warnings

        if module.params.get("_ip_to_sn_mapping"):
            payload["ip_to_sn_mapping"] = module.params.get("_ip_to_sn_mapping")

        return payload
