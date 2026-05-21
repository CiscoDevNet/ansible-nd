# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import json
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    EpFabricVrfsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_attachments import (
    EpFabricVrfsAttachmentsGet,
    EpFabricVrfsAttachmentsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLiteModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions import (
    AttachmentReconciler,
    _ensure_vrf_exists,
    _get_current_vrf_entry,
    _mark_changed_vrf,
    _post_attachment_payload,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    append_runtime_warning,
    get_config_actions,
    get_runtime_warnings,
    get_verify_settings,
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
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    _build_filter_set,
    query_vrf_lite_state,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation import (
    validate_vrf_lite_write_guardrails,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule as NDModuleV2


class ManageVrfLiteOrchestrator(NDBaseOrchestrator):
    """VRF Lite resource adapter for the generic ND state machine.

    The base state machine still decides merged/replaced/overridden/deleted
    lifecycle. This orchestrator adapts those generic method calls to VRF
    Lite's attachment API: create/update are attachment sync POSTs, delete is a
    detach POST, query is normalized from several controller reads, and deploy
    is a separate save/deploy action.
    """

    model_class: ClassVar[type[NDBaseModel]] = VrfLiteModel

    # Endpoint declarations document the controller surface.
    # VRF Lite uses a POST-based sub-resource API, so generic CRUD methods
    # are intentionally overridden.
    create_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsPost
    update_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsPost
    delete_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsPost
    query_one_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsAttachmentsGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpFabricVrfsGet

    # Module params preparation (called before orchestrator creation)

    @staticmethod
    def prepare_module_params(module: Any, module_config: Any, normalized_config: list[dict[str, Any]] | None = None) -> None:
        """Set up module.params for the orchestrator and state machine.

        Handles input validation, config_actions normalization, gathered state
        preparation, and runtime state initialization. Called once from the
        module's main() before NDStateMachine creation.
        """
        state = module_config.state
        if normalized_config is None:
            normalized_config = module_config.to_runtime_config()
        config_actions = get_config_actions(module.params)
        verify_settings = get_verify_settings(module.params)

        # Validate gathered + explicit save/deploy conflict
        if state == "gathered":
            raw_module_args = ManageVrfLiteOrchestrator._get_raw_module_args()
            raw_config_actions = raw_module_args.get("config_actions")
            if isinstance(raw_config_actions, dict):
                normalized_actions = module.params.get("config_actions") or {}
                save_requested = "save" in raw_config_actions and normalized_actions.get("save") is True
                deploy_requested = "deploy" in raw_config_actions and normalized_actions.get("deploy") is True
                if save_requested or deploy_requested:
                    module.fail_json(
                        msg="config_actions.save/config_actions.deploy are not allowed with 'gathered' state. "
                        "Gathered workflows are strictly read-only."
                    )

            config_actions = {
                "save": False,
                "deploy": False,
                "type": config_actions.get("type", "switch"),
            }

        # Validate deploy requires save
        if config_actions.get("deploy") and not config_actions.get("save"):
            module.fail_json(msg="Invalid config_actions: config_actions.deploy=true requires config_actions.save=true")

        # Warn about force on non-deleted states
        if module_config.force and state != "deleted":
            append_runtime_warning(
                module.params,
                "Parameter 'force' only applies to state 'deleted'. Ignoring force for state '{0}'.".format(state),
            )

        # Normalize module params
        module.params["config"] = normalized_config
        module.params["config_actions"] = config_actions
        module.params["verify"] = verify_settings

        if state == "gathered":
            module.params["_gather_filter_config"] = list(normalized_config)
            module.params["config"] = []
        else:
            module.params["_gather_filter_config"] = []

        # Validate deleted requires config
        if state == "deleted" and not module.params.get("config"):
            module.fail_json(msg="Config parameter is required for state 'deleted'. Specify one or more vrf_name entries in config.")

        # Initialize runtime state
        module.params["_changed_vrfs"] = []
        module.params["_not_in_sync_vrfs"] = []
        module.params["_ip_to_sn_mapping"] = {}
        module.params["_sn_to_ip_mapping"] = {}
        module.params["_have"] = []
        module.params["_have_loaded"] = False
        module.params["_raw_vrf_attachment_map"] = {}
        module.params["_fabric_switch_inventory"] = {}
        module.params["_warnings"] = (
            list(module.params.get("_warnings")) if isinstance(module.params.get("_warnings"), list) else []
        )

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

    # Private helpers

    def _module(self) -> Any:
        """Access the AnsibleModule instance through REST infrastructure."""
        return self.rest_send.sender.ansible_module

    # CRUD operations adapt generic state-machine calls to VRF Lite's
    # attachment sub-resource API.

    def query_all(self, **kwargs: Any) -> list[dict[str, Any]]:
        return self._query_current_state()

    def create(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        if self._module().check_mode:
            return model_instance.to_config()

        return self._run_vrf_lite_action(
            self._sync_vrf_attachments,
            model_instance,
            replace_mode=False,
        )

    def update(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        module = self._module()
        if module.check_mode:
            return model_instance.to_config()

        return self._run_vrf_lite_action(
            self._sync_vrf_attachments,
            model_instance,
            replace_mode=module.params.get("state") in ("replaced", "overridden"),
        )

    def delete(self, model_instance: Any, **kwargs: Any) -> bool:
        if self._module().check_mode:
            return True

        return self._run_vrf_lite_action(self._detach_vrf_attachments, model_instance)

    # Gathered state (read-only query)

    def gather(self) -> dict[str, Any]:
        """Execute gathered-state workflow and return formatted output."""
        module = self._module()
        gathered = self._query_current_state()
        output = {
            "output_level": module.params.get("output_level", "normal"),
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

    # Deploy (config save + VRF deployments after state reconciliation)

    def deploy_pending(self, result: dict[str, Any]) -> dict[str, Any] | None:
        """Execute save/deploy actions if config_actions are enabled.

        Returns deploy result dict, or None if no deploy actions are needed.
        """
        module = self._module()
        config_actions = get_config_actions(module.params)

        if not config_actions.get("save", False) and not config_actions.get("deploy", False):
            return None

        return self._execute_config_actions(result)

    # Post-operation utilities

    def refresh_verified_state(self, result: dict[str, Any]) -> dict[str, Any]:
        """Re-query state after write to confirm changes were applied."""
        module = self._module()
        verify_settings = get_verify_settings(module.params)
        if not verify_settings.get("enabled", True):
            return result
        if module.check_mode or not result.get("changed"):
            return result

        refreshed = self._query_current_state()
        result["after"] = refreshed
        result["current"] = refreshed
        return result

    # VRF Lite resource behavior

    def _run_vrf_lite_action(self, action: Any, *args: Any, **kwargs: Any) -> Any:
        try:
            return action(*args, **kwargs)
        except NDModuleError as error:
            error_dict = error.to_dict()
            if "msg" in error_dict:
                error_dict["api_error_msg"] = error_dict.pop("msg")
            _raise_vrf_lite_error(msg=error.msg, **error_dict)
        except VrfLiteResourceError:
            raise
        except Exception as error:
            _raise_vrf_lite_error(msg=str(error), exception_type=type(error).__name__)

    def _query_current_state(self) -> list[dict[str, Any]]:
        module = self._module()
        fabric_name = module.params.get("fabric_name")
        state = module.params.get("state", "merged")

        if not fabric_name:
            raise ValueError("fabric_name must be set")

        if state == "gathered":
            if module.params.get("_have_loaded") and isinstance(module.params.get("_have"), list):
                return module.params["_have"]
            config = module.params.get("_gather_filter_config") or []
        else:
            config = module.params.get("config") or []

        filter_vrfs = _build_filter_set(config)
        try:
            have = query_vrf_lite_state(
                module=module,
                fabric_name=fabric_name,
                filter_vrfs=(filter_vrfs if filter_vrfs else None),
            )
        except NDModuleError as error:
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
        if state in ("deleted", "overridden"):
            have = [item for item in have if item.get("attach")]
            module.params["_have"] = have

        module.params["_have_loaded"] = True
        return have

    def _sync_vrf_attachments(self, model_instance: Any, replace_mode: bool) -> dict[str, Any]:
        module = self._module()
        fabric_name = module.params.get("fabric_name")
        vrf_name = model_instance.vrf_name

        _ensure_vrf_exists(module, vrf_name)
        validate_vrf_lite_write_guardrails(module=module, model_instance=model_instance)

        nd_v2 = NDModuleV2(module)
        current_vrf = _get_current_vrf_entry(module, fabric_name, vrf_name)

        reconciler = AttachmentReconciler(module=module, nd_v2=nd_v2, model_instance=model_instance, current_vrf=current_vrf)
        changes = reconciler.sync_payloads(replace_mode=replace_mode)

        if not changes:
            return current_vrf or {}

        response = _post_attachment_payload(nd_v2, fabric_name, vrf_name, changes)
        _mark_changed_vrf(module, vrf_name)
        return response

    def _detach_vrf_attachments(self, model_instance: Any) -> bool:
        module = self._module()
        fabric_name = module.params.get("fabric_name")
        vrf_name = model_instance.vrf_name

        current_vrf = _get_current_vrf_entry(module, fabric_name, vrf_name)
        if not current_vrf:
            return False

        nd_v2 = NDModuleV2(module)
        reconciler = AttachmentReconciler(module=module, nd_v2=nd_v2, model_instance=model_instance, current_vrf=current_vrf)
        if not reconciler.have_map:
            return False

        detach_payloads = reconciler.detach_payloads()
        if not detach_payloads:
            return False

        _post_attachment_payload(nd_v2, fabric_name, vrf_name, detach_payloads)
        _mark_changed_vrf(module, vrf_name)
        return True

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
            return {
                "msg": "No changes or out-of-sync VRF Lite attachments detected, skipping config actions",
                "deployment_needed": False,
                "changed": False,
                "config_actions": config_actions,
                "response": [],
            }

        requested_deploy_vrfs = set(_target_vrfs_for_deploy(module))
        changed_deploy_vrfs = set(module.params.get("_changed_vrfs") or []) & requested_deploy_vrfs
        target_vrfs = sorted(changed_deploy_vrfs | requested_deploy_vrfs)

        planned_actions = []
        if save_enabled:
            planned_actions.append("POST {0}".format(VrfLiteEndpoints.config_save(fabric_name)))
        if deploy_enabled and target_vrfs:
            planned_actions.append("POST {0} vrfNames={1}".format(VrfLiteEndpoints.vrf_deployments(fabric_name), ",".join(target_vrfs)))

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

        nd_v2 = NDModuleV2(module)
        responses = []
        changed = False

        if save_enabled:
            save_payload = {"type": config_actions.get("type", "switch")}
            try:
                save_resp = nd_v2.request(VrfLiteEndpoints.config_save(fabric_name), HttpVerbEnum.POST, save_payload)
                responses.append(
                    {
                        "operation": "config_save",
                        "path": VrfLiteEndpoints.config_save(fabric_name),
                        "payload": save_payload,
                        "response": save_resp,
                        "success": True,
                    }
                )
                changed = True
            except NDModuleError as error:
                if deploy_enabled and _is_non_fatal_config_save_error(error):
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
            deploy_payload = {"vrfNames": ",".join(target_vrfs)}
            try:
                deploy_resp = nd_v2.request(VrfLiteEndpoints.vrf_deployments(fabric_name), HttpVerbEnum.POST, deploy_payload)
                responses.append(
                    {
                        "operation": "vrf_deploy",
                        "path": VrfLiteEndpoints.vrf_deployments(fabric_name),
                        "payload": deploy_payload,
                        "response": deploy_resp,
                        "success": True,
                    }
                )
                changed = True
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
        """Attach runtime warnings and IP mapping to the output."""
        module = self._module()
        warnings = get_runtime_warnings(module.params)
        if warnings:
            payload["warnings"] = warnings

        if module.params.get("_ip_to_sn_mapping"):
            payload["ip_to_sn_mapping"] = module.params.get("_ip_to_sn_mapping")

        return payload
