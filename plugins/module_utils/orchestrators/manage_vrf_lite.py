# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import json
from typing import Any, ClassVar, Optional

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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions import (
    custom_vrf_lite_create,
    custom_vrf_lite_delete,
    custom_vrf_lite_update,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    append_runtime_warning,
    get_config_actions,
    get_runtime_warnings,
    get_verify_settings,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.deploy import (
    custom_vrf_lite_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    custom_vrf_lite_query_all,
)


class _VrfLiteQueryContext:
    """Minimal context object exposing .module for custom query flows."""

    def __init__(self, module: Any) -> None:
        self.module = module


class ManageVrfLiteOrchestrator(NDBaseOrchestrator):
    """Self-contained orchestrator for VRF Lite management.

    Follows the 'declare, don't implement' pattern:
    - Declares model_class and endpoint types
    - Provides CRUD + deploy_pending() + gather() methods
    - Module only wires NDStateMachine and calls orchestrator methods
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
    def prepare_module_params(module: Any, module_config: Any, normalized_config: Optional[list[dict[str, Any]]] = None) -> None:
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

    # CRUD operations override the base methods for VRF Lite's POST-based API.

    def query_all(self, **kwargs: Any) -> list[dict[str, Any]]:
        module = self._module()
        return custom_vrf_lite_query_all(_VrfLiteQueryContext(module))

    def create(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        module = self._module()
        return custom_vrf_lite_create(model_instance=model_instance, module=module)

    def update(self, model_instance: Any, **kwargs: Any) -> dict[str, Any]:
        module = self._module()
        return custom_vrf_lite_update(model_instance=model_instance, module=module)

    def delete(self, model_instance: Any, **kwargs: Any) -> bool:
        module = self._module()
        return custom_vrf_lite_delete(model_instance=model_instance, module=module)

    # Gathered state (read-only query)

    def gather(self) -> dict[str, Any]:
        """Execute gathered-state workflow and return formatted output."""
        module = self._module()
        gathered = custom_vrf_lite_query_all(_VrfLiteQueryContext(module))
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

        fabric_name = module.params.get("fabric_name")
        return custom_vrf_lite_deploy(module, fabric_name=fabric_name, result=result)

    # Post-operation utilities

    def refresh_verified_state(self, result: dict[str, Any]) -> dict[str, Any]:
        """Re-query state after write to confirm changes were applied."""
        module = self._module()
        verify_settings = get_verify_settings(module.params)
        if not verify_settings.get("enabled", True):
            return result
        if module.check_mode or not result.get("changed"):
            return result

        refreshed = custom_vrf_lite_query_all(_VrfLiteQueryContext(module))
        result["after"] = refreshed
        result["current"] = refreshed
        return result

    def inject_runtime_metadata(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Attach runtime warnings and IP mapping to the output."""
        module = self._module()
        warnings = get_runtime_warnings(module.params)
        if warnings:
            payload["warnings"] = warnings

        if module.params.get("_ip_to_sn_mapping"):
            payload["ip_to_sn_mapping"] = module.params.get("_ip_to_sn_mapping")

        return payload
