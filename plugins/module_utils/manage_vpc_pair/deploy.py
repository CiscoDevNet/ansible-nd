# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations


from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import (
    _raise_vpc_error,
    get_config_actions,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule as NDModuleV2,
    NDModuleError,
)
from ansible_collections.cisco.nd.plugins.module_utils.utils import (
    FabricUtils,
    register_action_api_call,
)

try:
    from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
except Exception:
    # TODO: Remove fallback import once rest.results is guaranteed in all supported framework trees.
    from ansible_collections.cisco.nd.plugins.module_utils.results import Results


def _needs_deployment(result: dict[str, Any], nrm: Any) -> bool:
    """
    Determine if save/deploy actions are needed based on changes/signals.

    Deployment is needed if any of:
    1. There are items in the diff (configuration changes)
    2. There are pending create VPC pairs
    3. There are pending delete VPC pairs
    4. There are active pairs currently not in-sync (not yet deployed)

    Args:
        result: Module result dictionary with diff info
        nrm: NDStateMachine instance

    Returns:
        True if config action execution is needed, False otherwise
    """
    # Check if there are any changes in the result
    has_changes = result.get("changed", False)

    # Check diff - prefer explicit diff outputs over before/after structural
    # comparisons. before/after payloads can differ in ordering/details while
    # still representing no effective change.
    has_diff_changes = _has_explicit_diff_changes(result)

    # Check pending operations
    pending_create = nrm.module.params.get("_pending_create", [])
    pending_delete = nrm.module.params.get("_pending_delete", [])
    has_pending = bool(pending_create or pending_delete)
    not_in_sync_pairs = nrm.module.params.get("_not_in_sync_pairs", [])
    has_not_in_sync = bool(not_in_sync_pairs)

    needs_deploy = has_changes or has_diff_changes or has_pending or has_not_in_sync

    return needs_deploy


def _has_explicit_diff_changes(result: dict[str, Any]) -> bool:
    """
    Detect meaningful configuration deltas from explicit diff structures.

    Prefers class_diff (created/updated/deleted) when available. Falls back to
    the raw diff list for compatibility with older output shapes.
    """
    class_diff = result.get("class_diff")
    if isinstance(class_diff, dict):
        return bool(class_diff.get("created") or class_diff.get("updated") or class_diff.get("deleted"))

    diff = result.get("diff")
    return bool(diff)


def _is_non_fatal_config_save_error(error: NDModuleError) -> bool:
    """
    Return True only for known non-fatal configSave platform limitations.

    Args:
        error: NDModuleError from config-save API call

    Returns:
        True if the error matches a known non-fatal 500 signature
        (e.g. fabric peering not supported). False otherwise.
    """
    if not isinstance(error, NDModuleError):
        return False

    # Keep this allowlist tight to avoid masking real config-save failures.
    if error.status != 500:
        return False

    message = (error.msg or "").lower()
    non_fatal_signatures = (
        "vpc fabric peering is not supported",
        "vpcsanitycheck",
        "unexpected error generating vpc configuration",
    )
    return any(signature in message for signature in non_fatal_signatures)


def custom_vpc_deploy(nrm: Any, fabric_name: str, result: dict[str, Any]) -> dict[str, Any]:
    """
    Custom save/deploy action handler for vPC fabric changes using RestSend.

    - Smart action decision (_needs_deployment)
    - Optional Step 1: Save fabric configuration
    - Optional Step 2: Deploy fabric with forceShowRun=true
    - Proper error handling with NDModuleError
    - Results aggregation
    - Executes only if there are actual changes or pending operations

    Args:
        nrm: NDStateMachine instance
        fabric_name: Fabric name to deploy
        result: Module result dictionary to check for changes

    Returns:
        Save/deploy result dictionary

    Raises:
        NDModuleError: If deployment fails
    """
    config_actions = get_config_actions(nrm.module)
    save_enabled = bool(config_actions.get("save", True))
    deploy_enabled = bool(config_actions.get("deploy", True))
    action_type = config_actions.get("type", "switch")
    action_payload = {"type": action_type}

    # Defensive runtime validation (model validation already enforces this).
    if deploy_enabled and not save_enabled:
        _raise_vpc_error(msg="Invalid config_actions: deploy=true requires save=true")

    if not save_enabled and not deploy_enabled:
        return {
            "msg": "Config actions disabled (save=false, deploy=false), skipping config save/deploy",
            "fabric": fabric_name,
            "deployment_needed": False,
            "changed": False,
            "config_actions": config_actions,
        }

    # Smart deployment decision (from Common.needs_deployment)
    if not _needs_deployment(result, nrm):
        return {
            "msg": ("No configuration changes, pending operations, or out-of-sync pairs " "detected, skipping config actions"),
            "fabric": fabric_name,
            "deployment_needed": False,
            "changed": False,
            "config_actions": config_actions,
        }

    if nrm.module.check_mode:
        # check_mode deployment preview
        pending_create = nrm.module.params.get("_pending_create", [])
        pending_delete = nrm.module.params.get("_pending_delete", [])
        not_in_sync_pairs = nrm.module.params.get("_not_in_sync_pairs", [])
        planned_actions = []
        if save_enabled:
            save_path = FabricUtils.build_config_save_path(fabric_name)
            planned_actions.append(f"POST {save_path} payload={action_payload}")
        if deploy_enabled:
            deploy_path = FabricUtils.build_config_deploy_path(fabric_name, force_show_run=True)
            planned_actions.append(f"POST {deploy_path} payload={action_payload}")
        if save_enabled and deploy_enabled:
            preview_msg = "CHECK MODE: Would save and deploy fabric configuration"
        elif save_enabled:
            preview_msg = "CHECK MODE: Would save fabric configuration"
        else:
            preview_msg = "CHECK MODE: Would deploy fabric configuration"

        deployment_info = {
            "msg": preview_msg,
            "fabric": fabric_name,
            "deployment_needed": True,
            "changed": True,
            "would_save": save_enabled,
            "would_deploy": deploy_enabled,
            "config_actions": config_actions,
            "deployment_decision_factors": {
                "diff_has_changes": _has_explicit_diff_changes(result),
                "pending_create_operations": len(pending_create),
                "pending_delete_operations": len(pending_delete),
                "not_in_sync_pairs": len(not_in_sync_pairs),
                "actual_changes": result.get("changed", False),
            },
            "planned_actions": planned_actions,
        }
        return deployment_info

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
    fabric_utils = FabricUtils(nd_v2, fabric_name)
    results = Results()

    # Step 1: Save config
    if save_enabled:
        save_path = fabric_utils.config_save_path

        try:
            response = fabric_utils.save_config(action_payload)
            register_action_api_call(
                results=results,
                request_path=save_path,
                payload=action_payload,
                return_code=response.get("status"),
                message="Config saved successfully",
                success=True,
                changed=True,
            )

        except NDModuleError as error:
            is_non_fatal = _is_non_fatal_config_save_error(error)
            can_continue = is_non_fatal and deploy_enabled
            if can_continue:
                # Known platform limitation warning; continue to deploy step.
                nrm.module.warn(f"Config save failed: {error.msg}")
                register_action_api_call(
                    results=results,
                    request_path=save_path,
                    payload=action_payload,
                    return_code=error.status,
                    message=error.msg,
                    success=True,
                    changed=False,
                )
            else:
                # Unknown config-save failures are fatal. Non-fatal signatures are
                # only tolerated when deploy is also requested.
                register_action_api_call(
                    results=results,
                    request_path=save_path,
                    payload=action_payload,
                    return_code=error.status,
                    message=error.msg,
                    success=False,
                    changed=False,
                )
                results.build_final_result()
                final_result = dict(results.final_result)
                final_msg = final_result.pop("msg", f"Config save failed: {error.msg}")
                _raise_vpc_error(msg=final_msg, **final_result)

    # Step 2: Deploy
    if deploy_enabled:
        deploy_path = fabric_utils.config_deploy_path(force_show_run=True)

        try:
            response = fabric_utils.deploy_config(action_payload, force_show_run=True)
            register_action_api_call(
                results=results,
                request_path=deploy_path,
                payload=action_payload,
                return_code=response.get("status"),
                message="Deployment successful",
                success=True,
                changed=True,
            )

        except NDModuleError as error:
            register_action_api_call(
                results=results,
                request_path=deploy_path,
                payload=action_payload,
                return_code=error.status,
                message=error.msg,
                success=False,
                changed=False,
            )

            # Build final result and fail
            results.build_final_result()
            final_result = dict(results.final_result)
            final_msg = final_result.pop("msg", "Fabric deployment failed")
            _raise_vpc_error(msg=final_msg, **final_result)

    # Build final result
    results.build_final_result()
    final_result = dict(results.final_result)
    final_result["config_actions"] = config_actions
    return final_result
