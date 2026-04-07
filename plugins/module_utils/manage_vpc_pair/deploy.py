# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Any, Dict

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import (
    _raise_vpc_error,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runtime_endpoints import (
    VpcPairEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule as NDModuleV2,
    NDModuleError,
)

try:
    from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
except Exception:
    from ansible_collections.cisco.nd.plugins.module_utils.results import Results


def _needs_deployment(result: Dict, nrm) -> bool:
    """
    Determine if deployment is needed based on changes and pending operations.

    Deployment is needed if any of:
    1. There are items in the diff (configuration changes)
    2. There are pending create VPC pairs
    3. There are pending delete VPC pairs
    4. There are active pairs currently not in-sync (not yet deployed)

    Args:
        result: Module result dictionary with diff info
        nrm: NDStateMachine instance

    Returns:
        True if deployment is needed, False otherwise
    """
    # Check if there are any changes in the result
    has_changes = result.get("changed", False)

    # Check diff - framework stores before/after
    before = result.get("before", [])
    after = result.get("after", [])
    has_diff_changes = before != after

    # Check pending operations
    pending_create = nrm.module.params.get("_pending_create", [])
    pending_delete = nrm.module.params.get("_pending_delete", [])
    has_pending = bool(pending_create or pending_delete)
    not_in_sync_pairs = nrm.module.params.get("_not_in_sync_pairs", [])
    has_not_in_sync = bool(not_in_sync_pairs)

    needs_deploy = has_changes or has_diff_changes or has_pending or has_not_in_sync

    return needs_deploy


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


def custom_vpc_deploy(nrm, fabric_name: str, result: Dict) -> Dict[str, Any]:
    """
    Custom deploy function for fabric configuration changes using RestSend.

    - Smart deployment decision (Common.needs_deployment)
    - Step 1: Save fabric configuration
    - Step 2: Deploy fabric with forceShowRun=true
    - Proper error handling with NDModuleError
    - Results aggregation
    - Only deploys if there are actual changes or pending operations

    Args:
        nrm: NDStateMachine instance
        fabric_name: Fabric name to deploy
        result: Module result dictionary to check for changes

    Returns:
        Deployment result dictionary

    Raises:
        NDModuleError: If deployment fails
    """
    # Smart deployment decision (from Common.needs_deployment)
    if not _needs_deployment(result, nrm):
        return {
            "msg": "No configuration changes, pending operations, or out-of-sync pairs detected, skipping deployment",
            "fabric": fabric_name,
            "deployment_needed": False,
            "changed": False,
        }

    if nrm.module.check_mode:
        # check_mode deployment preview
        before = result.get("before", [])
        after = result.get("after", [])
        pending_create = nrm.module.params.get("_pending_create", [])
        pending_delete = nrm.module.params.get("_pending_delete", [])
        not_in_sync_pairs = nrm.module.params.get("_not_in_sync_pairs", [])

        deployment_info = {
            "msg": "CHECK MODE: Would save and deploy fabric configuration",
            "fabric": fabric_name,
            "deployment_needed": True,
            "changed": True,
            "would_deploy": True,
            "deployment_decision_factors": {
                "diff_has_changes": before != after,
                "pending_create_operations": len(pending_create),
                "pending_delete_operations": len(pending_delete),
                "not_in_sync_pairs": len(not_in_sync_pairs),
                "actual_changes": result.get("changed", False),
            },
            "planned_actions": [
                f"POST {VpcPairEndpoints.fabric_config_save(fabric_name)}",
                f"POST {VpcPairEndpoints.fabric_config_deploy(fabric_name, force_show_run=True)}",
            ],
        }
        return deployment_info

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
    results = Results()

    # Step 1: Save config
    save_path = VpcPairEndpoints.fabric_config_save(fabric_name)

    try:
        nd_v2.request(save_path, HttpVerbEnum.POST, {})

        results.response_current = {
            "RETURN_CODE": nd_v2.status,
            "METHOD": "POST",
            "REQUEST_PATH": save_path,
            "MESSAGE": "Config saved successfully",
            "DATA": {},
        }
        results.result_current = {"success": True, "changed": True}
        results.register_api_call()

    except NDModuleError as error:
        if _is_non_fatal_config_save_error(error):
            # Known platform limitation warning; continue to deploy step.
            nrm.module.warn(f"Config save failed: {error.msg}")

            results.response_current = {
                "RETURN_CODE": error.status if error.status else -1,
                "MESSAGE": error.msg,
                "REQUEST_PATH": save_path,
                "METHOD": "POST",
                "DATA": {},
            }
            results.result_current = {"success": True, "changed": False}
            results.register_api_call()
        else:
            # Unknown config-save failures are fatal.
            results.response_current = {
                "RETURN_CODE": error.status if error.status else -1,
                "MESSAGE": error.msg,
                "REQUEST_PATH": save_path,
                "METHOD": "POST",
                "DATA": {},
            }
            results.result_current = {"success": False, "changed": False}
            results.register_api_call()
            results.build_final_result()
            final_result = dict(results.final_result)
            final_msg = final_result.pop("msg", f"Config save failed: {error.msg}")
            _raise_vpc_error(msg=final_msg, **final_result)

    # Step 2: Deploy
    deploy_path = VpcPairEndpoints.fabric_config_deploy(fabric_name, force_show_run=True)

    try:
        nd_v2.request(deploy_path, HttpVerbEnum.POST, {})

        results.response_current = {
            "RETURN_CODE": nd_v2.status,
            "METHOD": "POST",
            "REQUEST_PATH": deploy_path,
            "MESSAGE": "Deployment successful",
            "DATA": {},
        }
        results.result_current = {"success": True, "changed": True}
        results.register_api_call()

    except NDModuleError as error:
        results.response_current = {
            "RETURN_CODE": error.status if error.status else -1,
            "MESSAGE": error.msg,
            "REQUEST_PATH": deploy_path,
            "METHOD": "POST",
            "DATA": {},
        }
        results.result_current = {"success": False, "changed": False}
        results.register_api_call()

        # Build final result and fail
        results.build_final_result()
        final_result = dict(results.final_result)
        final_msg = final_result.pop("msg", "Fabric deployment failed")
        _raise_vpc_error(msg=final_msg, **final_result)

    # Build final result
    results.build_final_result()
    return results.final_result
