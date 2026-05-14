# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    append_runtime_warning,
    get_config_actions,
    _raise_vrf_lite_error,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule as NDModuleV2


def _target_vrfs_for_deploy(module: Any) -> list[str]:
    target: set[str] = set()
    for item in module.params.get("config") or []:
        if not isinstance(item, dict):
            continue
        vrf_name = item.get("vrf_name") or item.get("vrfName")
        if not vrf_name:
            continue

        deploy = item.get("deploy")
        if deploy is False:
            continue
        if deploy is True:
            target.add(str(vrf_name).strip())
            continue

        attachments = item.get("attach") or []
        if not isinstance(attachments, list) or not attachments:
            target.add(str(vrf_name).strip())
            continue

        if any(isinstance(attachment, dict) and attachment.get("deploy") is not False for attachment in attachments):
            target.add(str(vrf_name).strip())
            continue

        if not any(isinstance(attachment, dict) for attachment in attachments):
            target.add(str(vrf_name).strip())
            continue

    return sorted(target)


def _is_non_fatal_config_save_error(error: NDModuleError) -> bool:
    if not isinstance(error, NDModuleError):
        return False
    if error.status != 500:
        return False

    message = (error.msg or "").lower()
    signatures = (
        "vpc fabric peering is not supported",
        "unexpected error generating vpc configuration",
        "vpcsanitycheck",
    )
    return any(signature in message for signature in signatures)


def _needs_deployment(result: dict[str, Any], module: Any) -> bool:
    if result.get("changed"):
        return True

    changed_vrfs = module.params.get("_changed_vrfs") or []
    if changed_vrfs:
        return True

    not_in_sync = set(module.params.get("_not_in_sync_vrfs") or [])
    if not not_in_sync:
        return False

    target_vrfs = set(_target_vrfs_for_deploy(module))
    if not target_vrfs:
        return False

    return len(target_vrfs & not_in_sync) > 0


def custom_vrf_lite_deploy(module: Any, fabric_name: str, result: dict[str, Any]) -> dict[str, Any]:
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
            _raise_vrf_lite_error(msg="VRF deployment failed: {0}".format(error.msg), **error_dict)

    return {
        "msg": "VRF Lite config actions completed",
        "deployment_needed": True,
        "changed": changed,
        "config_actions": config_actions,
        "target_vrfs": target_vrfs,
        "planned_actions": planned_actions,
        "response": responses,
    }
