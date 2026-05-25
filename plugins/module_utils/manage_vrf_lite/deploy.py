# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError


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
    """Return True only when actual config changes were applied.

    Deploying against the controller when no configuration changed would
    violate Ansible's idempotency contract.  A VRF that is still PENDING
    from a previous run is a controller-side timing concern; the module
    re-deploys only when the user's intent has actually been modified.
    """
    if result.get("changed"):
        return True

    changed_vrfs = module.params.get("_changed_vrfs") or []
    return bool(changed_vrfs)
