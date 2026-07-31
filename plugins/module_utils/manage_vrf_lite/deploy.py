# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    _resolve_serial,
    vrf_name_from_config_item,
)


def _deploy_intent_config(module: Any) -> list[dict[str, Any]]:
    """Return the preserved nested playbook config used for deploy intent."""
    nested_config = module.params.get("_vrf_lite_nested_config")
    if isinstance(nested_config, list):
        return nested_config

    config = module.params.get("config")
    return config if isinstance(config, list) else []


def _deployment_intent(module: Any) -> tuple[set[tuple[str, str]], set[tuple[str, str]], set[str]]:
    """Return enabled pairs, disabled pairs, and disabled VRFs for deploy."""
    enabled_pairs: set[tuple[str, str]] = set()
    disabled_pairs: set[tuple[str, str]] = set()
    disabled_vrfs: set[str] = set()

    for item in _deploy_intent_config(module):
        if not isinstance(item, dict):
            continue
        vrf_name = vrf_name_from_config_item(item)
        if not vrf_name:
            continue

        vrf_deploy = item.get("deploy")
        attachments = item.get("attach")
        if isinstance(attachments, list):
            if vrf_deploy is False:
                disabled_vrfs.add(vrf_name)
                continue

            for attachment in attachments:
                if not isinstance(attachment, dict):
                    continue
                switch_id = attachment.get("ip_address") or attachment.get("switch_ip") or attachment.get("serial_number")
                if not switch_id:
                    continue
                pair = (vrf_name, _resolve_serial(module, switch_id))
                if vrf_deploy is True or attachment.get("deploy") is not False:
                    enabled_pairs.add(pair)
                else:
                    disabled_pairs.add(pair)
            continue

        # Direct callers may provide the already-flattened attachment shape.
        switch_id = item.get("switch_ip") or item.get("ip_address") or item.get("serial_number")
        if switch_id:
            pair = (vrf_name, _resolve_serial(module, switch_id))
            (disabled_pairs if vrf_deploy is False else enabled_pairs).add(pair)
        elif vrf_deploy is False:
            disabled_vrfs.add(vrf_name)

    return enabled_pairs, disabled_pairs, disabled_vrfs


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


def _changed_entries_from_preview(before: Any, after: Any) -> list[Any]:
    """Recover the change set from the before/after preview.

    In check mode the state machine's ``sent`` collection is empty by design,
    so the deploy scope is derived from the previewed states instead: created
    or updated rows are taken from ``after``; removed rows are taken from
    ``before``. This mirrors the create/update/delete set a real run records in
    ``sent`` (VRF Lite tracks deletes there too), so a check-mode plan reports
    the same VRFs a real run would deploy instead of an empty (false-green) scope.
    """
    changed: list[Any] = []
    for entry in after:
        if before.get_diff_config(entry) != "no_diff":
            changed.append(entry)
    after_keys = set(after.keys())
    for entry in before:
        if entry.get_identifier_value() not in after_keys:
            changed.append(entry)
    return changed
