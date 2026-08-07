# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    _resolve_serial,
    get_config_actions,
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


def _scoped_pending_deploy_targets(module: Any) -> list[dict[str, str]]:
    """Return deploy-enabled pending targets covered by this invocation.

    Controller-derived pending rows are intentionally scoped by the requested
    resource state and config. This lets a later identical run deploy its own
    staged intent without sweeping unrelated pending work from the fabric.
    """
    pending_targets = module.params.get("_pending_deploy_targets") or []
    if not isinstance(pending_targets, list):
        return []

    state = module.params.get("_vrf_lite_requested_state") or module.params.get("state", "merged")
    config = _deploy_intent_config(module)
    configured_vrfs: set[str] = set()
    configured_pairs: set[tuple[str, str]] = set()
    delete_all_vrfs: set[str] = set()

    for item in config:
        if not isinstance(item, dict):
            continue
        vrf_name = vrf_name_from_config_item(item)
        if not vrf_name:
            continue
        configured_vrfs.add(vrf_name)
        attachments = item.get("attach")
        if state == "deleted" and not attachments:
            delete_all_vrfs.add(vrf_name)
        if not isinstance(attachments, list):
            continue
        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue
            switch_id = attachment.get("ip_address") or attachment.get("switch_ip") or attachment.get("serial_number")
            if switch_id:
                configured_pairs.add((vrf_name, _resolve_serial(module, switch_id)))

    enabled_pairs, disabled_pairs, disabled_vrfs = _deployment_intent(module)
    scoped: dict[tuple[str, str], dict[str, str]] = {}
    for target in pending_targets:
        if not isinstance(target, dict):
            continue
        vrf_name = str(target.get("vrf_name") or "").strip()
        switch_id = _resolve_serial(module, target.get("switch_ip"))
        operation = str(target.get("operation") or "").strip().lower()
        if not vrf_name or not switch_id or operation not in ("write", "delete"):
            continue

        pair = (vrf_name, switch_id)
        in_scope = False
        if state == "merged":
            in_scope = pair in configured_pairs
        elif state == "replaced":
            in_scope = vrf_name in configured_vrfs
        elif state == "overridden":
            in_scope = True
        elif state == "deleted":
            in_scope = operation == "delete" and (vrf_name in delete_all_vrfs or pair in configured_pairs)

        if not in_scope or vrf_name in disabled_vrfs or pair in disabled_pairs:
            continue
        if operation == "write" and pair not in enabled_pairs:
            continue

        scoped[pair] = {
            "vrf_name": vrf_name,
            "switch_ip": switch_id,
            "operation": operation,
        }

    return [scoped[key] for key in sorted(scoped)]


def _is_non_fatal_config_save_error(error: NDModuleError) -> bool:
    # TODO(4.2.1) vrf-lite-configsave-500-nonfatal: ND returns HTTP 500 for a
    # non-fatal vPC sanity condition on configSave instead of a success/no-op
    # status, so the message is sniffed to swallow it. Remove once the
    # controller returns a correct status for this condition (see bug-tracker
    # vault note).
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
    """Return whether this run must save changes or deploy staged intent."""
    if result.get("changed"):
        return True

    changed_vrfs = module.params.get("_changed_vrfs") or []
    if changed_vrfs:
        return True

    config_actions = get_config_actions(module.params)
    return bool(config_actions.get("deploy") and _scoped_pending_deploy_targets(module))


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
