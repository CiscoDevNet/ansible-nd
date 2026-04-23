# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import ipaddress
from typing import Any, Optional
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcActionEnum,
    VpcFieldNames,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.validation import (
    _is_switch_in_vpc_pair,
    _validate_fabric_switches,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import (
    get_config_actions,
    get_verify_timeout,
    _raise_vpc_error,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runtime_endpoints import (
    VpcPairEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runtime_payloads import (
    _get_api_field_value,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule as NDModuleV2,
    NDModuleError,
)


def _as_int_or_zero(value: Any) -> int:
    """
    Safely parse integer-like values used in overview status counters.

    Args:
        value: Any scalar value from API response.

    Returns:
        Parsed integer, or 0 when parsing fails.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_sync_status(value: Any) -> Optional[str]:
    """
    Normalize sync-status values by removing separator variants.

    Converts inputs such as "Out of Sync", "out_of_sync", and "out-of-sync"
    into a stable compact token for matching.
    """
    if value is None:
        return None

    text = str(value).strip().lower()
    if not text:
        return None

    return text.replace(" ", "").replace("_", "").replace("-", "")


def _sync_status_to_bool(value: Any) -> Optional[bool]:
    """
    Convert common sync status values to booleans.

    Returns True for in-sync signals, False for pending/out-of-sync/failure
    signals, and None when the value is unknown.
    """
    if isinstance(value, bool):
        return value

    normalized = _normalize_sync_status(value)
    if not normalized:
        return None

    if normalized in ("true", "insync"):
        return True
    if normalized in ("false", "pending", "outofsync", "notinsync", "failed", "error"):
        return False
    return None


def _is_switch_config_in_sync(switch_data: Optional[dict[str, Any]]) -> Optional[bool]:
    """
    Determine switch-level config sync state from switch inventory payload.

    Args:
        switch_data: Switch payload from /fabric/switches lookup.

    Returns:
        True when config sync is explicitly in-sync, False when explicitly
        non-sync/pending, or None when state is unavailable/unknown.
    """
    if not isinstance(switch_data, dict):
        return None

    additional = switch_data.get("additionalData")
    if isinstance(additional, dict):
        status = additional.get("configSyncStatus")
    else:
        status = switch_data.get("configSyncStatus")

    return _sync_status_to_bool(status)


def _is_pair_in_sync_from_overview(
    nd_v2: Any,
    fabric_name: str,
    switch_id: str,
    timeout: Optional[int] = None,
) -> Optional[bool]:
    """
    Determine vPC pair sync state using vpcPairOverview (componentType=full).

    This is used for deployment gating:
    - False => pair exists but has pending/out-of-sync signals (deploy recommended)
    - True => pair appears fully in-sync
    - None => unknown/unavailable; caller should not force deploy from this signal

    Args:
        nd_v2: NDModuleV2 instance.
        fabric_name: Fabric name.
        switch_id: Switch serial number.
        timeout: Optional timeout override.

    Returns:
        Optional bool as described above.
    """
    if not fabric_name or not switch_id:
        return None

    if timeout is None:
        timeout = get_verify_timeout(nd_v2.module)

    path = VpcPairEndpoints.switch_vpc_overview(
        fabric_name=fabric_name,
        switch_id=switch_id,
        component_type="full",
    )

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        response = nd_v2.request(path, HttpVerbEnum.GET)
    except NDModuleError as error:
        error_msg = (error.msg or "").lower()
        if error.status in (400, 404) and "not a part of vpc pair" in error_msg:
            return None
        return None
    except Exception:
        return None
    finally:
        rest_send.restore_settings()

    if not isinstance(response, dict):
        return None

    def _has_non_sync(counts: dict[str, Any]) -> bool:
        if not isinstance(counts, dict):
            return False
        return any(_as_int_or_zero(counts.get(key)) > 0 for key in ("pending", "outOfSync", "inProgress"))

    # Inventory sync status is the strongest direct signal.
    inventory = response.get(VpcFieldNames.INVENTORY)
    if isinstance(inventory, dict):
        sync_status = inventory.get("syncStatus")
        if isinstance(sync_status, dict):
            if _has_non_sync(sync_status):
                return False
            # If syncStatus exists and no non-sync counters are present,
            # consider it in-sync.
            return True
        scalar_sync_state = _sync_status_to_bool(sync_status)
        if scalar_sync_state is not None:
            return scalar_sync_state

    # Overlay counters can still indicate pending/out-of-sync conditions.
    overlay = response.get(VpcFieldNames.OVERLAY)
    if isinstance(overlay, dict):
        network_count = overlay.get(VpcFieldNames.NETWORK_COUNT)
        vrf_count = overlay.get(VpcFieldNames.VRF_COUNT)
        if _has_non_sync(network_count) or _has_non_sync(vrf_count):
            return False
        if isinstance(network_count, dict) or isinstance(vrf_count, dict):
            return True

    return None


def _is_external_fabric(nd_v2: Any, fabric_name: str, module: Any) -> bool:
    """
    Best-effort external-fabric detection from fabric details endpoint.

    Falls back to fabric name hint when details lookup is unavailable.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        module: AnsibleModule for warnings

    Returns:
        True when fabric appears to be external, else False.
    """
    fallback = "external" in str(fabric_name).lower()
    details_path = f"/api/v1/manage/fabrics/{quote(fabric_name, safe='')}"

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = get_verify_timeout(module)
    try:
        details = nd_v2.request(details_path, HttpVerbEnum.GET)
    except Exception as exc:
        module.warn(f"Unable to determine fabric type for '{fabric_name}': " f"{str(exc).splitlines()[0]}. Using fallback detection.")
        return fallback
    finally:
        rest_send.restore_settings()

    if not isinstance(details, dict):
        return fallback

    candidates: list[str] = []
    for key in ("fabricType", "fabricTechnology", "type", "category"):
        value = details.get(key)
        if isinstance(value, str):
            candidates.append(value.lower())

    management = details.get("management")
    if isinstance(management, dict):
        mgmt_type = management.get("type")
        if isinstance(mgmt_type, str):
            candidates.append(mgmt_type.lower())

    properties = details.get("properties")
    if isinstance(properties, dict):
        for key in ("fabricType", "fabricTechnology", "type"):
            value = properties.get(key)
            if isinstance(value, str):
                candidates.append(value.lower())

    if not candidates:
        return fallback

    return any("external" in token for token in candidates)


def _get_recommendation_details(nd_v2: Any, fabric_name: str, switch_id: str, timeout: Optional[int] = None) -> Optional[dict[str, Any]]:
    """
    Get VPC pair recommendation details from ND for a specific switch.

    Returns peer switch info and useVirtualPeerLink status.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        timeout: Optional timeout override (uses module param if not specified)

    Returns:
        Dict with peer info or None if not found (404)

    Raises:
        NDModuleError: On API errors other than 404 (timeouts, 500s, etc.)
    """
    # Validate inputs to prevent injection
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")
    if not switch_id or not isinstance(switch_id, str) or len(switch_id) < 3:
        raise ValueError(f"Invalid switch_id: {switch_id}")

    try:
        path = VpcPairEndpoints.switch_vpc_recommendations(fabric_name, switch_id)

        # Use query timeout from module params or override
        if timeout is None:
            timeout = get_verify_timeout(nd_v2.module)

        rest_send = nd_v2._get_rest_send()
        rest_send.save_settings()
        rest_send.timeout = timeout
        try:
            vpc_recommendations = nd_v2.request(path, HttpVerbEnum.GET)
        finally:
            rest_send.restore_settings()

        if vpc_recommendations is None or vpc_recommendations == {}:
            return None

        # Validate response structure and look for current peer
        if isinstance(vpc_recommendations, list):
            for sw in vpc_recommendations:
                # Validate each entry
                if not isinstance(sw, dict):
                    nd_v2.module.warn(f"Skipping invalid recommendation entry for switch {switch_id}: " f"expected dict, got {type(sw).__name__}")
                    continue

                # Check for current peer indicators
                if sw.get(VpcFieldNames.CURRENT_PEER) or sw.get(VpcFieldNames.IS_CURRENT_PEER):
                    # Validate required fields exist
                    if VpcFieldNames.SERIAL_NUMBER not in sw:
                        nd_v2.module.warn(f"Recommendation missing serialNumber field for switch {switch_id}")
                        continue
                    return sw
        elif vpc_recommendations:
            # Unexpected response format
            nd_v2.module.warn(f"Unexpected recommendation response format for switch {switch_id}: " f"expected list, got {type(vpc_recommendations).__name__}")

        return None
    except NDModuleError as error:
        # Handle expected error codes gracefully
        if error.status == 404:
            # No recommendations exist (expected for switches without VPC)
            return None
        elif error.status == 500:
            # Server error - recommendation API may be unstable
            # Treat as "no recommendations available" to allow graceful degradation
            nd_v2.module.warn(f"VPC recommendation API returned 500 error for switch {switch_id} - " f"treating as no recommendations available")
            return None
        # Let other errors (timeouts, rate limits) propagate
        raise


def _extract_vpc_pairs_from_list_response(vpc_pairs_response: Any) -> list[dict[str, Any]]:
    """
    Extract VPC pair list entries from /vpcPairs response payload.

    Supports common response wrappers used by ND API.

    Args:
        vpc_pairs_response: Raw API response dict from /vpcPairs list endpoint

    Returns:
        List of dicts with switchId, peerSwitchId, useVirtualPeerLink keys.
        Empty list if response is invalid or contains no pairs.
    """
    if not isinstance(vpc_pairs_response, dict):
        return []

    candidates = None
    for key in (VpcFieldNames.VPC_PAIRS, "items", VpcFieldNames.DATA):
        value = vpc_pairs_response.get(key)
        if isinstance(value, list):
            candidates = value
            break

    if not isinstance(candidates, list):
        return []

    extracted_pairs = []
    for item in candidates:
        if not isinstance(item, dict):
            continue

        switch_id = item.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = item.get(VpcFieldNames.PEER_SWITCH_ID)

        # Handle alternate response shape if switch IDs are nested under "switch"/"peerSwitch"
        if isinstance(switch_id, dict) and isinstance(peer_switch_id, dict):
            switch_id = switch_id.get("switch")
            peer_switch_id = peer_switch_id.get("peerSwitch")

        if not switch_id or not peer_switch_id:
            continue

        extracted_pair = {
            VpcFieldNames.SWITCH_ID: switch_id,
            VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
            VpcFieldNames.USE_VIRTUAL_PEER_LINK: item.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, False),
            VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
        }
        if VpcFieldNames.VPC_PAIR_DETAILS in item:
            extracted_pair[VpcFieldNames.VPC_PAIR_DETAILS] = item.get(VpcFieldNames.VPC_PAIR_DETAILS)

        extracted_pairs.append(extracted_pair)

    return extracted_pairs


def _get_direct_vpc_pair(
    nd_v2: Any,
    fabric_name: str,
    switch_id: str,
    timeout: Optional[int] = None,
) -> Optional[dict[str, Any]]:
    """
    Best-effort per-switch /vpcPair lookup.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        timeout: Optional timeout override (uses module query timeout policy if not specified)

    Returns:
        Direct vPC pair payload dict when available; otherwise None.
    """
    if not fabric_name or not switch_id:
        return None

    if timeout is None:
        timeout = get_verify_timeout(nd_v2.module)

    path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)
    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        direct_vpc = nd_v2.request(path, HttpVerbEnum.GET)
    except (NDModuleError, Exception):
        return None
    finally:
        rest_send.restore_settings()

    if isinstance(direct_vpc, dict):
        return direct_vpc
    return None


def _enrich_pairs_from_direct_vpc(
    nd_v2: Any,
    fabric_name: str,
    pairs: list[dict[str, Any]],
    timeout: Optional[int] = None,
) -> list[dict[str, Any]]:
    """
    Enrich pair fields from per-switch /vpcPair endpoint when available.

    The /vpcPairs list response may omit fields like useVirtualPeerLink.
    This helper preserves lightweight list discovery while improving field
    accuracy for gathered output.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        pairs: List of pair dicts from list endpoint
        timeout: Per-switch query timeout in seconds

    Returns:
        List of enriched pair dicts with updated field values from direct queries.
        Original values preserved when direct query fails.
    """
    if not pairs:
        return []

    if timeout is None:
        timeout = get_verify_timeout(nd_v2.module)

    enriched_pairs: list[dict[str, Any]] = []
    for pair in pairs:
        enriched = dict(pair)
        switch_id = enriched.get(VpcFieldNames.SWITCH_ID)
        if not switch_id:
            enriched_pairs.append(enriched)
            continue

        direct_vpc = _get_direct_vpc_pair(
            nd_v2=nd_v2,
            fabric_name=fabric_name,
            switch_id=switch_id,
            timeout=timeout,
        )

        if isinstance(direct_vpc, dict):
            peer_switch_id = direct_vpc.get(VpcFieldNames.PEER_SWITCH_ID)
            if peer_switch_id:
                enriched[VpcFieldNames.PEER_SWITCH_ID] = peer_switch_id

            use_virtual_peer_link = _get_api_field_value(
                direct_vpc,
                "useVirtualPeerLink",
                enriched.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK),
            )
            if use_virtual_peer_link is not None:
                enriched[VpcFieldNames.USE_VIRTUAL_PEER_LINK] = use_virtual_peer_link

            enriched[VpcFieldNames.VPC_ACTION] = VpcActionEnum.PAIR.value
            if VpcFieldNames.VPC_PAIR_DETAILS in direct_vpc:
                enriched[VpcFieldNames.VPC_PAIR_DETAILS] = direct_vpc.get(VpcFieldNames.VPC_PAIR_DETAILS)

        enriched_pairs.append(enriched)

    return enriched_pairs


def _filter_stale_vpc_pairs(
    nd_v2: Any,
    fabric_name: str,
    pairs: list[dict[str, Any]],
    module: Any,
) -> list[dict[str, Any]]:
    """
    Remove stale pairs using overview membership checks.

    `/vpcPairs` can briefly lag after unpair operations. We perform a lightweight
    best-effort membership check and drop entries that are explicitly reported as
    not part of a vPC pair.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        pairs: List of pair dicts to validate
        module: AnsibleModule instance for warnings

    Returns:
        Filtered list of pair dicts with stale entries removed.
    """
    if not pairs:
        return []

    pruned_pairs: list[dict[str, Any]] = []
    for pair in pairs:
        switch_id = pair.get(VpcFieldNames.SWITCH_ID)
        if not switch_id:
            pruned_pairs.append(pair)
            continue

        membership = _is_switch_in_vpc_pair(
            nd_v2,
            fabric_name,
            switch_id,
            timeout=get_verify_timeout(module),
        )
        if membership is False:
            module.warn(f"Excluding stale vPC pair entry for switch {switch_id} " "because overview reports it is not in a vPC pair.")
            continue
        pruned_pairs.append(pair)

    return pruned_pairs


def _filter_vpc_pairs_by_requested_config(
    pairs: list[dict[str, Any]],
    config: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Filter queried VPC pairs by explicit pair keys provided in gathered config.

    If gathered config is empty or does not contain complete switch pairs, return
    the unfiltered pair list.

    Args:
        pairs: List of discovered pair dicts from API
        config: List of user-requested pair dicts from playbook

    Returns:
        Filtered list of pair dicts matching requested config keys.
        Returns full pair list when config is empty or has no complete pairs.
    """
    # TODO: Revisit promoting this pair-key filtering into a shared helper if
    # similar gathered-filter logic is needed by other modules.
    if not pairs or not config:
        return list(pairs or [])

    requested_pair_keys = set()
    for item in config:
        switch_id = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)
        if switch_id and peer_switch_id:
            requested_pair_keys.add(tuple(sorted([switch_id, peer_switch_id])))

    if not requested_pair_keys:
        return list(pairs)

    filtered_pairs = []
    for item in pairs:
        switch_id = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)
        if switch_id and peer_switch_id:
            pair_key = tuple(sorted([switch_id, peer_switch_id]))
            if pair_key in requested_pair_keys:
                filtered_pairs.append(item)

    return filtered_pairs


def _is_ip_literal(value: Any) -> bool:
    """
    Return True when value is a valid IPv4/IPv6 literal string.

    Args:
        value: Any value to check

    Returns:
        True if value is a valid IP address string, False otherwise.
    """
    # TODO: Move to a shared network helper if additional modules need IP-literal detection.
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _resolve_config_switch_ips(
    nd_v2: Any,
    module: Any,
    fabric_name: str,
    config: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, str], Optional[dict[str, dict[str, Any]]]]:
    """
    Resolve switch identifiers from management IPs to serial numbers.

    If config contains IP literals in switch fields, query fabric switch inventory
    and replace those IPs with serial numbers in both snake_case and API keys.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        module: AnsibleModule instance for warnings
        fabric_name: Fabric name for inventory lookup
        config: List of config item dicts (may contain IP-based switch IDs)

    Returns:
        Tuple of (normalized_config, ip_to_sn_mapping, fabric_switches_dict).
        Returns (original_config, {}, None) when no IPs are found.
    """
    if not config:
        return list(config or []), {}, None

    has_ip_inputs = False
    for item in config:
        if not isinstance(item, dict):
            continue
        for key in ("switch_id", VpcFieldNames.SWITCH_ID, "peer_switch_id", VpcFieldNames.PEER_SWITCH_ID):
            if _is_ip_literal(item.get(key)):
                has_ip_inputs = True
                break
        if has_ip_inputs:
            break

    if not has_ip_inputs:
        return list(config), {}, None

    fabric_switches = _validate_fabric_switches(nd_v2, fabric_name)
    ip_to_sn = {
        str(sw.get(VpcFieldNames.FABRIC_MGMT_IP)).strip(): sw.get(VpcFieldNames.SERIAL_NUMBER)
        for sw in fabric_switches.values()
        if sw.get(VpcFieldNames.FABRIC_MGMT_IP) and sw.get(VpcFieldNames.SERIAL_NUMBER)
    }

    if not ip_to_sn:
        module.warn(
            "Switch IP identifiers were provided in config, but no "
            "fabricManagementIp to serialNumber mapping was discovered. "
            "Continuing with identifiers as provided."
        )
        return list(config), {}, fabric_switches

    normalized_config: list[dict[str, Any]] = []
    resolved_inputs: dict[str, str] = {}
    unresolved_inputs = set()

    for item in config:
        if not isinstance(item, dict):
            normalized_config.append(item)
            continue

        normalized_item = dict(item)
        for snake_key, api_key in (
            ("switch_id", VpcFieldNames.SWITCH_ID),
            ("peer_switch_id", VpcFieldNames.PEER_SWITCH_ID),
        ):
            raw_identifier = normalized_item.get(snake_key)
            if raw_identifier is None:
                raw_identifier = normalized_item.get(api_key)
            if raw_identifier is None:
                continue

            resolved_identifier = raw_identifier
            if _is_ip_literal(raw_identifier):
                ip_value = str(raw_identifier).strip()
                mapped_serial = ip_to_sn.get(ip_value)
                if mapped_serial:
                    resolved_identifier = mapped_serial
                    resolved_inputs[ip_value] = mapped_serial
                else:
                    unresolved_inputs.add(ip_value)

            normalized_item[snake_key] = resolved_identifier
            normalized_item[api_key] = resolved_identifier

        normalized_config.append(normalized_item)

    for ip_value, serial in sorted(resolved_inputs.items()):
        module.warn(f"Resolved playbook switch IP {ip_value} to switch serial {serial} " f"for fabric {fabric_name}.")

    if unresolved_inputs:
        module.warn(
            "Could not resolve playbook switch IP(s) to serial numbers for "
            f"fabric {fabric_name}: {', '.join(sorted(unresolved_inputs))}. "
            "Those values will be processed as provided."
        )

    return normalized_config, ip_to_sn, fabric_switches


def normalize_vpc_playbook_switch_identifiers(
    module: Any,
    nd_v2: Optional[Any] = None,
    fabric_name: Optional[str] = None,
    state: Optional[str] = None,
) -> Optional[dict[str, dict[str, Any]]]:
    """
    Normalize playbook switch identifiers from management IPs to serial numbers.

    Updates module params in-place:
    - merged/replaced/overridden/deleted: module.params["config"]
    - gathered: module.params["_gather_filter_config"]

    Also merges resolved IP->serial mappings into module.params["_ip_to_sn_mapping"].

    Args:
        module: AnsibleModule instance
        nd_v2: Optional NDModuleV2 instance (created internally if None)
        fabric_name: Optional fabric name override (defaults to module param)
        state: Optional state override (defaults to module param)

    Returns:
        Optional[dict[str, dict[str, Any]]]: Preloaded fabric switches map when queried, else None.
    """
    effective_state = state or module.params.get("state", "merged")
    effective_fabric = fabric_name if fabric_name is not None else module.params.get("fabric_name")

    if effective_state == "gathered":
        config = module.params.get("_gather_filter_config") or []
    else:
        config = module.params.get("config") or []

    if nd_v2 is None:
        nd_v2 = NDModuleV2(module)

    config, resolved_ip_to_sn, preloaded_fabric_switches = _resolve_config_switch_ips(
        nd_v2=nd_v2,
        module=module,
        fabric_name=effective_fabric,
        config=config,
    )

    if effective_state == "gathered":
        module.params["_gather_filter_config"] = list(config)
    else:
        module.params["config"] = list(config)

    if resolved_ip_to_sn:
        existing_map = module.params.get("_ip_to_sn_mapping") or {}
        merged_map = dict(existing_map) if isinstance(existing_map, dict) else {}
        merged_map.update(resolved_ip_to_sn)
        module.params["_ip_to_sn_mapping"] = merged_map

    return preloaded_fabric_switches


def custom_vpc_query_all(nrm: Any) -> list[dict[str, Any]]:
    """
    Query existing VPC pairs with state-aware enrichment.

    Flow:
    - Base query from /vpcPairs list (always attempted first)
    - gathered/deleted: use lightweight list-only data when available
    - merged/replaced/overridden: enrich with switch inventory and recommendation
      APIs to build have/pending_create/pending_delete sets

    Args:
        nrm: VpcPairStateMachine or query context with .module attribute

    Returns:
        List of existing pair dicts for NDConfigCollection initialization.
        Also populates module params: _have, _pending_create, _pending_delete,
        _fabric_switches, _fabric_switches_count, _ip_to_sn_mapping.

    Raises:
        VpcPairResourceError: On unrecoverable query failures
    """
    # TODO: Split this workflow into smaller helpers (list query, fallback discovery,
    # and state-specific enrichment) so the high-level flow stays easy to follow.
    fabric_name = nrm.module.params.get("fabric_name")

    if not fabric_name or not isinstance(fabric_name, str) or not fabric_name.strip():
        raise ValueError(f"fabric_name must be a non-empty string. Got: {fabric_name!r}")

    state = nrm.module.params.get("state", "merged")
    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
    if state in ("merged", "replaced", "overridden"):
        nrm.module.params["_is_external_fabric"] = _is_external_fabric(
            nd_v2=nd_v2,
            fabric_name=fabric_name,
            module=nrm.module,
        )
    else:
        nrm.module.params["_is_external_fabric"] = False
    preloaded_fabric_switches = normalize_vpc_playbook_switch_identifiers(
        module=nrm.module,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        state=state,
    )

    if state == "gathered":
        config = nrm.module.params.get("_gather_filter_config") or []
    else:
        config = nrm.module.params.get("config") or []

    def _set_lightweight_context(
        lightweight_have: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        nrm.module.params["_fabric_switches"] = []
        nrm.module.params["_fabric_switches_count"] = 0
        existing_map = nrm.module.params.get("_ip_to_sn_mapping")
        nrm.module.params["_ip_to_sn_mapping"] = dict(existing_map) if isinstance(existing_map, dict) else {}
        nrm.module.params["_have"] = lightweight_have
        nrm.module.params["_pending_create"] = []
        nrm.module.params["_pending_delete"] = []
        nrm.module.params["_not_in_sync_pairs"] = []
        return lightweight_have

    try:
        # Step 1: Base query from list endpoint (/vpcPairs)
        have = []
        list_query_succeeded = False
        try:
            list_path = VpcPairEndpoints.vpc_pairs_list(fabric_name)
            rest_send = nd_v2._get_rest_send()
            rest_send.save_settings()
            rest_send.timeout = get_verify_timeout(nrm.module)
            try:
                vpc_pairs_response = nd_v2.request(list_path, HttpVerbEnum.GET)
            finally:
                rest_send.restore_settings()
            have.extend(_extract_vpc_pairs_from_list_response(vpc_pairs_response))
            list_query_succeeded = True
        except Exception as list_error:
            nrm.module.warn(f"VPC pairs list query failed for fabric {fabric_name}: " f"{str(list_error).splitlines()[0]}.")

        # Lightweight path for gathered and explicit-pair delete workflows.
        if state in ("gathered", "deleted"):
            if list_query_succeeded:
                if state == "gathered":
                    have = _filter_vpc_pairs_by_requested_config(have, config)
                    have = _enrich_pairs_from_direct_vpc(
                        nd_v2=nd_v2,
                        fabric_name=fabric_name,
                        pairs=have,
                        timeout=get_verify_timeout(nrm.module),
                    )
                    have = _filter_stale_vpc_pairs(
                        nd_v2=nd_v2,
                        fabric_name=fabric_name,
                        pairs=have,
                        module=nrm.module,
                    )
                    if have:
                        return _set_lightweight_context(lightweight_have=have)
                    nrm.module.warn("vPC list query returned no active pairs for gathered workflow. Falling back to switch-level discovery.")
                elif have:
                    return _set_lightweight_context(have)
                elif config and list_query_succeeded:
                    nrm.module.warn("vPC list query returned no pairs for delete workflow. Falling back to switch-level discovery.")

            if not list_query_succeeded:
                nrm.module.warn("Skipping switch-level discovery for read-only/delete workflow because the vPC list endpoint is unavailable.")

            if state == "gathered":
                if not list_query_succeeded:
                    nrm.module.warn("vPC list endpoint unavailable for gathered workflow. Falling back to switch-level discovery.")
            else:
                # Preserve explicit delete intent without full-fabric discovery.
                # This keeps delete deterministic and avoids expensive inventory calls.
                fallback_have = []
                for item in config:
                    switch_id_val = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
                    peer_switch_id_val = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)
                    if not switch_id_val or not peer_switch_id_val:
                        continue

                    use_vpl_val = item.get("use_virtual_peer_link")
                    if use_vpl_val is None:
                        use_vpl_val = item.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, False)

                    fallback_pair = {
                        VpcFieldNames.SWITCH_ID: switch_id_val,
                        VpcFieldNames.PEER_SWITCH_ID: peer_switch_id_val,
                        VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl_val,
                        VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
                    }
                    if VpcFieldNames.VPC_PAIR_DETAILS in item:
                        fallback_pair[VpcFieldNames.VPC_PAIR_DETAILS] = item.get(VpcFieldNames.VPC_PAIR_DETAILS)
                    fallback_have.append(fallback_pair)

                if fallback_have:
                    nrm.module.warn("Using requested delete config as fallback existing set because vPC list query failed.")
                    return _set_lightweight_context(fallback_have)

                nrm.module.warn("Delete config did not contain complete vPC pairs. No delete intents can be built from list-query fallback.")
                return _set_lightweight_context([])

        # Step 2 (write-state enrichment): Query and validate fabric switches.
        fabric_switches = preloaded_fabric_switches
        if fabric_switches is None:
            fabric_switches = _validate_fabric_switches(nd_v2, fabric_name)

        if not fabric_switches:
            nrm.module.warn(f"No switches found in fabric {fabric_name}")
            nrm.module.params["_fabric_switches"] = []
            nrm.module.params["_fabric_switches_count"] = 0
            nrm.module.params["_have"] = []
            nrm.module.params["_pending_create"] = []
            nrm.module.params["_pending_delete"] = []
            nrm.module.params["_not_in_sync_pairs"] = []
            return []

        # Keep only switch IDs for validation and serialize safely in module params.
        fabric_switches_list = list(fabric_switches.keys())
        nrm.module.params["_fabric_switches"] = fabric_switches_list
        nrm.module.params["_fabric_switches_count"] = len(fabric_switches)

        # Build IP-to-SN mapping (extract before dict is discarded).
        ip_to_sn = {
            sw.get(VpcFieldNames.FABRIC_MGMT_IP): sw.get(VpcFieldNames.SERIAL_NUMBER) for sw in fabric_switches.values() if VpcFieldNames.FABRIC_MGMT_IP in sw
        }
        existing_map = nrm.module.params.get("_ip_to_sn_mapping") or {}
        merged_map = dict(existing_map) if isinstance(existing_map, dict) else {}
        merged_map.update(ip_to_sn)
        nrm.module.params["_ip_to_sn_mapping"] = merged_map

        # Step 3: Track 3-state VPC pairs (have/pending_create/pending_delete).
        pending_create = []
        pending_delete = []
        processed_switches = set()

        config_switch_ids = set()
        for item in config:
            # Config items are normalized to snake_case in main().
            switch_id_val = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
            peer_switch_id_val = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)

            if switch_id_val:
                config_switch_ids.add(switch_id_val)
            if peer_switch_id_val:
                config_switch_ids.add(peer_switch_id_val)

        for switch_id, switch in fabric_switches.items():
            if switch_id in processed_switches:
                continue

            vpc_configured = switch.get(VpcFieldNames.VPC_CONFIGURED, False)
            vpc_data = switch.get("vpcData", {})

            if vpc_configured and vpc_data:
                peer_switch_id = vpc_data.get("peerSwitchId")
                processed_switches.add(switch_id)
                processed_switches.add(peer_switch_id)

                # For configured pairs, prefer direct vPC query as source of truth.
                direct_vpc = _get_direct_vpc_pair(
                    nd_v2=nd_v2,
                    fabric_name=fabric_name,
                    switch_id=switch_id,
                    timeout=get_verify_timeout(nrm.module),
                )

                if direct_vpc:
                    resolved_peer_switch_id = direct_vpc.get(VpcFieldNames.PEER_SWITCH_ID) or peer_switch_id
                    if resolved_peer_switch_id:
                        processed_switches.add(resolved_peer_switch_id)
                    use_vpl = _get_api_field_value(direct_vpc, "useVirtualPeerLink", False)
                    vpc_pair_details = direct_vpc.get(VpcFieldNames.VPC_PAIR_DETAILS)

                    # Direct /vpcPair can be stale for a short period after delete.
                    # Cross-check overview to avoid reporting stale active pairs.
                    membership = _is_switch_in_vpc_pair(
                        nd_v2,
                        fabric_name,
                        switch_id,
                        timeout=get_verify_timeout(nrm.module),
                    )
                    if membership is False:
                        pending_delete.append(
                            {
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: resolved_peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                            }
                        )
                    else:
                        current_pair = {
                            VpcFieldNames.SWITCH_ID: switch_id,
                            VpcFieldNames.PEER_SWITCH_ID: resolved_peer_switch_id,
                            VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                            VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
                        }
                        if vpc_pair_details is not None:
                            current_pair[VpcFieldNames.VPC_PAIR_DETAILS] = vpc_pair_details
                        have.append(current_pair)
                else:
                    # Direct query failed. Check overview membership first to classify
                    # transitional create-vs-delete states before recommendation fallback.
                    membership = _is_switch_in_vpc_pair(
                        nd_v2,
                        fabric_name,
                        switch_id,
                        timeout=get_verify_timeout(nrm.module),
                    )
                    if membership is True:
                        pending_create.append(
                            {
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: _get_api_field_value(vpc_data, "useVirtualPeerLink", False),
                            }
                        )
                        continue
                    if membership is False:
                        pending_delete.append(
                            {
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: False,
                            }
                        )
                        continue

                    # Membership unknown - fall back to recommendation.
                    try:
                        recommendation = _get_recommendation_details(nd_v2, fabric_name, switch_id)
                    except Exception as rec_error:
                        error_msg = str(rec_error).splitlines()[0]
                        nrm.module.warn(f"Recommendation query failed for switch {switch_id}: {error_msg}. " f"Unable to read configured vPC pair details.")
                        recommendation = None

                    if recommendation:
                        resolved_peer_switch_id = _get_api_field_value(recommendation, "serialNumber") or peer_switch_id
                        if resolved_peer_switch_id:
                            processed_switches.add(resolved_peer_switch_id)
                        use_vpl = _get_api_field_value(recommendation, "useVirtualPeerLink", False)
                        have.append(
                            {
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: resolved_peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                                VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
                            }
                        )
                    else:
                        # Unknown membership and no recommendation; conservatively
                        # classify as pending-delete-like transitional state.
                        pending_delete.append(
                            {
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: False,
                            }
                        )
            elif not config_switch_ids or switch_id in config_switch_ids:
                # For unconfigured switches, prefer direct vPC pair query first.
                direct_vpc = _get_direct_vpc_pair(
                    nd_v2=nd_v2,
                    fabric_name=fabric_name,
                    switch_id=switch_id,
                    timeout=get_verify_timeout(nrm.module),
                )

                if direct_vpc:
                    peer_switch_id = direct_vpc.get(VpcFieldNames.PEER_SWITCH_ID)
                    if peer_switch_id:
                        processed_switches.add(switch_id)
                        processed_switches.add(peer_switch_id)

                        use_vpl = _get_api_field_value(direct_vpc, "useVirtualPeerLink", False)
                        vpc_pair_details = direct_vpc.get(VpcFieldNames.VPC_PAIR_DETAILS)
                        membership = _is_switch_in_vpc_pair(
                            nd_v2,
                            fabric_name,
                            switch_id,
                            timeout=get_verify_timeout(nrm.module),
                        )
                        if membership is False:
                            pending_delete.append(
                                {
                                    VpcFieldNames.SWITCH_ID: switch_id,
                                    VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                    VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                                }
                            )
                        else:
                            current_pair = {
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                                VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
                            }
                            if vpc_pair_details is not None:
                                current_pair[VpcFieldNames.VPC_PAIR_DETAILS] = vpc_pair_details
                            have.append(current_pair)
                else:
                    # No direct pair. Do not use recommendation for pending-create
                    # classification. Use overview membership only.
                    membership = _is_switch_in_vpc_pair(
                        nd_v2,
                        fabric_name,
                        switch_id,
                        timeout=get_verify_timeout(nrm.module),
                    )
                    if membership is True:
                        # Peer may be unknown without direct pair payload. Keep this
                        # entry only when config can provide peer context.
                        peer_switch_id = None
                        for cfg in config:
                            cfg_sw = cfg.get(VpcFieldNames.SWITCH_ID) or cfg.get("switch_id")
                            cfg_peer = cfg.get(VpcFieldNames.PEER_SWITCH_ID) or cfg.get("peer_switch_id")
                            if cfg_sw == switch_id:
                                peer_switch_id = cfg_peer
                                break
                            if cfg_peer == switch_id:
                                peer_switch_id = cfg_sw
                                break
                        if peer_switch_id:
                            processed_switches.add(switch_id)
                            processed_switches.add(peer_switch_id)
                            pending_create.append(
                                {
                                    VpcFieldNames.SWITCH_ID: switch_id,
                                    VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                    VpcFieldNames.USE_VIRTUAL_PEER_LINK: False,
                                }
                            )

        # Step 4: Store all states for use in create/update/delete.
        nrm.module.params["_have"] = have
        nrm.module.params["_pending_create"] = pending_create
        nrm.module.params["_pending_delete"] = pending_delete

        # Build effective existing set for state reconciliation:
        # - Include only active pairs (have).
        # - Exclude pending-delete pairs from active set to avoid stale
        #   idempotence false-negatives right after unpair operations.
        #
        # Pending-create candidates are transitional and not confirmed active pairs.
        # Treating them as existing causes false no-change outcomes for create.
        pair_by_key = {}
        for pair in have:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID)
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID)
            if not switch_id or not peer_switch_id:
                continue
            key = tuple(sorted([switch_id, peer_switch_id]))
            pair_by_key[key] = pair

        for pair in pending_delete:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID)
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID)
            if not switch_id or not peer_switch_id:
                continue
            key = tuple(sorted([switch_id, peer_switch_id]))
            pair_by_key.pop(key, None)

        existing_pairs = list(pair_by_key.values())

        config_actions = get_config_actions(nrm.module)
        not_in_sync_pairs = []
        if config_actions.get("deploy", False):
            # Step 5: Build in-sync deployment signal from overview endpoint.
            # This supports the config_actions.deploy=true no-diff case:
            # pair exists, but is still not deployed/in-sync on controller.
            for pair in existing_pairs:
                switch_id = pair.get(VpcFieldNames.SWITCH_ID)
                peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID)
                if not switch_id or not peer_switch_id:
                    continue

                sync_state = _is_pair_in_sync_from_overview(
                    nd_v2=nd_v2,
                    fabric_name=fabric_name,
                    switch_id=switch_id,
                    timeout=get_verify_timeout(nrm.module),
                )
                # Overview sync counters can remain unchanged in some external
                # fabric flows. Fall back to switch-level config sync status.
                switch_sync = _is_switch_config_in_sync(fabric_switches.get(switch_id))
                peer_switch_sync = _is_switch_config_in_sync(fabric_switches.get(peer_switch_id))
                config_sync_state = None
                if switch_sync is False or peer_switch_sync is False:
                    config_sync_state = False
                elif switch_sync is True and peer_switch_sync is True:
                    config_sync_state = True

                # Resolve pair sync state from both overview and switch signals.
                #
                # Precedence:
                # - overview=True is authoritative in-sync (ignore switch noise).
                # - overview=False is authoritative not-in-sync (deploy needed).
                # - overview=None falls back to explicit switch out-of-sync.
                pair_not_in_sync = False
                if sync_state is True:
                    pair_not_in_sync = False
                elif sync_state is False:
                    pair_not_in_sync = True
                else:
                    pair_not_in_sync = config_sync_state is False

                if pair_not_in_sync:
                    not_in_sync_pairs.append(
                        {
                            VpcFieldNames.SWITCH_ID: switch_id,
                            VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                        }
                    )

        nrm.module.params["_not_in_sync_pairs"] = not_in_sync_pairs
        return existing_pairs

    except NDModuleError as error:
        error_dict = error.to_dict()
        if "msg" in error_dict:
            error_dict["api_error_msg"] = error_dict.pop("msg")
        _raise_vpc_error(msg=f"Failed to query VPC pairs: {error.msg}", fabric=fabric_name, **error_dict)
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(msg=f"Failed to query VPC pairs: {str(e)}", fabric=fabric_name, exception_type=type(e).__name__)
