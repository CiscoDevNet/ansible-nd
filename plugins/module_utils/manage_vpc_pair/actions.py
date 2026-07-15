# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    ComponentTypeSupportEnum,
    VpcActionEnum,
    VpcFieldNames,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import (
    _is_update_needed,
    _raise_vpc_error,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.validation import (
    _get_pairing_support_details,
    _validate_fabric_peering_support,
    _validate_switch_conflicts,
    _validate_switches_exist_in_fabric,
    _validate_vpc_pair_deletion,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runtime_endpoints import (
    VpcPairEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.runtime_payloads import (
    _build_vpc_pair_payload,
    _get_api_field_value,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule as NDModuleV2,
    NDModuleError,
)

_BLOCKED_FABRIC_TYPE_TOKENS_FOR_VPC_PAIR_DETAILS = {"vxlanibgp", "vxlanebgp"}


def _normalize_fabric_type_token(value: Any) -> str:
    """
    Normalize fabric-type strings for stable comparisons.

    Examples:
      - "vxlanIbgp" -> "vxlanibgp"
      - "VXLAN_EBGP" -> "vxlanebgp"
    """
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]", "", value.strip().lower())


def _first_line(value: Any) -> str:
    """Return first non-empty line from value converted to string."""
    text = str(value).strip()
    if not text:
        return "unknown error"
    lines = text.splitlines()
    return lines[0] if lines else "unknown error"


def _resolve_fabric_type_token(nd_v2: NDModuleV2, fabric_name: str, module: Any) -> str:
    """
    Resolve and cache the normalized fabric-type token for current run.

        The lookup is fail-open: when type cannot be determined, return empty string
        and skip the VXLAN iBGP/eBGP vpc_pair_details block to avoid false
        negatives caused by transient fabric-details lookup failures.

        Candidate precedence is deterministic and favors top-level fabric type
        fields over nested properties:
            1. details.fabricType / fabricTechnology / type / category
            2. details.management.type
            3. details.properties.fabricType / fabricTechnology / type
    """
    cached = module.params.get("_fabric_type_token")
    if isinstance(cached, str) and cached:
        return cached

    details_path = f"/api/v1/manage/fabrics/{quote(fabric_name, safe='')}"
    try:
        details = nd_v2.request(details_path, HttpVerbEnum.GET)
    except Exception as exc:
        module.warn(
            f"Unable to determine fabric type for '{fabric_name}' while validating "
            f"vpc_pair_details: {_first_line(exc)}"
        )
        return ""

    if not isinstance(details, dict):
        return ""

    candidates: list[str] = []
    for key in ("fabricType", "fabricTechnology", "type", "category"):
        value = details.get(key)
        if isinstance(value, str):
            candidates.append(value)

    management = details.get("management")
    if isinstance(management, dict):
        mgmt_type = management.get("type")
        if isinstance(mgmt_type, str):
            candidates.append(mgmt_type)

    properties = details.get("properties")
    if isinstance(properties, dict):
        for key in ("fabricType", "fabricTechnology", "type"):
            value = properties.get(key)
            if isinstance(value, str):
                candidates.append(value)

    for candidate in candidates:
        token = _normalize_fabric_type_token(candidate)
        if token:
            module.params["_fabric_type_token"] = token
            return token

    return ""


def _get_proposed_vpc_pair_details(proposed_config: Any) -> dict[str, Any] | None:
    """Return non-empty proposed vpc_pair_details (snake_case or API key)."""
    if not isinstance(proposed_config, dict):
        return None

    details = proposed_config.get("vpc_pair_details")
    if details is None:
        details = proposed_config.get(VpcFieldNames.VPC_PAIR_DETAILS)
    if not isinstance(details, dict) or not details:
        return None
    return details


def _validate_vpc_pair_details_fabric_support(
    nrm: Any,
    nd_v2: NDModuleV2,
    fabric_name: str,
    allow_lookup: bool = True,
) -> None:
    """
    Block vpc_pair_details on fabrics where it is not supported.

    Currently blocked for VXLAN iBGP/eBGP fabrics. Allowed for other fabric
    types (for example External/ISN-style deployments) where the controller
    supports the additional settings.
    """
    proposed_details = _get_proposed_vpc_pair_details(nrm.proposed_config)
    if proposed_details is None:
        return

    token = nrm.module.params.get("_fabric_type_token")
    if not isinstance(token, str) or not token:
        if not allow_lookup:
            return
        token = _resolve_fabric_type_token(nd_v2, fabric_name, nrm.module)

    normalized_token = _normalize_fabric_type_token(token)
    if normalized_token in _BLOCKED_FABRIC_TYPE_TOKENS_FOR_VPC_PAIR_DETAILS:
        _raise_vpc_error(
            msg=(
                "Invalid nd_manage_vpc_pair input: 'vpc_pair_details' is not supported "
                "for iBGP/eBGP VXLAN fabrics. Use only peer switch IDs and "
                "'use_virtual_peer_link' for this fabric type."
            ),
            fabric=fabric_name,
            fabric_type=token,
            unsupported_field="vpc_pair_details",
        )


def _build_compare_payloads(nrm: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Build normalized want/have payloads for idempotence comparisons.

    For external fabrics, force comparison to include vpcAction and
    vpcPairDetails on both sides so missing controller echoes do not trigger
    false updates.
    """
    is_external = nrm.module.params.get("_is_external_fabric", False)
    if is_external:
        want_payload = _build_vpc_pair_payload(nrm.proposed_config)
        if isinstance(nrm.proposed_config, dict):
            proposed_details = nrm.proposed_config.get(VpcFieldNames.VPC_PAIR_DETAILS)
            if proposed_details is None:
                proposed_details = nrm.proposed_config.get("vpc_pair_details")
            if proposed_details is not None:
                want_payload[VpcFieldNames.VPC_PAIR_DETAILS] = proposed_details
    elif hasattr(nrm.proposed_config, "model_dump"):
        want_payload = nrm.proposed_config.model_dump(by_alias=True, exclude_none=True)
    elif isinstance(nrm.proposed_config, dict):
        want_payload = dict(nrm.proposed_config)
    else:
        want_payload = {}
    if hasattr(nrm.existing_config, "model_dump"):
        have_payload = nrm.existing_config.model_dump(by_alias=True, exclude_none=True)
    elif isinstance(nrm.existing_config, dict):
        have_payload = dict(nrm.existing_config)
    else:
        have_payload = {}

    if is_external:
        want_payload.setdefault(VpcFieldNames.VPC_ACTION, VpcActionEnum.PAIR.value)
        have_payload.setdefault(VpcFieldNames.VPC_ACTION, VpcActionEnum.PAIR.value)

        want_details = want_payload.get(VpcFieldNames.VPC_PAIR_DETAILS)
        have_details = have_payload.get(VpcFieldNames.VPC_PAIR_DETAILS)
        if want_details and not have_details:
            have_payload[VpcFieldNames.VPC_PAIR_DETAILS] = want_details
        elif have_details and not want_details:
            want_payload[VpcFieldNames.VPC_PAIR_DETAILS] = have_details

    return want_payload, have_payload


def custom_vpc_create(nrm: Any) -> dict[str, Any] | None:
    """
    Custom create function for VPC pairs using RestSend with PUT + discriminator.
    - Validates switches exist in fabric (Common.validate_switches_exist)
    - Checks for switch conflicts (Common.validate_no_switch_conflicts)
    - Uses PUT instead of POST (non-RESTful API)
    - Adds vpcAction: "pair" discriminator
    - Proper error handling with NDModuleError
    - Results aggregation

    Args:
        nrm: NDStateMachine instance

    Returns:
        API response dictionary or None

    Raises:
        ValueError: If fabric_name or switch_id is not provided
        AnsibleModule.fail_json: If validation fails
    """
    fabric_name = nrm.module.params.get("fabric_name")
    switch_id = nrm.proposed_config.get(VpcFieldNames.SWITCH_ID)
    peer_switch_id = nrm.proposed_config.get(VpcFieldNames.PEER_SWITCH_ID)

    # Path validation
    if not fabric_name:
        raise ValueError("fabric_name is required but was not provided")
    if not switch_id:
        raise ValueError("switch_id is required but was not provided")
    if not peer_switch_id:
        raise ValueError("peer_switch_id is required but was not provided")

    # Initialize RestSend via NDModuleV2.
    # Validate details support before create to fail early on unsupported
    # fabric types (iBGP/eBGP VXLAN).
    nd_v2 = NDModuleV2(nrm.module)
    _validate_vpc_pair_details_fabric_support(
        nrm=nrm,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        allow_lookup=not nrm.module.check_mode,
    )

    if nrm.module.check_mode:
        return nrm.proposed_config

    # Validation Step 1: both switches must exist in discovered fabric inventory.
    _validate_switches_exist_in_fabric(
        nrm=nrm,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
    )

    # Validation Step 2: Check for switch conflicts (from Common.validate_no_switch_conflicts)
    have_vpc_pairs = nrm.module.params.get("_have", [])
    if have_vpc_pairs:
        _validate_switch_conflicts([nrm.proposed_config], have_vpc_pairs, nrm.module)

    # Validation Step 3: Check if create is actually needed (idempotence check)
    if nrm.existing_config:
        want_dict, have_dict = _build_compare_payloads(nrm)

        if not _is_update_needed(want_dict, have_dict):
            # Already exists in desired state - return existing config without changes
            nrm.module.warn(f"VPC pair {nrm.current_identifier} already exists in desired state - skipping create")
            return nrm.existing_config

    use_virtual_peer_link = nrm.proposed_config.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, False)

    # Validate pairing support using dedicated endpoint.
    # Only fail when API explicitly states pairing is not allowed.
    try:
        support_details = _get_pairing_support_details(
            nd_v2,
            fabric_name=fabric_name,
            switch_id=switch_id,
            component_type=ComponentTypeSupportEnum.CHECK_PAIRING.value,
        )
        if support_details:
            is_pairing_allowed = _get_api_field_value(support_details, "isPairingAllowed", None)
            if is_pairing_allowed is False:
                reason = _get_api_field_value(support_details, "reason", "pairing blocked by support checks")
                _raise_vpc_error(
                    msg=f"VPC pairing is not allowed for switch {switch_id}: {reason}",
                    fabric=fabric_name,
                    switch_id=switch_id,
                    peer_switch_id=peer_switch_id,
                    support_details=support_details,
                )
    except VpcPairResourceError:
        raise
    except Exception as support_error:
        nrm.module.warn(
            f"Pairing support check failed for switch {switch_id}: "
            f"{_first_line(support_error)}. Continuing with create operation."
        )

    # Validate fabric peering support if virtual peer link is requested.
    _validate_fabric_peering_support(
        nrm=nrm,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
        use_virtual_peer_link=use_virtual_peer_link,
    )

    # Build path with switch ID using Manage API (not NDFC API)
    # The NDFC API (/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair) may not be available
    # Use Manage API (/api/v1/manage/fabrics/.../vpcPair) instead
    path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)

    # Build payload with discriminator using helper (supports vpc_pair_details)
    payload = _build_vpc_pair_payload(nrm.proposed_config)

    try:
        # Use PUT (not POST!) for create via RestSend
        response = nd_v2.request(path, HttpVerbEnum.PUT, payload)
        return response

    except NDModuleError as error:
        error_dict = error.to_dict()
        # Preserve original API error message with different key to avoid conflict
        if "msg" in error_dict:
            error_dict["api_error_msg"] = error_dict.pop("msg")
        _raise_vpc_error(
            msg=f"Failed to create VPC pair {nrm.current_identifier}: {error.msg}",
            fabric=fabric_name,
            switch_id=switch_id,
            peer_switch_id=peer_switch_id,
            path=path,
            **error_dict,
        )
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(
            msg=f"Failed to create VPC pair {nrm.current_identifier}: {str(e)}",
            fabric=fabric_name,
            switch_id=switch_id,
            peer_switch_id=peer_switch_id,
            path=path,
            exception_type=type(e).__name__,
        )


def custom_vpc_update(nrm: Any) -> dict[str, Any] | None:
    """
    Custom update function for VPC pairs using RestSend.

    - Uses PUT with discriminator (same as create)
    - Validates switches exist in fabric
    - Checks for switch conflicts
    - Uses normalized payload comparison to detect if update is needed
    - Proper error handling

    Args:
        nrm: NDStateMachine instance

    Returns:
        API response dictionary or None

    Raises:
        ValueError: If fabric_name or switch_id is not provided
    """
    fabric_name = nrm.module.params.get("fabric_name")
    switch_id = nrm.proposed_config.get(VpcFieldNames.SWITCH_ID)
    peer_switch_id = nrm.proposed_config.get(VpcFieldNames.PEER_SWITCH_ID)

    # Path validation
    if not fabric_name:
        raise ValueError("fabric_name is required but was not provided")
    if not switch_id:
        raise ValueError("switch_id is required but was not provided")
    if not peer_switch_id:
        raise ValueError("peer_switch_id is required but was not provided")

    # Initialize RestSend via NDModuleV2.
    # Validate details support before update to fail early on unsupported
    # fabric types (iBGP/eBGP VXLAN).
    nd_v2 = NDModuleV2(nrm.module)
    _validate_vpc_pair_details_fabric_support(
        nrm=nrm,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        allow_lookup=not nrm.module.check_mode,
    )

    if nrm.module.check_mode:
        return nrm.proposed_config

    # Validation Step 1: both switches must exist in discovered fabric inventory.
    _validate_switches_exist_in_fabric(
        nrm=nrm,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
    )

    # Validation Step 2: Check for switch conflicts (from Common.validate_no_switch_conflicts)
    have_vpc_pairs = nrm.module.params.get("_have", [])
    if have_vpc_pairs:
        # Filter out the current VPC pair being updated
        other_vpc_pairs = [vpc for vpc in have_vpc_pairs if vpc.get(VpcFieldNames.SWITCH_ID) != switch_id]
        if other_vpc_pairs:
            _validate_switch_conflicts([nrm.proposed_config], other_vpc_pairs, nrm.module)

    # Validation Step 3: Check if update is actually needed
    if nrm.existing_config:
        want_dict, have_dict = _build_compare_payloads(nrm)

        if not _is_update_needed(want_dict, have_dict):
            # No changes needed - return existing config
            nrm.module.warn(f"VPC pair {nrm.current_identifier} is already in desired state - skipping update")
            return nrm.existing_config

    use_virtual_peer_link = nrm.proposed_config.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, False)

    # Validate fabric peering support if virtual peer link is requested.
    _validate_fabric_peering_support(
        nrm=nrm,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
        use_virtual_peer_link=use_virtual_peer_link,
    )

    # Build path with switch ID using Manage API (not NDFC API)
    # The NDFC API (/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair) may not be available
    # Use Manage API (/api/v1/manage/fabrics/.../vpcPair) instead
    path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)

    # Build payload with discriminator using helper (supports vpc_pair_details)
    payload = _build_vpc_pair_payload(nrm.proposed_config)

    try:
        # Use PUT for update via RestSend
        response = nd_v2.request(path, HttpVerbEnum.PUT, payload)
        return response

    except NDModuleError as error:
        error_dict = error.to_dict()
        # Preserve original API error message with different key to avoid conflict
        if "msg" in error_dict:
            error_dict["api_error_msg"] = error_dict.pop("msg")
        _raise_vpc_error(
            msg=f"Failed to update VPC pair {nrm.current_identifier}: {error.msg}", fabric=fabric_name, switch_id=switch_id, path=path, **error_dict
        )
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(
            msg=f"Failed to update VPC pair {nrm.current_identifier}: {str(e)}",
            fabric=fabric_name,
            switch_id=switch_id,
            path=path,
            exception_type=type(e).__name__,
        )


def custom_vpc_delete(nrm: Any) -> bool:
    """
    Custom delete function for VPC pairs using RestSend with PUT + discriminator.

    - Pre-deletion validation (network/VRF/interface checks)
    - Uses PUT instead of DELETE (non-RESTful API)
    - Adds vpcAction: "unpair" discriminator
    - Proper error handling with NDModuleError

    Args:
        nrm: NDStateMachine instance

    Raises:
        ValueError: If fabric_name or switch_id is not provided
        AnsibleModule.fail_json: If validation fails (networks/VRFs attached)
    """
    if nrm.module.check_mode:
        return True

    fabric_name = nrm.module.params.get("fabric_name")
    switch_id = nrm.existing_config.get(VpcFieldNames.SWITCH_ID)
    peer_switch_id = nrm.existing_config.get(VpcFieldNames.PEER_SWITCH_ID)

    # Path validation
    if not fabric_name:
        raise ValueError("fabric_name is required but was not provided")
    if not switch_id:
        raise ValueError("switch_id is required but was not provided")

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)

    # CRITICAL: Pre-deletion validation to prevent data loss
    # Checks for active networks, VRFs, and warns about vPC interfaces
    vpc_pair_key = f"{switch_id}-{peer_switch_id}" if peer_switch_id else switch_id

    # Track whether force parameter was actually needed
    force_delete = nrm.module.params.get("force", False)
    validation_succeeded = False

    # Perform validation with timeout protection
    try:
        _validate_vpc_pair_deletion(nd_v2, fabric_name, switch_id, vpc_pair_key, nrm.module)
        validation_succeeded = True

        # If force was enabled but validation succeeded, inform user it wasn't needed
        if force_delete:
            nrm.module.warn(
                f"Force deletion was enabled for {vpc_pair_key}, but pre-deletion validation succeeded. "
                f"The 'force: true' parameter was not necessary in this case. "
                f"Consider removing 'force: true' to benefit from safety checks in future runs."
            )

    except ValueError as already_unpaired:
        # Sentinel from _validate_vpc_pair_deletion: pair no longer exists.
        # Treat as idempotent success — nothing to delete.
        nrm.module.warn(str(already_unpaired))
        return False

    except (NDModuleError, Exception) as validation_error:
        # Validation failed - check if force deletion is enabled
        if not force_delete:
            _raise_vpc_error(
                msg=(
                    f"Pre-deletion validation failed for VPC pair {vpc_pair_key}. "
                    f"Error: {str(validation_error)}. "
                    f"If you're certain the VPC pair can be safely deleted, use 'force: true' parameter. "
                    f"WARNING: Force deletion bypasses safety checks and may cause data loss."
                ),
                vpc_pair_key=vpc_pair_key,
                validation_error=str(validation_error),
                force_available=True,
            )
        else:
            # Force enabled and validation failed - this is when force was actually needed
            nrm.module.warn(
                f"Force deletion enabled for {vpc_pair_key} - bypassing pre-deletion validation. "
                f"Validation error was: {str(validation_error)}. "
                f"WARNING: Proceeding without safety checks - ensure no data loss will occur."
            )

    # Build path with switch ID using Manage API (not NDFC API)
    # The NDFC API (/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair) may not be available
    # Use Manage API (/api/v1/manage/fabrics/.../vpcPair) instead
    path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)

    # Build minimal payload with discriminator for delete
    payload = {
        VpcFieldNames.VPC_ACTION: VpcActionEnum.UNPAIR.value,  # ← Discriminator for DELETE
        VpcFieldNames.SWITCH_ID: nrm.existing_config.get(VpcFieldNames.SWITCH_ID),
        VpcFieldNames.PEER_SWITCH_ID: nrm.existing_config.get(VpcFieldNames.PEER_SWITCH_ID),
    }

    try:
        # Use PUT (not DELETE!) for unpair via RestSend
        nd_v2.request(path, HttpVerbEnum.PUT, payload)

    except NDModuleError as error:
        error_msg = str(error.msg).lower() if error.msg else ""
        status_code = error.status or 0

        # Idempotent handling: if the API says the switch is not part of any
        # vPC pair, the pair is already gone — treat as a successful no-op.
        # The API may return 400 or 404 depending on the ND version.
        if status_code in (400, 404) and "not a part of" in error_msg:
            nrm.module.warn(
                f"VPC pair {nrm.current_identifier} is already unpaired on the controller. " f"Treating as idempotent success. API response: {error.msg}"
            )
            return False

        error_dict = error.to_dict()
        # Preserve original API error message with different key to avoid conflict
        if "msg" in error_dict:
            error_dict["api_error_msg"] = error_dict.pop("msg")
        _raise_vpc_error(
            msg=f"Failed to delete VPC pair {nrm.current_identifier}: {error.msg}", fabric=fabric_name, switch_id=switch_id, path=path, **error_dict
        )
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(
            msg=f"Failed to delete VPC pair {nrm.current_identifier}: {str(e)}",
            fabric=fabric_name,
            switch_id=switch_id,
            path=path,
            exception_type=type(e).__name__,
        )

    return True
