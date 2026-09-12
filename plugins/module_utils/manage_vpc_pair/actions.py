# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

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
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.query import (
    _is_switch_config_in_sync,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.validation import (
    _get_pairing_support_details,
    _validate_fabric_peering_support,
    _validate_fabric_switches,
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule as NDModuleV2,
    NDModuleError,
)

_BLOCKED_FABRIC_TYPES_FOR_VPC_PAIR_DETAILS = {
    FabricTypeEnum.VXLAN_IBGP.value,
    FabricTypeEnum.VXLAN_EBGP.value,
}


def _first_exception_line(error: Exception) -> str:
    """Return the first message line for an exception."""
    if not isinstance(error, Exception):
        raise TypeError("error must be an exception")
    text = str(error).strip()
    return text.splitlines()[0] if text else type(error).__name__


def _resolve_fabric_type(nd_v2: NDModuleV2, fabric_name: str) -> str:
    """
    Resolve the canonical fabric type from the authoritative fabric endpoint.

    Nexus Dashboard returns the fabric type in ``management.type`` from
    ``GET /api/v1/manage/fabrics/<name>``. Failure to determine the type is
    fatal because callers use it to reject unsupported ``vpc_pair_details``
    before attempting a write.
    """
    details_path: str | None = None
    try:
        details_path = VpcPairEndpoints.fabric_details(fabric_name)
        details = nd_v2.request(details_path, HttpVerbEnum.GET)
    except NDModuleError as error:
        _raise_vpc_error(
            msg=(f"Unable to determine fabric type for '{fabric_name}' while validating " f"vpc_pair_details: {_first_exception_line(error)}"),
            fabric=fabric_name,
            path=details_path,
            status=error.status,
            exception_type=type(error).__name__,
        )
    except (TypeError, ValueError) as error:
        _raise_vpc_error(
            msg=(f"Unable to determine fabric type for '{fabric_name}' while validating " f"vpc_pair_details: {_first_exception_line(error)}"),
            fabric=fabric_name,
            path=details_path,
            exception_type=type(error).__name__,
        )

    if not isinstance(details, dict):
        _raise_vpc_error(
            msg=(
                f"Unable to determine fabric type for '{fabric_name}' while validating "
                f"vpc_pair_details: expected a dictionary response, got {type(details).__name__}"
            ),
            fabric=fabric_name,
            path=details_path,
            response_type=type(details).__name__,
        )

    management = details.get("management")
    if not isinstance(management, dict):
        _raise_vpc_error(
            msg=(f"Unable to determine fabric type for '{fabric_name}' while validating " "vpc_pair_details: response does not contain 'management.type'"),
            fabric=fabric_name,
            path=details_path,
            missing_field="management.type",
        )

    fabric_type = management.get("type")
    if not isinstance(fabric_type, str) or not fabric_type.strip():
        _raise_vpc_error(
            msg=(
                f"Unable to determine fabric type for '{fabric_name}' while validating "
                "vpc_pair_details: response does not contain a non-empty 'management.type'"
            ),
            fabric=fabric_name,
            path=details_path,
            missing_field="management.type",
        )
    return fabric_type.strip()


def _ensure_fabric_type(nrm: Any, nd_v2: NDModuleV2, fabric_name: str) -> str:
    """
    Resolve the fabric type once and cache it on the state machine.

    The resolved value is stored on ``nrm.fabric_type`` so repeated validation
    and payload-sanitization passes across the proposed items in a single run
    trigger at most one controller lookup.
    """
    fabric_type = nrm.fabric_type
    if fabric_type is None:
        fabric_type = _resolve_fabric_type(nd_v2, fabric_name)
        nrm.fabric_type = fabric_type
    return fabric_type


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


def _get_explicit_proposed_details(proposed_item: Any) -> dict[str, Any] | None:
    """
    Return non-empty vpc_pair_details only when the user explicitly supplied it.

    ``proposed_item`` is the raw user-intent model built directly from the
    playbook config, so ``model_dump(exclude_unset=True)`` reflects exactly the
    fields the user set; defaults and merge-inherited values are excluded. A
    plain dict is also accepted for convenience.
    """
    if hasattr(proposed_item, "model_dump"):
        explicit_config = proposed_item.model_dump(by_alias=True, exclude_none=True, exclude_unset=True)
    else:
        explicit_config = proposed_item
    return _get_proposed_vpc_pair_details(explicit_config)


def validate_proposed_details_support(nrm: Any, proposed_item: Any) -> None:
    """
    Reject vpc_pair_details on blocked fabrics using only raw user intent.

    This preflight check runs before the state machine computes diffs, so an
    unsupported field is rejected even when the requested value happens to match
    existing controller state; an idempotent request must not silently accept a
    prohibited field. Only fields the user explicitly supplied are considered, so
    inherited/merged details never cause a false rejection. The fabric type is
    resolved and cached lazily and only when explicit details are present, so the
    common id-only path performs no extra controller lookup.
    """
    proposed_details = _get_explicit_proposed_details(proposed_item)
    if proposed_details is None:
        return

    fabric_name = nrm.module.params.get("fabric_name")
    nd_v2 = NDModuleV2(nrm.module)
    fabric_type = _ensure_fabric_type(nrm, nd_v2, fabric_name)

    if fabric_type in _BLOCKED_FABRIC_TYPES_FOR_VPC_PAIR_DETAILS:
        _raise_vpc_error(
            msg=(
                "Invalid nd_manage_vpc_pair input: 'vpc_pair_details' is not supported "
                "for iBGP/eBGP VXLAN fabrics. Use only peer switch IDs and "
                "'use_virtual_peer_link' for this fabric type."
            ),
            fabric=fabric_name,
            fabric_type=fabric_type,
            unsupported_field="vpc_pair_details",
        )


def strip_inherited_details_for_blocked_fabric(nrm: Any, proposed_item: Any) -> None:
    """
    Drop merge-inherited vpc_pair_details from the outgoing payload on blocked fabrics.

    When a user omits vpc_pair_details on an update, ``merge()`` re-adds the
    vpcPairDetails carried by existing controller state into the reconciled
    payload. On iBGP/eBGP VXLAN fabrics that inherited field must never be sent
    back to Nexus Dashboard. Explicitly supplied details are left untouched here
    because they are already validated by :func:`validate_proposed_details_support`
    and remain permitted on External/ISN/LANClassic fabrics. The fabric lookup is
    performed only when the payload actually carries details.
    """
    if not isinstance(nrm.proposed_config, dict):
        return

    payload_details = nrm.proposed_config.get(VpcFieldNames.VPC_PAIR_DETAILS)
    if payload_details is None:
        payload_details = nrm.proposed_config.get("vpc_pair_details")
    if not payload_details:
        return

    if _get_explicit_proposed_details(proposed_item) is not None:
        # User explicitly supplied details; preflight already validated them and
        # supported fabrics must keep them.
        return

    fabric_name = nrm.module.params.get("fabric_name")
    nd_v2 = NDModuleV2(nrm.module)
    fabric_type = _ensure_fabric_type(nrm, nd_v2, fabric_name)

    if fabric_type in _BLOCKED_FABRIC_TYPES_FOR_VPC_PAIR_DETAILS:
        nrm.proposed_config.pop(VpcFieldNames.VPC_PAIR_DETAILS, None)
        nrm.proposed_config.pop("vpc_pair_details", None)


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
    nd_v2 = NDModuleV2(nrm.module)

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
        nrm.module.warn(f"Pairing support check failed for switch {switch_id}: " f"{_first_exception_line(support_error)}. Continuing with create operation.")

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
    nd_v2 = NDModuleV2(nrm.module)

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


def _flag_pending_member_switches_for_deploy(
    nrm: Any,
    nd_v2: NDModuleV2,
    fabric_name: str,
    switch_id: str,
    peer_switch_id: str | None,
) -> None:
    """
    Flush a staged delete even when the pair is already unpaired on the controller.

    A prior save=false delete unpairs the pair on the controller but leaves the
    member switches out-of-sync. When a later save/deploy delete finds the pair
    already gone, record any still out-of-sync member switch in
    ``_not_in_sync_pairs`` so the deploy step runs configSave + switchActions/deploy.
    Only switches explicitly reported out-of-sync are flagged, so the run stays
    idempotent once the switches are back in sync.
    """
    try:
        switches = _validate_fabric_switches(nd_v2, fabric_name)
    except Exception as switch_query_error:
        nrm.module.warn(
            f"Could not verify member switch sync state after idempotent unpair of "
            f"{nrm.current_identifier}: {_first_exception_line(switch_query_error)}. "
            f"A pending staged delete may require a manual save/deploy."
        )
        return

    pending_switch_ids = [serial for serial in (switch_id, peer_switch_id) if serial and _is_switch_config_in_sync(switches.get(serial)) is False]
    if not pending_switch_ids:
        return

    not_in_sync_pairs = nrm.module.params.get("_not_in_sync_pairs") or []
    not_in_sync_pairs.append(
        {
            VpcFieldNames.SWITCH_ID: switch_id,
            VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
            "pending_switch_ids": pending_switch_ids,
        }
    )
    nrm.module.params["_not_in_sync_pairs"] = not_in_sync_pairs
    nrm.module.warn(
        f"vPC pair {nrm.current_identifier} is already unpaired on the controller, but member "
        f"switch(es) {', '.join(pending_switch_ids)} remain out-of-sync from a prior staged "
        f"delete. Flushing the pending removal via save/deploy."
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
        # Treat as idempotent success — nothing to delete, but still flush any
        # staged removal left out-of-sync on the member switches (issue #467).
        nrm.module.warn(str(already_unpaired))
        _flag_pending_member_switches_for_deploy(nrm, nd_v2, fabric_name, switch_id, peer_switch_id)
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
            # Still flush any staged removal left out-of-sync on the switches (issue #467).
            _flag_pending_member_switches_for_deploy(nrm, nd_v2, fabric_name, switch_id, peer_switch_id)
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
