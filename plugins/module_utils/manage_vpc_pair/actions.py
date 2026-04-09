# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from typing import Any, Dict, Optional, Tuple

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


def _build_compare_payloads(nrm: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
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


def custom_vpc_create(nrm: Any) -> Optional[Dict[str, Any]]:
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
    if nrm.module.check_mode:
        return nrm.proposed_config

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

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
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
        nrm.module.warn(f"Pairing support check failed for switch {switch_id}: " f"{str(support_error).splitlines()[0]}. Continuing with create operation.")

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


def custom_vpc_update(nrm: Any) -> Optional[Dict[str, Any]]:
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
    if nrm.module.check_mode:
        return nrm.proposed_config

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

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
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
