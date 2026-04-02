# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from typing import Any, Dict, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    ComponentTypeSupportEnum,
    VpcFieldNames,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import (
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
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModuleError

def _get_pairing_support_details(
    nd_v2,
    fabric_name: str,
    switch_id: str,
    component_type: str = ComponentTypeSupportEnum.CHECK_PAIRING.value,
    timeout: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Query /vpcPairSupport endpoint to validate pairing support.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        component_type: Support check type (default: checkPairing)
        timeout: Optional timeout override (uses module query timeout policy if not specified)

    Returns:
        Dict with support details, or None if response is not a dict.

    Raises:
        ValueError: If fabric_name or switch_id are invalid
        NDModuleError: On API errors
    """
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")
    if not switch_id or not isinstance(switch_id, str) or len(switch_id) < 3:
        raise ValueError(f"Invalid switch_id: {switch_id}")

    path = VpcPairEndpoints.switch_vpc_support(
        fabric_name=fabric_name,
        switch_id=switch_id,
        component_type=component_type,
    )

    if timeout is None:
        timeout = get_verify_timeout(nd_v2.module)

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        support_details = nd_v2.request(path, HttpVerbEnum.GET)
    finally:
        rest_send.restore_settings()

    if isinstance(support_details, dict):
        return support_details
    return None


def _validate_fabric_peering_support(
    nrm,
    nd_v2,
    fabric_name: str,
    switch_id: str,
    peer_switch_id: str,
    use_virtual_peer_link: bool,
) -> None:
    """
    Validate fabric peering support when virtual peer link is requested.

    If API explicitly reports unsupported fabric peering, logs warning and
    continues. If support API is unavailable, logs warning and continues.

    Args:
        nrm: VpcPairStateMachine instance for logging warnings
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Primary switch serial number
        peer_switch_id: Peer switch serial number
        use_virtual_peer_link: Whether virtual peer link is requested
    """
    if not use_virtual_peer_link:
        return

    switches_to_check = [switch_id, peer_switch_id]
    for support_switch_id in switches_to_check:
        if not support_switch_id:
            continue

        try:
            support_details = _get_pairing_support_details(
                nd_v2,
                fabric_name=fabric_name,
                switch_id=support_switch_id,
                component_type=ComponentTypeSupportEnum.CHECK_FABRIC_PEERING_SUPPORT.value,
            )
            if not support_details:
                continue

            is_supported = _get_api_field_value(
                support_details, "isVpcFabricPeeringSupported", None
            )
            if is_supported is False:
                status = _get_api_field_value(
                    support_details, "status", "Fabric peering not supported"
                )
                nrm.module.warn(
                    f"VPC fabric peering is not supported for switch {support_switch_id}: {status}. "
                    f"Continuing, but config save/deploy may report a platform limitation. "
                    f"Consider setting use_virtual_peer_link=false for this platform."
                )
        except Exception as support_error:
            nrm.module.warn(
                f"Fabric peering support check failed for switch {support_switch_id}: "
                f"{str(support_error).splitlines()[0]}. Continuing with create/update operation."
            )


def _get_consistency_details(
    nd_v2,
    fabric_name: str,
    switch_id: str,
    timeout: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Query /vpcPairConsistency endpoint for consistency diagnostics.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        timeout: Optional timeout override (uses module query timeout policy if not specified)

    Returns:
        Dict with consistency details, or None if response is not a dict.

    Raises:
        ValueError: If fabric_name or switch_id are invalid
        NDModuleError: On API errors
    """
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")
    if not switch_id or not isinstance(switch_id, str) or len(switch_id) < 3:
        raise ValueError(f"Invalid switch_id: {switch_id}")

    path = VpcPairEndpoints.switch_vpc_consistency(fabric_name, switch_id)

    if timeout is None:
        timeout = get_verify_timeout(nd_v2.module)

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        consistency_details = nd_v2.request(path, HttpVerbEnum.GET)
    finally:
        rest_send.restore_settings()

    if isinstance(consistency_details, dict):
        return consistency_details
    return None


def _is_switch_in_vpc_pair(
    nd_v2,
    fabric_name: str,
    switch_id: str,
    timeout: Optional[int] = None,
) -> Optional[bool]:
    """
    Best-effort active-membership check via vPC overview endpoint.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        timeout: Optional timeout override (uses module query timeout policy if not specified)

    Returns:
        True: overview query succeeded (switch is part of a vPC pair)
        False: API explicitly reports switch is not in a vPC pair
        None: unknown/error (do not block caller logic)
    """
    if not fabric_name or not switch_id:
        return None

    path = VpcPairEndpoints.switch_vpc_overview(
        fabric_name, switch_id, component_type="full"
    )

    if timeout is None:
        timeout = get_verify_timeout(nd_v2.module)

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        nd_v2.request(path, HttpVerbEnum.GET)
        return True
    except NDModuleError as error:
        error_msg = (error.msg or "").lower()
        if error.status == 400 and "not a part of vpc pair" in error_msg:
            return False
        return None
    except Exception:
        return None
    finally:
        rest_send.restore_settings()


def _validate_fabric_switches(nd_v2, fabric_name: str) -> Dict[str, Dict]:
    """
    Query and validate fabric switch inventory.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name

    Returns:
        Dict mapping switch serial number to switch info

    Raises:
        ValueError: If inputs are invalid
        NDModuleError: If fabric switch query fails
    """
    # Input validation
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")

    switches_path = VpcPairEndpoints.fabric_switches(fabric_name)
    switches_response = nd_v2.request(switches_path, HttpVerbEnum.GET)

    if not switches_response:
        return {}

    # Validate response structure
    if not isinstance(switches_response, dict):
        nd_v2.module.warn(
            f"Unexpected switches response format: expected dict, got {type(switches_response).__name__}"
        )
        return {}

    switches = switches_response.get(VpcFieldNames.SWITCHES, [])

    # Validate switches is a list
    if not isinstance(switches, list):
        nd_v2.module.warn(
            f"Unexpected switches format: expected list, got {type(switches).__name__}"
        )
        return {}

    # Build validated switch dictionary
    result = {}
    for sw in switches:
        if not isinstance(sw, dict):
            nd_v2.module.warn(f"Skipping invalid switch entry: expected dict, got {type(sw).__name__}")
            continue

        serial_number = sw.get(VpcFieldNames.SERIAL_NUMBER)
        if not serial_number:
            continue

        # Validate serial number format
        if not isinstance(serial_number, str) or len(serial_number) < 3:
            nd_v2.module.warn(f"Skipping switch with invalid serial number: {serial_number}")
            continue

        result[serial_number] = sw

    return result


def _validate_switch_conflicts(want_configs: List[Dict], have_vpc_pairs: List[Dict], module) -> None:
    """
    Validate that switches in want configs aren't already in different VPC pairs.

    Optimized implementation using index-based lookup for O(n) time complexity instead of O(n²).

    Args:
        want_configs: List of desired VPC pair configs
        have_vpc_pairs: List of existing VPC pairs
        module: AnsibleModule instance for fail_json

    Raises:
        AnsibleModule.fail_json: If switch conflicts detected
    """
    conflicts = []

    # Build index of existing VPC pairs by switch ID - O(m) where m = len(have_vpc_pairs)
    # Maps switch_id -> list of VPC pairs containing that switch
    switch_to_vpc_index = {}
    for have in have_vpc_pairs:
        have_switch_id = have.get(VpcFieldNames.SWITCH_ID)
        have_peer_id = have.get(VpcFieldNames.PEER_SWITCH_ID)

        if have_switch_id:
            if have_switch_id not in switch_to_vpc_index:
                switch_to_vpc_index[have_switch_id] = []
            switch_to_vpc_index[have_switch_id].append(have)

        if have_peer_id:
            if have_peer_id not in switch_to_vpc_index:
                switch_to_vpc_index[have_peer_id] = []
            switch_to_vpc_index[have_peer_id].append(have)

    # Check each want config for conflicts - O(n) where n = len(want_configs)
    for want in want_configs:
        want_switches = {want.get(VpcFieldNames.SWITCH_ID), want.get(VpcFieldNames.PEER_SWITCH_ID)}
        want_switches.discard(None)

        # Build set of all VPC pairs that contain any switch from want_switches - O(1) lookup per switch
        # Use set to track VPC IDs we've already checked to avoid duplicate processing
        conflicting_vpcs = {}  # vpc_id -> vpc dict
        for switch in want_switches:
            if switch in switch_to_vpc_index:
                for vpc in switch_to_vpc_index[switch]:
                    # Use tuple of sorted switch IDs as unique identifier
                    vpc_id = tuple(sorted([vpc.get(VpcFieldNames.SWITCH_ID), vpc.get(VpcFieldNames.PEER_SWITCH_ID)]))
                    # Only add if we haven't seen this VPC ID before (avoids duplicate processing)
                    if vpc_id not in conflicting_vpcs:
                        conflicting_vpcs[vpc_id] = vpc

        # Check each potentially conflicting VPC pair
        for vpc_id, have in conflicting_vpcs.items():
            have_switches = {have.get(VpcFieldNames.SWITCH_ID), have.get(VpcFieldNames.PEER_SWITCH_ID)}
            have_switches.discard(None)

            # Same VPC pair is OK
            if want_switches == have_switches:
                continue

            # Check for switch overlap with different pairs
            switch_overlap = want_switches & have_switches
            if switch_overlap:
                # Filter out None values and ensure strings for joining
                overlap_list = [str(s) for s in switch_overlap if s is not None]
                want_key = f"{want.get(VpcFieldNames.SWITCH_ID)}-{want.get(VpcFieldNames.PEER_SWITCH_ID)}"
                have_key = f"{have.get(VpcFieldNames.SWITCH_ID)}-{have.get(VpcFieldNames.PEER_SWITCH_ID)}"
                conflicts.append(
                    f"Switch(es) {', '.join(overlap_list)} in wanted VPC pair {want_key} "
                    f"are already part of existing VPC pair {have_key}"
                )

    if conflicts:
        _raise_vpc_error(
            msg="Switch conflicts detected. A switch can only be part of one VPC pair at a time.",
            conflicts=conflicts
        )


def _validate_switches_exist_in_fabric(
    nrm,
    fabric_name: str,
    switch_id: str,
    peer_switch_id: str,
) -> None:
    """
    Validate both switches exist in discovered fabric inventory.

    This check is mandatory for create/update. Empty inventory is treated as
    a validation error to avoid bypassing guardrails and failing later with a
    less actionable API error.

    Args:
        nrm: VpcPairStateMachine instance with module params containing _fabric_switches
        fabric_name: Fabric name for error messages
        switch_id: Primary switch serial number
        peer_switch_id: Peer switch serial number

    Raises:
        VpcPairResourceError: If switches are missing from fabric inventory
    """
    fabric_switches = nrm.module.params.get("_fabric_switches")

    if fabric_switches is None:
        _raise_vpc_error(
            msg=(
                f"Switch validation failed for fabric '{fabric_name}': switch inventory "
                "was not loaded from query_all. Unable to validate requested vPC pair."
            ),
            vpc_pair_key=nrm.current_identifier,
            fabric=fabric_name,
        )

    valid_switches = sorted(list(fabric_switches))
    if not valid_switches:
        _raise_vpc_error(
            msg=(
                f"Switch validation failed for fabric '{fabric_name}': no switches were "
                "discovered in fabric inventory. Cannot create/update vPC pairs without "
                "validated switch membership."
            ),
            vpc_pair_key=nrm.current_identifier,
            fabric=fabric_name,
            total_valid_switches=0,
        )

    missing_switches = []
    if switch_id not in fabric_switches:
        missing_switches.append(switch_id)
    if peer_switch_id not in fabric_switches:
        missing_switches.append(peer_switch_id)

    if not missing_switches:
        return

    max_switches_in_error = 10
    error_msg = (
        f"Switch validation failed: The following switch(es) do not exist in fabric '{fabric_name}':\n"
        f"  Missing switches: {', '.join(missing_switches)}\n"
        f"  Affected vPC pair: {nrm.current_identifier}\n\n"
        "Please ensure:\n"
        "  1. Switch serial numbers are correct (not IP addresses)\n"
        "  2. Switches are discovered and present in the fabric\n"
        "  3. You have the correct fabric name specified\n\n"
    )

    if len(valid_switches) <= max_switches_in_error:
        error_msg += f"Valid switches in fabric: {', '.join(valid_switches)}"
    else:
        error_msg += (
            f"Valid switches in fabric (first {max_switches_in_error}): "
            f"{', '.join(valid_switches[:max_switches_in_error])} ... and "
            f"{len(valid_switches) - max_switches_in_error} more"
        )

    _raise_vpc_error(
        msg=error_msg,
        missing_switches=missing_switches,
        vpc_pair_key=nrm.current_identifier,
        total_valid_switches=len(valid_switches),
    )


def _validate_vpc_pair_deletion(nd_v2, fabric_name: str, switch_id: str, vpc_pair_key: str, module) -> None:
    """
    Validate VPC pair can be safely deleted by checking for dependencies.

    This function prevents data loss by ensuring the VPC pair has no active:
    1. Networks (networkCount must be 0 for all statuses)
    2. VRFs (vrfCount must be 0 for all statuses)
    3. Warns if vPC interfaces exist (vpcInterfaceCount > 0)

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        vpc_pair_key: VPC pair identifier (e.g., "FDO123-FDO456") for error messages
        module: AnsibleModule instance for fail_json/warn

    Raises:
        AnsibleModule.fail_json: If VPC pair has active networks or VRFs

    Example:
        _validate_vpc_pair_deletion(nd_v2, "myFabric", "FDO123", "FDO123-FDO456", module)
    """
    try:
        # Query overview endpoint with full component data
        overview_path = VpcPairEndpoints.switch_vpc_overview(fabric_name, switch_id, component_type="full")

        # Bound overview validation call by normalized query timeout.
        rest_send = nd_v2._get_rest_send()
        rest_send.save_settings()
        rest_send.timeout = get_verify_timeout(nd_v2.module)
        try:
            response = nd_v2.request(overview_path, HttpVerbEnum.GET)
        finally:
            rest_send.restore_settings()

        # If no response, VPC pair doesn't exist - deletion not needed
        if not response:
            module.warn(
                f"VPC pair {vpc_pair_key} not found in overview query. "
                f"It may not exist or may have already been deleted."
            )
            return

        # Query consistency endpoint for additional diagnostics before deletion.
        # This is best effort and should not block deletion workflows.
        try:
            consistency = _get_consistency_details(nd_v2, fabric_name, switch_id)
            if consistency:
                type2_consistency = _get_api_field_value(consistency, "type2Consistency", None)
                if type2_consistency is False:
                    reason = _get_api_field_value(
                        consistency, "type2ConsistencyReason", "unknown reason"
                    )
                    module.warn(
                        f"VPC pair {vpc_pair_key} reports type2 consistency issue: {reason}"
                    )
        except Exception as consistency_error:
            module.warn(
                f"Failed to query consistency details for VPC pair {vpc_pair_key}: "
                f"{str(consistency_error).splitlines()[0]}"
            )

        # Validate response structure
        if not isinstance(response, dict):
            _raise_vpc_error(
                msg=f"Expected dict response from vPC pair overview for {vpc_pair_key}, got {type(response).__name__}",
                response=response
            )

        # Validate overlay data exists
        overlay = response.get(VpcFieldNames.OVERLAY)
        if not overlay:
            # Overlay data unavailable — the pair may be in a transitional
            # state (e.g. already mid-unpair) or the controller has stale
            # data.  Since there is no overlay to validate against,
            # treat as safe to proceed with deletion.
            module.warn(
                f"vPC pair {vpc_pair_key} overlay data unavailable in overview response. "
                f"Proceeding with deletion — the pair may already be in a transitional state."
            )
            return

        # Check 1: Validate no networks are attached
        network_count = overlay.get(VpcFieldNames.NETWORK_COUNT, {})
        if isinstance(network_count, dict):
            for status, count in network_count.items():
                try:
                    count_int = int(count)
                    if count_int != 0:
                        _raise_vpc_error(
                            msg=(
                                f"Cannot delete vPC pair {vpc_pair_key}. "
                                f"{count_int} network(s) with status '{status}' still exist. "
                                f"Remove all networks from this vPC pair before deleting it."
                            ),
                            vpc_pair_key=vpc_pair_key,
                            network_count=network_count,
                            blocking_status=status,
                            blocking_count=count_int
                        )
                except (ValueError, TypeError) as e:
                    # Best effort - log warning and continue
                    module.warn(f"Error parsing network count for status '{status}': {e}")
        elif network_count:
            # Non-dict format - log warning
            module.warn(
                f"networkCount is not a dict for {vpc_pair_key}: {type(network_count).__name__}. "
                f"Skipping network validation."
            )

        # Check 2: Validate no VRFs are attached
        vrf_count = overlay.get(VpcFieldNames.VRF_COUNT, {})
        if isinstance(vrf_count, dict):
            for status, count in vrf_count.items():
                try:
                    count_int = int(count)
                    if count_int != 0:
                        _raise_vpc_error(
                            msg=(
                                f"Cannot delete vPC pair {vpc_pair_key}. "
                                f"{count_int} VRF(s) with status '{status}' still exist. "
                                f"Remove all VRFs from this vPC pair before deleting it."
                            ),
                            vpc_pair_key=vpc_pair_key,
                            vrf_count=vrf_count,
                            blocking_status=status,
                            blocking_count=count_int
                        )
                except (ValueError, TypeError) as e:
                    # Best effort - log warning and continue
                    module.warn(f"Error parsing VRF count for status '{status}': {e}")
        elif vrf_count:
            # Non-dict format - log warning
            module.warn(
                f"vrfCount is not a dict for {vpc_pair_key}: {type(vrf_count).__name__}. "
                f"Skipping VRF validation."
            )

        # Check 3: Warn if vPC interfaces exist (non-blocking)
        inventory = response.get(VpcFieldNames.INVENTORY, {})
        if inventory and isinstance(inventory, dict):
            vpc_interface_count = inventory.get(VpcFieldNames.VPC_INTERFACE_COUNT)
            if vpc_interface_count:
                try:
                    count_int = int(vpc_interface_count)
                    if count_int > 0:
                        module.warn(
                            f"vPC pair {vpc_pair_key} has {count_int} vPC interface(s). "
                            f"Deletion may fail or require manual cleanup of interfaces. "
                            f"Consider removing vPC interfaces before deleting the vPC pair."
                        )
                except (ValueError, TypeError) as e:
                    # Best effort - just log debug message
                    pass
        elif not inventory:
            # No inventory data - warn user
            module.warn(
                f"Inventory data not available in overview response for {vpc_pair_key}. "
                f"Proceeding with deletion, but it may fail if vPC interfaces exist."
            )

    except VpcPairResourceError:
        raise
    except NDModuleError as error:
        error_msg = str(error.msg).lower() if error.msg else ""
        status_code = error.status or 0

        # If the overview query returns 400 or 404 with "not a part of" it means
        # the pair no longer exists on the controller.  Signal the caller
        # by raising a ValueError with a sentinel message so that the
        # delete function can treat this as an idempotent no-op.
        if status_code in (400, 404) and "not a part of" in error_msg:
            raise ValueError(
                f"VPC pair {vpc_pair_key} is already unpaired on the controller. "
                f"No deletion required."
            )

        # Best effort validation - if overview query fails, log warning and proceed
        # The API will still reject deletion if dependencies exist
        module.warn(
            f"Could not validate vPC pair {vpc_pair_key} for deletion: {error.msg}. "
            f"Proceeding with deletion attempt. API will reject if dependencies exist."
        )

    except Exception as e:
        # Best effort validation - log warning and continue
        module.warn(
            f"Unexpected error validating VPC pair {vpc_pair_key} for deletion: {str(e)}. "
            f"Proceeding with deletion attempt."
        )


# ===== Custom Action Functions (used by VpcPairResourceService via orchestrator) =====
