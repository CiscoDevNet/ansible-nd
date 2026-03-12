# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage ND fabric switch lifecycle workflows.

This module validates desired switch state, performs discovery and fabric
operations, and coordinates POAP and RMA workflows.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_switches import (
    SwitchRole,
    SnmpV3AuthProtocol,
    PlatformType,
    DiscoveryStatus,
    SystemMode,
    ConfigSyncStatus,
    SwitchDiscoveryModel,
    SwitchDataModel,
    AddSwitchesRequestModel,
    ShallowDiscoveryRequestModel,
    BootstrapImportSwitchModel,
    ImportBootstrapSwitchesRequestModel,
    PreProvisionSwitchModel,
    PreProvisionSwitchesRequestModel,
    RMASwitchModel,
    SwitchConfigModel,
    SwitchCredentialsRequestModel,
    ChangeSwitchSerialNumberRequestModel,
    POAPConfigModel,
    RMAConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.utils.nd_manage_switches import (
    FabricUtils,
    SwitchWaitUtils,
    SwitchOperationError,
    mask_password,
    get_switch_field,
    group_switches_by_credentials,
    query_bootstrap_switches,
    build_bootstrap_index,
    build_poap_data_block,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.nd_manage_switches.fabric_switches import (
    V1ManageFabricSwitchesGet,
    V1ManageFabricSwitchesPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.nd_manage_switches.fabric_discovery import ( 
    V1ManageFabricShallowDiscoveryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.nd_manage_switches.fabric_switch_actions import (
    V1ManageFabricSwitchProvisionRMAPost,
    V1ManageFabricSwitchActionsImportBootstrapPost,
    V1ManageFabricSwitchActionsPreProvisionPost,
    V1ManageFabricSwitchActionsRemovePost,
    V1ManageFabricSwitchActionsChangeRolesPost,
    V1ManageFabricSwitchChangeSerialNumberPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.nd_manage_switches.credentials import ( 
    V1ManageCredentialsSwitchesPost,
)


# =========================================================================
# Shared Dependency Container
# =========================================================================

@dataclass
class SwitchServiceContext:
    """Store shared dependencies used by service classes.

    Attributes:
        nd: ND module wrapper for requests and module interactions.
        results: Shared results aggregator for task output.
        fabric: Target fabric name.
        log: Logger instance.
        save_config: Whether to run fabric save after changes.
        deploy_config: Whether to run fabric deploy after changes.
    """
    nd: NDModule
    results: Results
    fabric: str
    log: logging.Logger
    save_config: bool = True
    deploy_config: bool = True


# =========================================================================
# Validation & Diff
# =========================================================================

class SwitchDiffEngine:
    """Provide stateless validation and diff computation helpers."""

    @staticmethod
    def validate_configs(
        config: Union[Dict[str, Any], List[Dict[str, Any]]],
        state: str,
        nd: NDModule,
        log: logging.Logger,
    ) -> List[SwitchConfigModel]:
        """Validate raw module config and return typed switch configs.

        Args:
            config: Raw config dict or list of dicts from module parameters.
            state: Requested module state.
            nd: ND module wrapper used for failure handling.
            log: Logger instance.

        Returns:
            List of validated ``SwitchConfigModel`` objects.

        Raises:
            ValidationError: Raised by model validation for invalid input.
        """
        log.debug("ENTER: validate_configs()")

        configs_list = config if isinstance(config, list) else [config]
        log.debug(f"Normalized to {len(configs_list)} configuration(s)")

        validated_configs: List[SwitchConfigModel] = []
        for idx, cfg in enumerate(configs_list):
            try:
                validated = SwitchConfigModel.model_validate(
                    cfg, context={"state": state}
                )
                validated_configs.append(validated)
            except ValidationError as e:
                error_detail = e.errors() if hasattr(e, 'errors') else str(e)
                error_msg = (
                    f"Configuration validation failed for "
                    f"config index {idx}: {error_detail}"
                )
                log.error(error_msg)
                if hasattr(nd, 'module'):
                    nd.module.fail_json(msg=error_msg)
                else:
                    raise ValueError(error_msg) from e
            except Exception as e:
                error_msg = (
                    f"Configuration validation failed for "
                    f"config index {idx}: {str(e)}"
                )
                log.error(error_msg)
                if hasattr(nd, 'module'):
                    nd.module.fail_json(msg=error_msg)
                else:
                    raise ValueError(error_msg) from e

        if not validated_configs:
            log.warning("No valid configurations found in input")
            return validated_configs

        # Cross-config check — model can't do this per-instance
        try:
            SwitchConfigModel.validate_no_mixed_operations(validated_configs)
        except ValueError as e:
            error_msg = str(e)
            log.error(error_msg)
            if hasattr(nd, 'module'):
                nd.module.fail_json(msg=error_msg)
            else:
                raise

        operation_type = validated_configs[0].operation_type
        log.info(
            f"Successfully validated {len(validated_configs)} "
            f"configuration(s) with operation type: {operation_type}"
        )
        log.debug(
            f"EXIT: validate_configs() -> "
            f"{len(validated_configs)} configs, operation_type={operation_type}"
        )
        return validated_configs

    @staticmethod
    def compute_changes(
        proposed: List[SwitchDataModel],
        existing: List[SwitchDataModel],
        log: logging.Logger,
    ) -> Dict[str, List[SwitchDataModel]]:
        """Compare proposed and existing switches and categorize changes.

        Args:
            proposed: Switch models representing desired state.
            existing: Switch models currently present in inventory.
            log: Logger instance.

        Returns:
            Dict mapping change buckets to switch lists. Buckets are
            ``to_add``, ``to_update``, ``to_delete``, ``migration_mode``,
            and ``idempotent``.
        """
        log.debug("ENTER: compute_changes()")
        log.debug(
            f"Comparing {len(proposed)} proposed vs {len(existing)} existing switches"
        )

        # Build indexes for O(1) lookups
        existing_by_id = {sw.switch_id: sw for sw in existing}
        existing_by_ip = {sw.fabric_management_ip: sw for sw in existing}

        log.debug(
            f"Indexes built — existing_by_id: {list(existing_by_id.keys())}, "
            f"existing_by_ip: {list(existing_by_ip.keys())}"
        )

        # Only user-controllable fields populated by both discovery and
        # inventory APIs.  Server-managed fields (uptime, alerts, vpc info,
        # telemetry, etc.) are ignored.
        compare_fields = {
            "switch_id",
            "serial_number",
            "fabric_management_ip",
            "hostname",
            "model",
            "software_version",
            "switch_role",
        }

        changes: Dict[str, list] = {
            "to_add": [],
            "to_update": [],
            "role_change": [],
            "to_delete": [],
            "migration_mode": [],
            "idempotent": [],
        }

        # Categorise proposed switches
        for prop_sw in proposed:
            ip = prop_sw.fabric_management_ip
            sid = prop_sw.switch_id

            existing_sw = existing_by_id.get(sid)
            match_key = "switch_id" if existing_sw else None

            if not existing_sw:
                existing_sw = existing_by_ip.get(ip)
                if existing_sw:
                    match_key = "ip"

            if not existing_sw:
                log.info(
                    f"Switch {ip} (id={sid}) not found in existing — marking to_add"
                )
                changes["to_add"].append(prop_sw)
                continue

            log.debug(f"Switch {ip} (id={sid}) found in existing with {match_key} match {existing_sw}")
            log.debug(
                f"Switch {ip} matched existing by {match_key} "
                f"(existing_id={existing_sw.switch_id})"
            )

            if existing_sw.additional_data.system_mode == SystemMode.MIGRATION:
                log.info(
                    f"Switch {ip} ({existing_sw.switch_id}) is in Migration mode"
                )
                changes["migration_mode"].append(prop_sw)
                continue

            prop_dict = prop_sw.model_dump(
                by_alias=True, exclude_none=True, include=compare_fields
            )
            existing_dict = existing_sw.model_dump(
                by_alias=True, exclude_none=True, include=compare_fields
            )

            if prop_dict == existing_dict:
                log.debug(f"Switch {ip} is idempotent — no changes needed")
                changes["idempotent"].append(prop_sw)
            else:
                diff_keys = {
                    k for k in set(prop_dict) | set(existing_dict)
                    if prop_dict.get(k) != existing_dict.get(k)
                }
                if diff_keys == {"switch_role"}:
                    log.info(
                        f"Switch {ip} has role-only difference — marking role_change. "
                        f"proposed: {prop_dict.get('switch_role')}, "
                        f"existing: {existing_dict.get('switch_role')}"
                    )
                    changes["role_change"].append(prop_sw)
                else:
                    log.info(
                        f"Switch {ip} has differences — marking to_update. "
                        f"Changed fields: {diff_keys}"
                    )
                    log.debug(
                        f"Switch {ip} diff detail — "
                        f"proposed: { {k: prop_dict.get(k) for k in diff_keys} }, "
                        f"existing: { {k: existing_dict.get(k) for k in diff_keys} }"
                    )
                    changes["to_update"].append(prop_sw)

        # Switches in existing but not in proposed (for overridden state)
        proposed_ids = {sw.switch_id for sw in proposed}
        for existing_sw in existing:
            if existing_sw.switch_id not in proposed_ids:
                log.info(
                    f"Existing switch {existing_sw.fabric_management_ip} "
                    f"({existing_sw.switch_id}) not in proposed — marking to_delete"
                )
                changes["to_delete"].append(existing_sw)

        log.info(
            f"Compute changes summary: "
            f"to_add={len(changes['to_add'])}, "
            f"to_update={len(changes['to_update'])}, "
            f"role_change={len(changes['role_change'])}, "
            f"to_delete={len(changes['to_delete'])}, "
            f"migration_mode={len(changes['migration_mode'])}, "
            f"idempotent={len(changes['idempotent'])}"
        )
        log.debug("EXIT: compute_changes()")
        return changes


# =========================================================================
# Switch Discovery Service
# =========================================================================

class SwitchDiscoveryService:
    """Handle switch discovery and proposed-model construction."""

    def __init__(self, ctx: SwitchServiceContext):
        """Initialize the discovery service.

        Args:
            ctx: Shared service context.

        Returns:
            None.
        """
        self.ctx = ctx

    def discover(
        self,
        switch_configs: List[SwitchConfigModel],
    ) -> Dict[str, Dict[str, Any]]:
        """Discover switches for the provided config list.

        Args:
            switch_configs: Validated switch configuration entries.

        Returns:
            Dict mapping seed IP to raw discovery data.
        """
        log = self.ctx.log
        log.debug("Step 1: Grouping switches by credentials")
        credential_groups = group_switches_by_credentials(switch_configs, log)
        log.debug(f"Created {len(credential_groups)} credential group(s)")

        log.debug("Step 2: Bulk discovering switches")
        all_discovered: Dict[str, Dict[str, Any]] = {}
        for group_key, switches in credential_groups.items():
            username, _, auth_proto, platform_type, _ = group_key
            password = switches[0].password

            log.debug(
                f"Discovering group: {len(switches)} switches with username={username}"
            )
            try:
                discovered_batch = self.bulk_discover(
                    switches=switches,
                    username=username,
                    password=password,
                    auth_proto=auth_proto,
                    platform_type=platform_type,
                )
                all_discovered.update(discovered_batch)
            except Exception as e:
                seed_ips = [sw.seed_ip for sw in switches]
                msg = (
                    f"Discovery failed for credential group "
                    f"(username={username}, IPs={seed_ips}): {e}"
                )
                log.error(msg)
                self.ctx.nd.module.fail_json(msg=msg)

        log.debug(f"Total discovered: {len(all_discovered)} switches")
        return all_discovered

    def bulk_discover(
        self,
        switches: List[SwitchConfigModel],
        username: str,
        password: str,
        auth_proto: SnmpV3AuthProtocol,
        platform_type: PlatformType,
    ) -> Dict[str, Dict[str, Any]]:
        """Run one bulk discovery call for switches with shared credentials.

        Args:
            switches: Switches to discover.
            username: Discovery username.
            password: Discovery password.
            auth_proto: SNMP v3 authentication protocol.
            platform_type: Platform type for discovery.

        Returns:
            Dict mapping seed IP to discovered switch data.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: bulk_discover()")
        log.debug(f"Discovering {len(switches)} switches in bulk")

        endpoint = V1ManageFabricShallowDiscoveryPost()
        endpoint.fabric_name = self.ctx.fabric

        seed_ips = [switch.seed_ip for switch in switches]
        log.debug(f"Seed IPs: {seed_ips}")

        max_hops = switches[0].max_hops if hasattr(switches[0], 'max_hops') else 0

        discovery_request = ShallowDiscoveryRequestModel(
            seedIpCollection=seed_ips,
            maxHop=max_hops,
            platformType=platform_type,
            snmpV3AuthProtocol=auth_proto,
            username=username,
            password=password,
        )

        payload = discovery_request.to_payload()
        log.info(f"Bulk discovering {len(seed_ips)} switches: {', '.join(seed_ips)}")
        log.debug(f"Discovery endpoint: {endpoint.path}")
        log.debug(f"Discovery payload (password masked): {mask_password(payload)}")

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "discover"
            results.response_current = response
            results.result_current = result
            results.diff_current = payload
            results.register_task_result()

            # Extract discovered switches from response
            switches_data = []
            if response and isinstance(response, dict):
                if "DATA" in response and isinstance(response["DATA"], dict):
                    switches_data = response["DATA"].get("switches", [])
                elif "body" in response and isinstance(response["body"], dict):
                    switches_data = response["body"].get("switches", [])
                elif "switches" in response:
                    switches_data = response.get("switches", [])

            log.debug(
                f"Extracted {len(switches_data)} switches from discovery response"
            )

            discovered_results: Dict[str, Dict[str, Any]] = {}
            for discovered in switches_data:
                if not isinstance(discovered, dict):
                    continue

                ip = discovered.get("ip")
                status = discovered.get("status", "").lower()
                serial_number = discovered.get("serialNumber")

                if not serial_number:
                    msg = (
                        f"Switch {ip} discovery response missing serial number. "
                        f"Cannot proceed without a valid serial number."
                    )
                    log.error(msg)
                    nd.module.fail_json(msg=msg)
                if not ip:
                    msg = (
                        f"Switch with serial {serial_number} discovery response "
                        f"missing IP address. Cannot proceed without a valid IP."
                    )
                    log.error(msg)
                    nd.module.fail_json(msg=msg)

                if status in ("manageable", "ok"):
                    discovered_results[ip] = discovered
                    log.info(
                        f"Switch {ip} ({serial_number}) discovered successfully - status: {status}"
                    )
                elif status == "alreadymanaged":
                    log.info(f"Switch {ip} ({serial_number}) is already managed")
                    discovered_results[ip] = discovered
                else:
                    reason = discovered.get("statusReason", "Unknown")
                    log.error(
                        f"Switch {ip} discovery failed - status: {status}, reason: {reason}"
                    )

            for seed_ip in seed_ips:
                if seed_ip not in discovered_results:
                    log.warning(f"Switch {seed_ip} not found in discovery response")

            log.info(
                f"Bulk discovery completed: "
                f"{len(discovered_results)}/{len(seed_ips)} switches successful"
            )
            log.debug(f"Discovered switches: {list(discovered_results.keys())}")
            log.debug(
                f"EXIT: bulk_discover() -> {len(discovered_results)} discovered"
            )
            return discovered_results

        except Exception as e:
            msg = (
                f"Bulk discovery failed for switches "
                f"{', '.join(seed_ips)}: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

    def build_proposed(
        self,
        proposed_config: List[SwitchConfigModel],
        discovered_data: Dict[str, Dict[str, Any]],
        existing: List[SwitchDataModel],
    ) -> List[SwitchDataModel]:
        """Build proposed switch models from discovery and inventory data.

        Args:
            proposed_config: Validated switch config entries.
            discovered_data: Mapping of seed IP to raw discovery data.
            existing: Current fabric inventory snapshot.

        Returns:
            List of ``SwitchDataModel`` instances for proposed state.
        """
        log = self.ctx.log
        proposed: List[SwitchDataModel] = []

        for cfg in proposed_config:
            seed_ip = cfg.seed_ip
            discovered = discovered_data.get(seed_ip)

            if discovered:
                if cfg.role is not None:
                    discovered["role"] = cfg.role
                proposed.append(
                    SwitchDataModel.from_response(discovered)
                )
                log.debug(f"Built proposed model from discovery for {seed_ip}")
                continue

            # Fallback: switch may already be in the fabric inventory
            existing_match = next(
                (sw for sw in existing if sw.fabric_management_ip == seed_ip),
                None,
            )
            if existing_match:
                proposed.append(existing_match)
                log.warning(
                    f"Switch {seed_ip} not discovered but found in existing "
                    f"inventory — using existing record for comparison"
                )
                continue

            msg = (
                f"Switch with seed IP {seed_ip} not discovered "
                f"and not found in existing inventory."
            )
            log.error(msg)
            self.ctx.nd.module.fail_json(msg=msg)

        return proposed


# =========================================================================
# Bulk Fabric Operations
# =========================================================================

class SwitchFabricOps:
    """Run fabric mutation operations for add, delete, credentials, and roles."""

    def __init__(self, ctx: SwitchServiceContext, fabric_utils: FabricUtils):
        """Initialize the fabric operation service.

        Args:
            ctx: Shared service context.
            fabric_utils: Utility wrapper for fabric-level operations.

        Returns:
            None.
        """
        self.ctx = ctx
        self.fabric_utils = fabric_utils

    def bulk_add(
        self,
        switches: List[Tuple[SwitchConfigModel, Dict[str, Any]]],
        username: str,
        password: str,
        auth_proto: SnmpV3AuthProtocol,
        platform_type: PlatformType,
        preserve_config: bool,
    ) -> Dict[str, Any]:
        """Add multiple discovered switches to the fabric.

        Args:
            switches: List of ``(SwitchConfigModel, discovered_data)`` tuples.
            username: Discovery username.
            password: Discovery password.
            auth_proto: SNMP v3 authentication protocol.
            platform_type: Platform type.
            preserve_config: Whether to preserve existing switch config.

        Returns:
            API response payload.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: bulk_add()")
        log.debug(f"Adding {len(switches)} switches to fabric")

        endpoint = V1ManageFabricSwitchesPost()
        endpoint.fabric_name = self.ctx.fabric

        switch_discoveries = []
        for switch_config, discovered in switches:
            required_fields = ["hostname", "ip", "serialNumber", "model"]
            missing_fields = [f for f in required_fields if not discovered.get(f)]

            if missing_fields:
                msg = (
                    f"Switch missing required fields from discovery: "
                    f"{', '.join(missing_fields)}. Cannot add to fabric."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)

            switch_role = switch_config.role if hasattr(switch_config, 'role') else None

            switch_discovery = SwitchDiscoveryModel(
                hostname=discovered.get("hostname"),
                ip=discovered.get("ip"),
                serialNumber=discovered.get("serialNumber"),
                model=discovered.get("model"),
                softwareVersion=discovered.get("softwareVersion"),
                switchRole=switch_role,
            )
            switch_discoveries.append(switch_discovery)
            log.debug(
                f"Prepared switch for add: "
                f"{discovered.get('serialNumber')} ({discovered.get('hostname')})"
            )

        if not switch_discoveries:
            log.error("No valid switches to add after validation")
            raise SwitchOperationError("No valid switches to add - all failed validation")

        add_request = AddSwitchesRequestModel(
            switches=switch_discoveries,
            platformType=platform_type,
            preserveConfig=preserve_config,
            snmpV3AuthProtocol=auth_proto,
            username=username,
            password=password,
        )

        payload = add_request.to_payload()
        serial_numbers = [d.get("serialNumber") for _, d in switches]
        log.info(
            f"Bulk adding {len(switches)} switches to fabric "
            f"{self.ctx.fabric}: {', '.join(serial_numbers)}"
        )
        log.debug(f"Add endpoint: {endpoint.path}")
        log.debug(f"Add payload (password masked): {mask_password(payload)}")

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = (
                f"Bulk add switches to fabric '{self.ctx.fabric}' failed "
                f"for {', '.join(serial_numbers)}: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "create"
        results.response_current = response
        results.result_current = result
        results.diff_current = payload
        results.register_task_result()

        if not result.get("success"):
            msg = (
                f"Bulk add switches failed for "
                f"{', '.join(serial_numbers)}: {response}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        return response

    def bulk_delete(
        self,
        switches: List[Union[SwitchDataModel, SwitchDiscoveryModel]],
    ) -> List[str]:
        """Remove multiple switches from the fabric.

        Args:
            switches: Switch models to delete.

        Returns:
            List of switch identifiers submitted for deletion.

        Raises:
            SwitchOperationError: Raised when the delete API call fails.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: bulk_delete()")

        if nd.module.check_mode:
            log.debug("Check mode: Skipping actual deletion")
            return []

        serial_numbers: List[str] = []
        for switch in switches:
            sn = None
            if hasattr(switch, 'switch_id'):
                sn = switch.switch_id
            elif hasattr(switch, 'serial_number'):
                sn = switch.serial_number

            if sn:
                serial_numbers.append(sn)
            else:
                ip = getattr(switch, 'fabric_management_ip', None) or getattr(switch, 'ip', None)
                log.warning(f"Cannot delete switch {ip}: no serial number/switch_id")

        if not serial_numbers:
            log.warning("No valid serial numbers found for deletion")
            log.debug("EXIT: bulk_delete() - nothing to delete")
            return []

        endpoint = V1ManageFabricSwitchActionsRemovePost()
        endpoint.fabric_name = self.ctx.fabric
        payload = {"switchIds": serial_numbers}

        log.info(
            f"Bulk removing {len(serial_numbers)} switch(es) from fabric "
            f"{self.ctx.fabric}: {serial_numbers}"
        )
        log.debug(f"Delete endpoint: {endpoint.path}")
        log.debug(f"Delete payload: {payload}")

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "delete"
            results.response_current = response
            results.result_current = result
            results.diff_current = {"deleted": serial_numbers}
            results.register_task_result()

            log.info(f"Bulk delete submitted for {len(serial_numbers)} switch(es)")
            log.debug("EXIT: bulk_delete()")
            return serial_numbers

        except Exception as e:
            log.error(f"Bulk delete failed: {e}")
            raise SwitchOperationError(
                f"Bulk delete failed for {serial_numbers}: {e}"
            ) from e

    def bulk_save_credentials(
        self,
        switch_actions: List[Tuple[str, SwitchConfigModel]],
    ) -> None:
        """Save switch credentials grouped by username and password.

        Args:
            switch_actions: ``(switch_id, SwitchConfigModel)`` pairs.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: bulk_save_credentials()")

        cred_groups: Dict[Tuple[str, str], List[str]] = {}
        for sn, cfg in switch_actions:
            if not cfg.user_name or not cfg.password:
                log.debug(f"Skipping credentials for {sn}: missing user_name or password")
                continue
            key = (cfg.user_name, cfg.password)
            cred_groups.setdefault(key, []).append(sn)

        if not cred_groups:
            log.debug("EXIT: bulk_save_credentials() - no credentials to save")
            return

        endpoint = V1ManageCredentialsSwitchesPost()

        for (username, password), serial_numbers in cred_groups.items():
            creds_request = SwitchCredentialsRequestModel(
                switchIds=serial_numbers,
                switchUsername=username,
                switchPassword=password,
            )
            payload = creds_request.to_payload()

            log.info(
                f"Saving credentials for {len(serial_numbers)} switch(es): {serial_numbers}"
            )
            log.debug(f"Credentials endpoint: {endpoint.path}")
            log.debug(
                f"Credentials payload (masked): {mask_password(payload)}"
            )

            try:
                nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

                response = nd.rest_send.response_current
                result = nd.rest_send.result_current

                results.action = "save_credentials"
                results.response_current = response
                results.result_current = result
                results.diff_current = {
                    "switchIds": serial_numbers,
                    "username": username,
                }
                results.register_task_result()
                log.info(f"Credentials saved for {len(serial_numbers)} switch(es)")
            except Exception as e:
                msg = (
                    f"Failed to save credentials for "
                    f"switches {serial_numbers}: {e}"
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)

        log.debug("EXIT: bulk_save_credentials()")

    def bulk_update_roles(
        self,
        switch_actions: List[Tuple[str, SwitchConfigModel]],
    ) -> None:
        """Update switch roles in bulk.

        Args:
            switch_actions: ``(switch_id, SwitchConfigModel)`` pairs.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: bulk_update_roles()")

        switch_roles = []
        for sn, cfg in switch_actions:
            role = get_switch_field(cfg, ['role'])
            if not role:
                continue
            role_value = role.value if isinstance(role, SwitchRole) else str(role)
            switch_roles.append({"switchId": sn, "role": role_value})

        if not switch_roles:
            log.debug("EXIT: bulk_update_roles() - no roles to update")
            return

        endpoint = V1ManageFabricSwitchActionsChangeRolesPost()
        endpoint.fabric_name = self.ctx.fabric
        payload = {"switchRoles": switch_roles}

        log.info(f"Bulk updating roles for {len(switch_roles)} switch(es)")
        log.debug(f"ChangeRoles endpoint: {endpoint.path}")
        log.debug(f"ChangeRoles payload: {payload}")

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "update_role"
            results.response_current = response
            results.result_current = result
            results.diff_current = payload
            results.register_task_result()
            log.info(f"Roles updated for {len(switch_roles)} switch(es)")
        except Exception as e:
            msg = (
                f"Failed to bulk update roles for switches: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.debug("EXIT: bulk_update_roles()")

    def finalize(self) -> None:
        """Run optional save and deploy actions for the fabric.

        Uses service context flags to decide whether save and deploy should be
        executed. No-op in check mode.

        Returns:
            None.
        """
        if self.ctx.nd.module.check_mode:
            return

        if self.ctx.save_config:
            self.ctx.log.info("Saving fabric configuration")
            self.fabric_utils.save_config()

        if self.ctx.deploy_config:
            self.ctx.log.info("Deploying fabric configuration")
            self.fabric_utils.deploy_config()

    def post_add_processing(
        self,
        switch_actions: List[Tuple[str, SwitchConfigModel]],
        wait_utils,
        context: str,
        all_preserve_config: bool = False,
        skip_greenfield_check: bool = False,
        update_roles: bool = False,
    ) -> None:
        """Run post-add tasks for newly processed switches.

        Args:
            switch_actions: ``(switch_id, SwitchConfigModel)`` pairs.
            wait_utils: Wait utility used for manageability checks.
            context: Label used in logs and error messages.
            all_preserve_config: Whether to use preserve-config wait behavior.
            skip_greenfield_check: Whether to skip greenfield wait shortcut.
            update_roles: Whether to apply bulk role updates.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        all_serials = [sn for sn, _ in switch_actions]

        log.info(
            f"Waiting for {len(all_serials)} {context} "
            f"switch(es) to become manageable: {all_serials}"
        )

        wait_kwargs: Dict[str, Any] = {}
        if all_preserve_config:
            wait_kwargs["all_preserve_config"] = True
        if skip_greenfield_check:
            wait_kwargs["skip_greenfield_check"] = True

        success = wait_utils.wait_for_switch_manageable(
            all_serials,
            **wait_kwargs,
        )
        if not success:
            msg = (
                f"One or more {context} switches failed to become "
                f"manageable in fabric '{self.ctx.fabric}'. "
                f"Switches: {all_serials}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        self.bulk_save_credentials(switch_actions)

        if update_roles:
            self.bulk_update_roles(switch_actions)

        try:
            self.finalize()
        except Exception as e:
            msg = (
                f"Failed to finalize (config-save/deploy) for "
                f"{context} switches {all_serials}: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)


# =========================================================================
# POAP Handler (Bootstrap / Pre-Provision)
# =========================================================================

class POAPHandler:
    """Handle POAP workflows for bootstrap, pre-provision, and serial swap."""

    def __init__(
        self,
        ctx: SwitchServiceContext,
        fabric_ops: SwitchFabricOps,
        wait_utils: SwitchWaitUtils,
    ):
        """Initialize the POAP workflow handler.

        Args:
            ctx: Shared service context.
            fabric_ops: Fabric operation service.
            wait_utils: Switch wait utility service.

        Returns:
            None.
        """
        self.ctx = ctx
        self.fabric_ops = fabric_ops
        self.wait_utils = wait_utils

    def handle(
        self,
        proposed_config: List[SwitchConfigModel],
        existing: Optional[List[SwitchDataModel]] = None,
    ) -> None:
        """Execute POAP processing for the provided switch configs.

        Args:
            proposed_config: Validated switch configs for POAP operations.
            existing: Current fabric inventory snapshot.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: POAPHandler.handle()")
        log.info(f"Processing POAP for {len(proposed_config)} switch config(s)")

        # Check mode — preview only
        if nd.module.check_mode:
            log.info("Check mode: would run POAP bootstrap / pre-provision")
            results.action = "poap"
            results.response_current = {"MESSAGE": "check mode — skipped"}
            results.result_current = {"success": True, "changed": True}
            results.diff_current = {
                "poap_switches": [pc.seed_ip for pc in proposed_config]
            }
            results.register_task_result()
            return

        # Classify entries
        bootstrap_entries: List[Tuple[SwitchConfigModel, POAPConfigModel]] = []
        preprov_entries: List[Tuple[SwitchConfigModel, POAPConfigModel]] = []
        swap_entries: List[Tuple[SwitchConfigModel, POAPConfigModel]] = []

        for switch_cfg in proposed_config:
            if not switch_cfg.poap:
                log.warning(
                    f"Switch config for {switch_cfg.seed_ip} has no POAP block — skipping"
                )
                continue

            for poap_cfg in switch_cfg.poap:
                if poap_cfg.serial_number and poap_cfg.preprovision_serial:
                    swap_entries.append((switch_cfg, poap_cfg))
                elif poap_cfg.preprovision_serial:
                    preprov_entries.append((switch_cfg, poap_cfg))
                elif poap_cfg.serial_number:
                    bootstrap_entries.append((switch_cfg, poap_cfg))
                else:
                    log.warning(
                        f"POAP entry for {switch_cfg.seed_ip} has neither "
                        f"serial_number nor preprovision_serial — skipping"
                    )

        log.info(
            f"POAP classification: {len(bootstrap_entries)} bootstrap, "
            f"{len(preprov_entries)} pre-provision, "
            f"{len(swap_entries)} swap"
        )

        # Handle swap entries (change serial number on pre-provisioned switches)
        if swap_entries:
            self._handle_poap_swap(swap_entries, existing or [])

        # Handle bootstrap entries
        if bootstrap_entries:
            self._handle_poap_bootstrap(bootstrap_entries)

        # Handle pre-provision entries
        if preprov_entries:
            preprov_models: List[PreProvisionSwitchModel] = []
            for switch_cfg, poap_cfg in preprov_entries:
                pp_model = self._build_preprovision_model(switch_cfg, poap_cfg)
                preprov_models.append(pp_model)
                log.info(
                    f"Built pre-provision model for serial="
                    f"{pp_model.serial_number}, hostname={pp_model.hostname}, "
                    f"ip={pp_model.ip}"
                )

            if preprov_models:
                self._preprovision_switches(preprov_models)

        # Edge case: nothing actionable
        if not bootstrap_entries and not preprov_entries and not swap_entries:
            log.warning("No POAP switch models built — nothing to process")
            results.action = "poap"
            results.response_current = {"MESSAGE": "no switches to process"}
            results.result_current = {"success": True, "changed": False}
            results.diff_current = {}
            results.register_task_result()

        log.debug("EXIT: POAPHandler.handle()")

    def _handle_poap_bootstrap(
        self,
        bootstrap_entries: List[Tuple[SwitchConfigModel, POAPConfigModel]],
    ) -> None:
        """Process bootstrap POAP entries.

        Args:
            bootstrap_entries: ``(SwitchConfigModel, POAPConfigModel)`` pairs
                for bootstrap operations.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log

        log.debug("ENTER: _handle_poap_bootstrap()")
        log.info(f"Processing {len(bootstrap_entries)} bootstrap entries")

        bootstrap_switches = query_bootstrap_switches(nd, self.ctx.fabric, log)
        bootstrap_idx = build_bootstrap_index(bootstrap_switches)
        log.debug(
            f"Bootstrap index contains {len(bootstrap_idx)} switch(es): "
            f"{list(bootstrap_idx.keys())}"
        )

        import_models: List[BootstrapImportSwitchModel] = []
        for switch_cfg, poap_cfg in bootstrap_entries:
            serial = poap_cfg.serial_number
            bootstrap_data = bootstrap_idx.get(serial)

            if not bootstrap_data:
                msg = (
                    f"Serial {serial} not found in bootstrap API "
                    f"response. The switch is not in the POAP loop. "
                    f"Ensure the switch is powered on and POAP/DHCP "
                    f"is enabled in the fabric."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)

            model = self._build_bootstrap_import_model(
                switch_cfg, poap_cfg, bootstrap_data
            )
            import_models.append(model)
            log.info(
                f"Built bootstrap model for serial={serial}, "
                f"hostname={model.hostname}, ip={model.ip}"
            )

        if not import_models:
            log.warning("No bootstrap import models built")
            log.debug("EXIT: _handle_poap_bootstrap()")
            return

        self._import_bootstrap_switches(import_models)

        # Post-import: wait for manageability, save credentials, finalize
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []
        for switch_cfg, poap_cfg in bootstrap_entries:
            switch_actions.append((poap_cfg.serial_number, switch_cfg))

        self.fabric_ops.post_add_processing(
            switch_actions,
            wait_utils=self.wait_utils,
            context="bootstrap",
            skip_greenfield_check=True,
        )

        log.debug("EXIT: _handle_poap_bootstrap()")

    def _build_bootstrap_import_model(
        self,
        switch_cfg: SwitchConfigModel,
        poap_cfg: POAPConfigModel,
        bootstrap_data: Optional[Dict[str, Any]],
    ) -> BootstrapImportSwitchModel:
        """Build a bootstrap import model from config and bootstrap data.

        Args:
            switch_cfg: Parent switch config.
            poap_cfg: POAP config entry.
            bootstrap_data: Matching bootstrap response entry.

        Returns:
            Completed ``BootstrapImportSwitchModel`` for API submission.
        """
        log = self.ctx.log
        log.debug(
            f"ENTER: _build_bootstrap_import_model(serial={poap_cfg.serial_number})"
        )

        bs = bootstrap_data or {}

        # User config fields
        serial_number = poap_cfg.serial_number
        hostname = poap_cfg.hostname
        ip = switch_cfg.seed_ip
        model = poap_cfg.model
        version = poap_cfg.version
        image_policy = poap_cfg.image_policy
        gateway_ip_mask = poap_cfg.config_data.gateway if poap_cfg.config_data else None
        switch_role = switch_cfg.role
        password = switch_cfg.password
        auth_proto = SnmpV3AuthProtocol.MD5  # POAP/bootstrap always uses MD5

        discovery_username = getattr(poap_cfg, "discovery_username", None)
        discovery_password = getattr(poap_cfg, "discovery_password", None)

        # Bootstrap API response fields
        fingerprint = bs.get("fingerPrint", bs.get("fingerprint", ""))
        public_key = bs.get("publicKey", "")
        re_add = bs.get("reAdd", False)
        in_inventory = bs.get("inInventory", False)

        # Shared data block builder
        data_block = build_poap_data_block(poap_cfg)

        bootstrap_model = BootstrapImportSwitchModel(
            serialNumber=serial_number,
            model=model,
            version=version,
            hostname=hostname,
            ipAddress=ip,
            password=password,
            discoveryAuthProtocol=auth_proto,
            discoveryUsername=discovery_username,
            discoveryPassword=discovery_password,
            data=data_block,
            fingerprint=fingerprint,
            publicKey=public_key,
            reAdd=re_add,
            inInventory=in_inventory,
            imagePolicy=image_policy or "",
            switchRole=switch_role,
            ip=ip,
            softwareVersion=version,
            gatewayIpMask=gateway_ip_mask,
        )

        log.debug(
            f"EXIT: _build_bootstrap_import_model() -> {bootstrap_model.serial_number}"
        )
        return bootstrap_model

    def _import_bootstrap_switches(
        self,
        models: List[BootstrapImportSwitchModel],
    ) -> None:
        """Submit bootstrap import models.

        Args:
            models: ``BootstrapImportSwitchModel`` objects to submit.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: _import_bootstrap_switches()")

        endpoint = V1ManageFabricSwitchActionsImportBootstrapPost()
        endpoint.fabric_name = self.ctx.fabric

        request_model = ImportBootstrapSwitchesRequestModel(switches=models)
        payload = request_model.to_payload()

        log.debug(f"importBootstrap endpoint: {endpoint.path}")
        log.debug(
            f"importBootstrap payload (masked): {mask_password(payload)}"
        )
        log.info(
            f"Importing {len(models)} bootstrap switch(es): "
            f"{[m.serial_number for m in models]}"
        )

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = (
                f"importBootstrap API call failed for "
                f"{[m.serial_number for m in models]}: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "bootstrap"
        results.response_current = response
        results.result_current = result
        results.diff_current = payload
        results.register_task_result()

        if not result.get("success"):
            msg = (
                f"importBootstrap failed for "
                f"{[m.serial_number for m in models]}: {response}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.info(f"importBootstrap API response success: {result.get('success')}")
        log.debug("EXIT: _import_bootstrap_switches()")

    def _build_preprovision_model(
        self,
        switch_cfg: SwitchConfigModel,
        poap_cfg: POAPConfigModel,
    ) -> PreProvisionSwitchModel:
        """Build a pre-provision model from POAP configuration.

        Args:
            switch_cfg: Parent switch config.
            poap_cfg: POAP config entry.

        Returns:
            Completed ``PreProvisionSwitchModel`` for API submission.
        """
        log = self.ctx.log
        log.debug(
            f"ENTER: _build_preprovision_model(serial={poap_cfg.preprovision_serial})"
        )

        serial_number = poap_cfg.preprovision_serial
        hostname = poap_cfg.hostname
        ip = switch_cfg.seed_ip
        model_name = poap_cfg.model
        version = poap_cfg.version
        image_policy = poap_cfg.image_policy
        gateway_ip_mask = poap_cfg.config_data.gateway if poap_cfg.config_data else None
        switch_role = switch_cfg.role
        password = switch_cfg.password
        auth_proto = SnmpV3AuthProtocol.MD5  # Pre-provision always uses MD5

        discovery_username = getattr(poap_cfg, "discovery_username", None)
        discovery_password = getattr(poap_cfg, "discovery_password", None)

        # Shared data block builder
        data_block = build_poap_data_block(poap_cfg)

        preprov_model = PreProvisionSwitchModel(
            serialNumber=serial_number,
            hostname=hostname,
            ip=ip,
            model=model_name,
            softwareVersion=version,
            gatewayIpMask=gateway_ip_mask,
            password=password,
            discoveryAuthProtocol=auth_proto,
            discoveryUsername=discovery_username,
            discoveryPassword=discovery_password,
            data=data_block,
            imagePolicy=image_policy or None,
            switchRole=switch_role,
        )

        log.debug(
            f"EXIT: _build_preprovision_model() -> {preprov_model.serial_number}"
        )
        return preprov_model

    def _preprovision_switches(
        self,
        models: List[PreProvisionSwitchModel],
    ) -> None:
        """Submit pre-provision switch models.

        Args:
            models: ``PreProvisionSwitchModel`` objects to submit.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: _preprovision_switches()")

        endpoint = V1ManageFabricSwitchActionsPreProvisionPost()
        endpoint.fabric_name = self.ctx.fabric

        request_model = PreProvisionSwitchesRequestModel(switches=models)
        payload = request_model.to_payload()

        log.debug(f"preProvision endpoint: {endpoint.path}")
        log.debug(
            f"preProvision payload (masked): {mask_password(payload)}"
        )
        log.info(
            f"Pre-provisioning {len(models)} switch(es): "
            f"{[m.serial_number for m in models]}"
        )

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = (
                f"preProvision API call failed for "
                f"{[m.serial_number for m in models]}: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "preprovision"
        results.response_current = response
        results.result_current = result
        results.diff_current = payload
        results.register_task_result()

        if not result.get("success"):
            msg = (
                f"preProvision failed for "
                f"{[m.serial_number for m in models]}: {response}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.info(f"preProvision API response success: {result.get('success')}")
        log.debug("EXIT: _preprovision_switches()")

    def _handle_poap_swap(
        self,
        swap_entries: List[Tuple[SwitchConfigModel, POAPConfigModel]],
        existing: List[SwitchDataModel],
    ) -> None:
        """Process POAP serial-swap entries.

        Args:
            swap_entries: ``(SwitchConfigModel, POAPConfigModel)`` swap pairs.
            existing: Current fabric inventory snapshot.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results
        fabric = self.ctx.fabric

        log.debug("ENTER: _handle_poap_swap()")
        log.info(f"Processing {len(swap_entries)} POAP swap entries")

        # ------------------------------------------------------------------
        # Step 1: Validate preprovision serials exist in fabric inventory
        # ------------------------------------------------------------------
        fabric_index: Dict[str, Dict[str, Any]] = {
            sw.switch_id: sw.model_dump(by_alias=True)
            for sw in existing
            if sw.switch_id
        }
        log.debug(
            f"Fabric inventory contains {len(fabric_index)} switch(es): "
            f"{list(fabric_index.keys())}"
        )

        for switch_cfg, poap_cfg in swap_entries:
            old_serial = poap_cfg.preprovision_serial
            if old_serial not in fabric_index:
                msg = (
                    f"Pre-provisioned serial '{old_serial}' not found in "
                    f"fabric '{fabric}' inventory. The switch must be "
                    f"pre-provisioned before a swap can be performed."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)
            log.info(
                f"Validated: pre-provisioned serial '{old_serial}' exists "
                f"in fabric inventory"
            )

        # ------------------------------------------------------------------
        # Step 2: Validate new serials exist in bootstrap list
        # ------------------------------------------------------------------
        bootstrap_switches = query_bootstrap_switches(nd, fabric, log)
        bootstrap_index = build_bootstrap_index(bootstrap_switches)
        log.debug(
            f"Bootstrap list contains {len(bootstrap_index)} switch(es): "
            f"{list(bootstrap_index.keys())}"
        )

        for switch_cfg, poap_cfg in swap_entries:
            new_serial = poap_cfg.serial_number
            if new_serial not in bootstrap_index:
                msg = (
                    f"New serial '{new_serial}' not found in the bootstrap "
                    f"(POAP) list for fabric '{fabric}'. The physical "
                    f"switch must be in the POAP loop before a swap can be "
                    f"performed."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)
            log.info(
                f"Validated: new serial '{new_serial}' exists in "
                f"bootstrap list"
            )

        # ------------------------------------------------------------------
        # Step 3: Call changeSwitchSerialNumber for each swap entry
        # ------------------------------------------------------------------
        for switch_cfg, poap_cfg in swap_entries:
            old_serial = poap_cfg.preprovision_serial
            new_serial = poap_cfg.serial_number

            log.info(
                f"Swapping serial for pre-provisioned switch: "
                f"{old_serial} → {new_serial}"
            )

            endpoint = V1ManageFabricSwitchChangeSerialNumberPost()
            endpoint.fabric_name = fabric
            endpoint.switch_sn = old_serial

            request_body = ChangeSwitchSerialNumberRequestModel(
                newSwitchId=new_serial
            )
            payload = request_body.to_payload()

            log.debug(f"changeSwitchSerialNumber endpoint: {endpoint.path}")
            log.debug(f"changeSwitchSerialNumber payload: {payload}")

            try:
                nd.request(
                    path=endpoint.path, verb=endpoint.verb, data=payload
                )
            except Exception as e:
                msg = (
                    f"changeSwitchSerialNumber API call failed for "
                    f"{old_serial} → {new_serial}: {e}"
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "swap_serial"
            results.response_current = response
            results.result_current = result
            results.diff_current = {
                "old_serial": old_serial,
                "new_serial": new_serial,
            }
            results.register_task_result()

            if not result.get("success"):
                msg = (
                    f"Failed to swap serial number from {old_serial} "
                    f"to {new_serial}: {response}"
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)

            log.info(
                f"Serial number swap successful: {old_serial} → {new_serial}"
            )

        # ------------------------------------------------------------------
        # Step 4: Re-query bootstrap API for post-swap data
        # ------------------------------------------------------------------
        post_swap_bootstrap = query_bootstrap_switches(nd, fabric, log)
        post_swap_index = build_bootstrap_index(post_swap_bootstrap)
        log.debug(
            f"Post-swap bootstrap list contains "
            f"{len(post_swap_index)} switch(es)"
        )

        # ------------------------------------------------------------------
        # Step 5: Build BootstrapImportSwitchModels and POST importBootstrap
        # ------------------------------------------------------------------
        import_models: List[BootstrapImportSwitchModel] = []
        for switch_cfg, poap_cfg in swap_entries:
            new_serial = poap_cfg.serial_number
            bootstrap_data = post_swap_index.get(new_serial)

            if not bootstrap_data:
                msg = (
                    f"Serial '{new_serial}' not found in bootstrap API "
                    f"response after swap. The controller may not have "
                    f"updated the bootstrap list yet."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)

            model = self._build_bootstrap_import_model(
                switch_cfg, poap_cfg, bootstrap_data
            )
            import_models.append(model)
            log.info(
                f"Built bootstrap model for swapped serial={new_serial}, "
                f"hostname={model.hostname}, ip={model.ip}"
            )

        if not import_models:
            log.warning("No bootstrap import models built after swap")
            log.debug("EXIT: _handle_poap_swap()")
            return

        try:
            self._import_bootstrap_switches(import_models)
        except Exception as e:
            msg = (
                f"importBootstrap failed after serial swap: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        # ------------------------------------------------------------------
        # Step 6: Wait for manageability, save credentials, finalize
        # ------------------------------------------------------------------
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []
        for switch_cfg, poap_cfg in swap_entries:
            switch_actions.append((poap_cfg.serial_number, switch_cfg))

        self.fabric_ops.post_add_processing(
            switch_actions,
            wait_utils=self.wait_utils,
            context="swap",
            skip_greenfield_check=True,
        )

        log.info(
            f"POAP swap completed successfully for {len(swap_entries)} "
            f"switch(es): {[sn for sn, _ in switch_actions]}"
        )
        log.debug("EXIT: _handle_poap_swap()")


# =========================================================================
# RMA Handler (Return Material Authorization)
# =========================================================================

class RMAHandler:
    """Handle RMA workflows for switch replacement."""

    def __init__(
        self,
        ctx: SwitchServiceContext,
        fabric_ops: SwitchFabricOps,
        wait_utils: SwitchWaitUtils,
    ):
        """Initialize the RMA workflow handler.

        Args:
            ctx: Shared service context.
            fabric_ops: Fabric operation service.
            wait_utils: Switch wait utility service.

        Returns:
            None.
        """
        self.ctx = ctx
        self.fabric_ops = fabric_ops
        self.wait_utils = wait_utils

    def handle(
        self,
        proposed_config: List[SwitchConfigModel],
        existing: List[SwitchDataModel],
    ) -> None:
        """Execute RMA processing for the provided switch configs.

        Args:
            proposed_config: Validated switch configs for RMA operations.
            existing: Current fabric inventory snapshot.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: RMAHandler.handle()")
        log.info(f"Processing RMA for {len(proposed_config)} switch config(s)")

        # Check mode — preview only
        if nd.module.check_mode:
            log.info("Check mode: would run RMA provision")
            results.action = "rma"
            results.response_current = {"MESSAGE": "check mode — skipped"}
            results.result_current = {"success": True, "changed": True}
            results.diff_current = {
                "rma_switches": [pc.seed_ip for pc in proposed_config]
            }
            results.register_task_result()
            return

        # Collect (SwitchConfigModel, RMAConfigModel) pairs
        rma_entries: List[Tuple[SwitchConfigModel, RMAConfigModel]] = []
        for switch_cfg in proposed_config:
            if not switch_cfg.rma:
                log.warning(
                    f"Switch config for {switch_cfg.seed_ip} has no RMA block — skipping"
                )
                continue
            for rma_cfg in switch_cfg.rma:
                rma_entries.append((switch_cfg, rma_cfg))

        if not rma_entries:
            log.warning("No RMA entries found — nothing to process")
            results.action = "rma"
            results.response_current = {"MESSAGE": "no switches to process"}
            results.result_current = {"success": True, "changed": False}
            results.diff_current = {}
            results.register_task_result()
            return

        log.info(f"Found {len(rma_entries)} RMA entry/entries to process")

        # Validate old switches exist and are in correct state
        old_switch_info = self._validate_prerequisites(rma_entries, existing)

        # Query bootstrap API for publicKey / fingerPrint of new switches
        bootstrap_switches = query_bootstrap_switches(nd, self.ctx.fabric, log)
        bootstrap_idx = build_bootstrap_index(bootstrap_switches)
        log.debug(
            f"Bootstrap index contains {len(bootstrap_idx)} switch(es): "
            f"{list(bootstrap_idx.keys())}"
        )

        # Build and submit each RMA request
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []
        for switch_cfg, rma_cfg in rma_entries:
            new_serial = rma_cfg.serial_number
            bootstrap_data = bootstrap_idx.get(new_serial)

            if not bootstrap_data:
                msg = (
                    f"New switch serial {new_serial} not found in "
                    f"bootstrap API response. The switch is not in the "
                    f"POAP loop. Ensure the replacement switch is powered "
                    f"on and POAP/DHCP is enabled in the fabric."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)

            rma_model = self._build_rma_model(
                switch_cfg, rma_cfg, bootstrap_data,
                old_switch_info[rma_cfg.old_serial],
            )
            log.info(
                f"Built RMA model: replacing {rma_cfg.old_serial} with "
                f"{rma_model.new_switch_id}"
            )

            self._provision_rma_switch(rma_cfg.old_serial, rma_model)
            switch_actions.append((rma_model.new_switch_id, switch_cfg))

        # Post-processing: wait, save credentials, finalize
        self.fabric_ops.post_add_processing(
            switch_actions,
            wait_utils=self.wait_utils,
            context="RMA",
            skip_greenfield_check=True,
        )

        log.debug("EXIT: RMAHandler.handle()")

    def _validate_prerequisites(
        self,
        rma_entries: List[Tuple[SwitchConfigModel, RMAConfigModel]],
        existing: List[SwitchDataModel],
    ) -> Dict[str, Dict[str, Any]]:
        """Validate RMA prerequisites for each requested replacement.

        Args:
            rma_entries: ``(SwitchConfigModel, RMAConfigModel)`` pairs.
            existing: Current fabric inventory snapshot.

        Returns:
            Dict keyed by old serial with prerequisite metadata.
        """
        nd = self.ctx.nd
        log = self.ctx.log

        log.debug("ENTER: _validate_prerequisites()")

        existing_by_serial: Dict[str, SwitchDataModel] = {
            sw.serial_number: sw for sw in existing if sw.serial_number
        }

        result: Dict[str, Dict[str, Any]] = {}

        for switch_cfg, rma_cfg in rma_entries:
            old_serial = rma_cfg.old_serial

            old_switch = existing_by_serial.get(old_serial)
            if old_switch is None:
                nd.module.fail_json(
                    msg=(
                        f"RMA: old_serial '{old_serial}' not found in "
                        f"fabric '{self.ctx.fabric}'. The switch being "
                        f"replaced must exist in the inventory."
                    )
                )

            ad = old_switch.additional_data
            if ad is None:
                nd.module.fail_json(
                    msg=(
                        f"RMA: Switch '{old_serial}' has no additional data "
                        f"in the inventory response. Cannot verify discovery "
                        f"status and system mode."
                    )
                )

            if ad.discovery_status != DiscoveryStatus.UNREACHABLE.value:
                nd.module.fail_json(
                    msg=(
                        f"RMA: Switch '{old_serial}' has discovery status "
                        f"'{ad.discovery_status or 'unknown'}', "
                        f"expected 'unreachable'. The old switch must be "
                        f"unreachable before RMA can proceed."
                    )
                )

            if ad.system_mode != SystemMode.MAINTENANCE.value:
                nd.module.fail_json(
                    msg=(
                        f"RMA: Switch '{old_serial}' is in "
                        f"'{ad.system_mode or 'unknown'}' "
                        f"mode, expected 'maintenance'. Put the switch in "
                        f"maintenance mode before initiating RMA."
                    )
                )

            result[old_serial] = {
                "hostname": old_switch.hostname or "",
                "switch_data": old_switch,
            }
            log.info(
                f"RMA prerequisite check passed for old_serial "
                f"'{old_serial}' (hostname={old_switch.hostname}, "
                f"discovery={ad.discovery_status}, mode={ad.system_mode})"
            )

        log.debug("EXIT: _validate_prerequisites()")
        return result

    def _build_rma_model(
        self,
        switch_cfg: SwitchConfigModel,
        rma_cfg: RMAConfigModel,
        bootstrap_data: Dict[str, Any],
        old_switch_info: Dict[str, Any],
    ) -> RMASwitchModel:
        """Build an RMA model from config and bootstrap data.

        Args:
            switch_cfg: Parent switch config.
            rma_cfg: RMA config entry.
            bootstrap_data: Bootstrap response entry for the replacement switch.
            old_switch_info: Prerequisite metadata for the switch being replaced.

        Returns:
            Completed ``RMASwitchModel`` for API submission.
        """
        log = self.ctx.log
        log.debug(
            f"ENTER: _build_rma_model(new={rma_cfg.serial_number}, "
            f"old={rma_cfg.old_serial})"
        )

        # User config fields
        new_switch_id = rma_cfg.serial_number
        hostname = old_switch_info.get("hostname", "")
        ip = switch_cfg.seed_ip
        model_name = rma_cfg.model
        version = rma_cfg.version
        image_policy = rma_cfg.image_policy
        gateway_ip_mask = rma_cfg.config_data.gateway
        switch_role = switch_cfg.role
        password = switch_cfg.password
        auth_proto = SnmpV3AuthProtocol.MD5  # RMA always uses MD5

        discovery_username = rma_cfg.discovery_username
        discovery_password = rma_cfg.discovery_password

        # Bootstrap API response fields
        public_key = bootstrap_data.get("publicKey", "")
        finger_print = bootstrap_data.get(
            "fingerPrint", bootstrap_data.get("fingerprint", "")
        )

        rma_model = RMASwitchModel(
            gatewayIpMask=gateway_ip_mask,
            model=model_name,
            softwareVersion=version,
            imagePolicy=image_policy,
            switchRole=switch_role,
            password=password,
            discoveryAuthProtocol=auth_proto,
            discoveryUsername=discovery_username,
            discoveryPassword=discovery_password,
            hostname=hostname,
            ip=ip,
            newSwitchId=new_switch_id,
            publicKey=public_key,
            fingerPrint=finger_print,
        )

        log.debug(
            f"EXIT: _build_rma_model() -> newSwitchId={rma_model.new_switch_id}"
        )
        return rma_model

    def _provision_rma_switch(
        self,
        old_switch_id: str,
        rma_model: RMASwitchModel,
    ) -> None:
        """Submit an RMA provisioning request for one switch.

        Args:
            old_switch_id: Identifier of the switch being replaced.
            rma_model: RMA model for the replacement switch.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: _provision_rma_switch()")

        endpoint = V1ManageFabricSwitchProvisionRMAPost()
        endpoint.fabric_name = self.ctx.fabric
        endpoint.switch_id = old_switch_id

        payload = rma_model.to_payload()

        log.info(f"RMA: Replacing {old_switch_id} with {rma_model.new_switch_id}")
        log.debug(f"RMA endpoint: {endpoint.path}")
        log.debug(f"RMA payload (masked): {mask_password(payload)}")

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = (
                f"RMA provision API call failed for "
                f"{old_switch_id} → {rma_model.new_switch_id}: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "rma"
        results.response_current = response
        results.result_current = result
        results.diff_current = {
            "old_switch_id": old_switch_id,
            "new_switch_id": rma_model.new_switch_id,
        }
        results.register_task_result()

        if not result.get("success"):
            msg = (
                f"RMA provision failed for {old_switch_id} → "
                f"{rma_model.new_switch_id}: {response}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.info(f"RMA provision API response success: {result.get('success')}")
        log.debug("EXIT: _provision_rma_switch()")


# =========================================================================
# Orchestrator (Thin State Router)
# =========================================================================

class NDSwitchResourceModule():
    """Orchestrate switch lifecycle management across supported states."""

    # =====================================================================
    # Initialization & Lifecycle
    # =====================================================================

    def __init__(
        self,
        nd: NDModule,
        results: Results,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize module state, services, and inventory snapshots.

        Args:
            nd: ND module wrapper.
            results: Shared results aggregator.
            logger: Optional logger instance.

        Returns:
            None.
        """
        log = logger or logging.getLogger("nd.NDSwitchResourceModule")
        self.log = log
        self.nd = nd
        self.module = nd.module
        self.results = results

        # Module parameters
        self.config = self.module.params.get("config", {})
        self.fabric = self.module.params.get("fabric")
        self.state = self.module.params.get("state")

        # Shared context for service classes
        self.ctx = SwitchServiceContext(
            nd=nd,
            results=results,
            fabric=self.fabric,
            log=log,
            save_config=self.module.params.get("save", True),
            deploy_config=self.module.params.get("deploy", True),
        )

        # Switch collections
        try:
            self.proposed: List[SwitchDataModel] = []
            self.existing: List[SwitchDataModel] = [
                SwitchDataModel.model_validate(sw)
                for sw in self._query_all_switches()
            ]
            self.previous: List[SwitchDataModel] = deepcopy(self.existing)
        except Exception as e:
            msg = (
                f"Failed to query fabric '{self.fabric}' inventory "
                f"during initialization: {e}"
            )
            log.error(msg)
            nd.module.fail_json(msg=msg)

        # Operation tracking
        self.nd_logs: List[Dict[str, Any]] = []

        # Utility instances (SwitchWaitUtils / FabricUtils depend on self)
        self.fabric_utils = FabricUtils(self.nd, self.fabric, log)
        self.wait_utils = SwitchWaitUtils(
            self, self.fabric, log, fabric_utils=self.fabric_utils
        )

        # Service instances (Dependency Injection)
        self.discovery = SwitchDiscoveryService(self.ctx)
        self.fabric_ops = SwitchFabricOps(self.ctx, self.fabric_utils)
        self.poap_handler = POAPHandler(self.ctx, self.fabric_ops, self.wait_utils)
        self.rma_handler = RMAHandler(self.ctx, self.fabric_ops, self.wait_utils)

        log.info(f"Initialized NDSwitchResourceModule for fabric: {self.fabric}")

    def exit_json(self) -> None:
        """Finalize collected results and exit the Ansible module.

        Includes operation logs and previous/current inventory snapshots in the
        final response payload.

        Returns:
            None.
        """
        self.results.build_final_result()
        final = self.results.final_result

        final["logs"] = self.nd_logs
        final["previous"] = (
            [sw.model_dump(by_alias=True) for sw in self.previous]
            if self.previous
            else []
        )
        final["current"] = (
            [sw.model_dump(by_alias=True) for sw in self.existing]
            if self.existing
            else []
        )

        if True in self.results.failed:
            self.nd.module.fail_json(**final)
        self.nd.module.exit_json(**final)

    # =====================================================================
    # Public API – State Management
    # =====================================================================

    def manage_state(self) -> None:
        """Dispatch the requested module state to the appropriate workflow.

        This method validates input, routes POAP and RMA operations to dedicated
        handlers, and executes state-specific orchestration for query, merged,
        overridden, and deleted operations.

        Returns:
            None.
        """
        self.log.info(f"Managing state: {self.state}")

        # query / deleted — config is optional
        if self.state in ("query", "deleted"):
            proposed_config = (
                SwitchDiffEngine.validate_configs(self.config, self.state, self.nd, self.log)
                if self.config
                else None
            )
            if self.state == "deleted":
                return self._handle_deleted_state(proposed_config)
            return self._handle_query_state(proposed_config)

        # merged / overridden — config is required
        if not self.config:
            self.nd.module.fail_json(
                msg=f"'config' is required for '{self.state}' state."
            )

        proposed_config = SwitchDiffEngine.validate_configs(
            self.config, self.state, self.nd, self.log
        )
        self.operation_type = proposed_config[0].operation_type

        # POAP and RMA bypass normal discovery — delegate to handlers
        if self.operation_type == "poap":
            return self.poap_handler.handle(proposed_config, self.existing)
        if self.operation_type == "rma":
            return self.rma_handler.handle(proposed_config, self.existing)

        # Normal: discover → build proposed models → compute diff → delegate
        discovered_data = self.discovery.discover(proposed_config)
        self.proposed = self.discovery.build_proposed(
            proposed_config, discovered_data, self.existing
        )
        diff = SwitchDiffEngine.compute_changes(
            self.proposed, self.existing, self.log
        )

        state_handlers = {
            "merged": self._handle_merged_state,
            "overridden": self._handle_overridden_state,
        }
        handler = state_handlers.get(self.state)
        if handler is None:
            self.nd.module.fail_json(msg=f"Unsupported state: {self.state}")
        return handler(diff, proposed_config, discovered_data)

    # =====================================================================
    # State Handlers (orchestration only — delegate to services)
    # =====================================================================

    def _handle_query_state(
        self,
        proposed_config: Optional[List[SwitchConfigModel]] = None,
    ) -> None:
        """Return inventory switches matching the optional proposed config.

        Args:
            proposed_config: Optional filter config list for matching switches.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_query_state()")
        self.log.info("Handling query state")
        self.log.debug(f"Found {len(self.existing)} existing switches")

        if proposed_config is None:
            matched_switches = list(self.existing)
            self.log.info("No proposed config — returning all existing switches")
        else:
            matched_switches: List[SwitchDataModel] = []
            for cfg in proposed_config:
                match = next(
                    (
                        sw for sw in self.existing
                        if sw.fabric_management_ip == cfg.seed_ip
                    ),
                    None,
                )
                if match is None:
                    self.log.info(f"Switch {cfg.seed_ip} not found in fabric")
                    continue

                if cfg.role is not None and match.switch_role != cfg.role:
                    self.log.info(
                        f"Switch {cfg.seed_ip} found but role mismatch: "
                        f"expected {cfg.role.value}, got "
                        f"{match.switch_role.value if match.switch_role else 'None'}"
                    )
                    continue

                matched_switches.append(match)

            self.log.info(
                f"Matched {len(matched_switches)}/{len(proposed_config)} "
                f"switch(es) from proposed config"
            )

        switch_data = [sw.model_dump(by_alias=True) for sw in matched_switches]

        self.results.action = "query"
        self.results.state = self.state
        self.results.check_mode = self.nd.module.check_mode
        self.results.operation_type = OperationType.QUERY
        self.results.response_current = {
            "RETURN_CODE": 200,
            "MESSAGE": "OK",
            "DATA": switch_data,
        }
        self.results.result_current = {
            "found": len(matched_switches) > 0,
            "success": True,
        }
        self.results.diff_current = {}
        self.results.register_task_result()

        self.log.debug(f"Returning {len(switch_data)} switches in results")
        self.log.debug("EXIT: _handle_query_state()")

    def _handle_merged_state(
        self,
        diff: Dict[str, List[SwitchDataModel]],
        proposed_config: List[SwitchConfigModel],
        discovered_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        """Handle merged-state add and migration workflows.

        Args:
            diff: Categorized switch diff output.
            proposed_config: Validated switch config list.
            discovered_data: Optional discovery data by seed IP.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_merged_state()")
        self.log.info("Handling merged state")
        self.log.debug(f"Proposed configs: {len(self.proposed)}")
        self.log.debug(f"Existing switches: {len(self.existing)}")

        if not self.proposed:
            self.log.info("No configurations provided for merged state")
            self.log.debug("EXIT: _handle_merged_state() - no configs")
            return

        config_by_ip = {sw.seed_ip: sw for sw in proposed_config}
        existing_by_ip = {sw.fabric_management_ip: sw for sw in self.existing}

        # Phase 1: Handle role-change switches
        self._merged_handle_role_changes(diff, config_by_ip, existing_by_ip)

        # Phase 2: Handle idempotent switches that may need config sync
        self._merged_handle_idempotent(diff, existing_by_ip)

        # Phase 3: Fail on to_update (merged state doesn't support updates)
        self._merged_handle_to_update(diff)

        switches_to_add = diff.get("to_add", [])
        migration_switches = diff.get("migration_mode", [])

        if not switches_to_add and not migration_switches:
            self.log.info("No switches need adding or migration processing")
            return

        # Check mode — preview only
        if self.nd.module.check_mode:
            self.log.info(
                f"Check mode: would add {len(switches_to_add)} and "
                f"process {len(migration_switches)} migration switches"
            )
            self.results.action = "merge"
            self.results.state = self.state
            self.results.operation_type = OperationType.CREATE
            self.results.response_current = {"MESSAGE": "check mode — skipped", "RETURN_CODE": 200}
            self.results.result_current = {"success": True, "changed": True}
            self.results.diff_current = {
                "to_add": [sw.fabric_management_ip for sw in switches_to_add],
                "migration_mode": [sw.fabric_management_ip for sw in migration_switches],
            }
            self.results.register_task_result()
            return

        # Collect (serial_number, SwitchConfigModel) pairs for post-processing
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []

        # Phase 4: Bulk add new switches to fabric
        if switches_to_add and discovered_data:
            add_configs = []
            for sw in switches_to_add:
                cfg = config_by_ip.get(sw.fabric_management_ip)
                if cfg:
                    add_configs.append(cfg)
                else:
                    self.log.warning(
                        f"No config found for switch {sw.fabric_management_ip}, skipping add"
                    )

            if add_configs:
                credential_groups = group_switches_by_credentials(add_configs, self.log)
                for group_key, group_switches in credential_groups.items():
                    username, password_hash, auth_proto, platform_type, preserve_config = group_key
                    password = group_switches[0].password

                    pairs = []
                    for cfg in group_switches:
                        disc = discovered_data.get(cfg.seed_ip)
                        if disc:
                            pairs.append((cfg, disc))
                        else:
                            self.log.warning(f"No discovery data for {cfg.seed_ip}, skipping")

                    if not pairs:
                        continue

                    self.fabric_ops.bulk_add(
                        switches=pairs,
                        username=username,
                        password=password,
                        auth_proto=auth_proto,
                        platform_type=platform_type,
                        preserve_config=preserve_config,
                    )

                    for cfg, disc in pairs:
                        sn = disc.get("serialNumber")
                        if sn:
                            switch_actions.append((sn, cfg))
                            self._log_operation("add", cfg.seed_ip)

        # Phase 5: Collect migration switches for post-processing
        # Migration mode switches get role updates during post-add processing.
        for mig_sw in migration_switches:
            cfg = config_by_ip.get(mig_sw.fabric_management_ip)
            if cfg and mig_sw.switch_id:
                switch_actions.append((mig_sw.switch_id, cfg))
                self._log_operation("migrate", mig_sw.fabric_management_ip)

        if not switch_actions:
            self.log.info("No switch actions to process after add/migration collection")
            return

        # Common post-processing for all switches (new + migration)
        # Brownfield optimisation: if every switch in this batch uses
        # preserve_config=True the switches will NOT reload after being
        # added to the fabric.  Passing this flag lets the wait utility
        # skip the unreachable/reload detection phases.
        all_preserve_config = all(
            cfg.preserve_config for _, cfg in switch_actions
        )
        if all_preserve_config:
            self.log.info(
                "All switches in batch are brownfield (preserve_config=True) — "
                "reload detection will be skipped"
            )

        self.fabric_ops.post_add_processing(
            switch_actions,
            wait_utils=self.wait_utils,
            context="merged",
            all_preserve_config=all_preserve_config,
            update_roles=True,
        )

        self.log.debug("EXIT: _handle_merged_state() - completed")

    # -----------------------------------------------------------------
    # Merged-state sub-handlers (modular phases)
    # -----------------------------------------------------------------

    def _merged_handle_role_changes(
        self,
        diff: Dict[str, List[SwitchDataModel]],
        config_by_ip: Dict[str, SwitchConfigModel],
        existing_by_ip: Dict[str, SwitchDataModel],
    ) -> None:
        """Handle role-change switches in merged state.

        Role changes are only allowed when configSyncStatus is notApplicable.
        Any other status fails the module.

        Args:
            diff: Categorized switch diff output.
            config_by_ip: Config lookup by seed IP.
            existing_by_ip: Existing switch lookup by management IP.

        Returns:
            None.
        """
        role_change_switches = diff.get("role_change", [])
        if not role_change_switches:
            return

        # Validate configSyncStatus for every role-change switch
        for sw in role_change_switches:
            existing_sw = existing_by_ip.get(sw.fabric_management_ip)
            status = (
                existing_sw.additional_data.config_sync_status
                if existing_sw and existing_sw.additional_data
                else None
            )
            if status != ConfigSyncStatus.NOT_APPLICABLE:
                self.nd.module.fail_json(
                    msg=(
                        f"Role change not possible for switch "
                        f"{sw.fabric_management_ip} ({sw.switch_id}). "
                        f"configSyncStatus is "
                        f"'{status.value if status else 'unknown'}', "
                        f"expected '{ConfigSyncStatus.NOT_APPLICABLE.value}'."
                    )
                )

        # Build (switch_id, SwitchConfigModel) pairs and apply role change
        role_actions: List[Tuple[str, SwitchConfigModel]] = []
        for sw in role_change_switches:
            cfg = config_by_ip.get(sw.fabric_management_ip)
            if cfg and sw.switch_id:
                role_actions.append((sw.switch_id, cfg))

        if role_actions:
            self.log.info(
                f"Performing role change for {len(role_actions)} switch(es)"
            )
            self.fabric_ops.bulk_update_roles(role_actions)
            self.fabric_ops.finalize()

    def _merged_handle_idempotent(
        self,
        diff: Dict[str, List[SwitchDataModel]],
        existing_by_ip: Dict[str, SwitchDataModel],
    ) -> None:
        """Handle idempotent switches that may need config save and deploy.

        If configSyncStatus is anything other than inSync, run config save
        and deploy to bring the switch back in sync.

        Args:
            diff: Categorized switch diff output.
            existing_by_ip: Existing switch lookup by management IP.

        Returns:
            None.
        """
        idempotent_switches = diff.get("idempotent", [])
        if not idempotent_switches:
            return

        finalize_needed = False
        for sw in idempotent_switches:
            existing_sw = existing_by_ip.get(sw.fabric_management_ip)
            status = (
                existing_sw.additional_data.config_sync_status
                if existing_sw and existing_sw.additional_data
                else None
            )
            if status != ConfigSyncStatus.IN_SYNC:
                self.log.info(
                    f"Switch {sw.fabric_management_ip} ({sw.switch_id}) is "
                    f"config-idempotent but configSyncStatus is "
                    f"'{status.value if status else 'unknown'}' — "
                    f"will run config save and deploy"
                )
                finalize_needed = True
            else:
                self.log.info(
                    f"Switch {sw.fabric_management_ip} ({sw.switch_id}) "
                    f"is idempotent — no changes needed"
                )

        if finalize_needed:
            self.fabric_ops.finalize()

    def _merged_handle_to_update(
        self,
        diff: Dict[str, List[SwitchDataModel]],
    ) -> None:
        """Fail the module if switches require field-level updates.

        Merged state does not support in-place updates beyond role changes.
        Use overridden state which performs delete-and-re-add.

        Args:
            diff: Categorized switch diff output.

        Returns:
            None.
        """
        to_update = diff.get("to_update", [])
        if not to_update:
            return

        ips = [sw.fabric_management_ip for sw in to_update]
        self.nd.module.fail_json(
            msg=(
                f"Switches require updates that are not supported in merged state. "
                f"Use 'overridden' state for in-place updates. "
                f"Affected switches: {ips}"
            )
        )

    def _handle_overridden_state(
        self,
        diff: Dict[str, List[SwitchDataModel]],
        proposed_config: List[SwitchConfigModel],
        discovered_data: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        """Handle overridden-state reconciliation for the fabric.

        Args:
            diff: Categorized switch diff output.
            proposed_config: Validated switch config list.
            discovered_data: Optional discovery data by seed IP.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_overridden_state()")
        self.log.info("Handling overridden state")

        if not self.proposed:
            self.log.warning("No configurations provided for overridden state")
            return

        # Merge role_change into to_update — overridden uses delete-and-re-add
        diff["to_update"].extend(diff.get("role_change", []))
        diff["role_change"] = []

        # Check mode — preview only
        if self.nd.module.check_mode:
            n_delete = len(diff.get("to_delete", []))
            n_update = len(diff.get("to_update", []))
            n_add = len(diff.get("to_add", []))
            n_migrate = len(diff.get("migration_mode", []))
            self.log.info(
                f"Check mode: would delete {n_delete}, "
                f"delete-and-re-add {n_update}, "
                f"add {n_add}, migrate {n_migrate}"
            )
            would_change = (n_delete + n_update + n_add + n_migrate) > 0
            self.results.action = "override"
            self.results.state = self.state
            self.results.operation_type = OperationType.CREATE
            self.results.response_current = {"MESSAGE": "check mode — skipped", "RETURN_CODE": 200}
            self.results.result_current = {"success": True, "changed": would_change}
            self.results.diff_current = {
                "to_delete": n_delete,
                "to_update": n_update,
                "to_add": n_add,
                "migration_mode": n_migrate,
            }
            self.results.register_task_result()
            return

        switches_to_delete: List[SwitchDataModel] = []

        # Phase 1: Switches not in proposed config
        for sw in diff.get("to_delete", []):
            self.log.info(
                f"Marking for deletion (not in proposed): "
                f"{sw.fabric_management_ip} ({sw.switch_id})"
            )
            switches_to_delete.append(sw)
            self._log_operation("delete", sw.fabric_management_ip)

        # Phase 2: Switches that need updating (delete-then-re-add)
        for sw in diff.get("to_update", []):
            existing_sw = next(
                (e for e in self.existing
                 if e.switch_id == sw.switch_id
                 or e.fabric_management_ip == sw.fabric_management_ip),
                None,
            )
            if existing_sw:
                self.log.info(
                    f"Marking for deletion (re-add update): "
                    f"{existing_sw.fabric_management_ip} ({existing_sw.switch_id})"
                )
                switches_to_delete.append(existing_sw)
                self._log_operation("delete_for_update", existing_sw.fabric_management_ip)

            diff["to_add"].append(sw)

        if switches_to_delete:
            try:
                self.fabric_ops.bulk_delete(switches_to_delete)
            except SwitchOperationError as e:
                msg = (
                    f"Failed to delete switches during overridden state: {e}"
                )
                self.log.error(msg)
                self.nd.module.fail_json(msg=msg)

        diff["to_update"] = []

        # Phase 3: Delegate add + migration to merged state
        self._handle_merged_state(diff, proposed_config, discovered_data)
        self.log.debug("EXIT: _handle_overridden_state()")

    def _handle_deleted_state(
        self,
        proposed_config: Optional[List[SwitchConfigModel]] = None,
    ) -> None:
        """Handle deleted-state switch removal.

        Args:
            proposed_config: Optional config list that limits deletion scope.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_deleted_state()")
        self.log.info("Handling deleted state")

        if proposed_config is None:
            switches_to_delete = list(self.existing)
            self.log.info(
                f"No proposed config — targeting all {len(switches_to_delete)} "
                f"existing switch(es) for deletion"
            )
            for sw in switches_to_delete:
                self._log_operation("delete", sw.fabric_management_ip)
        else:
            switches_to_delete: List[SwitchDataModel] = []
            for switch_config in proposed_config:
                identifier = switch_config.seed_ip
                self.log.debug(f"Looking for switch to delete with seed IP: {identifier}")
                existing_switch = next(
                    (sw for sw in self.existing if sw.fabric_management_ip == identifier),
                    None,
                )
                if existing_switch:
                    self.log.info(
                        f"Marking for deletion: {identifier} ({existing_switch.switch_id})"
                    )
                    switches_to_delete.append(existing_switch)
                else:
                    self.log.info(f"Switch not found for deletion: {identifier}")

        self.log.info(f"Total switches marked for deletion: {len(switches_to_delete)}")
        if not switches_to_delete:
            self.log.info("No switches to delete")
            return

        # Check mode — preview only
        if self.nd.module.check_mode:
            self.log.info(f"Check mode: would delete {len(switches_to_delete)} switch(es)")
            self.results.action = "delete"
            self.results.state = self.state
            self.results.operation_type = OperationType.DELETE
            self.results.response_current = {"MESSAGE": "check mode — skipped", "RETURN_CODE": 200}
            self.results.result_current = {"success": True, "changed": True}
            self.results.diff_current = {
                "to_delete": [sw.fabric_management_ip for sw in switches_to_delete],
            }
            self.results.register_task_result()
            return

        self.log.info(
            f"Proceeding to delete {len(switches_to_delete)} switch(es) from fabric"
        )
        self.fabric_ops.bulk_delete(switches_to_delete)
        self.log.debug("EXIT: _handle_deleted_state()")

    # =====================================================================
    # Query Helpers
    # =====================================================================

    def _query_all_switches(self) -> List[Dict[str, Any]]:
        """Query all switches from the fabric inventory API.

        Returns:
            List of raw switch dictionaries returned by the controller.
        """
        endpoint = V1ManageFabricSwitchesGet()
        endpoint.fabric_name = self.fabric
        self.log.debug(f"Querying all switches with endpoint: {endpoint.path}")
        self.log.debug(f"Query verb: {endpoint.verb}")

        try:
            result = self.nd.request(path=endpoint.path, verb=endpoint.verb)
        except Exception as e:
            msg = (
                f"Failed to query switches from "
                f"fabric '{self.fabric}': {e}"
            )
            self.log.error(msg)
            self.nd.module.fail_json(msg=msg)

        if isinstance(result, list):
            switches = result
        elif isinstance(result, dict):
            switches = result.get("switches", [])
        else:
            switches = []

        self.log.debug(f"Queried {len(switches)} switches from fabric {self.fabric}")
        return switches

    # =====================================================================
    # Operation Tracking
    # =====================================================================

    def _log_operation(self, operation: str, identifier: str) -> None:
        """Append a successful operation record to the module log.

        Args:
            operation: Operation label.
            identifier: Switch identifier for the operation.

        Returns:
            None.
        """
        self.nd_logs.append({
            "operation": operation,
            "identifier": identifier,
            "status": "success",
        })
