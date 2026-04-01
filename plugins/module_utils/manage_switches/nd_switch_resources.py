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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)

from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (
    SwitchRole,
    SnmpV3AuthProtocol,
    PlatformType,
    DiscoveryStatus,
    SystemMode,
    ConfigSyncStatus,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.discovery_models import (
    SwitchDiscoveryModel,
    AddSwitchesRequestModel,
    ShallowDiscoveryRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import (
    SwitchDataModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.bootstrap_models import (
    BootstrapImportSwitchModel,
    ImportBootstrapSwitchesRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.preprovision_models import (
    PreProvisionSwitchModel,
    PreProvisionSwitchesRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.rma_models import (
    RMASwitchModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_actions_models import (
    SwitchCredentialsRequestModel,
    ChangeSwitchSerialNumberRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import (
    SwitchConfigModel,
    POAPConfigModel,
    PreprovisionConfigModel,
    RMAConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.utils import (
    FabricUtils,
    SwitchOperationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.utils import (
    SwitchWaitUtils,
    mask_password,
    get_switch_field,
    group_switches_by_credentials,
    query_bootstrap_switches,
    build_bootstrap_index,
    build_poap_data_block,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricsSwitchesGet,
    EpManageFabricsSwitchesPost,
    EpManageFabricsSwitchProvisionRMAPost,
    EpManageFabricsSwitchChangeSerialNumberPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions import (
    EpManageFabricsActionsShallowDiscoveryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switchactions import (
    EpManageFabricsSwitchActionsImportBootstrapPost,
    EpManageFabricsSwitchActionsPreProvisionPost,
    EpManageFabricsSwitchActionsRemovePost,
    EpManageFabricsSwitchActionsChangeRolesPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_credentials_switches import (
    EpManageCredentialsSwitchesPost,
)

# =========================================================================
# Constants & Globals
# =========================================================================

# Max hops is not supported by the module.
_DISCOVERY_MAX_HOPS: int = 0


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


@dataclass
class SwitchPlan:
    """Unified action plan produced by :meth:`SwitchDiffEngine.compute_changes`.

    All lists contain :class:`SwitchConfigModel` objects so that every state
    handler receives the original user config (credentials, role, etc.) and can
    act on it directly.  Existing inventory entries are kept alongside only
    where removal requires a serial number.

    Attributes:
        to_add:         New normal switches that need ``bulk_add``.
        to_update:      Normal switches already in fabric but with field
                        differences — remove-and-re-add (overridden only).
        to_delete:      Switches in fabric that have no corresponding config
                        entry (overridden / deleted states).
        migration_mode: Normal switches currently in migration mode — no add
                        needed, but role update and finalize are applied.
        idempotent:     Normal switches that match desired state exactly.
        to_bootstrap:   POAP bootstrap configs that need the import-bootstrap
                        API call (switch not in fabric, or mismatch + unreachable).
        normal_readd:   POAP/preprovision configs whose switch *is* reachable
                        and can be re-added via the normal bulk_add path.
        to_preprovision: Pre-provision configs that need the preProvision API call.
        to_swap:        Serial-swap configs (poap + preprovision both present).
        to_rma:         RMA configs.
        poap_ips:       Seed IPs of all POAP/preprovision/swap configs — used by
                        overridden to skip these IPs during the cleanup sweep.
        to_delete_existing: Existing ``SwitchDataModel`` records for switches that
                        must be deleted before re-add (POAP/preprovision mismatches
                        and overridden normal updates).  Kept parallel to the
                        config-level lists above.
    """

    # Normal-switch diff buckets (config side)
    to_add: List["SwitchConfigModel"]
    to_update: List["SwitchConfigModel"]
    to_delete: List["SwitchDataModel"]
    migration_mode: List["SwitchConfigModel"]
    idempotent: List["SwitchConfigModel"]

    # POAP/preprovision/swap/RMA buckets
    to_bootstrap: List["SwitchConfigModel"]
    normal_readd: List["SwitchConfigModel"]
    to_preprovision: List["SwitchConfigModel"]
    to_swap: List["SwitchConfigModel"]
    to_rma: List["SwitchConfigModel"]

    # Cross-cutting helpers
    poap_ips: set
    to_delete_existing: List["SwitchDataModel"]


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
        log.debug("Normalized to %s configuration(s)", len(configs_list))

        validated_configs: List[SwitchConfigModel] = []
        for idx, cfg in enumerate(configs_list):
            try:
                validated = SwitchConfigModel.model_validate(cfg, context={"state": state})
                validated_configs.append(validated)
            except ValidationError as e:
                error_detail = e.errors() if hasattr(e, "errors") else str(e)
                error_msg = f"Configuration validation failed for " f"config index {idx}: {error_detail}"
                log.error(error_msg)
                if hasattr(nd, "module"):
                    nd.module.fail_json(msg=error_msg)
                else:
                    raise ValueError(error_msg) from e
            except Exception as e:
                error_msg = f"Configuration validation failed for " f"config index {idx}: {str(e)}"
                log.error(error_msg)
                if hasattr(nd, "module"):
                    nd.module.fail_json(msg=error_msg)
                else:
                    raise ValueError(error_msg) from e

        if not validated_configs:
            log.warning("No valid configurations found in input")
            return validated_configs

        # Duplicate seed_ip check
        seen_ips: set = set()
        duplicate_ips: set = set()
        for cfg in validated_configs:
            if cfg.seed_ip in seen_ips:
                duplicate_ips.add(cfg.seed_ip)
            seen_ips.add(cfg.seed_ip)
        if duplicate_ips:
            error_msg = f"Duplicate seed_ip entries found in config: " f"{sorted(duplicate_ips)}. Each switch must appear only once."
            log.error(error_msg)
            if hasattr(nd, "module"):
                nd.module.fail_json(msg=error_msg)
            else:
                raise ValueError(error_msg)

        operation_types = {c.operation_type for c in validated_configs}
        log.info(
            "Successfully validated %s configuration(s) with operation type(s): %s",
            len(validated_configs),
            operation_types,
        )
        log.debug(
            "EXIT: validate_configs() -> %s configs, operation_types=%s",
            len(validated_configs),
            operation_types,
        )
        return validated_configs

    @staticmethod
    def compute_changes(
        proposed_configs: List[SwitchConfigModel],
        existing: List[SwitchDataModel],
        log: logging.Logger,
    ) -> "SwitchPlan":
        """Classify all proposed configs against the current fabric inventory.

        Accepts the full mix of normal, POAP/preprovision, swap, and RMA configs
        and produces a unified :class:`SwitchPlan` that each state handler can
        act on directly.  This is the single idempotency gate for all operation
        types.

        Idempotency rules by operation type:

        * **normal** — compare ``seed_ip``, ``serial_number`` (via discovery),
          ``hostname``, ``model``, ``software_version``, and ``role`` against
          the existing inventory.
        * **poap / preprovision** — compare ``seed_ip``, ``serial_number``
          (from ``poap.serial_number`` / ``preprovision.serial_number``), and
          ``role`` against the existing inventory.  If all three match the
          switch is idempotent and skipped.  On a mismatch the routing depends
          on ``discovery_status``:

          - Bootstrap mismatch, ``discovery_status == OK`` → ``normal_readd``
          - Bootstrap mismatch, anything else → ``to_bootstrap``
          - Preprovision mismatch, ``discovery_status == UNREACHABLE`` → ``to_preprovision``
          - Preprovision mismatch, anything else → ``normal_readd``

        * **swap** — always active (no idempotency check; the caller validates
          preconditions).
        * **rma** — always active (no idempotency check; caller validates).

        Args:
            proposed_configs: All validated switch configs for this run.
            existing: Current fabric inventory snapshot.
            log: Logger instance.

        Returns:
            :class:`SwitchPlan` with all buckets populated.
        """
        log.debug("ENTER: compute_changes()")
        log.info(
            "compute_changes: %s proposed config(s) vs %s existing switch(es)",
            len(proposed_configs),
            len(existing),
        )

        existing_by_ip: Dict[str, SwitchDataModel] = {
            sw.fabric_management_ip: sw for sw in existing if sw.fabric_management_ip
        }
        existing_by_id: Dict[str, SwitchDataModel] = {
            sw.switch_id: sw for sw in existing if sw.switch_id
        }

        # Fields compared for normal switches
        compare_fields = {
            "switch_id",
            "serial_number",
            "fabric_management_ip",
            "hostname",
            "model",
            "software_version",
            "switch_role",
        }

        # Output buckets
        to_add: List[SwitchConfigModel] = []
        to_update: List[SwitchConfigModel] = []
        to_delete_existing: List[SwitchDataModel] = []
        migration_mode: List[SwitchConfigModel] = []
        idempotent: List[SwitchConfigModel] = []
        to_bootstrap: List[SwitchConfigModel] = []
        normal_readd: List[SwitchConfigModel] = []
        to_preprovision: List[SwitchConfigModel] = []
        to_swap: List[SwitchConfigModel] = []
        to_rma: List[SwitchConfigModel] = []
        poap_ips: set = set()

        # Track which existing switch IDs are accounted for by a config
        accounted_ids: set = set()

        for cfg in proposed_configs:
            op = cfg.operation_type

            # ------------------------------------------------------------------
            # RMA — no idempotency check; always active
            # ------------------------------------------------------------------
            if op == "rma":
                to_rma.append(cfg)
                continue

            existing_sw = existing_by_ip.get(cfg.seed_ip)
            if existing_sw:
                accounted_ids.add(existing_sw.switch_id)

            # ------------------------------------------------------------------
            # POAP swap — both poap and preprovision blocks present
            # ------------------------------------------------------------------
            if op == "swap":
                poap_ips.add(cfg.seed_ip)
                to_swap.append(cfg)
                continue

            # ------------------------------------------------------------------
            # POAP bootstrap
            # ------------------------------------------------------------------
            if op == "poap":
                poap_ips.add(cfg.seed_ip)
                serial = cfg.poap.serial_number if cfg.poap else None

                if not existing_sw:
                    log.info("Bootstrap %s: not in fabric — queue for bootstrap", cfg.seed_ip)
                    to_bootstrap.append(cfg)
                    continue

                serial_match = serial and serial in (existing_sw.serial_number, existing_sw.switch_id)
                role_match = cfg.role is None or cfg.role == existing_sw.switch_role
                if serial_match and role_match:
                    log.info(
                        "Bootstrap %s serial=%s role=%s — idempotent, skipping",
                        cfg.seed_ip, serial, cfg.role,
                    )
                    idempotent.append(cfg)
                    continue

                status = existing_sw.additional_data.discovery_status if existing_sw.additional_data else None
                log.info(
                    "Bootstrap %s differs (serial_match=%s, role_match=%s, status=%s) — deleting existing",
                    cfg.seed_ip, serial_match, role_match,
                    getattr(status, "value", status) if status else "unknown",
                )
                to_delete_existing.append(existing_sw)
                if status == DiscoveryStatus.OK:
                    log.info("Bootstrap %s: switch reachable — routing to normal_readd", cfg.seed_ip)
                    normal_readd.append(cfg)
                else:
                    log.info("Bootstrap %s: switch unreachable — routing to bootstrap workflow", cfg.seed_ip)
                    to_bootstrap.append(cfg)
                continue

            # ------------------------------------------------------------------
            # Pre-provision
            # ------------------------------------------------------------------
            if op == "preprovision":
                poap_ips.add(cfg.seed_ip)
                serial = cfg.preprovision.serial_number if cfg.preprovision else None

                if not existing_sw:
                    log.info("Preprovision %s: not in fabric — queue for preprovision", cfg.seed_ip)
                    to_preprovision.append(cfg)
                    continue

                serial_match = serial and serial in (existing_sw.serial_number, existing_sw.switch_id)
                role_match = cfg.role is None or cfg.role == existing_sw.switch_role
                if serial_match and role_match:
                    log.info(
                        "Preprovision %s serial=%s role=%s — idempotent, skipping",
                        cfg.seed_ip, serial, cfg.role,
                    )
                    idempotent.append(cfg)
                    continue

                status = existing_sw.additional_data.discovery_status if existing_sw.additional_data else None
                log.info(
                    "Preprovision %s differs (serial_match=%s, role_match=%s, status=%s) — deleting existing",
                    cfg.seed_ip, serial_match, role_match,
                    getattr(status, "value", status) if status else "unknown",
                )
                to_delete_existing.append(existing_sw)
                if status == DiscoveryStatus.UNREACHABLE:
                    log.info("Preprovision %s: switch unreachable — routing to preprovision workflow", cfg.seed_ip)
                    to_preprovision.append(cfg)
                else:
                    log.info("Preprovision %s: switch reachable — routing to normal_readd", cfg.seed_ip)
                    normal_readd.append(cfg)
                continue

            # ------------------------------------------------------------------
            # Normal switch
            # ------------------------------------------------------------------
            # Note: serial/id comparison happens after discovery via build_proposed;
            # here we rely on the SwitchDataModel that build_proposed will produce
            # being present in existing.  Since this function receives SwitchConfigModel
            # objects (not yet resolved to SwitchDataModel), normal-switch idempotency
            # is done after discover() + build_proposed() by comparing the resulting
            # SwitchDataModel against existing using compare_fields.
            #
            # The code below handles the case where the switch is *already* in the
            # fabric (no discovery needed) and can be evaluated immediately.
            if op == "normal":
                if not existing_sw:
                    log.info("Normal %s: not in fabric — queue for discovery + add", cfg.seed_ip)
                    to_add.append(cfg)
                    continue

                if existing_sw.additional_data and existing_sw.additional_data.system_mode == SystemMode.MIGRATION:
                    log.info("Normal %s (%s): in migration mode", cfg.seed_ip, existing_sw.switch_id)
                    migration_mode.append(cfg)
                    continue

                # Build a lightweight comparison dict from config vs existing
                # for fields we can evaluate without discovery data.
                role_match = cfg.role is None or cfg.role == existing_sw.switch_role
                # IP always matches (looked up by IP), so only role matters
                # for an already-in-fabric switch; other fields (model, version,
                # hostname) are only verifiable after discovery.
                if role_match:
                    log.info("Normal %s: in fabric, role matches — checking field diff after build_proposed", cfg.seed_ip)
                    # Defer final diff to after build_proposed; treat as to_add
                    # so the caller runs discovery and build_proposed, then sees
                    # the switch in to_update/idempotent from a second pass.
                    # For now simply indicate "needs evaluation" by placing in to_add.
                    to_add.append(cfg)
                else:
                    log.info(
                        "Normal %s: role mismatch (config=%s, existing=%s) — marking to_update",
                        cfg.seed_ip, cfg.role, existing_sw.switch_role,
                    )
                    to_update.append(cfg)
                continue

        # Switches in fabric that no config entry accounts for
        # (only meaningful for overridden / deleted states)
        to_delete: List[SwitchDataModel] = []
        for sw in existing:
            if sw.switch_id and sw.switch_id not in accounted_ids and sw.fabric_management_ip not in poap_ips:
                log.info(
                    "Existing %s (%s) has no config entry — marking to_delete",
                    sw.fabric_management_ip, sw.switch_id,
                )
                to_delete.append(sw)

        plan = SwitchPlan(
            to_add=to_add,
            to_update=to_update,
            to_delete=to_delete,
            migration_mode=migration_mode,
            idempotent=idempotent,
            to_bootstrap=to_bootstrap,
            normal_readd=normal_readd,
            to_preprovision=to_preprovision,
            to_swap=to_swap,
            to_rma=to_rma,
            poap_ips=poap_ips,
            to_delete_existing=to_delete_existing,
        )
        log.info(
            "compute_changes: to_add=%s, to_update=%s, to_delete=%s, migration=%s, "
            "idempotent=%s, bootstrap=%s, normal_readd=%s, preprov=%s, swap=%s, rma=%s",
            len(plan.to_add), len(plan.to_update), len(plan.to_delete), len(plan.migration_mode),
            len(plan.idempotent), len(plan.to_bootstrap), len(plan.normal_readd),
            len(plan.to_preprovision), len(plan.to_swap), len(plan.to_rma),
        )
        log.debug("EXIT: compute_changes()")
        return plan

    @staticmethod
    def validate_switch_api_fields(
        nd: NDModule,
        serial: str,
        model: Optional[str],
        version: Optional[str],
        config_data,
        bootstrap_data: Dict[str, Any],
        log: logging.Logger,
        context: str,
        hostname: Optional[str] = None,
    ) -> None:
        """Validate user-supplied switch fields against the bootstrap API response.

        Only fields that are provided (non-None) are validated against the API.
        Fields that are omitted are silently filled in from the API at build
        time — no error is raised for those. Any omitted fields are logged at
        INFO level so the operator can see what was sourced from the API.

        Args:
            nd: ND module wrapper used for failure handling.
            serial: Serial number of the switch being processed.
            model: User-provided switch model, or None if omitted.
            version: User-provided software version, or None if omitted.
            config_data: User-provided ``ConfigDataModel``, or None if omitted.
            bootstrap_data: Matching entry from the bootstrap GET API.
            log: Logger instance.
            context: Label used in error messages (e.g. ``"Bootstrap"`` or ``"RMA"``).
            hostname: User-provided hostname, or None if omitted (bootstrap only).

        Returns:
            None.
        """
        bs_data = bootstrap_data.get("data") or {}
        mismatches: List[str] = []

        if model is not None and model != bootstrap_data.get("model"):
            mismatches.append(f"model: provided '{model}', " f"bootstrap reports '{bootstrap_data.get('model')}'")

        if version is not None and version != bootstrap_data.get("softwareVersion"):
            mismatches.append(f"version: provided '{version}', " f"bootstrap reports '{bootstrap_data.get('softwareVersion')}'")

        if config_data is not None:
            bs_gateway = bootstrap_data.get("gatewayIpMask") or bs_data.get("gatewayIpMask")
            if config_data.gateway is not None and config_data.gateway != bs_gateway:
                mismatches.append(f"config_data.gateway: provided '{config_data.gateway}', " f"bootstrap reports '{bs_gateway}'")

            bs_models = bs_data.get("models", [])
            if config_data.models and sorted(config_data.models) != sorted(bs_models):
                mismatches.append(f"config_data.models: provided {config_data.models}, " f"bootstrap reports {bs_models}")

        if mismatches:
            nd.module.fail_json(
                msg=(
                    f"{context} field mismatch for serial '{serial}'. "
                    f"The following provided values do not match the "
                    f"bootstrap API data:\n" + "\n".join(f"  - {m}" for m in mismatches)
                )
            )

        # Log any fields that were omitted and will be sourced from the API
        pulled: List[str] = []
        if model is None:
            pulled.append("model")
        if version is None:
            pulled.append("version")
        if hostname is None:
            pulled.append("hostname")
        if config_data is None:
            pulled.append("config_data (gateway + models)")
        if pulled:
            log.info(
                "%s serial '%s': the following fields were not provided and will be sourced from the bootstrap API: %s",
                context,
                serial,
                ", ".join(pulled),
            )
        else:
            log.debug("%s field validation passed for serial '%s'", context, serial)


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
        log.debug("Created %s credential group(s)", len(credential_groups))

        log.debug("Step 2: Bulk discovering switches")
        all_discovered: Dict[str, Dict[str, Any]] = {}
        for group_key, switches in credential_groups.items():
            username, _pw_hash, auth_proto, platform_type, _preserve = group_key
            password = switches[0].password

            log.debug(
                "Discovering group: %s switches with username=%s",
                len(switches),
                username,
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
                msg = f"Discovery failed for credential group " f"(username={username}, IPs={seed_ips}): {e}"
                log.error(msg)
                self.ctx.nd.module.fail_json(msg=msg)

        log.debug("Total discovered: %s switches", len(all_discovered))
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
        log.debug("Discovering %s switches in bulk", len(switches))

        endpoint = EpManageFabricsActionsShallowDiscoveryPost()
        endpoint.fabric_name = self.ctx.fabric

        seed_ips = [switch.seed_ip for switch in switches]
        log.debug("Seed IPs: %s", seed_ips)

        max_hops = _DISCOVERY_MAX_HOPS

        discovery_request = ShallowDiscoveryRequestModel(
            seedIpCollection=seed_ips,
            maxHop=max_hops,
            platformType=platform_type,
            snmpV3AuthProtocol=auth_proto,
            username=username,
            password=password,
        )

        payload = discovery_request.to_payload()
        log.info("Bulk discovering %s switches: %s", len(seed_ips), ", ".join(seed_ips))
        log.debug("Discovery endpoint: %s", endpoint.path)
        log.debug("Discovery payload (password masked): %s", mask_password(payload))

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "discover"
            results.operation_type = OperationType.QUERY
            results.response_current = response
            results.result_current = result
            results.diff_current = payload
            results.register_api_call()

            # Extract discovered switches from response
            switches_data = []
            if response and isinstance(response, dict):
                if "DATA" in response and isinstance(response["DATA"], dict):
                    switches_data = response["DATA"].get("switches", [])
                elif "body" in response and isinstance(response["body"], dict):
                    switches_data = response["body"].get("switches", [])
                elif "switches" in response:
                    switches_data = response.get("switches", [])

            log.debug("Extracted %s switches from discovery response", len(switches_data))

            discovered_results: Dict[str, Dict[str, Any]] = {}
            for discovered in switches_data:
                if not isinstance(discovered, dict):
                    continue

                ip = discovered.get("ip")
                status = discovered.get("status", "").lower()
                serial_number = discovered.get("serialNumber")

                if not serial_number:
                    msg = f"Switch {ip} discovery response missing serial number. " f"Cannot proceed without a valid serial number."
                    log.error(msg)
                    nd.module.fail_json(msg=msg)
                if not ip:
                    msg = f"Switch with serial {serial_number} discovery response " f"missing IP address. Cannot proceed without a valid IP."
                    log.error(msg)
                    nd.module.fail_json(msg=msg)

                if status in ("manageable", "ok"):
                    discovered_results[ip] = discovered
                    log.info(
                        "Switch %s (%s) discovered successfully - status: %s",
                        ip,
                        serial_number,
                        status,
                    )
                elif status == "alreadymanaged":
                    log.info("Switch %s (%s) is already managed", ip, serial_number)
                    discovered_results[ip] = discovered
                else:
                    reason = discovered.get("statusReason", "Unknown")
                    log.error(
                        "Switch %s discovery failed - status: %s, reason: %s",
                        ip,
                        status,
                        reason,
                    )

            for seed_ip in seed_ips:
                if seed_ip not in discovered_results:
                    log.warning("Switch %s not found in discovery response", seed_ip)

            log.info(
                "Bulk discovery completed: %s/%s switches successful",
                len(discovered_results),
                len(seed_ips),
            )
            log.debug("Discovered switches: %s", list(discovered_results.keys()))
            log.debug("EXIT: bulk_discover() -> %s discovered", len(discovered_results))
            return discovered_results

        except Exception as e:
            msg = f"Bulk discovery failed for switches " f"{', '.join(seed_ips)}: {e}"
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
                    discovered = {**discovered, "role": cfg.role}
                proposed.append(SwitchDataModel.from_response(discovered))
                log.debug("Built proposed model from discovery for %s", seed_ip)
                continue

            # Fallback: switch may already be in the fabric inventory
            existing_match = next(
                (sw for sw in existing if sw.fabric_management_ip == seed_ip),
                None,
            )
            if existing_match:
                if cfg.role is not None:
                    data = existing_match.model_dump(by_alias=True)
                    data["switchRole"] = cfg.role.value if isinstance(cfg.role, SwitchRole) else cfg.role
                    proposed.append(SwitchDataModel.model_validate(data))
                else:
                    proposed.append(existing_match)
                log.debug(
                    "Switch %s already in fabric inventory — using existing record (discovery skipped)",
                    seed_ip,
                )
                continue

            msg = f"Switch with seed IP {seed_ip} not discovered " f"and not found in existing inventory."
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
        log.debug("Adding %s switches to fabric", len(switches))

        endpoint = EpManageFabricsSwitchesPost()
        endpoint.fabric_name = self.ctx.fabric

        switch_discoveries = []
        for switch_config, discovered in switches:
            required_fields = ["hostname", "ip", "serialNumber", "model"]
            missing_fields = [f for f in required_fields if not discovered.get(f)]

            if missing_fields:
                msg = f"Switch missing required fields from discovery: " f"{', '.join(missing_fields)}. Cannot add to fabric."
                log.error(msg)
                nd.module.fail_json(msg=msg)

            switch_role = switch_config.role if hasattr(switch_config, "role") else None

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
                "Prepared switch for add: %s (%s)",
                discovered.get("serialNumber"),
                discovered.get("hostname"),
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
        serial_numbers = [d.get("serialNumber") for _cfg, d in switches]
        log.info(
            "Bulk adding %s switches to fabric %s: %s",
            len(switches),
            self.ctx.fabric,
            ", ".join(serial_numbers),
        )
        log.debug("Add endpoint: %s", endpoint.path)
        log.debug("Add payload (password masked): %s", mask_password(payload))

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = f"Bulk add switches to fabric '{self.ctx.fabric}' failed " f"for {', '.join(serial_numbers)}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "create"
        results.operation_type = OperationType.CREATE
        results.response_current = response
        results.result_current = result
        results.diff_current = payload
        results.register_api_call()

        if not result.get("success"):
            msg = f"Bulk add switches failed for " f"{', '.join(serial_numbers)}: {response}"
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
            if hasattr(switch, "switch_id"):
                sn = switch.switch_id
            elif hasattr(switch, "serial_number"):
                sn = switch.serial_number

            if sn:
                serial_numbers.append(sn)
            else:
                ip = getattr(switch, "fabric_management_ip", None) or getattr(switch, "ip", None)
                log.warning("Cannot delete switch %s: no serial number/switch_id", ip)

        if not serial_numbers:
            log.warning("No valid serial numbers found for deletion")
            log.debug("EXIT: bulk_delete() - nothing to delete")
            return []

        endpoint = EpManageFabricsSwitchActionsRemovePost()
        endpoint.fabric_name = self.ctx.fabric
        payload = {"switchIds": serial_numbers}

        log.info(
            "Bulk removing %s switch(es) from fabric %s: %s",
            len(serial_numbers),
            self.ctx.fabric,
            serial_numbers,
        )
        log.debug("Delete endpoint: %s", endpoint.path)
        log.debug("Delete payload: %s", payload)

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "delete"
            results.operation_type = OperationType.DELETE
            results.response_current = response
            results.result_current = result
            results.diff_current = {"deleted": serial_numbers}
            results.register_api_call()

            log.info("Bulk delete submitted for %s switch(es)", len(serial_numbers))
            log.debug("EXIT: bulk_delete()")
            return serial_numbers

        except Exception as e:
            log.error("Bulk delete failed: %s", e)
            raise SwitchOperationError(f"Bulk delete failed for {serial_numbers}: {e}") from e

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
            if not cfg.username or not cfg.password:
                log.debug("Skipping credentials for %s: missing username or password", sn)
                continue
            key = (cfg.username, cfg.password)
            cred_groups.setdefault(key, []).append(sn)

        if not cred_groups:
            log.debug("EXIT: bulk_save_credentials() - no credentials to save")
            return

        endpoint = EpManageCredentialsSwitchesPost()

        for (username, password), serial_numbers in cred_groups.items():
            creds_request = SwitchCredentialsRequestModel(
                switchIds=serial_numbers,
                switchUsername=username,
                switchPassword=password,
            )
            payload = creds_request.to_payload()

            log.info(
                "Saving credentials for %s switch(es): %s",
                len(serial_numbers),
                serial_numbers,
            )
            log.debug("Credentials endpoint: %s", endpoint.path)
            log.debug("Credentials payload (masked): %s", mask_password(payload))

            try:
                nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

                response = nd.rest_send.response_current
                result = nd.rest_send.result_current

                results.action = "save_credentials"
                results.operation_type = OperationType.UPDATE
                results.response_current = response
                results.result_current = result
                results.diff_current = {
                    "switchIds": serial_numbers,
                    "username": username,
                }
                results.register_api_call()
                log.info("Credentials saved for %s switch(es)", len(serial_numbers))
            except Exception as e:
                msg = f"Failed to save credentials for " f"switches {serial_numbers}: {e}"
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
            role = get_switch_field(cfg, ["role"])
            if not role:
                continue
            role_value = role.value if isinstance(role, SwitchRole) else str(role)
            switch_roles.append({"switchId": sn, "role": role_value})

        if not switch_roles:
            log.debug("EXIT: bulk_update_roles() - no roles to update")
            return

        endpoint = EpManageFabricsSwitchActionsChangeRolesPost()
        endpoint.fabric_name = self.ctx.fabric
        payload = {"switchRoles": switch_roles}

        log.info("Bulk updating roles for %s switch(es)", len(switch_roles))
        log.debug("ChangeRoles endpoint: %s", endpoint.path)
        log.debug("ChangeRoles payload: %s", payload)

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "update_role"
            results.operation_type = OperationType.UPDATE
            results.response_current = response
            results.result_current = result
            results.diff_current = payload
            results.register_api_call()
            log.info("Roles updated for %s switch(es)", len(switch_roles))
        except Exception as e:
            msg = f"Failed to bulk update roles for switches: {e}"
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
        all_serials = [sn for sn, _cfg in switch_actions]

        log.info(
            "Waiting for %s %s switch(es) to become manageable: %s",
            len(all_serials),
            context,
            all_serials,
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
            msg = f"One or more {context} switches failed to become " f"manageable in fabric '{self.ctx.fabric}'. " f"Switches: {all_serials}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        self.bulk_save_credentials(switch_actions)

        if update_roles:
            self.bulk_update_roles(switch_actions)

        try:
            self.finalize()
        except Exception as e:
            msg = f"Failed to finalize (config-save/deploy) for " f"{context} switches {all_serials}: {e}"
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
        log.info("Processing POAP for %s switch config(s)", len(proposed_config))

        # Classify entries first so check mode can report per-operation counts
        bootstrap_entries: List[Tuple[SwitchConfigModel, POAPConfigModel]] = []
        preprov_entries: List[Tuple[SwitchConfigModel, PreprovisionConfigModel]] = []
        swap_entries: List[Tuple[SwitchConfigModel, POAPConfigModel, PreprovisionConfigModel]] = []

        for switch_cfg in proposed_config:
            has_poap = bool(switch_cfg.poap)
            has_preprov = bool(switch_cfg.preprovision)

            if has_poap and has_preprov:
                # Swap: only serial_number is meaningful on each side; warn about extras
                poap_extra = [
                    f
                    for f in [
                        "hostname",
                        "image_policy",
                        "discovery_username",
                        "discovery_password",
                    ]
                    if getattr(switch_cfg.poap, f, None)
                ]
                preprov_extra = [
                    f
                    for f in [
                        "model",
                        "version",
                        "hostname",
                        "config_data",
                        "image_policy",
                        "discovery_username",
                        "discovery_password",
                    ]
                    if getattr(switch_cfg.preprovision, f, None)
                ]
                if poap_extra:
                    log.warning(
                        "Swap (%s): extra fields in 'poap' will be ignored during swap: %s",
                        switch_cfg.seed_ip,
                        poap_extra,
                    )
                if preprov_extra:
                    log.warning(
                        "Swap (%s): extra fields in 'preprovision' will be ignored during swap: %s",
                        switch_cfg.seed_ip,
                        preprov_extra,
                    )
                swap_entries.append((switch_cfg, switch_cfg.poap, switch_cfg.preprovision))
            elif has_preprov:
                preprov_entries.append((switch_cfg, switch_cfg.preprovision))
            elif has_poap:
                bootstrap_entries.append((switch_cfg, switch_cfg.poap))
            else:
                log.warning(
                    "Switch config for %s has no poap or preprovision block — skipping",
                    switch_cfg.seed_ip,
                )

        log.info(
            "POAP classification: %s bootstrap, %s pre-provision, %s swap",
            len(bootstrap_entries),
            len(preprov_entries),
            len(swap_entries),
        )

        # Check mode — preview only
        if nd.module.check_mode:
            log.info(
                "Check mode: would bootstrap %s, pre-provision %s, swap %s",
                len(bootstrap_entries),
                len(preprov_entries),
                len(swap_entries),
            )
            results.action = "poap"
            results.operation_type = OperationType.CREATE
            results.response_current = {"MESSAGE": "check mode — skipped"}
            results.result_current = {"success": True, "changed": False}
            results.diff_current = {
                "bootstrap": [cfg.seed_ip for cfg, _sw in bootstrap_entries],
                "preprovision": [cfg.seed_ip for cfg, _sw in preprov_entries],
                "swap": [cfg.seed_ip for cfg, _sw in swap_entries],
            }
            results.register_api_call()
            return

        # Idempotency: skip entries whose target serial is already in the fabric.
        # Build lookup structures for idempotency checks.
        # Bootstrap: idempotent when both IP address AND serial number match.
        # PreProvision: idempotent when IP address alone matches.
        existing_by_ip = {sw.fabric_management_ip: sw for sw in existing if sw.fabric_management_ip}

        active_bootstrap = []
        for switch_cfg, poap_cfg in bootstrap_entries:
            existing_sw = existing_by_ip.get(switch_cfg.seed_ip)
            if existing_sw and poap_cfg.serial_number in (
                existing_sw.serial_number,
                existing_sw.switch_id,
            ):
                log.info(
                    "Bootstrap: IP '%s' with serial '%s' already in fabric — idempotent, skipping",
                    switch_cfg.seed_ip,
                    poap_cfg.serial_number,
                )
            else:
                active_bootstrap.append((switch_cfg, poap_cfg))
        bootstrap_entries = active_bootstrap

        active_preprov = []
        for switch_cfg, preprov_cfg in preprov_entries:
            if switch_cfg.seed_ip in existing_by_ip:
                log.info(
                    "PreProvision: IP '%s' already in fabric — idempotent, skipping",
                    switch_cfg.seed_ip,
                )
            else:
                active_preprov.append((switch_cfg, preprov_cfg))
        preprov_entries = active_preprov

        # Handle swap entries (change serial number on pre-provisioned switches)
        if swap_entries:
            self._handle_poap_swap(swap_entries, existing or [])

        # Handle bootstrap entries
        if bootstrap_entries:
            self._handle_poap_bootstrap(bootstrap_entries)

        # Handle pre-provision entries
        if preprov_entries:
            preprov_models: List[PreProvisionSwitchModel] = []
            for switch_cfg, preprov_cfg in preprov_entries:
                pp_model = self._build_preprovision_model(switch_cfg, preprov_cfg)
                preprov_models.append(pp_model)
                log.info(
                    "Built pre-provision model for serial=%s, hostname=%s, ip=%s",
                    pp_model.serial_number,
                    pp_model.hostname,
                    pp_model.ip,
                )

            if preprov_models:
                self._preprovision_switches(preprov_models)

        # Edge case: nothing actionable
        if not bootstrap_entries and not preprov_entries and not swap_entries:
            log.warning("No POAP switch models built — nothing to process")
            results.action = "poap"
            results.operation_type = OperationType.QUERY
            results.response_current = {"MESSAGE": "no switches to process"}
            results.result_current = {"success": True, "changed": False}
            results.diff_current = {}
            results.register_api_call()

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
        log.info("Processing %s bootstrap entries", len(bootstrap_entries))

        bootstrap_switches = query_bootstrap_switches(nd, self.ctx.fabric, log)
        bootstrap_idx = build_bootstrap_index(bootstrap_switches)
        log.debug(
            "Bootstrap index contains %s switch(es): %s",
            len(bootstrap_idx),
            list(bootstrap_idx.keys()),
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

            model = self._build_bootstrap_import_model(switch_cfg, poap_cfg, bootstrap_data)
            import_models.append(model)
            log.info(
                "Built bootstrap model for serial=%s, hostname=%s, ip=%s",
                serial,
                model.hostname,
                model.ip,
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
        log.debug("ENTER: _build_bootstrap_import_model(serial=%s)", poap_cfg.serial_number)

        bs = bootstrap_data or {}
        bs_data = bs.get("data") or {}

        serial_number = poap_cfg.serial_number
        ip = switch_cfg.seed_ip
        switch_role = switch_cfg.role
        password = switch_cfg.password
        auth_proto = SnmpV3AuthProtocol.MD5  # POAP/bootstrap always uses MD5
        image_policy = poap_cfg.image_policy

        discovery_username = getattr(poap_cfg, "discovery_username", None)
        discovery_password = getattr(poap_cfg, "discovery_password", None)

        # model, version and config_data always come from the bootstrap API for
        # bootstrap-only operations.
        model = bs.get("model", "")
        version = bs.get("softwareVersion", "")

        gateway_ip_mask = bs.get("gatewayIpMask") or bs_data.get("gatewayIpMask")
        data_models = bs_data.get("models", [])

        # Hostname: user-provided via poap.hostname is the default; if the
        # bootstrap API returns a different value, the API wins and we warn.
        user_hostname = poap_cfg.hostname
        api_hostname = bs.get("hostname", "")
        if api_hostname and api_hostname != user_hostname:
            log.warning(
                "Bootstrap (%s): API hostname '%s' overrides user-provided hostname '%s'. Using API value.",
                serial_number,
                api_hostname,
                user_hostname,
            )
            hostname = api_hostname
        else:
            hostname = user_hostname

        # Role: switch_cfg.role is user-provided; if the bootstrap API carries a
        # role and it differs, the API value wins and we warn.
        api_role_raw = bs.get("switchRole") or bs_data.get("switchRole")
        if api_role_raw:
            try:
                api_role = SwitchRole.normalize(api_role_raw)
                if api_role and api_role != switch_role:
                    log.warning(
                        "Bootstrap (%s): API role '%s' overrides user-provided role '%s'. Using API value.",
                        serial_number,
                        api_role_raw,
                        switch_role,
                    )
                    switch_role = api_role
            except Exception:
                pass

        # Build the data block from resolved values (replaces build_poap_data_block)
        data_block: Optional[Dict[str, Any]] = None
        if gateway_ip_mask or data_models:
            data_block = {}
            if gateway_ip_mask:
                data_block["gatewayIpMask"] = gateway_ip_mask
            if data_models:
                data_block["models"] = data_models

        # Bootstrap API response fields
        fingerprint = bs.get("fingerPrint") or bs.get("fingerprint", "")
        public_key = bs.get("publicKey", "")
        re_add = bs.get("reAdd", False)
        in_inventory = bs.get("inInventory", False)

        bootstrap_model = BootstrapImportSwitchModel(
            serialNumber=serial_number,
            model=model,
            hostname=hostname,
            ip=ip,
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
            softwareVersion=version,
            gatewayIpMask=gateway_ip_mask,
        )

        log.debug("EXIT: _build_bootstrap_import_model() -> %s", bootstrap_model.serial_number)
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

        endpoint = EpManageFabricsSwitchActionsImportBootstrapPost()
        endpoint.fabric_name = self.ctx.fabric

        request_model = ImportBootstrapSwitchesRequestModel(switches=models)
        payload = request_model.to_payload()

        log.debug("importBootstrap endpoint: %s", endpoint.path)
        log.debug("importBootstrap payload (masked): %s", mask_password(payload))
        log.info(
            "Importing %s bootstrap switch(es): %s",
            len(models),
            [m.serial_number for m in models],
        )

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = f"importBootstrap API call failed for " f"{[m.serial_number for m in models]}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "bootstrap"
        results.operation_type = OperationType.CREATE
        results.response_current = response
        results.result_current = result
        results.diff_current = payload
        results.register_api_call()

        if not result.get("success"):
            msg = f"importBootstrap failed for " f"{[m.serial_number for m in models]}: {response}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.info("importBootstrap API response success: %s", result.get("success"))
        log.debug("EXIT: _import_bootstrap_switches()")

    def _build_preprovision_model(
        self,
        switch_cfg: SwitchConfigModel,
        preprov_cfg: "PreprovisionConfigModel",
    ) -> PreProvisionSwitchModel:
        """Build a pre-provision model from PreprovisionConfigModel configuration.

        Args:
            switch_cfg: Parent switch config.
            preprov_cfg: Pre-provision config entry.

        Returns:
            Completed ``PreProvisionSwitchModel`` for API submission.
        """
        log = self.ctx.log
        log.debug("ENTER: _build_preprovision_model(serial=%s)", preprov_cfg.serial_number)

        serial_number = preprov_cfg.serial_number
        hostname = preprov_cfg.hostname
        ip = switch_cfg.seed_ip
        model_name = preprov_cfg.model
        version = preprov_cfg.version
        image_policy = preprov_cfg.image_policy
        gateway_ip_mask = preprov_cfg.config_data.gateway
        switch_role = switch_cfg.role
        password = switch_cfg.password
        auth_proto = SnmpV3AuthProtocol.MD5  # Pre-provision always uses MD5

        discovery_username = getattr(preprov_cfg, "discovery_username", None)
        discovery_password = getattr(preprov_cfg, "discovery_password", None)

        # Build data block from mandatory config_data
        data_block = build_poap_data_block(preprov_cfg)

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

        log.debug("EXIT: _build_preprovision_model() -> %s", preprov_model.serial_number)
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

        endpoint = EpManageFabricsSwitchActionsPreProvisionPost()
        endpoint.fabric_name = self.ctx.fabric

        request_model = PreProvisionSwitchesRequestModel(switches=models)
        payload = request_model.to_payload()

        log.debug("preProvision endpoint: %s", endpoint.path)
        log.debug("preProvision payload (masked): %s", mask_password(payload))
        log.info(
            "Pre-provisioning %s switch(es): %s",
            len(models),
            [m.serial_number for m in models],
        )

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = f"preProvision API call failed for " f"{[m.serial_number for m in models]}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "preprovision"
        results.operation_type = OperationType.CREATE
        results.response_current = response
        results.result_current = result
        results.diff_current = payload
        results.register_api_call()

        if not result.get("success"):
            msg = f"preProvision failed for " f"{[m.serial_number for m in models]}: {response}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.info("preProvision API response success: %s", result.get("success"))
        log.debug("EXIT: _preprovision_switches()")

    def _handle_poap_swap(
        self,
        swap_entries: List[Tuple[SwitchConfigModel, POAPConfigModel, "PreprovisionConfigModel"]],
        existing: List[SwitchDataModel],
    ) -> None:
        """Process POAP serial-swap entries.

        Args:
            swap_entries: ``(SwitchConfigModel, POAPConfigModel, PreprovisionConfigModel)``
                swap triples where poap carries the new serial and preprovision
                carries the old (pre-provisioned) serial.
            existing: Current fabric inventory snapshot.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results
        fabric = self.ctx.fabric

        log.debug("ENTER: _handle_poap_swap()")
        log.info("Processing %s POAP swap entries", len(swap_entries))

        # ------------------------------------------------------------------
        # Step 1: Validate preprovision serials exist in fabric inventory
        # ------------------------------------------------------------------
        fabric_index: Dict[str, Dict[str, Any]] = {sw.switch_id: sw.model_dump(by_alias=True) for sw in existing if sw.switch_id}
        log.debug(
            "Fabric inventory contains %s switch(es): %s",
            len(fabric_index),
            list(fabric_index.keys()),
        )

        for switch_cfg, poap_cfg, preprov_cfg in swap_entries:
            old_serial = preprov_cfg.serial_number
            if old_serial not in fabric_index:
                msg = (
                    f"Pre-provisioned serial '{old_serial}' not found in "
                    f"fabric '{fabric}' inventory. The switch must be "
                    f"pre-provisioned before a swap can be performed."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)
            log.info(
                "Validated: pre-provisioned serial '%s' exists in fabric inventory",
                old_serial,
            )

        # ------------------------------------------------------------------
        # Step 2: Validate new serials exist in bootstrap list
        # ------------------------------------------------------------------
        bootstrap_switches = query_bootstrap_switches(nd, fabric, log)
        bootstrap_index = build_bootstrap_index(bootstrap_switches)
        log.debug(
            "Bootstrap list contains %s switch(es): %s",
            len(bootstrap_index),
            list(bootstrap_index.keys()),
        )

        for switch_cfg, poap_cfg, preprov_cfg in swap_entries:
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
            log.info("Validated: new serial '%s' exists in bootstrap list", new_serial)

        # ------------------------------------------------------------------
        # Step 3: Call changeSwitchSerialNumber for each swap entry
        # ------------------------------------------------------------------
        for switch_cfg, poap_cfg, preprov_cfg in swap_entries:
            old_serial = preprov_cfg.serial_number
            new_serial = poap_cfg.serial_number

            log.info(
                "Swapping serial for pre-provisioned switch: %s → %s",
                old_serial,
                new_serial,
            )

            endpoint = EpManageFabricsSwitchChangeSerialNumberPost()
            endpoint.fabric_name = fabric
            endpoint.switch_sn = old_serial

            request_body = ChangeSwitchSerialNumberRequestModel(newSwitchId=new_serial)
            payload = request_body.to_payload()

            log.debug("changeSwitchSerialNumber endpoint: %s", endpoint.path)
            log.debug("changeSwitchSerialNumber payload: %s", payload)

            try:
                nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
            except Exception as e:
                msg = f"changeSwitchSerialNumber API call failed for " f"{old_serial} → {new_serial}: {e}"
                log.error(msg)
                nd.module.fail_json(msg=msg)

            response = nd.rest_send.response_current
            result = nd.rest_send.result_current

            results.action = "swap_serial"
            results.operation_type = OperationType.UPDATE
            results.response_current = response
            results.result_current = result
            results.diff_current = {
                "old_serial": old_serial,
                "new_serial": new_serial,
            }
            results.register_api_call()

            if not result.get("success"):
                msg = f"Failed to swap serial number from {old_serial} " f"to {new_serial}: {response}"
                log.error(msg)
                nd.module.fail_json(msg=msg)

            log.info("Serial number swap successful: %s → %s", old_serial, new_serial)
        # ------------------------------------------------------------------
        # Step 4: Re-query bootstrap API for post-swap data
        # ------------------------------------------------------------------
        post_swap_bootstrap = query_bootstrap_switches(nd, fabric, log)
        post_swap_index = build_bootstrap_index(post_swap_bootstrap)
        log.debug("Post-swap bootstrap list contains %s switch(es)", len(post_swap_index))

        # ------------------------------------------------------------------
        # Step 5: Build BootstrapImportSwitchModels and POST importBootstrap
        # ------------------------------------------------------------------
        import_models: List[BootstrapImportSwitchModel] = []
        for switch_cfg, poap_cfg, preprov_cfg in swap_entries:
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

            model = self._build_bootstrap_import_model(switch_cfg, poap_cfg, bootstrap_data)
            import_models.append(model)
            log.info(
                "Built bootstrap model for swapped serial=%s, hostname=%s, ip=%s",
                new_serial,
                model.hostname,
                model.ip,
            )

        if not import_models:
            log.warning("No bootstrap import models built after swap")
            log.debug("EXIT: _handle_poap_swap()")
            return

        try:
            self._import_bootstrap_switches(import_models)
        except Exception as e:
            msg = f"importBootstrap failed after serial swap: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        # ------------------------------------------------------------------
        # Step 6: Wait for manageability, save credentials, finalize
        # ------------------------------------------------------------------
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []
        for switch_cfg, poap_cfg, preprov_cfg in swap_entries:
            switch_actions.append((poap_cfg.serial_number, switch_cfg))

        self.fabric_ops.post_add_processing(
            switch_actions,
            wait_utils=self.wait_utils,
            context="swap",
            skip_greenfield_check=True,
        )

        log.info(
            "POAP swap completed successfully for %s switch(es): %s",
            len(swap_entries),
            [sn for sn, _cfg in switch_actions],
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
        log.info("Processing RMA for %s switch config(s)", len(proposed_config))

        # Check mode — preview only
        if nd.module.check_mode:
            log.info("Check mode: would run RMA provision")
            results.action = "rma"
            results.operation_type = OperationType.CREATE
            results.response_current = {"MESSAGE": "check mode — skipped"}
            results.result_current = {"success": True, "changed": False}
            results.diff_current = {"rma_switches": [pc.seed_ip for pc in proposed_config]}
            results.register_api_call()
            return

        # Collect (SwitchConfigModel, RMAConfigModel) pairs
        rma_entries: List[Tuple[SwitchConfigModel, RMAConfigModel]] = []
        for switch_cfg in proposed_config:
            if not switch_cfg.rma:
                log.warning(
                    "Switch config for %s has no RMA block — skipping",
                    switch_cfg.seed_ip,
                )
                continue
            for rma_cfg in switch_cfg.rma:
                rma_entries.append((switch_cfg, rma_cfg))

        if not rma_entries:
            log.warning("No RMA entries found — nothing to process")
            results.action = "rma"
            results.operation_type = OperationType.QUERY
            results.response_current = {"MESSAGE": "no switches to process"}
            results.result_current = {"success": True, "changed": False}
            results.diff_current = {}
            results.register_api_call()
            return

        log.info("Found %s RMA entry/entries to process", len(rma_entries))

        # Validate old switches exist and are in correct state; look up by seed_ip
        old_switch_info = self._validate_prerequisites(rma_entries, existing)

        # Query bootstrap API for new switch data
        bootstrap_switches = query_bootstrap_switches(nd, self.ctx.fabric, log)
        bootstrap_idx = build_bootstrap_index(bootstrap_switches)
        log.debug(
            "Bootstrap index contains %s switch(es): %s",
            len(bootstrap_idx),
            list(bootstrap_idx.keys()),
        )

        # Build and submit each RMA request
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []
        for switch_cfg, rma_cfg in rma_entries:
            new_serial = rma_cfg.new_serial_number
            old_serial = old_switch_info[switch_cfg.seed_ip]["old_serial"]
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
                switch_cfg,
                rma_cfg,
                bootstrap_data,
                old_switch_info[switch_cfg.seed_ip],
            )
            log.info(
                "Built RMA model: replacing %s with %s",
                old_serial,
                rma_model.new_switch_id,
            )

            self._provision_rma_switch(rma_model)
            switch_actions.append((rma_model.new_switch_id, switch_cfg))

        # Post-processing: wait for RMA switches to become ready, then
        # save credentials and finalize.  RMA switches come up via POAP
        # bootstrap and never enter migration mode, so we use the
        # RMA-specific wait (unreachable → ok) instead of the generic
        # wait_for_switch_manageable which would time out on the
        # migration-mode phase.
        all_new_serials = [sn for sn, _cfg in switch_actions]
        log.info(
            "Waiting for %s RMA replacement switch(es) to become ready: %s",
            len(all_new_serials),
            all_new_serials,
        )
        success = self.wait_utils.wait_for_rma_switch_ready(all_new_serials)
        if not success:
            msg = f"One or more RMA replacement switches failed to become " f"discoverable in fabric '{self.ctx.fabric}'. " f"Switches: {all_new_serials}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        self.fabric_ops.bulk_save_credentials(switch_actions)

        try:
            self.fabric_ops.finalize()
        except Exception as e:
            msg = f"Failed to finalize (config-save/deploy) for RMA " f"switches {all_new_serials}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.debug("EXIT: RMAHandler.handle()")

    def _validate_prerequisites(
        self,
        rma_entries: List[Tuple[SwitchConfigModel, RMAConfigModel]],
        existing: List[SwitchDataModel],
    ) -> Dict[str, Dict[str, Any]]:
        """Validate RMA prerequisites for each requested replacement.

        Looks up the switch to be replaced by ``seed_ip`` (the fabric management
        IP).  The serial number of the old switch is derived from inventory —
        it is not required in the playbook config.

        Args:
            rma_entries: ``(SwitchConfigModel, RMAConfigModel)`` pairs.
            existing: Current fabric inventory snapshot.

        Returns:
            Dict keyed by ``seed_ip`` with prerequisite metadata including
            ``old_serial``, ``hostname``, and ``switch_data``.
        """
        nd = self.ctx.nd
        log = self.ctx.log

        log.debug("ENTER: _validate_prerequisites()")

        existing_by_ip: Dict[str, SwitchDataModel] = {
            sw.fabric_management_ip: sw for sw in existing if sw.fabric_management_ip
        }

        result: Dict[str, Dict[str, Any]] = {}

        for switch_cfg, _rma_cfg in rma_entries:
            seed_ip = switch_cfg.seed_ip

            old_switch = existing_by_ip.get(seed_ip)
            if old_switch is None:
                nd.module.fail_json(
                    msg=(
                        f"RMA: seed_ip '{seed_ip}' not found in "
                        f"fabric '{self.ctx.fabric}' inventory. The switch "
                        f"being replaced must exist in the fabric."
                    )
                )

            old_serial = old_switch.serial_number or old_switch.switch_id
            if not old_serial:
                nd.module.fail_json(
                    msg=(
                        f"RMA: Switch at '{seed_ip}' has no serial number in "
                        f"the inventory response."
                    )
                )

            ad = old_switch.additional_data
            if ad is None:
                nd.module.fail_json(
                    msg=(
                        f"RMA: Switch at '{seed_ip}' (serial '{old_serial}') has no "
                        f"additional data in the inventory response. Cannot verify "
                        f"discovery status and system mode."
                    )
                )

            if ad.discovery_status != DiscoveryStatus.UNREACHABLE:
                nd.module.fail_json(
                    msg=(
                        f"RMA: Switch at '{seed_ip}' (serial '{old_serial}') has discovery status "
                        f"'{getattr(ad.discovery_status, 'value', ad.discovery_status) if ad.discovery_status else 'unknown'}', "
                        f"expected 'unreachable'. The old switch must be "
                        f"unreachable before RMA can proceed."
                    )
                )

            if ad.system_mode != SystemMode.MAINTENANCE:
                nd.module.fail_json(
                    msg=(
                        f"RMA: Switch at '{seed_ip}' (serial '{old_serial}') is in "
                        f"'{getattr(ad.system_mode, 'value', ad.system_mode) if ad.system_mode else 'unknown'}' "
                        f"mode, expected 'maintenance'. Put the switch in "
                        f"maintenance mode before initiating RMA."
                    )
                )

            result[seed_ip] = {
                "old_serial": old_serial,
                "hostname": old_switch.hostname or "",
                "switch_data": old_switch,
            }
            log.info(
                "RMA prerequisite check passed for '%s' (serial=%s, discovery=%s, mode=%s)",
                seed_ip,
                old_serial,
                ad.discovery_status,
                ad.system_mode,
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

        All switch properties (model, version, gateway, modules) are sourced
        exclusively from the bootstrap API response.  Only the new serial number,
        optional image policy, and optional discovery credentials come from the
        playbook config.

        Args:
            switch_cfg: Parent switch config.
            rma_cfg: RMA config entry.
            bootstrap_data: Bootstrap response entry for the replacement switch.
            old_switch_info: Prerequisite metadata keyed from _validate_prerequisites.

        Returns:
            Completed ``RMASwitchModel`` for API submission.
        """
        log = self.ctx.log
        old_serial = old_switch_info["old_serial"]
        log.debug(
            "ENTER: _build_rma_model(new=%s, old=%s)",
            rma_cfg.new_serial_number,
            old_serial,
        )

        bs_data = bootstrap_data.get("data") or {}

        gateway_ip_mask = bootstrap_data.get("gatewayIpMask") or bs_data.get("gatewayIpMask", "")
        data_models = bs_data.get("models", [])
        model = bootstrap_data.get("model", "")
        software_version = bootstrap_data.get("softwareVersion", "")
        public_key = bootstrap_data.get("publicKey", "")
        finger_print = bootstrap_data.get("fingerPrint") or bootstrap_data.get("fingerprint", "")

        rma_model = RMASwitchModel(
            gatewayIpMask=gateway_ip_mask,
            model=model,
            softwareVersion=software_version,
            imagePolicy=rma_cfg.image_policy,
            switchRole=switch_cfg.role,
            password=switch_cfg.password,
            discoveryAuthProtocol=SnmpV3AuthProtocol.MD5,
            discoveryUsername=rma_cfg.discovery_username,
            discoveryPassword=rma_cfg.discovery_password,
            hostname=old_switch_info.get("hostname", ""),
            ip=switch_cfg.seed_ip,
            newSwitchId=rma_cfg.new_serial_number,
            oldSwitchId=old_serial,
            publicKey=public_key,
            fingerPrint=finger_print,
            data=(
                {"gatewayIpMask": gateway_ip_mask, "models": data_models}
                if (gateway_ip_mask or data_models)
                else None
            ),
        )

        log.debug("EXIT: _build_rma_model() -> newSwitchId=%s, oldSwitchId=%s", rma_model.new_switch_id, old_serial)
        return rma_model

    def _provision_rma_switch(
        self,
        rma_model: RMASwitchModel,
    ) -> None:
        """Submit an RMA provisioning request for one switch.

        The old and new switch IDs are embedded in the payload via
        ``oldSwitchId`` and ``newSwitchId`` fields on the model.

        Args:
            rma_model: RMA model for the replacement switch.

        Returns:
            None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: _provision_rma_switch()")

        endpoint = EpManageFabricsSwitchProvisionRMAPost()
        endpoint.fabric_name = self.ctx.fabric
        endpoint.switch_sn = rma_model.old_switch_id

        payload = rma_model.to_payload()

        log.info("RMA: Replacing %s with %s", rma_model.old_switch_id, rma_model.new_switch_id)
        log.debug("RMA endpoint: %s", endpoint.path)
        log.debug("RMA payload (masked): %s", mask_password(payload))

        try:
            nd.request(path=endpoint.path, verb=endpoint.verb, data=payload)
        except Exception as e:
            msg = f"RMA provision API call failed for {rma_model.old_switch_id} → {rma_model.new_switch_id}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        response = nd.rest_send.response_current
        result = nd.rest_send.result_current

        results.action = "rma"
        results.operation_type = OperationType.CREATE
        results.response_current = response
        results.result_current = result
        results.diff_current = {
            "old_switch_id": rma_model.old_switch_id,
            "new_switch_id": rma_model.new_switch_id,
        }
        results.register_api_call()

        if not result.get("success"):
            msg = f"RMA provision failed for {rma_model.old_switch_id} → {rma_model.new_switch_id}: {response}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.info("RMA provision API response success: %s", result.get("success"))
        log.debug("EXIT: _provision_rma_switch()")


# =========================================================================
# Orchestrator (Thin State Router)
# =========================================================================


class NDSwitchResourceModule:
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
            save_config=self.module.params.get("save"),
            deploy_config=self.module.params.get("deploy"),
        )

        # Switch collections
        try:
            self.proposed: NDConfigCollection = NDConfigCollection(model_class=SwitchDataModel)
            self.existing: NDConfigCollection = NDConfigCollection.from_api_response(
                response_data=self._query_all_switches(),
                model_class=SwitchDataModel,
            )
            self.before: NDConfigCollection = self.existing.copy()
            self.sent: NDConfigCollection = NDConfigCollection(model_class=SwitchDataModel)
        except Exception as e:
            msg = f"Failed to query fabric '{self.fabric}' inventory " f"during initialization: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        # Operation tracking
        self.nd_logs: List[Dict[str, Any]] = []
        self.output: NDOutput = NDOutput(output_level=self.module.params.get("output_level", "normal"))
        self.output.assign(before=self.before, after=self.existing)

        # Utility instances (SwitchWaitUtils / FabricUtils depend on self)
        self.fabric_utils = FabricUtils(self.nd, self.fabric, log)
        self.wait_utils = SwitchWaitUtils(self, self.fabric, log, fabric_utils=self.fabric_utils)

        # Service instances (Dependency Injection)
        self.discovery = SwitchDiscoveryService(self.ctx)
        self.fabric_ops = SwitchFabricOps(self.ctx, self.fabric_utils)
        self.poap_handler = POAPHandler(self.ctx, self.fabric_ops, self.wait_utils)
        self.rma_handler = RMAHandler(self.ctx, self.fabric_ops, self.wait_utils)

        log.info("Initialized NDSwitchResourceModule for fabric: %s", self.fabric)

    def exit_json(self) -> None:
        """Finalize collected results and exit the Ansible module.

        Includes operation logs and previous/current inventory snapshots in the
        final response payload.

        Returns:
            None.
        """
        self.results.build_final_result()
        final = self.results.final_result

        if self.state == "gathered":
            # gathered: expose the already-queried inventory in config shape.
            # No re-query needed — nothing was changed.
            gathered = []
            for sw in self.existing:
                try:
                    gathered.append(SwitchConfigModel.from_switch_data(sw).to_gathered_dict())
                except (ValueError, Exception) as exc:
                    msg = f"Failed to convert switch {sw.switch_id!r} to gathered format: {exc}"
                    self.log.error(msg)
                    self.nd.module.fail_json(msg=msg)
            self.output.assign(after=self.existing)
            final.update(self.output.format(gathered=gathered))
        else:
            # Re-query the fabric to get the actual post-operation inventory so
            # that "after" reflects real state rather than the pre-op snapshot.
            if True not in self.results.failed and not self.nd.module.check_mode:
                self.existing = NDConfigCollection.from_api_response(
                    response_data=self._query_all_switches(),
                    model_class=SwitchDataModel,
                )
            self.output.assign(after=self.existing, diff=self.sent)
            final.update(self.output.format())

        if True in self.results.failed:
            self.nd.module.fail_json(**final)
        self.nd.module.exit_json(**final)

    # =====================================================================
    # Public API – State Management
    # =====================================================================

    def manage_state(self) -> None:
        """Dispatch the requested module state to the appropriate workflow.

        Unified entry point for all states.  The flow is:

        1. Validate and route simple states (gathered, deleted).
        2. Validate the full config, enforce state constraints.
        3. Call ``compute_changes`` with **all** configs in one pass — this
           classifies normal, POAP/preprovision, swap, and RMA configs against
           the current fabric inventory and handles idempotency.
        4. Discover all switches that need it in **one combined call**.
        5. Delegate to the appropriate state handler with the populated plan
           and the single ``discovered_data`` dict.

        Returns:
            None.
        """
        self.log.info("Managing state: %s", self.state)

        # gathered — read-only, no config accepted
        if self.state == "gathered":
            if self.config:
                self.nd.module.fail_json(msg="'config' must not be provided for 'gathered' state.")
            return self._handle_gathered_state()

        # deleted — config is optional; handled separately (lighter path)
        if self.state == "deleted":
            proposed_config = SwitchDiffEngine.validate_configs(self.config, self.state, self.nd, self.log) if self.config else None
            return self._handle_deleted_state(proposed_config)

        # merged — config required
        if self.state == "merged" and not self.config:
            self.nd.module.fail_json(msg="'config' is required for 'merged' state.")

        # overridden with no/empty config — delete everything
        if self.state == "overridden" and not self.config:
            self.log.info("Overridden state with no config — deleting all switches from fabric")
            return self._handle_deleted_state(None)

        # --- Validate & classify ------------------------------------------------
        proposed_config = SwitchDiffEngine.validate_configs(self.config, self.state, self.nd, self.log)

        # Enforce state constraints
        rma_configs = [c for c in proposed_config if c.operation_type == "rma"]
        poap_configs = [c for c in proposed_config if c.operation_type in ("poap", "preprovision", "swap")]
        if rma_configs and self.state != "merged":
            self.nd.module.fail_json(msg="RMA configs are only supported with state=merged")
        if poap_configs and self.state not in ("merged", "overridden"):
            self.nd.module.fail_json(msg="POAP and pre-provision configs require state=merged or state=overridden")

        # Capture all proposed configs for NDOutput
        output_proposed: NDConfigCollection = NDConfigCollection(model_class=SwitchConfigModel)
        for cfg in proposed_config:
            output_proposed.add(cfg)
        self.output.assign(proposed=output_proposed)

        # Classify all configs in one pass — idempotency included
        plan = SwitchDiffEngine.compute_changes(proposed_config, list(self.existing), self.log)

        # --- Single combined discovery pass -------------------------------------
        # Discover every switch that is not yet in the fabric:
        #   • plan.to_add      — normal switches not in inventory
        #   • plan.normal_readd — POAP/preprov mismatches that are reachable
        # Switches already in the fabric (to_update, migration_mode) are
        # skipped here; overridden will re-discover them after deletion.
        configs_to_discover = plan.to_add + plan.normal_readd
        if configs_to_discover:
            self.log.info(
                "Discovering %s switch(es): %s normal-add, %s poap-readd",
                len(configs_to_discover),
                len(plan.to_add),
                len(plan.normal_readd),
            )
            discovered_data = self.discovery.discover(configs_to_discover)
        else:
            self.log.info("No switches need discovery in this run")
            discovered_data = {}

        # Build proposed SwitchDataModel collection for normal switches only
        # (needed for the self.proposed reference used in check-mode reporting)
        normal_configs = [c for c in proposed_config if c.operation_type == "normal"]
        if normal_configs:
            built = self.discovery.build_proposed(normal_configs, discovered_data, list(self.existing))
            self.proposed = NDConfigCollection(model_class=SwitchDataModel, items=built)

        # --- Dispatch -----------------------------------------------------------
        if self.state == "merged":
            self._handle_merged_state(plan, discovered_data)
        elif self.state == "overridden":
            self._handle_overridden_state(plan, discovered_data)
        else:
            self.nd.module.fail_json(msg=f"Unsupported state: {self.state}")

    # =====================================================================
    # State Handlers (orchestration only — delegate to services)
    # =====================================================================

    def _handle_merged_state(
        self,
        plan: "SwitchPlan",
        discovered_data: Dict[str, Dict[str, Any]],
    ) -> None:
        """Handle merged-state workflows for all operation types.

        Processes normal adds, migration-mode switches, POAP bootstrap,
        pre-provision, swap, normal re-adds, and RMA in a single pass.
        Normal switches that require field-level updates fail fast; use
        ``overridden`` state for in-place updates.

        Args:
            plan: Unified action plan from :meth:`SwitchDiffEngine.compute_changes`.
            discovered_data: Discovery data keyed by seed IP for all switches
                             that required discovery this run.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_merged_state()")
        self.log.info("Handling merged state")

        # Fail if any normal switches need field-level updates
        if plan.to_update:
            ips = [cfg.seed_ip for cfg in plan.to_update]
            self.nd.module.fail_json(
                msg=(
                    f"Switches require updates not supported in merged state. "
                    f"Use 'overridden' state for in-place updates. "
                    f"Affected switches: {ips}"
                )
            )

        # Check whether any idempotent switch (normal or POAP) is out of
        # config-sync and needs a deploy without a re-add.
        # Pre-provisioned switches are placeholder entries that are never
        # in-sync by design, so they are excluded from this check. Only relevant when deploy is enabled.
        existing_by_ip = {sw.fabric_management_ip: sw for sw in self.existing}
        idempotent_save_req = False
        if self.ctx.deploy_config:
            for cfg in plan.idempotent:
                if cfg.operation_type == "preprovision":
                    continue
                sw = existing_by_ip.get(cfg.seed_ip)
                status = sw.additional_data.config_sync_status if sw and sw.additional_data else None
                if status != ConfigSyncStatus.IN_SYNC:
                    self.log.info(
                        "Switch %s is idempotent but configSyncStatus='%s' — will finalize",
                        cfg.seed_ip,
                        getattr(status, "value", status) if status else "unknown",
                    )
                    idempotent_save_req = True
                    break

        has_work = bool(
            plan.to_add or plan.migration_mode or plan.to_bootstrap
            or plan.normal_readd or plan.to_preprovision or plan.to_swap
            or plan.to_rma or idempotent_save_req
        )
        if not has_work:
            self.log.info("merged: nothing to do — all switches idempotent")
            return

        # Check mode
        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: add=%s, migrate=%s, bootstrap=%s, "
                "readd=%s, preprov=%s, swap=%s, rma=%s, save_deploy=%s",
                len(plan.to_add), len(plan.migration_mode), len(plan.to_bootstrap),
                len(plan.normal_readd), len(plan.to_preprovision), len(plan.to_swap),
                len(plan.to_rma), idempotent_save_req,
            )
            self.results.action = "merge"
            self.results.state = self.state
            self.results.operation_type = OperationType.CREATE
            self.results.response_current = {"MESSAGE": "check mode — skipped", "RETURN_CODE": 200}
            self.results.result_current = {"success": True, "changed": False}
            self.results.diff_current = {
                "to_add": [c.seed_ip for c in plan.to_add],
                "migration_mode": [c.seed_ip for c in plan.migration_mode],
                "bootstrap": [c.seed_ip for c in plan.to_bootstrap],
                "normal_readd": [c.seed_ip for c in plan.normal_readd],
                "preprovision": [c.seed_ip for c in plan.to_preprovision],
                "swap": [c.seed_ip for c in plan.to_swap],
                "rma": [c.seed_ip for c in plan.to_rma],
                "save_deploy_required": idempotent_save_req,
            }
            self.results.register_api_call()
            return

        # --- Normal + normal_readd bulk_add (one combined pass) -----------------
        add_configs = plan.to_add + plan.normal_readd
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []
        have_migration = bool(plan.migration_mode)

        if add_configs and discovered_data:
            credential_groups = group_switches_by_credentials(add_configs, self.log)
            for group_key, group_switches in credential_groups.items():
                username, _pw_hash, auth_proto, platform_type, preserve_config = group_key
                password = group_switches[0].password
                pairs = [
                    (cfg, discovered_data[cfg.seed_ip])
                    for cfg in group_switches
                    if cfg.seed_ip in discovered_data
                ]
                if not pairs:
                    self.log.warning(
                        "No discovery data for group %s — skipping bulk_add",
                        [cfg.seed_ip for cfg in group_switches],
                    )
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

        # Migration-mode switches — no add needed, but role + finalize applies
        for cfg in plan.migration_mode:
            sw = existing_by_ip.get(cfg.seed_ip)
            if sw and sw.switch_id:
                switch_actions.append((sw.switch_id, cfg))
                self._log_operation("migrate", cfg.seed_ip)

        if switch_actions:
            all_preserve_config = all(cfg.preserve_config for _sn, cfg in switch_actions)
            if all_preserve_config:
                self.log.info("All switches brownfield (preserve_config=True) — reload detection skipped")
            self.fabric_ops.post_add_processing(
                switch_actions,
                wait_utils=self.wait_utils,
                context="merged",
                all_preserve_config=all_preserve_config,
                update_roles=have_migration,
            )
        elif idempotent_save_req:
            self.log.info("No adds/migrations but config-sync required — running finalize")
            self.fabric_ops.finalize()

        # --- POAP / preprovision / swap / RMA -----------------------------------
        # normal_readd was already processed via bulk_add above.
        # Only route the pure POAP-workflow configs to the handler.
        poap_workflow_configs = plan.to_bootstrap + plan.to_preprovision + plan.to_swap
        if poap_workflow_configs:
            self.poap_handler.handle(poap_workflow_configs, list(self.existing))
        if plan.to_rma:
            self.rma_handler.handle(plan.to_rma, list(self.existing))

        self.log.debug("EXIT: _handle_merged_state()")

    def _handle_overridden_state(
        self,
        plan: "SwitchPlan",
        discovered_data: Dict[str, Dict[str, Any]],
    ) -> None:
        """Handle overridden-state reconciliation for the fabric.

        Reconciles the fabric to match exactly the desired config.  Switches
        in the fabric that have no config entry are deleted.  POAP/preprovision
        switches at ``plan.poap_ips`` are excluded from the cleanup sweep.
        Normal switches with field differences are deleted and re-added.

        Args:
            plan: Unified action plan from :meth:`SwitchDiffEngine.compute_changes`.
            discovered_data: Discovery data keyed by seed IP.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_overridden_state()")
        self.log.info("Handling overridden state")

        has_work = bool(
            plan.to_add or plan.to_update or plan.to_delete or plan.migration_mode
            or plan.to_bootstrap or plan.normal_readd or plan.to_preprovision or plan.to_swap
        )
        if not has_work and not self.proposed:
            self.log.info("overridden: nothing to do")
            return

        # Check mode
        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: delete_orphans=%s, update=%s, add=%s, migrate=%s, "
                "bootstrap=%s, readd=%s, preprov=%s, swap=%s",
                len(plan.to_delete), len(plan.to_update), len(plan.to_add),
                len(plan.migration_mode), len(plan.to_bootstrap), len(plan.normal_readd),
                len(plan.to_preprovision), len(plan.to_swap),
            )
            self.results.action = "override"
            self.results.state = self.state
            self.results.operation_type = OperationType.CREATE
            self.results.response_current = {"MESSAGE": "check mode — skipped", "RETURN_CODE": 200}
            self.results.result_current = {"success": True, "changed": False}
            self.results.diff_current = {
                "to_delete": len(plan.to_delete) + len(plan.to_delete_existing),
                "to_update": len(plan.to_update),
                "to_add": len(plan.to_add),
                "migration_mode": len(plan.migration_mode),
                "bootstrap": len(plan.to_bootstrap),
                "normal_readd": len(plan.normal_readd),
                "preprovision": len(plan.to_preprovision),
                "swap": len(plan.to_swap),
            }
            self.results.register_api_call()
            return

        existing_by_ip = {sw.fabric_management_ip: sw for sw in self.existing}

        # --- Phase 1: Combined delete -------------------------------------------
        # Merge three sources of deletions into one bulk_delete call:
        #   a) Orphans (in fabric, not in any config)
        #   b) POAP/preprovision mismatches (to_delete_existing from compute_changes)
        #   c) Normal switches that need field updates (to_update)
        switches_to_delete: List[SwitchDataModel] = list(plan.to_delete)
        for sw in plan.to_delete:
            self._log_operation("delete", sw.fabric_management_ip)

        for sw in plan.to_delete_existing:
            self.log.info("Deleting POAP/preprovision mismatch %s before re-add", sw.fabric_management_ip)
            switches_to_delete.append(sw)
            self._log_operation("delete", sw.fabric_management_ip)

        update_ips: set = set()
        for cfg in plan.to_update:
            sw = existing_by_ip.get(cfg.seed_ip)
            if sw:
                self.log.info("Deleting normal switch %s for field update re-add", cfg.seed_ip)
                switches_to_delete.append(sw)
                update_ips.add(cfg.seed_ip)
                self._log_operation("delete_for_update", cfg.seed_ip)

        if switches_to_delete:
            try:
                self.fabric_ops.bulk_delete(switches_to_delete)
            except SwitchOperationError as e:
                msg = f"Failed to delete switches during overridden state: {e}"
                self.log.error(msg)
                self.nd.module.fail_json(msg=msg)
            for sw in switches_to_delete:
                self.sent.add(sw)

        # --- Phase 2: Re-discover updated normal switches -----------------------
        # to_update configs were already discovered (they were in-fabric) but
        # we deleted them; re-discover so bulk_add has current data.
        re_discover_configs = [cfg for cfg in plan.to_update if cfg.seed_ip in update_ips]
        if re_discover_configs:
            self.log.info(
                "Re-discovering %s updated switch(es) after deletion",
                len(re_discover_configs),
            )
            fresh = self.discovery.discover(re_discover_configs)
            discovered_data = {**discovered_data, **fresh}

        # --- Phase 3: Combined add (normal to_add + to_update + normal_readd) ---
        add_configs = plan.to_add + plan.to_update + plan.normal_readd
        switch_actions: List[Tuple[str, SwitchConfigModel]] = []
        have_migration = bool(plan.migration_mode)

        if add_configs and discovered_data:
            credential_groups = group_switches_by_credentials(add_configs, self.log)
            for group_key, group_switches in credential_groups.items():
                username, _pw_hash, auth_proto, platform_type, preserve_config = group_key
                password = group_switches[0].password
                pairs = [
                    (cfg, discovered_data[cfg.seed_ip])
                    for cfg in group_switches
                    if cfg.seed_ip in discovered_data
                ]
                if not pairs:
                    self.log.warning(
                        "No discovery data for group %s — skipping",
                        [cfg.seed_ip for cfg in group_switches],
                    )
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

        for cfg in plan.migration_mode:
            sw = existing_by_ip.get(cfg.seed_ip)
            if sw and sw.switch_id:
                switch_actions.append((sw.switch_id, cfg))
                self._log_operation("migrate", cfg.seed_ip)

        if switch_actions:
            all_preserve_config = all(cfg.preserve_config for _sn, cfg in switch_actions)
            self.fabric_ops.post_add_processing(
                switch_actions,
                wait_utils=self.wait_utils,
                context="overridden",
                all_preserve_config=all_preserve_config,
                update_roles=have_migration,
            )

        # --- Phase 4: POAP workflows (bootstrap / preprovision / swap) ----------
        # plan.to_delete_existing was deleted in Phase 1.
        # Route pure POAP-workflow configs to the handler.
        poap_workflow_configs = plan.to_bootstrap + plan.to_preprovision + plan.to_swap
        if poap_workflow_configs:
            self.poap_handler.handle(poap_workflow_configs, list(self.existing))

        self.log.debug("EXIT: _handle_overridden_state()")

    def _handle_gathered_state(self) -> None:
        """Handle gathered-state read of the fabric inventory.

        No API writes are performed. The existing inventory is serialised into
        SwitchConfigModel shape by exit_json(). This method only records the
        result metadata so that Results aggregation works correctly.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_gathered_state()")
        self.log.info("Gathering inventory for fabric '%s'", self.fabric)

        if not self.existing:
            self.log.info("Fabric '%s' has no switches in inventory", self.fabric)

        self.results.action = "gathered"
        self.results.state = self.state
        self.results.operation_type = OperationType.QUERY
        self.results.response_current = {"MESSAGE": "gathered", "RETURN_CODE": 200}
        self.results.result_current = {"success": True, "changed": False}
        self.results.diff_current = {}
        self.results.register_api_call()

        self.log.info(
            "Gathered %s switch(es) from fabric '%s'",
            len(list(self.existing)),
            self.fabric,
        )
        self.log.debug("EXIT: _handle_gathered_state()")

    def _handle_deleted_state(
        self,
        proposed_config: Optional[List[SwitchConfigModel]] = None,
    ) -> None:
        """Handle deleted-state switch removal.

        Matches switches to delete by ``seed_ip`` and optionally ``role``.
        POAP/preprovision sub-config blocks (``poap``, ``preprovision``) are
        ignored; only ``seed_ip`` and ``role`` matter.  When no config is
        provided, all switches in the fabric are deleted.

        Args:
            proposed_config: Optional config list that limits deletion scope.
                             Pass ``None`` to delete all switches.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_deleted_state()")
        self.log.info("Handling deleted state")

        if proposed_config is None:
            switches_to_delete = list(self.existing)
            self.log.info(
                "No proposed config — targeting all %s existing switch(es) for deletion",
                len(switches_to_delete),
            )
            for sw in switches_to_delete:
                self._log_operation("delete", sw.fabric_management_ip)
        else:
            existing_by_ip = {sw.fabric_management_ip: sw for sw in self.existing}
            switches_to_delete: List[SwitchDataModel] = []
            for cfg in proposed_config:
                existing_sw = existing_by_ip.get(cfg.seed_ip)
                if not existing_sw:
                    self.log.info("deleted: switch %s not in fabric — skipping", cfg.seed_ip)
                    continue
                # Role filter: if config specifies a role, only delete if it matches
                if cfg.role is not None and cfg.role != existing_sw.switch_role:
                    self.log.info(
                        "deleted: switch %s role mismatch (config=%s, fabric=%s) — skipping",
                        cfg.seed_ip, cfg.role, existing_sw.switch_role,
                    )
                    continue
                self.log.info(
                    "deleted: marking %s (%s) for deletion",
                    cfg.seed_ip, existing_sw.switch_id,
                )
                switches_to_delete.append(existing_sw)
                self._log_operation("delete", cfg.seed_ip)

        self.log.info("Total switches marked for deletion: %s", len(switches_to_delete))
        if not switches_to_delete:
            self.log.info("No switches to delete")
            return

        # Check mode
        if self.nd.module.check_mode:
            self.log.info("Check mode: would delete %s switch(es)", len(switches_to_delete))
            self.results.action = "delete"
            self.results.state = self.state
            self.results.operation_type = OperationType.DELETE
            self.results.response_current = {"MESSAGE": "check mode — skipped", "RETURN_CODE": 200}
            self.results.result_current = {"success": True, "changed": False}
            self.results.diff_current = {
                "to_delete": [sw.fabric_management_ip for sw in switches_to_delete],
            }
            self.results.register_api_call()
            return

        self.log.info("Proceeding to delete %s switch(es) from fabric", len(switches_to_delete))
        self.fabric_ops.bulk_delete(switches_to_delete)
        for sw in switches_to_delete:
            self.sent.add(sw)
        self.log.debug("EXIT: _handle_deleted_state()")

    # =====================================================================
    # Query Helpers
    # =====================================================================

    def _query_all_switches(self) -> List[Dict[str, Any]]:
        """Query all switches from the fabric inventory API.

        Returns:
            List of raw switch dictionaries returned by the controller.
        """
        endpoint = EpManageFabricsSwitchesGet()
        endpoint.fabric_name = self.fabric
        self.log.debug("Querying all switches with endpoint: %s", endpoint.path)
        self.log.debug("Query verb: %s", endpoint.verb)

        try:
            result = self.nd.request(path=endpoint.path, verb=endpoint.verb)
        except Exception as e:
            msg = f"Failed to query switches from " f"fabric '{self.fabric}': {e}"
            self.log.error(msg)
            self.nd.module.fail_json(msg=msg)

        if isinstance(result, list):
            switches = result
        elif isinstance(result, dict):
            switches = result.get("switches", [])
        else:
            switches = []

        self.log.debug("Queried %s switches from fabric %s", len(switches), self.fabric)
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
        self.nd_logs.append(
            {
                "operation": operation,
                "identifier": identifier,
                "status": "success",
            }
        )
