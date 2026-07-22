# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage ND fabric switch lifecycle workflows.

This module validates desired switch state, performs discovery and fabric
operations, and coordinates POAP and RMA workflows.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDModuleError,
)

from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType, PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (
    SwitchRole,
    SnmpV3AuthProtocol,
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
from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory import (
    FabricSwitchInventory,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_details_cache import (
    FabricDetailsCache,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.utils import (
    ApiDataChecker,
    SwitchFabricUtils,
    SwitchWaitUtils,
    SwitchOperationError,
    mask_password,
    get_switch_field,
    group_switches_by_credentials,
    query_bootstrap_switches,
    build_bootstrap_index,
    build_poap_data_block,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.fabric_switch_capabilities import (
    SwitchFabricCapabilityError,
    validate_switch_configs_for_fabric_type,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
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
_REQUEST_RETRY_COUNT: int = 1
_REQUEST_RETRY_DELAY: int = 1
_REQUEST_ERRORS = (NDModuleError, TypeError, ValueError)
_MODEL_ERRORS = (ValidationError, TypeError, ValueError)
_OUTPUT_CONVERSION_ERRORS = (AttributeError, TypeError, ValueError)
_FABRIC_OPERATION_ERRORS = (NDModuleError, SwitchOperationError, RuntimeError, TypeError, ValueError)


@dataclass
class ApiCallSpec:
    """Arguments for a tracked switch API call."""

    endpoint: Any
    payload: dict[str, Any]
    action: str
    op_type: OperationType
    diff: dict[str, Any] | None = None
    context: str = ""


@dataclass
class SwitchApiFieldValidationSpec:
    """Arguments for validating config fields against bootstrap API data."""

    nd: NDModule
    serial: str
    model: str | None
    version: str | None
    config_data: Any
    bootstrap_data: dict[str, Any]
    log: logging.Logger
    context: str
    hostname: str | None = None


@dataclass
class DiscoveryBatchSpec:
    """Arguments for one bulk discovery request."""

    switches: list["SwitchConfigModel"]
    username: str
    password: str
    auth_proto: SnmpV3AuthProtocol
    platform_type: PlatformType


@dataclass
class BulkAddSpec:
    """Arguments for one bulk add request."""

    switches: list[tuple["SwitchConfigModel", dict[str, Any]]]
    username: str
    password: str
    auth_proto: SnmpV3AuthProtocol
    platform_type: PlatformType
    preserve_config: bool


@dataclass
class PostAddProcessingSpec:
    """Arguments for post-add wait, credentials, role update, and finalize tasks."""

    switch_actions: list[tuple[str, "SwitchConfigModel"]]
    wait_utils: Any
    context: str
    skip_greenfield_check: bool = False
    update_roles: bool = False


@dataclass
class SwitchWaitSets:
    """Post-add switch wait groups split by reload behavior."""

    nxos_reload: list[tuple[str, "SwitchConfigModel"]]
    nxos_preserve: list[tuple[str, "SwitchConfigModel"]]
    ready_without_reload: list[tuple[str, "SwitchConfigModel"]]


@dataclass
class AddPhaseSpec:
    """Arguments for a normal add phase."""

    add_configs: list["SwitchConfigModel"]
    plan: "SwitchPlan"
    discovered_data: dict[str, dict[str, Any]]
    existing_by_ip: dict[str, "SwitchDataModel"]
    context: str


def _request_with_retry_policy(
    nd: NDModule,
    *,
    path: str,
    verb: Any,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run nd.request with a short-lived RestSend retry policy.

    RestSend models retries as timeout / send_interval.  Keep retry_delay at
    least one second because a zero interval would never reduce the timeout.
    """
    rest_send = nd._get_rest_send()  # pylint: disable=protected-access
    original_timeout = rest_send.timeout
    original_send_interval = rest_send.send_interval

    rest_send.timeout = _REQUEST_RETRY_COUNT * _REQUEST_RETRY_DELAY
    rest_send.send_interval = _REQUEST_RETRY_DELAY
    try:
        return nd.request(path=path, verb=verb, data=data)
    finally:
        rest_send.timeout = original_timeout
        rest_send.send_interval = original_send_interval


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
    deploy_type: str = "switch"

    def api_call(
        self,
        spec: ApiCallSpec,
    ) -> dict[str, Any]:
        """Execute an API call with standard error handling and result registration.

        ## Parameters

        - `spec`: API call details, result metadata, and error context.

        ## Returns

        - The API response dict.
        """
        try:
            _request_with_retry_policy(
                self.nd,
                path=spec.endpoint.path,
                verb=spec.endpoint.verb,
                data=spec.payload,
            )
        except _REQUEST_ERRORS as e:
            msg = f"{spec.context}: {e}" if spec.context else str(e)
            self.log.error(msg)
            self.nd.module.fail_json(msg=msg)

        response = self.nd.rest_send.response_current
        result = self.nd.rest_send.result_current
        ApiDataChecker.check(response.get("DATA", {}), spec.context, self.log, self.nd.module.fail_json)

        self.results.action = spec.action
        self.results.operation_type = spec.op_type
        self.results.response_current = response
        self.results.result_current = result
        self.results.diff_current = spec.diff if spec.diff is not None else spec.payload
        self.results.register_api_call()

        if not result.get("success"):
            msg = f"{spec.context} failed: {response}" if spec.context else f"API call failed: {response}"
            self.log.error(msg)
            self.nd.module.fail_json(msg=msg)

        return response


class BootstrapCache:
    """Cache bootstrap API queries to avoid redundant HTTP calls within a single run."""

    def __init__(self, nd: "NDModule", fabric: str, log: logging.Logger):
        self._nd = nd
        self._fabric = fabric
        self._log = log
        self._switches: list[dict[str, Any]] | None = None
        self._index: dict[str, dict[str, Any]] | None = None

    def get_index(self, *, refresh: bool = False) -> dict[str, dict[str, Any]]:
        """Return the bootstrap serial → data index, querying the API only on first call or refresh.

        ## Parameters

        - `refresh`: Force re-query of the bootstrap API.

        ## Returns

        - Dict mapping serial number to bootstrap data.
        """
        if self._switches is None or refresh:
            self._log.debug("BootstrapCache: querying bootstrap API (refresh=%s)", refresh)
            self._switches = query_bootstrap_switches(self._nd, self._fabric, self._log)
            self._index = build_bootstrap_index(self._switches)
        return self._index

    def invalidate(self) -> None:
        """Clear the cache so the next access re-queries the API."""
        self._switches = None
        self._index = None


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
        to_delete_existing: Existing ``SwitchDataModel`` records for switches that
                        must be deleted before re-add (POAP/preprovision mismatches
                        and overridden normal updates).  Kept parallel to the
                        config-level lists above.
    """

    # Normal-switch diff buckets (config side)
    to_add: list["SwitchConfigModel"]
    to_update: list["SwitchConfigModel"]
    to_delete: list["SwitchDataModel"]
    migration_mode: list["SwitchConfigModel"]
    idempotent: list["SwitchConfigModel"]

    # POAP/preprovision/swap/RMA buckets
    to_bootstrap: list["SwitchConfigModel"]
    normal_readd: list["SwitchConfigModel"]
    to_preprovision: list["SwitchConfigModel"]
    to_swap: list["SwitchConfigModel"]
    to_rma: list["SwitchConfigModel"]

    # Cross-cutting helpers
    to_delete_existing: list["SwitchDataModel"]


class SwitchDiffEngine:
    """Provide stateless validation and diff computation helpers."""

    @staticmethod
    def validate_configs(
        config: dict[str, Any] | list[dict[str, Any]],
        state: str,
        nd: NDModule,
        log: logging.Logger,
    ) -> list[SwitchConfigModel]:
        """
        # Summary

        Validate raw module config and return typed switch configs.

        ## Parameters

        - `config`: Raw config dict or list of dicts from module parameters.
        - `state`: Requested module state.
        - `nd`: ND module wrapper used for failure handling.
        - `log`: Logger instance.

        ## Returns

        - List of validated ``SwitchConfigModel`` objects.

        ## Raises

        - `ValueError`: Raised when model validation fails outside an Ansible
            module context or duplicate seed IP entries are provided.
        """
        log.debug("ENTER: validate_configs()")

        configs_list = config if isinstance(config, list) else [config]
        log.debug("Normalized to %s configuration(s)", len(configs_list))

        validated_configs: list[SwitchConfigModel] = []
        for idx, cfg in enumerate(configs_list):
            try:
                cfg_for_validation = dict(cfg)
                # AnsibleModule injects omitted suboptions as None; keep omitted role distinct for the model contract.
                if cfg_for_validation.get("role") is None:
                    cfg_for_validation.pop("role", None)
                validated = SwitchConfigModel.model_validate(cfg_for_validation, context={"state": state})
                validated_configs.append(validated)
            except ValidationError as e:
                error_detail = e.errors() if hasattr(e, "errors") else str(e)
                error_msg = f"Configuration validation failed for " f"config index {idx}: {error_detail}"
                log.error(error_msg)
                if hasattr(nd, "module"):
                    nd.module.fail_json(msg=error_msg)
                else:
                    raise ValueError(error_msg) from e
            except (TypeError, ValueError) as e:
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
        proposed_configs: list[SwitchConfigModel],
        existing: list[SwitchDataModel],
        log: logging.Logger,
    ) -> "SwitchPlan":
        """Classify all proposed configs against the current fabric inventory.

        Accepts the full mix of normal, POAP/preprovision, swap, and RMA configs
        and produces a unified :class:`SwitchPlan` that each state handler can
        act on directly.  This is the single idempotency gate for all operation
        types.

        Idempotency rules by operation type:

        * **normal** — compare ``role`` against the existing inventory entry
          found by ``seed_ip``.  Role is the only user-specifiable field for
          normal switches; hostname, model, and software version are not
          user-supplied and are not compared.  No discovery is performed for
          switches already in the fabric.
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

        ## Parameters

        - `proposed_configs`: All validated switch configs for this run.
        - `existing`: Current fabric inventory snapshot.
        - `log`: Logger instance.

        ## Returns

        - :class:`SwitchPlan` with all buckets populated.
        """
        log.debug("ENTER: compute_changes()")
        log.info(
            "compute_changes: %s proposed config(s) vs %s existing switch(es)",
            len(proposed_configs),
            len(existing),
        )

        _idx = FabricSwitchInventory(existing)
        existing_by_ip: dict[str, SwitchDataModel] = _idx.by_ip()

        # Output buckets
        to_add: list[SwitchConfigModel] = []
        to_update: list[SwitchConfigModel] = []
        to_delete_existing: list[SwitchDataModel] = []
        migration_mode: list[SwitchConfigModel] = []
        idempotent: list[SwitchConfigModel] = []
        to_bootstrap: list[SwitchConfigModel] = []
        normal_readd: list[SwitchConfigModel] = []
        to_preprovision: list[SwitchConfigModel] = []
        to_swap: list[SwitchConfigModel] = []
        to_rma: list[SwitchConfigModel] = []
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
                        cfg.seed_ip,
                        serial,
                        cfg.role,
                    )
                    idempotent.append(cfg)
                    continue

                status = existing_sw.additional_data.discovery_status if existing_sw.additional_data else None
                log.info(
                    "Bootstrap %s differs (serial_match=%s, role_match=%s, status=%s) — deleting existing",
                    cfg.seed_ip,
                    serial_match,
                    role_match,
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
                pp = cfg.preprovision
                serial = pp.serial_number if pp else None

                if not existing_sw:
                    log.info("Preprovision %s: not in fabric — queue for preprovision", cfg.seed_ip)
                    to_preprovision.append(cfg)
                    continue

                serial_match = bool(serial and serial in (existing_sw.serial_number, existing_sw.switch_id))
                role_match = cfg.role is None or cfg.role == existing_sw.switch_role
                model_match = pp is None or pp.model is None or pp.model == existing_sw.model
                version_match = pp is None or pp.version is None or pp.version == existing_sw.software_version
                hostname_match = pp is None or pp.hostname is None or pp.hostname == existing_sw.hostname

                if serial_match and role_match and model_match and version_match and hostname_match:
                    log.info(
                        "Preprovision %s serial=%s role=%s model=%s version=%s hostname=%s — idempotent, skipping",
                        cfg.seed_ip,
                        serial,
                        cfg.role,
                        pp.model if pp else None,
                        pp.version if pp else None,
                        pp.hostname if pp else None,
                    )
                    idempotent.append(cfg)
                    continue

                diffs = []
                if not serial_match:
                    diffs.append(f"serial(config={serial}, fabric={existing_sw.serial_number})")
                if not role_match:
                    diffs.append(f"role(config={cfg.role}, fabric={existing_sw.switch_role})")
                if not model_match:
                    diffs.append(f"model(config={pp.model if pp else None}, fabric={existing_sw.model})")
                if not version_match:
                    diffs.append(f"version(config={pp.version if pp else None}, fabric={existing_sw.software_version})")
                if not hostname_match:
                    diffs.append(f"hostname(config={pp.hostname if pp else None}, fabric={existing_sw.hostname})")

                status = existing_sw.additional_data.discovery_status if existing_sw.additional_data else None
                log.info(
                    "Preprovision %s differs [%s] (status=%s) — deleting existing",
                    cfg.seed_ip,
                    ", ".join(diffs),
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
            if op == "normal":
                if not existing_sw:
                    log.info("Normal %s: not in fabric — queue for discovery + add", cfg.seed_ip)
                    to_add.append(cfg)
                    continue

                if existing_sw.additional_data and existing_sw.additional_data.system_mode == SystemMode.MIGRATION:
                    log.info("Normal %s (%s): in migration mode", cfg.seed_ip, existing_sw.switch_id)
                    migration_mode.append(cfg)
                    continue

                # Role is the only user-specifiable field for a normal switch.
                # hostname, model, and software_version are device-reported and
                # not part of desired config — no discovery needed.
                role_match = cfg.role is None or cfg.role == existing_sw.switch_role
                if role_match:
                    log.info("Normal %s: in fabric, role matches — idempotent", cfg.seed_ip)
                    idempotent.append(cfg)
                else:
                    log.info(
                        "Normal %s: role mismatch (config=%s, existing=%s) — marking to_update",
                        cfg.seed_ip,
                        cfg.role,
                        existing_sw.switch_role,
                    )
                    to_update.append(cfg)
                continue

        # Switches in fabric that no config entry accounts for
        # (only meaningful for overridden / deleted states)
        to_delete: list[SwitchDataModel] = []
        for sw in existing:
            if sw.switch_id and sw.switch_id not in accounted_ids and sw.fabric_management_ip not in poap_ips:
                log.info(
                    "Existing %s (%s) has no config entry — marking to_delete",
                    sw.fabric_management_ip,
                    sw.switch_id,
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
            to_delete_existing=to_delete_existing,
        )
        log.info(
            "compute_changes: to_add=%s, to_update=%s, to_delete=%s, migration=%s, "
            "idempotent=%s, bootstrap=%s, normal_readd=%s, preprov=%s, swap=%s, rma=%s",
            len(plan.to_add),
            len(plan.to_update),
            len(plan.to_delete),
            len(plan.migration_mode),
            len(plan.idempotent),
            len(plan.to_bootstrap),
            len(plan.normal_readd),
            len(plan.to_preprovision),
            len(plan.to_swap),
            len(plan.to_rma),
        )
        log.debug("EXIT: compute_changes()")
        return plan

    @staticmethod
    def validate_switch_api_fields(
        spec: SwitchApiFieldValidationSpec,
    ) -> None:
        """Validate user-supplied switch fields against the bootstrap API response.

        Only fields that are provided (non-None) are validated against the API.
        Fields that are omitted are silently filled in from the API at build
        time — no error is raised for those. Any omitted fields are logged at
        INFO level so the operator can see what was sourced from the API.

        ## Parameters

        - `nd`: ND module wrapper used for failure handling.
        - `serial`: Serial number of the switch being processed.
        - `model`: User-provided switch model, or None if omitted.
        - `version`: User-provided software version, or None if omitted.
        - `config_data`: User-provided ``ConfigDataModel``, or None if omitted.
        - `bootstrap_data`: Matching entry from the bootstrap GET API.
        - `log`: Logger instance.
        - `context`: Label used in error messages (e.g. ``"Bootstrap"`` or ``"RMA"``).
        - `hostname`: User-provided hostname, or None if omitted (bootstrap only).

        ## Returns

        - None.
        """
        bs_data = spec.bootstrap_data.get("data") or {}
        mismatches: list[str] = []

        if spec.model is not None and spec.model != spec.bootstrap_data.get("model"):
            mismatches.append(f"model: provided '{spec.model}', " f"bootstrap reports '{spec.bootstrap_data.get('model')}'")

        if spec.version is not None and spec.version != spec.bootstrap_data.get("softwareVersion"):
            mismatches.append(f"version: provided '{spec.version}', " f"bootstrap reports '{spec.bootstrap_data.get('softwareVersion')}'")

        if spec.config_data is not None:
            bs_gateway = spec.bootstrap_data.get("gatewayIpMask") or bs_data.get("gatewayIpMask")
            if spec.config_data.gateway is not None and spec.config_data.gateway != bs_gateway:
                mismatches.append(f"config_data.gateway: provided '{spec.config_data.gateway}', " f"bootstrap reports '{bs_gateway}'")

            bs_models = bs_data.get("models", [])
            if spec.config_data.models and sorted(spec.config_data.models) != sorted(bs_models):
                mismatches.append(f"config_data.models: provided {spec.config_data.models}, " f"bootstrap reports {bs_models}")

        if mismatches:
            spec.nd.module.fail_json(
                msg=(
                    f"{spec.context} field mismatch for serial '{spec.serial}'. "
                    f"The following provided values do not match the "
                    f"bootstrap API data:\n" + "\n".join(f"  - {m}" for m in mismatches)
                )
            )

        # Log any fields that were omitted and will be sourced from the API
        pulled: list[str] = []
        if spec.model is None:
            pulled.append("model")
        if spec.version is None:
            pulled.append("version")
        if spec.hostname is None:
            pulled.append("hostname")
        if spec.config_data is None:
            pulled.append("config_data (gateway + models)")
        if pulled:
            spec.log.info(
                "%s serial '%s': the following fields were not provided and will be sourced from the bootstrap API: %s",
                spec.context,
                spec.serial,
                ", ".join(pulled),
            )
        else:
            spec.log.debug("%s field validation passed for serial '%s'", spec.context, spec.serial)


# =========================================================================
# Switch Discovery Service
# =========================================================================


class SwitchDiscoveryService:
    """Handle switch discovery and proposed-model construction."""

    def __init__(self, ctx: SwitchServiceContext):
        """Initialize the discovery service.

        ## Parameters

        - `ctx`: Shared service context.

        ## Returns

        - None.
        """
        self.ctx = ctx

    def discover(
        self,
        switch_configs: list[SwitchConfigModel],
    ) -> dict[str, dict[str, Any]]:
        """Discover switches for the provided config list.

        ## Parameters

        - `switch_configs`: Validated switch configuration entries.

        ## Returns

        - Dict mapping seed IP to raw discovery data.
        """
        log = self.ctx.log
        log.debug("Step 1: Grouping switches by credentials")
        credential_groups = group_switches_by_credentials(switch_configs, log)
        log.debug("Created %s credential group(s)", len(credential_groups))

        log.debug("Step 2: Bulk discovering switches")
        all_discovered: dict[str, dict[str, Any]] = {}
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
                    DiscoveryBatchSpec(
                        switches=switches,
                        username=username,
                        password=password,
                        auth_proto=auth_proto,
                        platform_type=platform_type,
                    )
                )
                all_discovered.update(discovered_batch)
            except _REQUEST_ERRORS as e:
                seed_ips = [sw.seed_ip for sw in switches]
                msg = f"Discovery failed for credential group " f"(username={username}, IPs={seed_ips}): {e}"
                log.error(msg)
                self.ctx.nd.module.fail_json(msg=msg)

        log.debug("Total discovered: %s switches", len(all_discovered))
        return all_discovered

    def bulk_discover(
        self,
        spec: DiscoveryBatchSpec,
    ) -> dict[str, dict[str, Any]]:
        """Run one bulk discovery call for switches with shared credentials.

        ## Parameters

        - `switches`: Switches to discover.
        - `username`: Discovery username.
        - `password`: Discovery password.
        - `auth_proto`: SNMP v3 authentication protocol.
        - `platform_type`: Platform type for discovery.

        ## Returns

        - Dict mapping seed IP to discovered switch data.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: bulk_discover()")
        log.debug("Discovering %s switches in bulk", len(spec.switches))

        endpoint = EpManageFabricsActionsShallowDiscoveryPost()
        endpoint.fabric_name = self.ctx.fabric

        seed_ips = [switch.seed_ip for switch in spec.switches]
        log.debug("Seed IPs: %s", seed_ips)

        max_hops = _DISCOVERY_MAX_HOPS

        discovery_request = ShallowDiscoveryRequestModel(
            seedIpCollection=seed_ips,
            maxHop=max_hops,
            platformType=spec.platform_type,
            snmpV3AuthProtocol=spec.auth_proto,
            username=spec.username,
            password=spec.password,
        )

        payload = discovery_request.to_payload()
        log.info("Bulk discovering %s switches: %s", len(seed_ips), ", ".join(seed_ips))
        log.debug("Discovery endpoint: %s", endpoint.path)
        log.debug("Discovery payload (password masked): %s", mask_password(payload))

        try:
            _request_with_retry_policy(
                nd,
                path=endpoint.path,
                verb=endpoint.verb,
                data=payload,
            )

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
            response_data: dict[str, Any] = {}
            if response and isinstance(response, dict):
                if "DATA" in response and isinstance(response["DATA"], dict):
                    response_data = response["DATA"]
                    switches_data = response_data.get("switches", [])
                elif "body" in response and isinstance(response["body"], dict):
                    response_data = response["body"]
                    switches_data = response_data.get("switches", [])
                elif "switches" in response:
                    switches_data = response.get("switches", [])

            log.debug("Extracted %s switches from discovery response", len(switches_data))

            ApiDataChecker.check(response_data, f"Switch discovery for {seed_ips}", log, nd.module.fail_json)

            # Fail early for any unreachable switches — before data touches models.
            # The API returns status="notReachable" with an empty serialNumber and
            # a top-level "warning" string explaining reachability requirements.
            unreachable = [sw for sw in switches_data if isinstance(sw, dict) and sw.get("status", "").lower() == "notreachable"]
            if unreachable:
                api_warning = response_data.get("warning", "").strip()
                msg = f"Switch discovery failed: {api_warning}"
                log.error(msg)
                nd.module.fail_json(msg=msg)

            discovered_results: dict[str, dict[str, Any]] = {}
            for discovered in switches_data:
                if not isinstance(discovered, dict):
                    continue

                ip = discovered.get("ip")
                status = discovered.get("status", "").lower()
                serial_number = discovered.get("serialNumber")

                # Fail early for switches the controller cannot manage.
                # The API returns empty serialNumber for these — check status
                # first to provide a meaningful error message.
                if status == "notmanageable":
                    reason = discovered.get("statusReason", "Unknown reason")
                    msg = f"Switch {ip} is not manageable: {reason}. " f"Verify connectivity and credentials before retrying."
                    log.error(msg)
                    nd.module.fail_json(msg=msg)

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

        except _REQUEST_ERRORS as e:
            msg = f"Bulk discovery failed for switches " f"{', '.join(seed_ips)}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

    def build_proposed(
        self,
        proposed_config: list[SwitchConfigModel],
        discovered_data: dict[str, dict[str, Any]],
        existing: list[SwitchDataModel],
    ) -> list[SwitchDataModel]:
        """Build proposed switch models from discovery and inventory data.

        ## Parameters

        - `proposed_config`: Validated switch config entries.
        - `discovered_data`: Mapping of seed IP to raw discovery data.
        - `existing`: Current fabric inventory snapshot.

        ## Returns

        - List of ``SwitchDataModel`` instances for proposed state.
        """
        log = self.ctx.log
        proposed: list[SwitchDataModel] = []
        existing_by_ip = FabricSwitchInventory(existing).by_ip()

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
            existing_match = existing_by_ip.get(seed_ip)
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

    def __init__(self, ctx: SwitchServiceContext, fabric_utils: SwitchFabricUtils):
        """Initialize the fabric operation service.

        ## Parameters

        - `ctx`: Shared service context.
        - `fabric_utils`: Utility wrapper for fabric-level operations.

        ## Returns

        - None.
        """
        self.ctx = ctx
        self.fabric_utils = fabric_utils

    def bulk_add(
        self,
        spec: BulkAddSpec,
    ) -> dict[str, Any]:
        """
        # Summary

        Add multiple discovered switches to the fabric.

        ## Parameters

        - `switches`: List of ``(SwitchConfigModel, discovered_data)`` tuples.
        - `username`: Discovery username.
        - `password`: Discovery password.
        - `auth_proto`: SNMP v3 authentication protocol.
        - `platform_type`: Platform type.
        - `preserve_config`: Whether to preserve existing switch config.

        ## Returns

        - API response payload.

        ## Raises

        - `SwitchOperationError`: Raised when no valid discovered switch payloads
            are available for the add request.
        """
        nd = self.ctx.nd
        log = self.ctx.log

        log.debug("ENTER: bulk_add()")
        log.debug("Adding %s switches to fabric", len(spec.switches))

        endpoint = EpManageFabricsSwitchesPost()
        endpoint.fabric_name = self.ctx.fabric

        switch_discoveries = []
        for switch_config, discovered in spec.switches:
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
            platformType=spec.platform_type,
            preserveConfig=spec.preserve_config,
            snmpV3AuthProtocol=spec.auth_proto,
            username=spec.username,
            password=spec.password,
        )

        payload = add_request.to_payload()
        serial_numbers = [d.get("serialNumber") for _cfg, d in spec.switches]
        log.info(
            "Bulk adding %s switches to fabric %s: %s",
            len(spec.switches),
            self.ctx.fabric,
            ", ".join(serial_numbers),
        )
        log.debug("Add endpoint: %s", endpoint.path)
        log.debug("Add payload (password masked): %s", mask_password(payload))

        response = self.ctx.api_call(
            ApiCallSpec(
                endpoint=endpoint,
                payload=payload,
                action="create",
                op_type=OperationType.CREATE,
                context=f"Bulk add switches to fabric '{self.ctx.fabric}' ({', '.join(serial_numbers)})",
            )
        )

        return response

    def bulk_delete(
        self,
        switches: list[SwitchDataModel | SwitchDiscoveryModel],
    ) -> list[str]:
        """
        # Summary

        Remove multiple switches from the fabric.

        ## Parameters

        - `switches`: Switch models to delete.

        ## Returns

        - List of switch identifiers submitted for deletion.

        ## Raises

        - `SwitchOperationError`: Raised when the delete API call fails.
        """
        nd = self.ctx.nd
        log = self.ctx.log

        log.debug("ENTER: bulk_delete()")

        if nd.module.check_mode:
            log.debug("Check mode: Skipping actual deletion")
            return []

        serial_numbers: list[str] = []
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
            self.ctx.api_call(
                ApiCallSpec(
                    endpoint=endpoint,
                    payload=payload,
                    action="delete",
                    op_type=OperationType.DELETE,
                    diff={"deleted": serial_numbers},
                    context=f"Bulk delete switches from fabric '{self.ctx.fabric}' ({serial_numbers})",
                )
            )

            log.info("Bulk delete submitted for %s switch(es)", len(serial_numbers))
            log.debug("EXIT: bulk_delete()")
            return serial_numbers

        except Exception as e:
            log.error("Bulk delete failed: %s", e)
            raise SwitchOperationError(f"Bulk delete failed for {serial_numbers}: {e}") from e

    def bulk_save_credentials(
        self,
        switch_actions: list[tuple[str, SwitchConfigModel]],
    ) -> None:
        """Save switch credentials grouped by username and password.

        ## Parameters

        - `switch_actions`: ``(switch_id, SwitchConfigModel)`` pairs.

        ## Returns

        - None.
        """
        log = self.ctx.log

        log.debug("ENTER: bulk_save_credentials()")

        cred_groups: dict[tuple[str, str], list[str]] = {}
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

            self.ctx.api_call(
                ApiCallSpec(
                    endpoint=endpoint,
                    payload=payload,
                    action="save_credentials",
                    op_type=OperationType.UPDATE,
                    diff={"switchIds": serial_numbers, "username": username},
                    context=f"Save credentials for switches {serial_numbers}",
                )
            )
            log.info("Credentials saved for %s switch(es)", len(serial_numbers))

        log.debug("EXIT: bulk_save_credentials()")

    def bulk_update_roles(
        self,
        switch_actions: list[tuple[str, SwitchConfigModel]],
    ) -> None:
        """Update switch roles in bulk.

        ## Parameters

        - `switch_actions`: ``(switch_id, SwitchConfigModel)`` pairs.

        ## Returns

        - None.
        """
        log = self.ctx.log

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

        self.ctx.api_call(
            ApiCallSpec(
                endpoint=endpoint,
                payload=payload,
                action="update_role",
                op_type=OperationType.UPDATE,
                context=f"Update switch roles in fabric '{self.ctx.fabric}'",
            )
        )
        log.info("Roles updated for %s switch(es)", len(switch_roles))

        log.debug("EXIT: bulk_update_roles()")

    def _register_fabric_operation(
        self,
        *,
        endpoint: Any,
        payload: dict[str, Any] | None,
        response: dict[str, Any],
        action: str,
    ) -> None:
        """Record a fabric helper API call in the shared module results."""
        registered_response = self.ctx.nd.rest_send.response_current or response
        self.ctx.results.action = action
        self.ctx.results.operation_type = OperationType.UPDATE
        self.ctx.results.response_current = registered_response
        self.ctx.results.result_current = self.ctx.nd.rest_send.result_current
        self.ctx.results.diff_current = payload or {}
        self.ctx.results.path_current = endpoint.path
        self.ctx.results.verb_current = endpoint.verb
        self.ctx.results.payload_current = payload
        self.ctx.results.register_api_call()

    def finalize(self, serial_numbers: list[str] | None = None) -> None:
        """Run optional save and deploy actions for the fabric.

        Uses service context flags to decide whether save and deploy should be
        executed. No-op in check mode.

        ## Parameters

        - `serial_numbers`: Switch serial numbers to deploy when
                            ``deploy_type`` is ``switch``. Falls back to
                            global deploy if empty or ``None``.

        ## Returns

        - None.
        """
        if self.ctx.nd.module.check_mode:
            return

        if self.ctx.save_config:
            self.ctx.log.info("Saving fabric configuration")
            response = self.fabric_utils.save_config()
            self._register_fabric_operation(
                endpoint=self.fabric_utils.ep_config_save,
                payload=None,
                response=response,
                action="config_save",
            )

        if self.ctx.deploy_config:
            if self.ctx.deploy_type == "switch" and serial_numbers:
                self.ctx.log.info("Switch-level deploy for: %s", serial_numbers)
                payload = {"switchIds": serial_numbers}
                response = self.fabric_utils.deploy_switches(serial_numbers)
                self._register_fabric_operation(
                    endpoint=self.fabric_utils.ep_switch_deploy,
                    payload=payload,
                    response=response,
                    action="deploy_switches",
                )
            else:
                if self.ctx.deploy_type == "switch" and not serial_numbers:
                    self.ctx.log.warning("Switch-level deploy requested but no serial numbers provided — falling back to global deploy")
                self.ctx.log.info("Deploying fabric configuration (global)")
                response = self.fabric_utils.deploy_config()
                self._register_fabric_operation(
                    endpoint=self.fabric_utils.ep_config_deploy,
                    payload=None,
                    response=response,
                    action="deploy_config",
                )

    def post_add_processing(
        self,
        spec: PostAddProcessingSpec,
    ) -> None:
        """Run post-add tasks for newly processed switches.

        ## Parameters

        - `switch_actions`: ``(switch_id, SwitchConfigModel)`` pairs.
        - `wait_utils`: Wait utility used for manageability checks.
        - `context`: Label used in logs and error messages.
        - `skip_greenfield_check`: Whether to skip greenfield wait shortcut.
        - `update_roles`: Whether to apply bulk role updates.

        ## Returns

        - None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        all_serials = [sn for sn, _cfg in spec.switch_actions]
        wait_sets = self._split_post_add_wait_sets(spec.switch_actions)

        log.info(
            "Waiting for %s %s switch(es) to become manageable: %s (nxos_reload=%s, nxos_preserve=%s, ready_without_reload=%s)",
            len(all_serials),
            spec.context,
            all_serials,
            len(wait_sets.nxos_reload),
            len(wait_sets.nxos_preserve),
            len(wait_sets.ready_without_reload),
        )

        success = spec.wait_utils.wait_for_post_add_switches(
            nxos_reload=[sn for sn, _cfg in wait_sets.nxos_reload],
            nxos_preserve=[sn for sn, _cfg in wait_sets.nxos_preserve],
            ready_without_reload=[sn for sn, _cfg in wait_sets.ready_without_reload],
            skip_greenfield_check=spec.skip_greenfield_check,
        )
        if not success:
            msg = self._post_add_wait_failure_message(spec.context, spec.switch_actions)
            log.error(msg)
            nd.module.fail_json(msg=msg)

        self.bulk_save_credentials(spec.switch_actions)

        if spec.update_roles:
            self.bulk_update_roles(spec.switch_actions)

        try:
            self.finalize(serial_numbers=all_serials)
        except _FABRIC_OPERATION_ERRORS as e:
            msg = f"Failed to finalize (config-save/deploy) for " f"{spec.context} switches {all_serials}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

    @staticmethod
    def _split_post_add_wait_sets(
        switch_actions: list[tuple[str, "SwitchConfigModel"]],
    ) -> SwitchWaitSets:
        """Split post-add wait sets by platform reload behavior."""
        nxos_reload: list[tuple[str, SwitchConfigModel]] = []
        nxos_preserve: list[tuple[str, SwitchConfigModel]] = []
        ready_without_reload: list[tuple[str, SwitchConfigModel]] = []

        for serial_number, cfg in switch_actions:
            if cfg.platform_type == PlatformType.NX_OS:
                if cfg.preserve_config:
                    nxos_preserve.append((serial_number, cfg))
                else:
                    nxos_reload.append((serial_number, cfg))
            else:
                ready_without_reload.append((serial_number, cfg))

        return SwitchWaitSets(
            nxos_reload=nxos_reload,
            nxos_preserve=nxos_preserve,
            ready_without_reload=ready_without_reload,
        )

    def _post_add_wait_failure_message(
        self,
        context: str,
        switch_actions: list[tuple[str, "SwitchConfigModel"]],
    ) -> str:
        """Build a standard post-add wait failure message."""
        serials = [sn for sn, _cfg in switch_actions]
        return f"One or more {context} switches failed to become manageable in fabric '{self.ctx.fabric}'. Switches: {serials}"


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
        bootstrap_cache: "BootstrapCache",
    ):
        """Initialize the POAP workflow handler.

        ## Parameters

        - `ctx`: Shared service context.
        - `fabric_ops`: Fabric operation service.
        - `wait_utils`: Switch wait utility service.
        - `bootstrap_cache`: Shared bootstrap API cache.

        ## Returns

        - None.
        """
        self.ctx = ctx
        self.fabric_ops = fabric_ops
        self.wait_utils = wait_utils
        self.bootstrap_cache = bootstrap_cache

    def handle(
        self,
        proposed_config: list[SwitchConfigModel],
        existing: list[SwitchDataModel] | None = None,
    ) -> None:
        """Execute POAP processing for the provided switch configs.

        ## Parameters

        - `proposed_config`: Validated switch configs for POAP operations.
        - `existing`: Current fabric inventory snapshot.

        ## Returns

        - None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        results = self.ctx.results

        log.debug("ENTER: POAPHandler.handle()")
        log.info("Processing POAP for %s switch config(s)", len(proposed_config))

        # Classify entries first so check mode can report per-operation counts
        bootstrap_entries: list[tuple[SwitchConfigModel, POAPConfigModel]] = []
        preprov_entries: list[tuple[SwitchConfigModel, PreprovisionConfigModel]] = []
        swap_entries: list[tuple[SwitchConfigModel, POAPConfigModel, PreprovisionConfigModel]] = []

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

        # Idempotency is handled entirely by compute_changes before entries
        # reach this handler.  Everything in bootstrap_entries / preprov_entries
        # has already been classified as needing action — no re-checking here.

        # Handle swap entries (change serial number on pre-provisioned switches)
        if swap_entries:
            self._handle_poap_swap(swap_entries, existing or [])

        # Handle bootstrap entries
        if bootstrap_entries:
            self._handle_poap_bootstrap(bootstrap_entries)

        # Handle pre-provision entries
        if preprov_entries:
            preprov_models: list[PreProvisionSwitchModel] = []
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
        bootstrap_entries: list[tuple[SwitchConfigModel, POAPConfigModel]],
    ) -> None:
        """Process bootstrap POAP entries.

        ## Parameters

        - `bootstrap_entries`: ``(SwitchConfigModel, POAPConfigModel)`` pairs
                for bootstrap operations.

        ## Returns

        - None.
        """
        nd = self.ctx.nd
        log = self.ctx.log

        log.debug("ENTER: _handle_poap_bootstrap()")
        log.info("Processing %s bootstrap entries", len(bootstrap_entries))

        bootstrap_idx = self.bootstrap_cache.get_index()
        log.debug(
            "Bootstrap index contains %s switch(es): %s",
            len(bootstrap_idx),
            list(bootstrap_idx.keys()),
        )

        import_models: list[BootstrapImportSwitchModel] = []
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

            try:
                model = self._build_bootstrap_import_model(switch_cfg, poap_cfg, bootstrap_data)
            except ValidationError as exc:
                msg = f"Bootstrap import model validation failed for serial {serial}: {exc}"
                log.error(msg)
                nd.module.fail_json(msg=msg)
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
        switch_actions: list[tuple[str, SwitchConfigModel]] = []
        for switch_cfg, poap_cfg in bootstrap_entries:
            switch_actions.append((poap_cfg.serial_number, switch_cfg))

        self.fabric_ops.post_add_processing(
            PostAddProcessingSpec(
                switch_actions=switch_actions,
                wait_utils=self.wait_utils,
                context="bootstrap",
                skip_greenfield_check=True,
            )
        )

        log.debug("EXIT: _handle_poap_bootstrap()")

    def _build_bootstrap_import_model(
        self,
        switch_cfg: SwitchConfigModel,
        poap_cfg: POAPConfigModel,
        bootstrap_data: dict[str, Any] | None,
    ) -> BootstrapImportSwitchModel:
        """Build a bootstrap import model from config and bootstrap data.

        ## Parameters

        - `switch_cfg`: Parent switch config.
        - `poap_cfg`: POAP config entry.
        - `bootstrap_data`: Matching bootstrap response entry.

        ## Returns

        - Completed ``BootstrapImportSwitchModel`` for API submission.
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
            except ValueError:
                pass

        # Build the data block from resolved values (replaces build_poap_data_block)
        data_block: dict[str, Any] | None = None
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
        models: list[BootstrapImportSwitchModel],
    ) -> None:
        """Submit bootstrap import models.

        ## Parameters

        - `models`: ``BootstrapImportSwitchModel`` objects to submit.

        ## Returns

        - None.
        """
        log = self.ctx.log

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

        self.ctx.api_call(
            ApiCallSpec(
                endpoint=endpoint,
                payload=payload,
                action="bootstrap",
                op_type=OperationType.CREATE,
                context=f"importBootstrap for {[m.serial_number for m in models]}",
            )
        )

        log.info("importBootstrap API response success")
        log.debug("EXIT: _import_bootstrap_switches()")

    def _build_preprovision_model(
        self,
        switch_cfg: SwitchConfigModel,
        preprov_cfg: "PreprovisionConfigModel",
    ) -> PreProvisionSwitchModel:
        """Build a pre-provision model from PreprovisionConfigModel configuration.

        ## Parameters

        - `switch_cfg`: Parent switch config.
        - `preprov_cfg`: Pre-provision config entry.

        ## Returns

        - Completed ``PreProvisionSwitchModel`` for API submission.
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
        models: list[PreProvisionSwitchModel],
    ) -> None:
        """Submit pre-provision switch models.

        ## Parameters

        - `models`: ``PreProvisionSwitchModel`` objects to submit.

        ## Returns

        - None.
        """
        log = self.ctx.log

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

        self.ctx.api_call(
            ApiCallSpec(
                endpoint=endpoint,
                payload=payload,
                action="preprovision",
                op_type=OperationType.CREATE,
                context=f"preProvision for {[m.serial_number for m in models]}",
            )
        )

        log.info("preProvision API response success")
        log.debug("EXIT: _preprovision_switches()")

    def _handle_poap_swap(
        self,
        swap_entries: list[tuple[SwitchConfigModel, POAPConfigModel, "PreprovisionConfigModel"]],
        existing: list[SwitchDataModel],
    ) -> None:
        """Process POAP serial-swap entries.

        ## Parameters

        - `swap_entries`: ``(SwitchConfigModel, POAPConfigModel, PreprovisionConfigModel)``
                swap triples where poap carries the new serial and preprovision
                carries the old (pre-provisioned) serial.
        - `existing`: Current fabric inventory snapshot.

        ## Returns

        - None.
        """
        nd = self.ctx.nd
        log = self.ctx.log
        fabric = self.ctx.fabric

        log.debug("ENTER: _handle_poap_swap()")
        log.info("Processing %s POAP swap entries", len(swap_entries))

        # ------------------------------------------------------------------
        # Step 1: Validate preprovision serials exist in fabric inventory
        #         and new serials exist in bootstrap list (combined pass)
        # ------------------------------------------------------------------
        fabric_index: dict[str, dict[str, Any]] = {sw.switch_id: sw.model_dump(by_alias=True) for sw in existing if sw.switch_id}
        log.debug(
            "Fabric inventory contains %s switch(es): %s",
            len(fabric_index),
            list(fabric_index.keys()),
        )

        bootstrap_index = self.bootstrap_cache.get_index()
        log.debug(
            "Bootstrap list contains %s switch(es): %s",
            len(bootstrap_index),
            list(bootstrap_index.keys()),
        )

        for switch_cfg, poap_cfg, preprov_cfg in swap_entries:
            old_serial = preprov_cfg.serial_number
            new_serial = poap_cfg.serial_number
            if old_serial not in fabric_index:
                msg = (
                    f"Pre-provisioned serial '{old_serial}' not found in "
                    f"fabric '{fabric}' inventory. The switch must be "
                    f"pre-provisioned before a swap can be performed."
                )
                log.error(msg)
                nd.module.fail_json(msg=msg)
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
                "Validated: pre-provisioned serial '%s' exists in fabric, new serial '%s' exists in bootstrap",
                old_serial,
                new_serial,
            )

        # ------------------------------------------------------------------
        # Step 2: Call changeSwitchSerialNumber for each swap entry
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

            self.ctx.api_call(
                ApiCallSpec(
                    endpoint=endpoint,
                    payload=payload,
                    action="swap_serial",
                    op_type=OperationType.UPDATE,
                    diff={"old_serial": old_serial, "new_serial": new_serial},
                    context=f"changeSwitchSerialNumber {old_serial} → {new_serial}",
                )
            )

            log.info("Serial number swap successful: %s → %s", old_serial, new_serial)
        # ------------------------------------------------------------------
        # Step 3: Re-query bootstrap API for post-swap data
        # ------------------------------------------------------------------
        post_swap_index = self.bootstrap_cache.get_index(refresh=True)
        log.debug("Post-swap bootstrap list contains %s switch(es)", len(post_swap_index))

        # ------------------------------------------------------------------
        # Step 4: Build BootstrapImportSwitchModels and POST importBootstrap
        # ------------------------------------------------------------------
        import_models: list[BootstrapImportSwitchModel] = []
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
        except _REQUEST_ERRORS as e:
            msg = f"importBootstrap failed after serial swap: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        # ------------------------------------------------------------------
        # Step 5: Wait for manageability, save credentials, finalize
        # ------------------------------------------------------------------
        switch_actions: list[tuple[str, SwitchConfigModel]] = []
        for switch_cfg, poap_cfg, preprov_cfg in swap_entries:
            switch_actions.append((poap_cfg.serial_number, switch_cfg))

        self.fabric_ops.post_add_processing(
            PostAddProcessingSpec(
                switch_actions=switch_actions,
                wait_utils=self.wait_utils,
                context="swap",
                skip_greenfield_check=True,
            )
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
        bootstrap_cache: "BootstrapCache",
    ):
        """Initialize the RMA workflow handler.

        ## Parameters

        - `ctx`: Shared service context.
        - `fabric_ops`: Fabric operation service.
        - `wait_utils`: Switch wait utility service.
        - `bootstrap_cache`: Shared bootstrap API cache.

        ## Returns

        - None.
        """
        self.ctx = ctx
        self.fabric_ops = fabric_ops
        self.wait_utils = wait_utils
        self.bootstrap_cache = bootstrap_cache

    def handle(
        self,
        proposed_config: list[SwitchConfigModel],
        existing: list[SwitchDataModel],
    ) -> None:
        """Execute RMA processing for the provided switch configs.

        ## Parameters

        - `proposed_config`: Validated switch configs for RMA operations.
        - `existing`: Current fabric inventory snapshot.

        ## Returns

        - None.
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
        rma_entries: list[tuple[SwitchConfigModel, RMAConfigModel]] = []
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
        bootstrap_idx = self.bootstrap_cache.get_index()
        log.debug(
            "Bootstrap index contains %s switch(es): %s",
            len(bootstrap_idx),
            list(bootstrap_idx.keys()),
        )

        # Build and submit each RMA request
        switch_actions: list[tuple[str, SwitchConfigModel]] = []
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

            try:
                rma_model = self._build_rma_model(
                    switch_cfg,
                    rma_cfg,
                    bootstrap_data,
                    old_switch_info[switch_cfg.seed_ip],
                )
            except ValidationError as exc:
                msg = f"RMA model validation failed for serial {new_serial}: {exc}"
                log.error(msg)
                nd.module.fail_json(msg=msg)
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
            self.fabric_ops.finalize(serial_numbers=all_new_serials)
        except _FABRIC_OPERATION_ERRORS as e:
            msg = f"Failed to finalize (config-save/deploy) for RMA " f"switches {all_new_serials}: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        log.debug("EXIT: RMAHandler.handle()")

    def _validate_prerequisites(
        self,
        rma_entries: list[tuple[SwitchConfigModel, RMAConfigModel]],
        existing: list[SwitchDataModel],
    ) -> dict[str, dict[str, Any]]:
        """Validate RMA prerequisites for each requested replacement.

        Looks up the switch to be replaced by ``seed_ip`` (the fabric management
        IP).  The serial number of the old switch is derived from inventory —
        it is not required in the playbook config.

        ## Parameters

        - `rma_entries`: ``(SwitchConfigModel, RMAConfigModel)`` pairs.
        - `existing`: Current fabric inventory snapshot.

        ## Returns

        - Dict keyed by ``seed_ip`` with prerequisite metadata including
            ``old_serial``, ``hostname``, and ``switch_data``.
        """
        nd = self.ctx.nd
        log = self.ctx.log

        log.debug("ENTER: _validate_prerequisites()")

        existing_by_ip: dict[str, SwitchDataModel] = FabricSwitchInventory(existing).by_ip()

        result: dict[str, dict[str, Any]] = {}

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
                nd.module.fail_json(msg=f"RMA: Switch at '{seed_ip}' has no serial number in " f"the inventory response.")

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
        bootstrap_data: dict[str, Any],
        old_switch_info: dict[str, Any],
    ) -> RMASwitchModel:
        """Build an RMA model from config and bootstrap data.

        All switch properties (model, version, gateway, modules) are sourced
        exclusively from the bootstrap API response.  Only the new serial number,
        optional image policy, and optional discovery credentials come from the
        playbook config.

        ## Parameters

        - `switch_cfg`: Parent switch config.
        - `rma_cfg`: RMA config entry.
        - `bootstrap_data`: Bootstrap response entry for the replacement switch.
        - `old_switch_info`: Prerequisite metadata keyed from _validate_prerequisites.

        ## Returns

        - Completed ``RMASwitchModel`` for API submission.
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
            data=({"gatewayIpMask": gateway_ip_mask, "models": data_models} if (gateway_ip_mask or data_models) else None),
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

        ## Parameters

        - `rma_model`: RMA model for the replacement switch.

        ## Returns

        - None.
        """
        log = self.ctx.log

        log.debug("ENTER: _provision_rma_switch()")

        endpoint = EpManageFabricsSwitchProvisionRMAPost()
        endpoint.fabric_name = self.ctx.fabric
        endpoint.switch_sn = rma_model.old_switch_id

        payload = rma_model.to_payload()

        log.info("RMA: Replacing %s with %s", rma_model.old_switch_id, rma_model.new_switch_id)
        log.debug("RMA endpoint: %s", endpoint.path)
        log.debug("RMA payload (masked): %s", mask_password(payload))

        self.ctx.api_call(
            ApiCallSpec(
                endpoint=endpoint,
                payload=payload,
                action="rma",
                op_type=OperationType.CREATE,
                diff={
                    "old_switch_id": rma_model.old_switch_id,
                    "new_switch_id": rma_model.new_switch_id,
                },
                context=f"RMA provision {rma_model.old_switch_id} → {rma_model.new_switch_id}",
            )
        )

        log.info("RMA provision API response success")
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
        logger: logging.Logger | None = None,
    ):
        """Initialize module state, services, and inventory snapshots.

        ## Parameters

        - `nd`: ND module wrapper.
        - `results`: Shared results aggregator.
        - `logger`: Optional logger instance.

        ## Returns

        - None.
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
        config_actions = self.module.params.get("config_actions") or {}

        # Keep switch lifecycle API failures fast. RestSend models retries as
        # timeout / send_interval, so these values are applied per request by
        # _request_with_retry_policy() and restored immediately afterward.

        self.ctx = SwitchServiceContext(
            nd=nd,
            results=results,
            fabric=self.fabric,
            log=log,
            save_config=config_actions.get("save", True),
            deploy_config=config_actions.get("deploy", True),
            deploy_type=config_actions.get("type", "switch"),
        )

        # Switch collections
        try:
            self.proposed: NDConfigCollection = NDConfigCollection(model_class=SwitchDataModel)
            self.inventory = FabricSwitchInventory.from_fabric(nd, self.fabric, log, SwitchDataModel)
            self.existing: NDConfigCollection = self.inventory.collection
            self.before: NDConfigCollection = self.existing.copy()
            self.sent: NDConfigCollection = NDConfigCollection(model_class=SwitchDataModel)
            self.sent_adds: list[SwitchConfigModel] = []
            self.proposed_cfgs: list[SwitchConfigModel] = []
            # Plan stored here after compute_changes so check-mode output can use it
            self._plan: SwitchPlan | None = None
        except _FABRIC_OPERATION_ERRORS as e:
            msg = f"Failed to query fabric '{self.fabric}' inventory " f"during initialization: {e}"
            log.error(msg)
            nd.module.fail_json(msg=msg)

        # Operation tracking
        self.nd_logs: list[dict[str, Any]] = []
        self.msg: str = ""
        self.output: NDOutput = NDOutput(output_level=self.module.params.get("output_level", "normal"))
        self.output.assign(before=self.before, after=self.existing)

        # Utility instances: FabricDetailsCache handles fabric details; SwitchFabricUtils handles switch-specific fabric actions.
        self.fabric_details_cache = FabricDetailsCache(self.nd._get_rest_send(), self.fabric)  # pylint: disable=protected-access
        self.switch_fabric_utils = SwitchFabricUtils(self.nd, self.fabric, log)
        self.wait_utils = SwitchWaitUtils(self, self.fabric, log, fabric_details_cache=self.fabric_details_cache)
        self.bootstrap_cache = BootstrapCache(self.nd, self.fabric, log)

        # Service instances (Dependency Injection)
        self.discovery = SwitchDiscoveryService(self.ctx)
        self.fabric_ops = SwitchFabricOps(self.ctx, self.switch_fabric_utils)
        self.poap_handler = POAPHandler(self.ctx, self.fabric_ops, self.wait_utils, self.bootstrap_cache)
        self.rma_handler = RMAHandler(self.ctx, self.fabric_ops, self.wait_utils, self.bootstrap_cache)

        log.info("Initialized NDSwitchResourceModule for fabric: %s", self.fabric)

    def _inventory_to_config_list(self, collection: "NDConfigCollection") -> list[dict[str, Any]]:
        """Convert an inventory collection (SwitchDataModel) to gathered-format config dicts.

        Produces the same shape as gathered state output: seed_ip, role, auth_proto,
        preserve_config, username/password placeholders.  Built directly from
        SwitchDataModel fields to avoid re-running Pydantic validators.
        """
        result = []
        for sw in collection:
            if not sw.fabric_management_ip:
                continue
            role = sw.switch_role
            result.append(
                {
                    "seed_ip": sw.fabric_management_ip,
                    "role": getattr(role, "value", str(role)) if role else "leaf",
                    "auth_proto": "MD5",
                    "preserve_config": False,
                    "username": "<username>",
                    "password": "<password>",
                }
            )
        return result

    def _proposed_to_config_list(self, configs: list["SwitchConfigModel"]) -> list[dict[str, Any]]:
        """Serialize proposed configs for output, stripping internal fields and masking passwords."""
        result = []
        for cfg in configs:
            try:
                entry = cfg.to_config()
                entry.pop("platform_type", None)
                entry.pop("operation_type", None)
                entry["password"] = "<password>"
                result.append(entry)
            except _OUTPUT_CONVERSION_ERRORS as exc:
                self.log.warning("Could not convert config %s for output: %s", cfg.seed_ip, exc)
        return result

    def _validate_fabric_capabilities(self, configs: list["SwitchConfigModel"]) -> None:
        """Validate desired switches against the target fabric support matrix."""
        if not configs:
            return
        try:
            fabric_type = self.fabric_details_cache.get_fabric_type()
            capability = validate_switch_configs_for_fabric_type(self.fabric, fabric_type, configs)
            self.log.debug(
                "Switch capability validation passed for fabric %s using %s matrix",
                self.fabric,
                capability.family,
            )
        except SwitchFabricCapabilityError as exc:
            msg = str(exc)
            self.log.error(msg)
            self.nd.module.fail_json(msg=msg)
        except _FABRIC_OPERATION_ERRORS as exc:
            msg = f"Failed to query fabric '{self.fabric}' capabilities: {exc}"
            self.log.error(msg)
            self.nd.module.fail_json(msg=msg)

    def _build_check_mode_output(self) -> dict[str, Any]:
        """Build before/after/diff/changed output for check mode.

        Since no API writes are issued in check mode, ``self.sent`` and
        ``self.sent_adds`` are always empty.  This method derives the same
        information directly from the action plan (``self._plan``) and the
        real pre-operation inventory snapshot (``self.before``).

        For ``deleted`` state the plan may be ``None`` (no config supplied),
        so the entire existing inventory is treated as the deletion target.

        ## Returns

        - Dict suitable for merging into the final ``exit_json`` payload,
            containing ``before``, ``after``, ``diff``, and ``changed``.
        """
        before_list = self._inventory_to_config_list(self.before)
        diff_list: list[dict[str, Any]] = []

        if self._plan is not None:
            plan = self._plan

            # Switches that would be deleted
            deleted_sws: list[SwitchDataModel] = list(plan.to_delete) + list(plan.to_delete_existing)
            if self.state == "deleted":
                # _handle_deleted_state fills plan.to_delete only for
                # overridden; for state=deleted the deletions come from the
                # handler's own switch-by-switch loop which we replicate here.
                deleted_sws = [
                    sw for sw in self.before if sw.fabric_management_ip in {cfg.seed_ip for cfg in (self.proposed_cfgs or [])} or not self.proposed_cfgs
                ]
            for sw in deleted_sws:
                if not sw.fabric_management_ip:
                    continue
                role = sw.switch_role
                diff_list.append(
                    {
                        "seed_ip": sw.fabric_management_ip,
                        "role": getattr(role, "value", str(role)) if role else "leaf",
                        "_action": "deleted",
                    }
                )

            # Switches that would be added (normal to_add + POAP/preprov/rma)
            adds: list[SwitchConfigModel] = (
                list(plan.to_add) + list(plan.normal_readd) + list(plan.to_bootstrap) + list(plan.to_preprovision) + list(plan.to_swap) + list(plan.to_rma)
            )
            for cfg in adds:
                try:
                    entry = cfg.to_config()
                    entry.pop("platform_type", None)
                    entry.pop("operation_type", None)
                    entry["password"] = "<password>"
                    entry["_action"] = "added"
                    diff_list.append(entry)
                except _OUTPUT_CONVERSION_ERRORS as exc:
                    self.log.warning("check_mode diff: could not convert %s: %s", cfg.seed_ip, exc)

            # Switches whose role would be updated (overridden/replaced)
            for cfg in plan.to_update:
                try:
                    entry = cfg.to_config()
                    entry.pop("platform_type", None)
                    entry.pop("operation_type", None)
                    entry["password"] = "<password>"
                    entry["_action"] = "updated"
                    diff_list.append(entry)
                except _OUTPUT_CONVERSION_ERRORS as exc:
                    self.log.warning("check_mode diff: could not convert %s: %s", cfg.seed_ip, exc)

            # Simulate the post-operation inventory for "after":
            #   start from before, remove deletions, add additions as stubs
            deleted_ips = {sw.fabric_management_ip for sw in deleted_sws}
            after_list = [e for e in before_list if e.get("seed_ip") not in deleted_ips]
            for cfg in adds:
                # Mirror the format produced by _inventory_to_config_list — no
                # poap/preprovision sub-blocks since those reflect the user's
                # desired discovery method, not the resulting inventory state.
                role = cfg.role
                after_list.append(
                    {
                        "seed_ip": cfg.seed_ip,
                        "role": getattr(role, "value", str(role)) if role else "leaf",
                        "auth_proto": "MD5",
                        "preserve_config": bool(getattr(cfg, "preserve_config", False)),
                        "username": "<username>",
                        "password": "<password>",
                    }
                )
            # Apply role updates in-place
            update_role_map = {cfg.seed_ip: cfg for cfg in plan.to_update}
            for entry in after_list:
                ip = entry.get("seed_ip")
                if ip in update_role_map:
                    role = update_role_map[ip].role
                    entry["role"] = getattr(role, "value", str(role)) if role else entry.get("role")
        else:
            # deleted state with no config — would delete everything
            after_list = []
            for sw in self.before:
                if not sw.fabric_management_ip:
                    continue
                role = sw.switch_role
                diff_list.append(
                    {
                        "seed_ip": sw.fabric_management_ip,
                        "role": getattr(role, "value", str(role)) if role else "leaf",
                        "_action": "deleted",
                    }
                )

        changed = bool(diff_list)
        output_level = self.module.params.get("output_level", "normal")
        result: dict[str, Any] = {
            "output_level": output_level,
            "changed": changed,
            "before": before_list,
            "after": after_list,
            "diff": diff_list,
        }
        if output_level in ("info", "debug"):
            result["proposed"] = self._proposed_to_config_list(self.proposed_cfgs)
        return result

    def exit_json(self) -> None:
        """Finalize collected results and exit the Ansible module.

        Includes operation logs and previous/current inventory snapshots in the
        final response payload.

        ## Returns

        - None.
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
                except _OUTPUT_CONVERSION_ERRORS as exc:
                    msg = f"Failed to convert switch {sw.switch_id!r} to gathered format: {exc}"
                    self.log.error(msg)
                    self.nd.module.fail_json(msg=msg)
            self.output.assign(after=self.existing)
            final.update(self.output.format(gathered=gathered))
        elif self.nd.module.check_mode:
            final.update(self._build_check_mode_output())
        else:
            # Re-query the fabric to get the actual post-operation inventory so
            # that "after" reflects real state rather than the pre-op snapshot.
            if True not in self.results.failed:
                self.existing = FabricSwitchInventory.from_fabric(self.nd, self.fabric, self.log, SwitchDataModel).collection
            # Build diff: deletes (from self.sent) + adds (from self.sent_adds)
            diff_list: list[dict[str, Any]] = []
            for sw in self.sent:
                if not sw.fabric_management_ip:
                    continue
                role = sw.switch_role
                entry = {
                    "seed_ip": sw.fabric_management_ip,
                    "role": getattr(role, "value", str(role)) if role else "leaf",
                    "auth_proto": "MD5",
                    "preserve_config": False,
                    "username": "<username>",
                    "password": "<password>",
                    "_action": "deleted",
                }
                diff_list.append(entry)
            for cfg in self.sent_adds:
                try:
                    entry = cfg.to_config()
                    entry.pop("platform_type", None)
                    entry.pop("operation_type", None)
                    entry["password"] = "<password>"
                    entry["_action"] = "added"
                    diff_list.append(entry)
                except _OUTPUT_CONVERSION_ERRORS as exc:
                    self.log.warning("Could not convert added config for diff: %s", exc)
            output_level = self.module.params.get("output_level", "normal")
            fmt_kwargs: dict[str, Any] = {
                "before": self._inventory_to_config_list(self.before),
                "after": self._inventory_to_config_list(self.existing),
                "diff": diff_list,
            }
            if output_level in ("info", "debug"):
                fmt_kwargs["proposed"] = self._proposed_to_config_list(self.proposed_cfgs)
            self.output.assign(before=self.before, after=self.existing)
            final.update(self.output.format(**fmt_kwargs))

        if self.msg:
            final["msg"] = self.msg
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

        ## Returns

        - None.
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

        # merged / replaced — config required
        if self.state in ("merged", "replaced") and not self.config:
            self.nd.module.fail_json(msg=f"'config' is required for '{self.state}' state.")

        # overridden with no/empty config — delete everything
        if self.state == "overridden" and not self.config:
            self.log.info("Overridden state with no config — deleting all switches from fabric")
            return self._handle_deleted_state(None)

        if self.state not in ("merged", "replaced", "overridden"):
            self.nd.module.fail_json(msg=f"Unsupported state: {self.state}")

        # --- Validate & classify ------------------------------------------------
        proposed_config = SwitchDiffEngine.validate_configs(self.config, self.state, self.nd, self.log)
        self._validate_fabric_capabilities(proposed_config)

        # Enforce state constraints
        rma_configs = [c for c in proposed_config if c.operation_type == "rma"]
        if rma_configs and self.state != "merged":
            self.nd.module.fail_json(msg="RMA configs are only supported with state=merged")

        # Capture all proposed configs for NDOutput
        output_proposed: NDConfigCollection = NDConfigCollection(model_class=SwitchConfigModel)
        for cfg in proposed_config:
            output_proposed.add(cfg)
        self.output.assign(proposed=output_proposed)
        self.proposed_cfgs = list(proposed_config)

        # Classify all configs in one pass — idempotency included
        plan = SwitchDiffEngine.compute_changes(proposed_config, list(self.existing), self.log)
        self._plan = plan

        # --- Single combined discovery pass -------------------------------------
        # Discover every switch that is not yet in the fabric:
        #   • plan.to_add      — normal switches not in inventory
        #   • plan.normal_readd — POAP/preprov mismatches that are reachable
        # Switches already in the fabric (to_update, migration_mode) are
        # skipped here; overridden will re-discover them after deletion.
        #
        # In check mode, discovery is skipped entirely: new switches are not
        # yet reachable/enrolled so shallow discovery would fail or return no
        # data. The per-state check-mode guards handle reporting via the diff.
        configs_to_discover = plan.to_add + plan.normal_readd
        if configs_to_discover:
            if self.nd.module.check_mode:
                self.log.info(
                    "Check mode: skipping discovery for %s switch(es) (%s normal-add, %s poap-readd) — assuming to_add",
                    len(configs_to_discover),
                    len(plan.to_add),
                    len(plan.normal_readd),
                )
                discovered_data = {}
            else:
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
        # (needed for the self.proposed reference used in check-mode reporting).
        # Skipped in check mode since discovered_data is empty for new switches.
        normal_configs = [c for c in proposed_config if c.operation_type == "normal"]
        if normal_configs and not self.nd.module.check_mode:
            built = self.discovery.build_proposed(normal_configs, discovered_data, list(self.existing))
            self.proposed = NDConfigCollection(model_class=SwitchDataModel, items=built)

        # --- Dispatch -----------------------------------------------------------
        if self.state == "merged":
            self._handle_merged_state(plan, discovered_data)
        elif self.state == "replaced":
            self._handle_replaced_state(plan, discovered_data)
        elif self.state == "overridden":
            self._handle_overridden_state(plan, discovered_data)
        else:
            self.nd.module.fail_json(msg=f"Unsupported state: {self.state}")

    # =====================================================================
    # State Handlers (orchestration only — delegate to services)
    # =====================================================================

    def _check_idempotent_sync(
        self,
        plan: "SwitchPlan",
        existing_by_ip: dict[str, "SwitchDataModel"],
    ) -> bool:
        """Return True if any non-preprovision idempotent switch is out of config-sync.

        Pre-provisioned switches are placeholder entries that are never
        in-sync by design and are excluded from this check.  Only relevant
        when deploy is enabled; returns False immediately otherwise.

        ## Parameters

        - `plan`: Action plan from :meth:`SwitchDiffEngine.compute_changes`.
        - `existing_by_ip`: Existing switches keyed by fabric management IP.

        ## Returns

        - True if finalize should run for idempotent switches, False otherwise.
        """
        if not self.ctx.deploy_config:
            return False
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
                return True
        return False

    def _register_check_mode_result(
        self,
        action: str,
        diff_current: dict[str, Any],
    ) -> None:
        """Register a check-mode result with standard metadata.

        ## Parameters

        - `action`: Action label (e.g. ``"merge"``, ``"override"``).
        - `diff_current`: Diff payload describing what would change.

        ## Returns

        - None.
        """
        self.results.action = action
        self.results.state = self.state
        self.results.operation_type = OperationType.CREATE
        self.results.response_current = {"MESSAGE": "check mode — skipped", "RETURN_CODE": 200}
        self.results.result_current = {"success": True, "changed": False}
        self.results.diff_current = diff_current
        self.results.register_api_call()

    def _execute_add_phase(
        self,
        spec: AddPhaseSpec,
    ) -> list[tuple[str, "SwitchConfigModel"]]:
        """Shared credential-group → bulk_add → migration → post-processing logic.

        Groups ``add_configs`` by credentials, runs ``bulk_add`` for each group,
        appends migration-mode switches, and executes post-add processing
        (wait, credentials, roles, finalize).

        ## Parameters

        - `add_configs`: Switch configs to add via bulk discovery+add.
        - `plan`: The current action plan (used for migration_mode).
        - `discovered_data`: Discovery data keyed by seed IP.
        - `existing_by_ip`: Existing inventory keyed by management IP.
        - `context`: Label used in logs and wait error messages.

        ## Returns

        - List of ``(serial_number, SwitchConfigModel)`` pairs that were processed.
        """
        switch_actions: list[tuple[str, SwitchConfigModel]] = []
        have_migration = bool(spec.plan.migration_mode)

        if spec.add_configs and spec.discovered_data:
            credential_groups = group_switches_by_credentials(spec.add_configs, self.log)
            for group_key, group_switches in credential_groups.items():
                username, _pw_hash, auth_proto, platform_type, preserve_config = group_key
                password = group_switches[0].password
                pairs = [(cfg, spec.discovered_data[cfg.seed_ip]) for cfg in group_switches if cfg.seed_ip in spec.discovered_data]
                if not pairs:
                    self.log.warning(
                        "No discovery data for group %s — skipping bulk_add",
                        [cfg.seed_ip for cfg in group_switches],
                    )
                    continue
                self.fabric_ops.bulk_add(
                    BulkAddSpec(
                        switches=pairs,
                        username=username,
                        password=password,
                        auth_proto=auth_proto,
                        platform_type=platform_type,
                        preserve_config=preserve_config,
                    )
                )
                for cfg, disc in pairs:
                    sn = disc.get("serialNumber")
                    if sn:
                        switch_actions.append((sn, cfg))
                        self._log_operation("add", cfg.seed_ip)
                        self.sent_adds.append(cfg)

        # Migration-mode switches — no add needed, but role + finalize applies
        for cfg in spec.plan.migration_mode:
            sw = spec.existing_by_ip.get(cfg.seed_ip)
            if sw and sw.switch_id:
                switch_actions.append((sw.switch_id, cfg))
                self._log_operation("migrate", cfg.seed_ip)
                self.sent_adds.append(cfg)

        if switch_actions:
            self.fabric_ops.post_add_processing(
                PostAddProcessingSpec(
                    switch_actions=switch_actions,
                    wait_utils=self.wait_utils,
                    context=spec.context,
                    update_roles=have_migration,
                )
            )

        return switch_actions

    def _handle_merged_state(
        self,
        plan: "SwitchPlan",
        discovered_data: dict[str, dict[str, Any]],
    ) -> None:
        """Handle merged-state workflows for all operation types.

        Processes normal adds, migration-mode switches, POAP bootstrap,
        pre-provision, swap, normal re-adds, and RMA in a single pass.
        Normal switches that require field-level updates fail fast; use
        ``overridden`` state for in-place updates.

        ## Parameters

        - `plan`: Unified action plan from :meth:`SwitchDiffEngine.compute_changes`.
        - `discovered_data`: Discovery data keyed by seed IP for all switches
                             that required discovery this run.

        ## Returns

        - None.
        """
        self.log.debug("ENTER: _handle_merged_state()")
        self.log.info("Handling merged state")

        # Fail if any normal switches need field-level updates
        if plan.to_update:
            ips = [cfg.seed_ip for cfg in plan.to_update]
            self.nd.module.fail_json(
                msg=(
                    f"Switches require role updates not supported in merged state. "
                    f"Use 'overridden' or 'replaced' state for in-place updates. "
                    f"Affected switches: {ips}"
                )
            )

        # Fail if any POAP/preprovision switches already in fabric differ on
        # one or more of: serial, role, model, version, hostname —
        # delete+re-provision is destructive and only permitted in overridden or
        # replaced state.
        if plan.to_delete_existing:
            ips = [sw.fabric_management_ip for sw in plan.to_delete_existing]
            self.nd.module.fail_json(
                msg=(
                    f"POAP/preprovision switches already in fabric have a "
                    f"field mismatch (serial, role, model, version, or hostname) "
                    f"and require delete + re-provision. "
                    f"Use 'overridden' or 'replaced' state to apply this change. "
                    f"Affected switches: {ips}"
                )
            )

        # Check whether any idempotent switch (normal or POAP) is out of
        # config-sync and needs a deploy without a re-add.
        # Pre-provisioned switches are placeholder entries that are never
        # in-sync by design, so they are excluded from this check. Only relevant when deploy is enabled.
        existing_by_ip = self.inventory.by_ip()
        idempotent_save_req = self._check_idempotent_sync(plan, existing_by_ip)

        has_work = bool(
            plan.to_add
            or plan.migration_mode
            or plan.to_bootstrap
            or plan.normal_readd
            or plan.to_preprovision
            or plan.to_swap
            or plan.to_rma
            or idempotent_save_req
        )
        if not has_work:
            self.log.info("merged: nothing to do — all switches idempotent")
            self.msg = "No switches to merge — fabric already matches desired config"
            return

        # Check mode
        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: add=%s, migrate=%s, bootstrap=%s, readd=%s, preprov=%s, swap=%s, rma=%s, save_deploy=%s",
                len(plan.to_add),
                len(plan.migration_mode),
                len(plan.to_bootstrap),
                len(plan.normal_readd),
                len(plan.to_preprovision),
                len(plan.to_swap),
                len(plan.to_rma),
                idempotent_save_req,
            )
            self._register_check_mode_result(
                "merge",
                {
                    "to_add": [c.seed_ip for c in plan.to_add],
                    "migration_mode": [c.seed_ip for c in plan.migration_mode],
                    "bootstrap": [c.seed_ip for c in plan.to_bootstrap],
                    "normal_readd": [c.seed_ip for c in plan.normal_readd],
                    "preprovision": [c.seed_ip for c in plan.to_preprovision],
                    "swap": [c.seed_ip for c in plan.to_swap],
                    "rma": [c.seed_ip for c in plan.to_rma],
                    "save_deploy_required": idempotent_save_req,
                },
            )
            return

        # --- Normal + normal_readd bulk_add (one combined pass) -----------------
        add_configs = plan.to_add + plan.normal_readd
        switch_actions = self._execute_add_phase(
            AddPhaseSpec(
                add_configs=add_configs,
                plan=plan,
                discovered_data=discovered_data,
                existing_by_ip=existing_by_ip,
                context="merged",
            )
        )

        if not switch_actions and idempotent_save_req:
            self.log.info("No adds/migrations but config-sync required — running finalize")
            sync_serials = [
                existing_by_ip[cfg.seed_ip].switch_id for cfg in plan.idempotent if cfg.seed_ip in existing_by_ip and existing_by_ip[cfg.seed_ip].switch_id
            ]
            self.fabric_ops.finalize(serial_numbers=sync_serials)

        # --- POAP / preprovision / swap / RMA -----------------------------------
        # normal_readd was already processed via bulk_add above.
        # Only route the pure POAP-workflow configs to the handler.
        poap_workflow_configs = plan.to_bootstrap + plan.to_preprovision + plan.to_swap
        if poap_workflow_configs:
            self.sent_adds.extend(poap_workflow_configs)
            self.poap_handler.handle(poap_workflow_configs, list(self.existing))
        if plan.to_rma:
            self.sent_adds.extend(plan.to_rma)
            self.rma_handler.handle(plan.to_rma, list(self.existing))

        self.log.debug("EXIT: _handle_merged_state()")

    def _handle_overridden_state(
        self,
        plan: "SwitchPlan",
        discovered_data: dict[str, dict[str, Any]],
    ) -> None:
        """Handle overridden-state reconciliation for the fabric.

        Reconciles the fabric to match exactly the desired config.  Switches
        in the fabric that have no config entry are deleted via ``to_delete``.
        POAP/preprovision mismatches that need replacement are deleted via
        ``to_delete_existing`` before their add workflow runs. Normal switches
        with field differences are deleted and re-added.

        ## Parameters

        - `plan`: Unified action plan from :meth:`SwitchDiffEngine.compute_changes`.
        - `discovered_data`: Discovery data keyed by seed IP.

        ## Returns

        - None.
        """
        self.log.debug("ENTER: _handle_overridden_state()")
        self.log.info("Handling overridden state")

        existing_by_ip = self.inventory.by_ip()
        idempotent_save_req = self._check_idempotent_sync(plan, existing_by_ip)

        has_work = bool(
            plan.to_add
            or plan.to_update
            or plan.to_delete
            or plan.migration_mode
            or plan.to_bootstrap
            or plan.normal_readd
            or plan.to_preprovision
            or plan.to_swap
            or idempotent_save_req
        )
        if not has_work:
            self.log.info("overridden: nothing to do")
            self.msg = "No switches to override — fabric already matches desired config"
            return

        # Check mode
        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: delete_orphans=%s, update=%s, add=%s, migrate=%s, bootstrap=%s, readd=%s, preprov=%s, swap=%s, save_deploy=%s",
                len(plan.to_delete),
                len(plan.to_update),
                len(plan.to_add),
                len(plan.migration_mode),
                len(plan.to_bootstrap),
                len(plan.normal_readd),
                len(plan.to_preprovision),
                len(plan.to_swap),
                idempotent_save_req,
            )
            self._register_check_mode_result(
                "override",
                {
                    "to_delete": len(plan.to_delete) + len(plan.to_delete_existing),
                    "to_update": len(plan.to_update),
                    "to_add": len(plan.to_add),
                    "migration_mode": len(plan.migration_mode),
                    "bootstrap": len(plan.to_bootstrap),
                    "normal_readd": len(plan.normal_readd),
                    "preprovision": len(plan.to_preprovision),
                    "swap": len(plan.to_swap),
                    "save_deploy_required": idempotent_save_req,
                },
            )
            return

        # --- Phase 1: Combined delete -------------------------------------------
        # Merge three sources of deletions into one bulk_delete call:
        #   a) Orphans (in fabric, not in any config)
        #   b) POAP/preprovision mismatches (to_delete_existing from compute_changes)
        #   c) Normal switches that need field updates (to_update)
        switches_to_delete: list[SwitchDataModel] = list(plan.to_delete)
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
        switch_actions = self._execute_add_phase(
            AddPhaseSpec(
                add_configs=add_configs,
                plan=plan,
                discovered_data=discovered_data,
                existing_by_ip=existing_by_ip,
                context="overridden",
            )
        )

        if not switch_actions and idempotent_save_req:
            self.log.info("No adds/migrations but config-sync required — running finalize")
            sync_serials = [
                existing_by_ip[cfg.seed_ip].switch_id for cfg in plan.idempotent if cfg.seed_ip in existing_by_ip and existing_by_ip[cfg.seed_ip].switch_id
            ]
            self.fabric_ops.finalize(serial_numbers=sync_serials)

        # --- Phase 4: POAP workflows (bootstrap / preprovision / swap) ----------
        # plan.to_delete_existing was deleted in Phase 1.
        # Route pure POAP-workflow configs to the handler.
        poap_workflow_configs = plan.to_bootstrap + plan.to_preprovision + plan.to_swap
        if poap_workflow_configs:
            self.sent_adds.extend(poap_workflow_configs)
            self.poap_handler.handle(poap_workflow_configs, list(self.existing))

        self.log.debug("EXIT: _handle_overridden_state()")

    def _handle_replaced_state(
        self,
        plan: "SwitchPlan",
        discovered_data: dict[str, Any],
    ) -> None:
        """Handle replaced-state reconciliation for the fabric.

        Reconciles only the switches listed in the desired config.  Field
        differences trigger delete and re-add, and POAP/preprovision mismatches
        are also re-provisioned.

        ## Parameters

        - `plan`: Unified action plan from :meth:`SwitchDiffEngine.compute_changes`.
        - `discovered_data`: Discovery data keyed by seed IP.

        ## Returns

        - None.
        """
        self.log.debug("ENTER: _handle_replaced_state()")
        self.log.info("Handling replaced state")

        existing_by_ip = self.inventory.by_ip()
        idempotent_save_req = self._check_idempotent_sync(plan, existing_by_ip)

        has_work = bool(
            plan.to_add
            or plan.to_update
            or plan.to_delete_existing
            or plan.migration_mode
            or plan.to_bootstrap
            or plan.normal_readd
            or plan.to_preprovision
            or plan.to_swap
            or idempotent_save_req
        )
        if not has_work:
            self.log.info("replaced: nothing to do")
            self.msg = "No switches to replace — fabric already matches desired config"
            return

        # Check mode
        if self.nd.module.check_mode:
            self.log.info(
                "Check mode: poap_mismatch_delete=%s, update=%s, add=%s, migrate=%s, bootstrap=%s, readd=%s, preprov=%s, swap=%s, save_deploy=%s",
                len(plan.to_delete_existing),
                len(plan.to_update),
                len(plan.to_add),
                len(plan.migration_mode),
                len(plan.to_bootstrap),
                len(plan.normal_readd),
                len(plan.to_preprovision),
                len(plan.to_swap),
                idempotent_save_req,
            )
            self._register_check_mode_result(
                "replace",
                {
                    "to_delete": len(plan.to_delete_existing),
                    "to_update": len(plan.to_update),
                    "to_add": len(plan.to_add),
                    "migration_mode": len(plan.migration_mode),
                    "bootstrap": len(plan.to_bootstrap),
                    "normal_readd": len(plan.normal_readd),
                    "preprovision": len(plan.to_preprovision),
                    "swap": len(plan.to_swap),
                    "save_deploy_required": idempotent_save_req,
                },
            )
            return

        # --- Phase 1: Combined delete -------------------------------------------
        # Two sources of deletions (orphans intentionally excluded):
        #   a) POAP/preprovision mismatches (to_delete_existing from compute_changes)
        #   b) Normal switches that need field updates (to_update)
        switches_to_delete: list[SwitchDataModel] = []

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
                msg = f"Failed to delete switches during replaced state: {e}"
                self.log.error(msg)
                self.nd.module.fail_json(msg=msg)
            for sw in switches_to_delete:
                self.sent.add(sw)

        # --- Phase 2: Re-discover updated normal switches -----------------------
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
        switch_actions = self._execute_add_phase(
            AddPhaseSpec(
                add_configs=add_configs,
                plan=plan,
                discovered_data=discovered_data,
                existing_by_ip=existing_by_ip,
                context="replaced",
            )
        )

        if not switch_actions and idempotent_save_req:
            self.log.info("No adds/migrations but config-sync required — running finalize")
            sync_serials = [
                existing_by_ip[cfg.seed_ip].switch_id for cfg in plan.idempotent if cfg.seed_ip in existing_by_ip and existing_by_ip[cfg.seed_ip].switch_id
            ]
            self.fabric_ops.finalize(serial_numbers=sync_serials)

        # --- Phase 4: POAP workflows (bootstrap / preprovision / swap) ----------
        poap_workflow_configs = plan.to_bootstrap + plan.to_preprovision + plan.to_swap
        if poap_workflow_configs:
            self.sent_adds.extend(poap_workflow_configs)
            self.poap_handler.handle(poap_workflow_configs, list(self.existing))

        self.log.debug("EXIT: _handle_replaced_state()")

    def _handle_gathered_state(self) -> None:
        """Handle gathered-state read of the fabric inventory.

        No API writes are performed. The existing inventory is serialised into
        SwitchConfigModel shape by exit_json(). This method only records the
        result metadata so that Results aggregation works correctly.

        ## Returns

        - None.
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
        proposed_config: list[SwitchConfigModel] | None = None,
    ) -> None:
        """Handle deleted-state switch removal.

        Matches switches to delete by ``seed_ip`` and optionally ``role``.
        POAP/preprovision sub-config blocks (``poap``, ``preprovision``) are
        ignored; only ``seed_ip`` and ``role`` matter.  When no config is
        provided, all switches in the fabric are deleted.

        ## Parameters

        - `proposed_config`: Optional config list that limits deletion scope.
                             Pass ``None`` to delete all switches.

        ## Returns

        - None.
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
            existing_by_ip = self.inventory.by_ip()
            switches_to_delete: list[SwitchDataModel] = []
            for cfg in proposed_config:
                existing_sw = existing_by_ip.get(cfg.seed_ip)
                if not existing_sw:
                    self.log.info("deleted: switch %s not in fabric — skipping", cfg.seed_ip)
                    continue
                # Role filter: if config specifies a role, only delete if it matches
                if cfg.role is not None and cfg.role != existing_sw.switch_role:
                    self.log.info(
                        "deleted: switch %s role mismatch (config=%s, fabric=%s) — skipping",
                        cfg.seed_ip,
                        cfg.role,
                        existing_sw.switch_role,
                    )
                    continue
                self.log.info(
                    "deleted: marking %s (%s) for deletion",
                    cfg.seed_ip,
                    existing_sw.switch_id,
                )
                switches_to_delete.append(existing_sw)
                self._log_operation("delete", cfg.seed_ip)

        self.log.info("Total switches marked for deletion: %s", len(switches_to_delete))
        if not switches_to_delete:
            self.log.info("No switches to delete")
            self.msg = "No switches to delete - fabric already matches desired config"
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
    # Operation Tracking
    # =====================================================================

    def _log_operation(self, operation: str, identifier: str) -> None:
        """Append a successful operation record to the module log.

        ## Parameters

        - `operation`: Operation label.
        - `identifier`: Switch identifier for the operation.

        ## Returns

        - None.
        """
        self.nd_logs.append(
            {
                "operation": operation,
                "identifier": identifier,
                "status": "success",
            }
        )
