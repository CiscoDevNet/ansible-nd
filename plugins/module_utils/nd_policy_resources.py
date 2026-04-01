# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Policy Resource Module.

Provides all business logic for switch policy management on NDFC 4.x:
    - Policy CRUD (create, read, update, delete)
    - Idempotency diff calculation for merged, deleted states
    - Deploy (pushConfig) orchestration
    - Conditional delete flow:
      deploy=true  → markDelete → pushConfig → remove
      deploy=false → markDelete only

The module file ``nd_policy.py`` contains only DOCUMENTATION, argument_spec,
and a thin ``main()`` that instantiates this class and calls ``manage_state()``.

Models (from ``models.nd_manage_policies``):
    - ``PolicyCreate``      - single policy create payload
    - ``PolicyCreateBulk``  - bulk policy create wrapper
    - ``PolicyUpdate``      - policy update payload (extends PolicyCreate)
    - ``PolicyIds``         - list of policy IDs for actions
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import copy
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_config_templates import (
    EpManageConfigTemplateParametersGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_policies import (
    EpManagePoliciesDelete,
    EpManagePoliciesGet,
    EpManagePoliciesPost,
    EpManagePoliciesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_policy_actions import (
    EpManagePolicyActionsMarkDeletePost,
    EpManagePolicyActionsPushConfigPost,
    EpManagePolicyActionsRemovePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switch_actions import (
    EpManageSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_base import (
    PolicyCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_crud import (
    PolicyCreateBulk,
    PolicyUpdate,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_actions import (
    PolicyIds,
    SwitchIds,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    NDModuleError,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.config_models import PlaybookPolicyConfig


# =============================================================================
# Module-level helpers (stateless, used by NDPolicyModule)
# =============================================================================


def _looks_like_ip(value):
    """Return True if *value* looks like a dotted-quad IPv4 address.

    Args:
        value: String to check.

    Returns:
        True if the value matches a dotted-quad IPv4 pattern, False otherwise.
    """
    parts = value.split(".")
    if len(parts) == 4:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return False


def _needs_resolution(value):
    """Return True if the switch identifier needs IP/hostname → serial resolution.

    Serial numbers are alphanumeric strings (e.g. ``FDO25031SY4``).
    IPs look like dotted quads.  Hostnames contain dots or look like FQDNs.
    If the value is already a serial number we can skip the fabric API call.

    Args:
        value: Switch identifier string to inspect.

    Returns:
        True if the value looks like an IP or hostname, False if it
        appears to be a serial number already.
    """
    if not value:
        return False
    v = str(value).strip()
    if _looks_like_ip(v):
        return True
    if "." in v:
        return True
    return False


class NDPolicyModule:
    """Specialized module for switch policy lifecycle management.

    Provides policy-specific operations on top of NDModule:
        - Query and match existing policies (Lucene + post-filtering)
        - Idempotent diff calculation across 16 merged / 16 deleted cases
        - Create, update, delete_and_create actions
        - Bulk deploy via pushConfig
        - Conditional delete flow:
          deploy=true  → markDelete → pushConfig → remove
          deploy=false → markDelete only

    Schema models (from ``models.nd_manage_policies``):
        - ``PolicyCreate``      - single policy create request body
        - ``PolicyCreateBulk``  - bulk create wrapper
        - ``PolicyUpdate``      - update request body (extends PolicyCreate)
        - ``PolicyIds``         - list of policy IDs for bulk actions
    """

    # =========================================================================
    # Initialization & Lifecycle
    # =========================================================================

    def __init__(
        self,
        nd: NDModule,
        results: Results,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize the Policy Resource Module.

        Args:
            nd:      NDModule instance (wraps the Ansible module and REST client).
            results: Results aggregation instance for task output.
            logger:  Optional logger; defaults to ``nd.NDPolicyModule``.

        Returns:
            None.
        """
        self.log = logger or logging.getLogger("nd.NDPolicyModule")
        self.nd = nd
        self.module = nd.module
        self.results = results

        # Module parameters
        self.fabric_name = self.module.params.get("fabric_name")
        self.config = self.module.params.get("config")
        self.state = self.module.params.get("state")
        self.use_desc_as_key = self.module.params.get("use_desc_as_key")
        self.deploy = self.module.params.get("deploy")
        self.ticket_id = self.module.params.get("ticket_id")
        self.cluster_name = self.module.params.get("cluster_name")
        self.check_mode = self.module.check_mode

        if not self.config:
            if self.state != "gathered":
                self.module.fail_json(
                    msg=f"'config' element is mandatory for state '{self.state}'."
                )
            # For gathered without config, initialise to empty list so
            # downstream code can iterate safely.
            self.config = []

        # Template parameter cache: {templateName: [param_dict, ...]}
        # Populated lazily by _fetch_template_params() to avoid
        # redundant API calls when multiple config entries share the
        # same template.
        self._template_params_cache: Dict[str, List[Dict]] = {}

        # Before/after snapshot lists — populated during _execute_* methods.
        # Merged into exit_json output so the caller sees what changed.
        self._before: List[Dict] = []
        self._after: List[Dict] = []
        self._proposed: List[Dict] = []
        self._gathered: List[Dict] = []

        self.log.info(
            f"Initialized NDPolicyModule for fabric: {self.fabric_name}, state: {self.state}"
        )

    def exit_json(self) -> None:
        """Build final result from all registered tasks and exit.

        Merges the ``Results`` aggregation and the before/after/proposed
        snapshot lists, then delegates to ``exit_json`` or ``fail_json``.

        Returns:
            None.
        """
        self.results.build_final_result()
        final = self.results.final_result

        # Attach before/after snapshots
        final["before"] = self._before
        final["after"] = self._after

        # Attach gathered output when gathered state produces results
        if self._gathered:
            final["gathered"] = self._gathered

        # Only expose proposed at info/debug output levels
        output_level = self.module.params.get("output_level", "normal")
        if output_level in ("debug", "info"):
            final["proposed"] = self._proposed

        if True in self.results.failed:
            self.module.fail_json(
                msg="Policy operation failed. See task results for details.",
                **final,
            )
        self.module.exit_json(**final)

    # =========================================================================
    # Config Translation & Switch Resolution
    # =========================================================================

    @staticmethod
    def translate_config(config, use_desc_as_key):
        """Translate the playbook config into a flat list of per-switch policy dicts.

        The playbook config uses a two-level structure:
            - Global policy entries: dicts with ``name``, ``description``, etc.
            - A switch entry: a dict with ``switch`` key containing a list of
              switch dicts, each with ``serial_number`` and optional ``policies``.

        This function:
            1. Separates global policy entries from the switch entry (non-destructive).
            2. Collects per-switch overrides keyed by ``(template_name, switch_sn)``.
            3. For each (global_policy, switch) pair, emits either the override
               (when ``use_desc_as_key=false`` and a same-name override exists)
               or the global.  When ``use_desc_as_key=true``, both are emitted.
            4. Appends per-switch-only policies (overrides whose template name
               doesn't appear in any global).
            5. Returns a flat list where each dict has a ``switch`` key with a
               single serial number string.

        The input ``config`` list is **not** mutated.

        Args:
            config: The raw config list from the playbook.
            use_desc_as_key: Whether descriptions are used as unique keys.

        Returns:
            Flat list of policy dicts, each with a ``switch`` (serial number) key.
        """
        if not config:
            return []

        # ── Step 0: Detect gathered / self-contained format ─────────────
        #
        # ``state=gathered`` returns each policy with its own embedded
        # ``switch`` list (e.g., ``[{"serial_number": "FDO..."}]``).
        # This makes the output directly usable as ``config:`` in a
        # new ``state=merged`` task ("copy-paste round-trip").
        #
        # Detect this format: every entry that has a ``name`` also
        # has a ``switch`` list.  If so, flatten each entry by
        # extracting the serial number from its embedded switch list
        # and return immediately — no global/switch separation needed.
        has_self_contained = False
        all_self_contained = True
        for entry in config:
            if entry.get("name") and isinstance(entry.get("switch"), list):
                has_self_contained = True
            elif entry.get("name"):
                all_self_contained = False

        if has_self_contained and all_self_contained:
            result = []
            for entry in config:
                flat = copy.deepcopy(entry)
                sw_list = flat.get("switch", [])
                if isinstance(sw_list, list) and sw_list:
                    sn = sw_list[0].get("serial_number") or sw_list[0].get("ip", "")
                    flat["switch"] = sn
                # Gathered output contains both ``name`` (template name)
                # and ``policy_id`` (e.g. ``POLICY-28440``).  When
                # ``policy_id`` is present, promote it to ``name`` so
                # that merged state updates the existing policy in-place
                # by ID.  The template name is preserved alongside for
                # readability.
                #
                # If the user wants to create FRESH copies (new IDs)
                # instead of updating, they simply remove the
                # ``policy_id`` lines from the gathered output before
                # feeding it back — ``name`` will remain as the template
                # name and trigger a create.
                policy_id = flat.pop("policy_id", None)
                if policy_id:
                    flat["name"] = policy_id
                result.append(flat)
            return result

        # ── Step 1: Separate globals from the switch entry ──────────────
        global_policies = []
        switch_entry = None
        for entry in config:
            if isinstance(entry.get("switch"), list):
                switch_entry = entry
            else:
                global_policies.append(entry)

        # No switch entry → nothing to target
        if switch_entry is None:
            return config

        switches = switch_entry["switch"]
        if not switches:
            return []

        # ── Step 2: Extract switch serial numbers and per-switch overrides ──
        #
        # overrides_by_switch: {sn: [policy_dict, ...]}
        # override_names:      {sn: {template_name, ...}}  (for fast lookup)
        switch_serials = []
        overrides_by_switch = {}
        override_names = {}

        for sw in switches:
            sn = sw.get("serial_number") or sw.get("ip", "")
            switch_serials.append(sn)

            if sw.get("policies"):
                overrides_by_switch[sn] = sw["policies"]
                override_names[sn] = {p.get("name") for p in sw["policies"]}
            else:
                overrides_by_switch[sn] = []
                override_names[sn] = set()

        # ── Step 3: No globals and no overrides → bare switch entries ───
        if not global_policies and not any(overrides_by_switch.values()):
            return [{"switch": sn} for sn in switch_serials]

        # ── Step 4: Build the flat result in one pass ───────────────────
        result = []
        global_names = {g.get("name") for g in global_policies}

        for sn in switch_serials:
            sn_override_names = override_names.get(sn, set())
            sn_overrides = overrides_by_switch.get(sn, [])

            # 4a: Emit global policies for this switch.
            #     When use_desc_as_key=false, skip globals whose template
            #     name is overridden for this switch.
            for g in global_policies:
                gname = g.get("name")
                if not use_desc_as_key and gname in sn_override_names:
                    # Overridden for this switch — skip the global
                    continue
                entry = copy.deepcopy(g)
                entry["switch"] = sn
                result.append(entry)

            # 4b: Emit per-switch overrides for this switch.
            #     When use_desc_as_key=false, only overrides whose name
            #     matches a global were "replacements" (handled above by
            #     skipping the global).  Overrides with names NOT in
            #     globals are "extras" — always emitted.
            #     When use_desc_as_key=true, all overrides are emitted
            #     (globals were already emitted above, both coexist).
            for ovr in sn_overrides:
                entry = copy.deepcopy(ovr)
                entry["switch"] = sn
                result.append(entry)

        return result

    def resolve_switch_identifiers(self, config):
        """Resolve switch IP/hostname inputs to serial numbers.

        The user's arg-spec field is ``serial_number`` with alias ``ip``.
        After ``translate_config()`` the value lives in ``entry["switch"]``
        as a plain string.

        Resolution logic:
            1. If the value does NOT look like an IP or hostname it is
               assumed to be a serial number already → pass through.
            2. If the value looks like an IP or hostname, query the fabric
               switch inventory and resolve it to a serial number.
            3. If resolution fails, fail with a clear error.

        Args:
            config: Flat config list from ``translate_config()``.

        Returns:
            The config list with all switch identifiers resolved to serials.
        """
        if config is None:
            return []

        needs_lookup = set()
        for entry in config:
            switch_value = entry.get("switch")
            if isinstance(switch_value, list):
                for switch_entry in switch_value:
                    val = switch_entry.get("serial_number") or switch_entry.get("ip") or ""
                    if _needs_resolution(val):
                        needs_lookup.add(val)
            elif isinstance(switch_value, str) and _needs_resolution(switch_value):
                needs_lookup.add(switch_value)

        if not needs_lookup:
            return config

        switches = self._query_fabric_switches()

        ip_map = {}
        hostname_map = {}
        for switch in switches:
            switch_id = switch.get("switchId") or switch.get("serialNumber")
            if not switch_id:
                continue
            fabric_ip = switch.get("fabricManagementIp") or switch.get("ip")
            if fabric_ip:
                ip_map[str(fabric_ip).strip()] = switch_id
            hostname = switch.get("hostname")
            if hostname:
                hostname_map[str(hostname).strip().lower()] = switch_id

        def _resolve(identifier):
            if identifier is None:
                return None
            value = str(identifier).strip()
            if not value:
                return value
            return ip_map.get(value) or hostname_map.get(value.lower())

        for entry in config:
            switch_value = entry.get("switch")

            if isinstance(switch_value, list):
                for switch_entry in switch_value:
                    original = switch_entry.get("serial_number") or switch_entry.get("ip")
                    if not _needs_resolution(original):
                        continue
                    resolved = _resolve(original)
                    if resolved is None:
                        self.module.fail_json(
                            msg=(
                                f"Unable to resolve switch identifier '{original}' to a serial number "
                                f"in fabric '{self.fabric_name}'. Provide a valid switch serial_number, "
                                "management IP, or hostname from the fabric inventory."
                            )
                        )
                    switch_entry["serial_number"] = resolved
                    if "ip" in switch_entry:
                        switch_entry["ip"] = resolved
            elif isinstance(switch_value, str):
                if not _needs_resolution(switch_value):
                    continue
                resolved = _resolve(switch_value)
                if resolved is None:
                    self.module.fail_json(
                        msg=(
                            f"Unable to resolve switch identifier '{switch_value}' to a serial number "
                            f"in fabric '{self.fabric_name}'. Provide a valid switch serial_number, "
                            "management IP, or hostname from the fabric inventory."
                        )
                    )
                entry["switch"] = resolved

        return config

    def _query_fabric_switches(self) -> List[Dict]:
        """Query all switches for the fabric and return raw switch records.

        Uses RestSend save_settings/restore_settings to temporarily force
        check_mode=False so that this read-only GET always hits the controller,
        even when the module is running in Ansible check mode.

        Returns:
            List of switch record dicts from the fabric inventory API.
        """
        path = f"{BasePath.path('fabrics', self.fabric_name, 'switches')}?max=10000"

        rest_send = self.nd._get_rest_send()
        rest_send.save_settings()
        rest_send.check_mode = False
        try:
            response = self.nd.request(path)
        finally:
            rest_send.restore_settings()

        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            return response.get("switches", [])
        return []

    def validate_translated_config(self, translated_config):
        """Validate the translated (flat) config before handing it to manage_state.

        Checks performed:
            - Every entry must have a ``switch`` serial number.

        Note:
            Field-level validation (name required, priority range, description
            length, etc.) is handled by ``PlaybookPolicyConfig`` Pydantic
            models before translation.  This method only checks post-
            translation invariants.

        Args:
            translated_config: Flat config list from ``translate_config()``.

        Returns:
            None.

        Raises:
            Calls ``module.fail_json`` on validation failure.
        """
        for idx, entry in enumerate(translated_config):
            if not entry.get("switch"):
                self.module.fail_json(
                    msg=f"config[{idx}]: every policy entry must have a switch serial number after translation."
                )

    # =========================================================================
    # Public API - State Management
    # =========================================================================

    def validate_and_prepare_config(self) -> None:
        """Validate, normalize, resolve, and flatten the playbook config.

        Full pipeline executed before state dispatch:
            1. **Pydantic validation** — each ``config[]`` entry is validated
               against ``PlaybookPolicyConfig``.  Also applies defaults
               (priority=500, description="", etc.) since the nested arg_spec
               options were removed in favour of Pydantic.
            2. **Resolve switch identifiers** — IPs/hostnames → serial numbers
               via a fabric inventory API call.
            3. **Translate config** — flatten the two-level (globals + switch
               entry) structure into one dict per (policy, switch).
            4. **Validate translated config** — ensure every entry has a switch.

        After this method, ``self.config`` and ``module.params["config"]``
        contain the flat, validated, ready-to-process list.

        Returns:
            None.
        """
        self.log.info("Validating and preparing config")

        # Step 1: Pydantic validation + normalization
        validation_context = {"state": self.state, "use_desc_as_key": self.use_desc_as_key}
        normalized_config = []
        for idx, entry in enumerate(self.config):
            try:
                validated = PlaybookPolicyConfig.model_validate(entry, context=validation_context)
                normalized_config.append(validated.model_dump(by_alias=False, exclude_none=False))
            except ValidationError as ve:
                self.module.fail_json(
                    msg=f"Input validation failed for config[{idx}]: {ve}"
                )
            except ValueError as ve:
                self.module.fail_json(
                    msg=f"Input validation failed for config[{idx}]: {ve}"
                )
        self.config = normalized_config
        self.module.params["config"] = normalized_config

        # Step 2: Resolve switch IPs/hostnames → serial numbers
        resolved_config = self.resolve_switch_identifiers(
            copy.deepcopy(self.config),
        )

        # Step 3: Flatten multi-switch config into one entry per (policy, switch)
        translated_config = self.translate_config(
            resolved_config,
            self.use_desc_as_key,
        )

        # Step 4: Validate translated config
        self.validate_translated_config(translated_config)

        # Update config references
        self.config = translated_config
        self.module.params["config"] = translated_config

    def manage_state(self) -> None:
        """Main entry point for state management.

        Validates, normalizes, and prepares the config, then dispatches
        to the appropriate handler:
            - **merged**  - create / update / skip policies
            - **deleted** - deploy=true: markDelete → pushConfig → remove
                          - deploy=false: markDelete only

        The entire task is treated as an atomic unit — any validation
        failure aborts the run before any changes are made.

        Returns:
            None.
        """
        self.log.info(f"Managing state: {self.state}")

        # Gathered state: skip the full config pipeline when config is empty
        if self.state == "gathered":
            if self.config:
                # With config: validate & prepare, then gather matching policies
                self.validate_and_prepare_config()
            self._handle_gathered_state()
            return

        # Full config pipeline: pydantic → resolve → translate → validate
        self.validate_and_prepare_config()

        # Upfront cross-entry validation — hard-fail before any API mutations
        self._validate_config()

        if self.state == "merged":
            self._handle_merged_state()
        elif self.state == "deleted":
            self._handle_deleted_state()
        else:
            self.module.fail_json(msg=f"Unsupported state: {self.state}")

    # =========================================================================
    # Upfront Validation
    # =========================================================================

    def _validate_config(self) -> None:
        """Validate cross-entry invariants before any API calls are made.

        When ``use_desc_as_key=true``, the ``description + switch``
        combination must be unique across all config entries within
        the playbook.  Duplicate pairs would lead to ambiguous matching
        at the controller and are rejected.

        Note:
            Per-entry checks (name required, description non-empty,
            priority range, max-length, etc.) are handled by
            ``PlaybookPolicyConfig`` Pydantic validation in
            ``validate_and_prepare_config()``.  This method only
            validates cross-entry constraints that Pydantic cannot
            enforce because it sees one entry at a time.

        Returns:
            None.
        """
        if not self.use_desc_as_key:
            return

        self.log.debug("ENTER: _validate_config() [use_desc_as_key=true]")

        desc_switch_counts: Dict[str, int] = {}

        for idx, entry in enumerate(self.config):
            name = entry.get("name", "")
            switch = entry.get("switch", "")
            description = entry.get("description", "")

            # Skip validation for policy-ID lookups (direct by ID) and
            # switch-only entries (no name → "all policies on switch").
            if name and self._is_policy_id(name):
                continue
            if not name:
                continue

            # Cross-entry uniqueness: description + switch must be unique.
            if description:
                key = f"{description}|{switch}"
                desc_switch_counts[key] = desc_switch_counts.get(key, 0) + 1

        # Report all duplicates at once
        duplicates = [
            f"description='{k.split('|')[0]}', switch='{k.split('|')[1]}'"
            for k, count in desc_switch_counts.items()
            if count > 1
        ]
        if duplicates:
            self.module.fail_json(
                msg=(
                    "Duplicate description+switch combinations found in the "
                    "playbook config (use_desc_as_key=true requires each "
                    "description to be unique per switch): "
                    + "; ".join(duplicates)
                )
            )

        self.log.debug("EXIT: _validate_config() — all checks passed")

    # =========================================================================
    # State Handlers
    # =========================================================================

    def _handle_merged_state(self) -> None:
        """Handle state=merged: create, update, or skip policies.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_merged_state()")
        self.log.info("Handling merged state")
        self.log.debug(f"Config entries: {len(self.config)}")

        # Phase 1: Build want and have for each config entry
        diff_results = []
        for config_entry in self.config:
            want = self._build_want(config_entry, state="merged")

            # Phase 1a: Validate templateInputs against template schema
            template_name = want.get("templateName")
            template_inputs = want.get("templateInputs") or {}
            if template_name and not self._is_policy_id(template_name):
                validation_errors = self._validate_template_inputs(
                    template_name, template_inputs
                )
                if validation_errors:
                    error_msg = (
                        f"Template input validation failed for '{template_name}': "
                        + "; ".join(validation_errors)
                    )
                    self.log.error(error_msg)
                    diff_results.append({
                        "action": "fail",
                        "want": want,
                        "have": None,
                        "diff": None,
                        "policy_id": None,
                        "error_msg": error_msg,
                    })
                    continue

            have_list, error_msg = self._build_have(want)

            if error_msg:
                self.log.error(f"Build have failed: {error_msg}")
                diff_results.append({
                    "action": "fail",
                    "want": want,
                    "have": None,
                    "diff": None,
                    "policy_id": None,
                    "error_msg": error_msg,
                })
                continue

            # Phase 2: Compute diff
            diff_entry = self._get_diff_merged_single(want, have_list)
            self.log.debug(
                f"Diff result for {want.get('templateName', want.get('policyId', 'unknown'))}: "
                f"action={diff_entry['action']}"
            )
            diff_results.append(diff_entry)

        self.log.info(f"Computed {len(diff_results)} diff results")

        # Phase 3: Execute actions
        policy_ids_to_deploy = self._execute_merged(diff_results)

        # Phase 4: Deploy if requested
        if self.deploy and policy_ids_to_deploy:
            self.log.info(f"Deploying {len(policy_ids_to_deploy)} policies")
            deploy_success = self._deploy_policies(policy_ids_to_deploy)
            if not deploy_success:
                self.log.error(
                    "pushConfig failed for one or more policies after "
                    "create/update. Policies exist on the controller but "
                    "have not been deployed to the switch."
                )
                self._register_result(
                    action="policy_deploy_failed",
                    operation_type=OperationType.UPDATE,
                    return_code=-1,
                    message=(
                        "pushConfig failed for one or more policies. "
                        "Policies were created/updated on the controller but "
                        "not deployed to the switch. Fix device connectivity "
                        "and re-run with deploy=true."
                    ),
                    success=False,
                    found=True,
                    diff={
                        "action": "deploy_failed",
                        "policy_ids": policy_ids_to_deploy,
                        "reason": "pushConfig per-policy failure",
                    },
                )
        elif not self.deploy:
            self.log.info("Deploy not requested, skipping pushConfig")

        self.log.debug("EXIT: _handle_merged_state()")

    def _handle_deleted_state(self) -> None:
        """Handle state=deleted: remove policies from NDFC.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_deleted_state()")
        self.log.info("Handling deleted state")
        self.log.debug(f"Config entries: {len(self.config)}")

        # Phase 1: Build want and have for each config entry
        diff_results = []
        for config_entry in self.config:
            want = self._build_want(config_entry, state="deleted")
            have_list, error_msg = self._build_have(want)

            if error_msg:
                self.log.error(f"Build have failed: {error_msg}")
                diff_results.append({
                    "action": "fail",
                    "want": want,
                    "policies": [],
                    "policy_ids": [],
                    "match_count": 0,
                    "warning": None,
                    "error_msg": error_msg,
                })
                continue

            # Phase 2: Compute delete result
            diff_entry = self._get_diff_deleted_single(want, have_list)
            self.log.debug(
                f"Delete diff for {want.get('templateName', want.get('policyId', 'switch-only'))}: "
                f"action={diff_entry['action']}"
            )
            diff_results.append(diff_entry)

        # Phase 3: Execute delete actions
        self.log.info(f"Computed {len(diff_results)} delete results")
        self._execute_deleted(diff_results)
        self.log.debug("EXIT: _handle_deleted_state()")

    # =========================================================================
    # Gathered State
    # =========================================================================

    def _handle_gathered_state(self) -> None:
        """Handle state=gathered: export existing policies as playbook-ready config.

        Two modes:
            - **With config** — ``self.config`` is non-empty. For each config
              entry, look up matching policies and
              convert each match into a playbook-compatible config dict.
            - **Without config** — ``self.config`` is empty. Fetch *all*
              policies on the fabric and convert them.

        The converted output is stored in ``self._gathered`` and surfaced
        in the module return under the ``gathered`` key.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_gathered_state()")
        self.log.info("Handling gathered state")

        policies: List[Dict] = []

        if self.config:
            # --- With config: query matching policies per entry ---
            self.log.info(f"Gathered with config: {len(self.config)} entries")
            for config_entry in self.config:
                want = self._build_want(config_entry, state="gathered")
                have_list, error_msg = self._build_have(want)

                if error_msg:
                    self.log.warning(f"Gathered: build_have error: {error_msg}")
                    self._register_result(
                        action="policy_gathered",
                        state="gathered",
                        operation_type=OperationType.QUERY,
                        return_code=-1,
                        message=error_msg,
                        success=False,
                        found=False,
                        diff={"action": "fail", "want": want, "error": error_msg},
                    )
                    continue

                policies.extend(have_list)
        else:
            # --- Without config: fetch every policy on every switch ---
            self.log.info("Gathered without config: fetching all fabric switches")
            switches = self._get_fabric_switches()
            if not switches:
                self.log.warning("No switches found in fabric")
                self._register_result(
                    action="policy_gathered",
                    state="gathered",
                    operation_type=OperationType.QUERY,
                    return_code=200,
                    message="No switches found in fabric",
                    success=True,
                    found=False,
                    diff={"action": "not_found"},
                )
                self.log.debug("EXIT: _handle_gathered_state()")
                return

            for switch_sn in switches:
                self.log.debug(f"Gathering policies for switch {switch_sn}")
                lucene = self._build_lucene_filter(switchId=switch_sn)
                switch_policies = self._query_policies(lucene, include_mark_deleted=False)
                self.log.info(
                    f"Found {len(switch_policies)} policies on switch {switch_sn}"
                )
                policies.extend(switch_policies)

        if not policies:
            self.log.info("Gathered: no policies found")
            self._register_result(
                action="policy_gathered",
                state="gathered",
                operation_type=OperationType.QUERY,
                return_code=200,
                message="No policies found",
                success=True,
                found=False,
                diff={"action": "not_found", "match_count": 0},
            )
            self.log.debug("EXIT: _handle_gathered_state()")
            return

        # De-duplicate by policyId (multiple config entries might match
        # the same underlying policy).
        seen_ids: set = set()
        unique_policies: List[Dict] = []
        for pol in policies:
            pid = pol.get("policyId")
            if pid and pid in seen_ids:
                continue
            if pid:
                seen_ids.add(pid)
            unique_policies.append(pol)

        self.log.info(f"Gathered {len(unique_policies)} unique policies (from {len(policies)} total)")

        # Convert each policy to playbook-ready config
        for policy in unique_policies:
            config_entry = self._policy_to_config(policy)
            self._gathered.append(config_entry)

        self._register_result(
            action="policy_gathered",
            state="gathered",
            operation_type=OperationType.QUERY,
            return_code=200,
            message=f"Gathered {len(self._gathered)} policies",
            data=self._gathered,
            success=True,
            found=True,
            diff={"action": "gathered", "match_count": len(self._gathered)},
        )

        self.log.debug("EXIT: _handle_gathered_state()")

    def _get_fabric_switches(self) -> List[str]:
        """Fetch all switch serial numbers in the current fabric.

        Delegates to ``_query_fabric_switches()`` for the API call and
        extracts serial numbers from the raw switch records.

        Returns:
            List of serial number strings.
        """
        self.log.debug("ENTER: _get_fabric_switches()")

        try:
            records = self._query_fabric_switches()
        except Exception as exc:
            self.log.warning(f"Failed to fetch fabric switches: {exc}")
            return []

        switches = []
        for sw in records:
            sn = sw.get("serialNumber") or sw.get("switchId") or sw.get("switchDbID")
            if sn:
                switches.append(sn)

        self.log.info(f"Found {len(switches)} switches in fabric '{self.fabric_name}'")
        self.log.debug(f"EXIT: _get_fabric_switches() -> {switches}")
        return switches

    def _policy_to_config(self, policy: Dict) -> Dict:
        """Convert a controller policy dict to a playbook-compatible config entry.

        The output format matches what ``state=merged`` expects, so the
        user can copy-paste the gathered output directly into a playbook.

        Internal template input keys (e.g., ``FABRIC_NAME``, ``POLICY_ID``,
        ``SERIAL_NUMBER``) are stripped via ``_clean_template_inputs()``.

        Args:
            policy: Raw policy dict from the NDFC API.

        Returns:
            Dict with keys: name, policy_id, switch, description, priority,
            template_inputs, create_additional_policy.
        """
        template_name = policy.get("templateName", "")
        policy_id = policy.get("policyId", "")
        description = policy.get("description", "")
        priority = policy.get("priority", 500)
        switch_id = policy.get("switchId") or policy.get("serialNumber", "")

        # Parse templateInputs — stored as a JSON-encoded string or dict
        raw_inputs = policy.get("templateInputs") or policy.get("nvPairs") or {}
        if isinstance(raw_inputs, str):
            import json
            try:
                raw_inputs = json.loads(raw_inputs)
            except (json.JSONDecodeError, ValueError):
                self.log.warning(
                    f"Failed to parse templateInputs for {policy_id}: {raw_inputs!r}"
                )
                raw_inputs = {}

        # Clean internal keys from template inputs
        cleaned_inputs = self._clean_template_inputs(template_name, raw_inputs)

        config_entry = {
            "name": template_name,
            "policy_id": policy_id,
            "switch": [{"serial_number": switch_id}],
            "description": description,
            "priority": priority,
            "template_inputs": cleaned_inputs,
            "create_additional_policy": False,
        }

        self.log.debug(f"Converted policy {policy_id} to config: {config_entry}")
        return config_entry

    def _clean_template_inputs(
        self, template_name: str, raw_inputs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Remove system-injected keys from template inputs.

        Fetches the template's parameter definitions via the
        configTemplates API and keeps **only** the keys that appear in
        the template's parameter list.  Any key in ``raw_inputs`` that
        is not a declared template parameter (e.g. ``FABRIC_NAME``,
        ``POLICY_ID``, ``SERIAL_NUMBER``) is an NDFC-injected system
        key and is stripped.

        If the template parameter fetch fails, falls back to a
        hardcoded set of known NDFC-injected keys and emits a warning.

        Args:
            template_name: Template name for fetching parameter definitions.
            raw_inputs:    Raw ``templateInputs`` dict from the controller.

        Returns:
            Cleaned dict with only actual template parameter keys.
        """
        self.log.debug(
            f"ENTER: _clean_template_inputs(template={template_name}, "
            f"keys={list(raw_inputs.keys())})"
        )

        params = self._fetch_template_params(template_name)

        if params:
            # Build set of ALL parameter names declared in the template.
            # Only keys present in this set are real template inputs;
            # everything else is NDFC-injected and should be stripped.
            template_param_names: set = set()
            for p in params:
                name = p.get("name")
                if name:
                    template_param_names.add(name)

            self.log.debug(
                f"Template '{template_name}': {len(template_param_names)} "
                f"declared params: {sorted(template_param_names)}"
            )

            cleaned = {
                k: v for k, v in raw_inputs.items()
                if k in template_param_names
            }

            stripped = set(raw_inputs.keys()) - template_param_names
            if stripped:
                self.log.debug(
                    f"Stripped {len(stripped)} non-template keys: {sorted(stripped)}"
                )
        else:
            # Fallback: strip commonly known NDFC-injected keys
            _KNOWN_INTERNAL_KEYS = {
                "FABRIC_NAME", "POLICY_ID", "POLICY_DESC", "PRIORITY",
                "SERIAL_NUMBER", "SECENTITY", "SECENTTYPE", "SOURCE",
                "MARK_DELETED", "SWITCH_DB_ID", "POLICY_GROUP_ID",
            }
            self.log.warning(
                f"Could not fetch template params for '{template_name}'. "
                f"Falling back to hardcoded internal keys: {sorted(_KNOWN_INTERNAL_KEYS)}"
            )
            cleaned = {
                k: v for k, v in raw_inputs.items()
                if k not in _KNOWN_INTERNAL_KEYS
            }

        self.log.debug(
            f"EXIT: _clean_template_inputs() -> {len(cleaned)} keys "
            f"(removed {len(raw_inputs) - len(cleaned)})"
        )
        return cleaned

    # =========================================================================
    # Helpers: Classification & Filtering
    # =========================================================================

    @staticmethod
    def _is_policy_id(name: str) -> bool:
        """Return True if name looks like a policy ID (starts with POLICY-).

        Args:
            name: Policy name or ID string to check.

        Returns:
            True if the name starts with ``POLICY-``, False otherwise.
        """
        return name.upper().startswith("POLICY-")

    @staticmethod
    def _build_lucene_filter(**kwargs: Any) -> str:
        """Build a Lucene filter string from keyword arguments.

        Example::

            _build_lucene_filter(switchId="FDO123", templateName="feature_enable")
            # Returns: "switchId:FDO123 AND templateName:feature_enable"

        Args:
            **kwargs: Key-value pairs to include in the Lucene filter.
                None values are skipped.

        Returns:
            Lucene filter string with terms joined by ``AND``.
        """
        parts = []
        for key, value in kwargs.items():
            if value is not None:
                parts.append(f"{key}:{value}")
        return " AND ".join(parts)

    @staticmethod
    def _policies_differ(want: Dict, have: Dict) -> Dict:
        """Compare want vs have policy to determine if an update is needed.

        Fields compared:
            - description
            - priority
            - templateInputs (only keys the user specified, with str() normalization.
              The controller injects extra keys like FABRIC_NAME that we must ignore.)

        Fields NOT compared (identity/read-only):
            - policyId, switchId, templateName, source
            - entityType, entityName, createTimestamp, updateTimestamp
            - generatedConfig, markDeleted

        Args:
            want: Desired policy state dict.
            have: Existing policy dict from the controller.

        Returns:
            Dict with changed fields, or empty dict if identical.
        """
        diff = {}

        # Compare description
        want_desc = want.get("description", "") or ""
        have_desc = have.get("description", "") or ""
        if want_desc != have_desc:
            diff["description"] = {"want": want_desc, "have": have_desc}

        # Compare priority
        want_priority = want.get("priority", 500)
        have_priority = have.get("priority", 500)
        if want_priority != have_priority:
            diff["priority"] = {"want": want_priority, "have": have_priority}

        # Compare templateInputs — only check keys the user specified.
        # The controller injects additional keys (e.g., FABRIC_NAME) that
        # the user didn't provide. We must ignore those to avoid false diffs.
        want_inputs = want.get("templateInputs") or {}
        have_inputs = have.get("templateInputs") or {}
        input_diff = {}
        for key in want_inputs:
            want_val = str(want_inputs[key])
            have_val = str(have_inputs.get(key, ""))
            if want_val != have_val:
                input_diff[key] = {"want": want_inputs[key], "have": have_inputs.get(key)}
        if input_diff:
            diff["templateInputs"] = input_diff

        return diff

    # =========================================================================
    # API Query Helpers
    # =========================================================================

    def _query_policies_raw(
        self, lucene_filter: Optional[str] = None
    ) -> List[Dict]:
        """Query policies from the controller using GET /policies (unfiltered).

        Returns **all** matching policies including ``markDeleted`` and
        internal (``source != ""``) entries.  Callers that need the raw
        list (cleanup routines, gathered-state export) should use this
        directly.  For idempotency checks use ``_query_policies()``
        which filters out stale records.

        Args:
            lucene_filter: Optional Lucene filter string.

        Returns:
            List of policy dicts from the response.
        """
        self.log.debug(f"Querying policies (raw) with filter: {lucene_filter}")

        ep = EpManagePoliciesGet()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if lucene_filter:
            ep.lucene_params.filter = lucene_filter
        # Set max to retrieve all matching policies.
        # Default page size is 10 which causes missed matches.
        ep.lucene_params.max = 10000

        data = self.nd.request(ep.path, ep.verb)
        if isinstance(data, dict):
            policies = data.get("policies", [])
            self.log.debug(f"Raw query returned {len(policies)} policies")
            return policies
        self.log.debug("Query returned non-dict response, returning empty list")
        return []

    def _query_policies(
        self,
        lucene_filter: Optional[str] = None,
        include_mark_deleted: bool = False,
    ) -> List[Dict]:
        """Query policies with idempotency-safe filtering.

        Wraps ``_query_policies_raw()`` and applies post-filters:

        - **markDeleted** — when ``include_mark_deleted=False`` (default),
          policies pending deletion are excluded so they don't interfere
          with idempotency checks.  When ``True``, they are kept and
          annotated with ``_markDeleted_stale: True`` so callers can
          surface the status to the user.
        - **source != ""** — internal NDFC sub-policies are always
          excluded; they are artefacts that cause false duplicate
          matches.

        Args:
            lucene_filter: Optional Lucene filter string.
            include_mark_deleted: When True, keep markDeleted policies
                and annotate them instead of filtering them out.

        Returns:
            List of policy dicts from the response.
        """
        raw = self._query_policies_raw(lucene_filter)
        if not raw:
            return []

        result: List[Dict] = []
        excluded = 0
        for p in raw:
            # Always exclude internal NDFC sub-policies (source != "")
            if p.get("source", "") != "":
                excluded += 1
                continue

            if p.get("markDeleted", False):
                if include_mark_deleted:
                    # Annotate so callers can display the status
                    p["_markDeleted_stale"] = True
                    result.append(p)
                else:
                    excluded += 1
                continue

            result.append(p)

        self.log.debug(
            f"After filtering: {len(result)} policies "
            f"(excluded {excluded}, include_mark_deleted={include_mark_deleted})"
        )
        return result

    def _query_policy_by_id(
        self, policy_id: str, include_mark_deleted: bool = False
    ) -> Optional[Dict]:
        """Query a single policy by its ID.

        By default, policies marked for deletion (``markDeleted=True``)
        are treated as non-existent because they are pending removal
        and cannot be updated.  When ``include_mark_deleted=True``,
        they are returned with an annotation so the
        caller can surface the status.

        Args:
            policy_id: Policy ID (e.g., "POLICY-121110").
            include_mark_deleted: When True, return markDeleted policies
                annotated with ``_markDeleted_stale: True``.

        Returns:
            Policy dict, or None if not found.
        """
        self.log.debug(f"Looking up policy by ID: {policy_id}")

        ep = EpManagePoliciesGet()
        ep.fabric_name = self.fabric_name
        ep.policy_id = policy_id
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name

        try:
            data = self.nd.request(ep.path, ep.verb)
            if isinstance(data, dict) and data:
                # The controller may return a 200 with an error body when the
                # policy is not found, e.g. {'code': 404, 'message': '...not found'}.
                # Only treat the response as a valid policy if it contains a policyId.
                if "policyId" not in data:
                    self.log.info(
                        f"Policy {policy_id} not found (response has no policyId: "
                        f"{data.get('message', data.get('code', 'unknown'))})"
                    )
                    return None
                if data.get("markDeleted", False):
                    if include_mark_deleted:
                        data["_markDeleted_stale"] = True
                        self.log.info(
                            f"Policy {policy_id} is marked for deletion (included with annotation)"
                        )
                        return data
                    self.log.info(
                        f"Policy {policy_id} is marked for deletion, treating as not found"
                    )
                    return None
                self.log.debug(f"Policy {policy_id} found")
                return data
            self.log.info(f"Policy {policy_id} not found (empty response)")
            return None
        except NDModuleError as error:
            # 404 means policy not found
            if error.status == 404:
                self.log.info(f"Policy {policy_id} not found (404)")
                return None
            raise

    # =========================================================================
    # Core: Build want / have
    # =========================================================================

    def _build_want(self, config_entry: Dict, state: str = "merged") -> Dict:
        """Translate a single user config entry to the API-compatible want dict.

        For merged state, ``name`` is required and all fields are included.
        For gathered/deleted state, ``name`` is optional — when omitted, only
        ``switchId`` is set, which means "return all policies on this switch".

        Args:
            config_entry: Single dict from the user's config list.
            state: Module state ("merged", "gathered", or "deleted").

        Returns:
            Dict with camelCase keys matching the API schema.
        """
        self.log.debug(f"Building want for state={state}, name={config_entry.get('name')}")

        want = {
            "switchId": config_entry["switch"],
        }

        name = config_entry.get("name")

        if name and self._is_policy_id(name):
            want["policyId"] = name
        elif name:
            want["templateName"] = name

        # Per-entry create_additional_policy flag (carried on want dict)
        want["create_additional_policy"] = config_entry.get("create_additional_policy", True)

        # For merged state, include all payload fields
        if state == "merged":
            want["entityType"] = "switch"
            want["entityName"] = "SWITCH"
            want["description"] = config_entry.get("description", "")
            want["priority"] = config_entry.get("priority", 500)
            want["templateInputs"] = config_entry.get("template_inputs") or {}
        else:
            # For gathered/deleted state, only include description if provided
            description = config_entry.get("description", "")
            if description:
                want["description"] = description

        self.log.debug(f"Built want: {want}")
        return want

    # =========================================================================
    # Template Input Validation
    # =========================================================================

    def _fetch_template_params(self, template_name: str) -> List[Dict]:
        """Fetch and cache parameter definitions for a config template.

        Calls ``GET /api/v1/manage/configTemplates/{templateName}`` and
        extracts the ``parameters`` array. Results are cached per
        ``template_name`` so multiple config entries sharing the same
        template incur only one API call.

        Args:
            template_name: The NDFC template name (e.g., ``switch_freeform``).

        Returns:
            List of parameter dicts, each with at minimum ``name``,
            ``parameterType``, ``optional``, and ``defaultValue`` keys.
            Returns an empty list if the template has no parameters or
            the API call fails.
        """
        self.log.debug(f"ENTER: _fetch_template_params(template_name={template_name})")

        if template_name in self._template_params_cache:
            self.log.debug(
                f"Template params cache hit for '{template_name}': "
                f"{len(self._template_params_cache[template_name])} params"
            )
            return self._template_params_cache[template_name]

        ep = EpManageConfigTemplateParametersGet()
        ep.template_name = template_name

        try:
            data = self.nd.request(ep.path, ep.verb)
        except Exception as exc:
            self.log.warning(
                f"Failed to fetch template '{template_name}' parameters: {exc}. "
                "Skipping template input validation."
            )
            self._template_params_cache[template_name] = []
            return []

        # The response is a templateData object with 'parameters' key.
        # 'parameters' is a list of templateParameter objects.
        params = data.get("parameters") if isinstance(data, dict) else []
        if params is None:
            params = []

        self._template_params_cache[template_name] = params
        self.log.info(
            f"Fetched {len(params)} parameter definitions for template '{template_name}'"
        )
        self.log.debug(
            f"Template '{template_name}' param names: "
            f"{[p.get('name') for p in params]}"
        )
        self.log.debug(f"EXIT: _fetch_template_params()")
        return params

    def _validate_template_inputs(
        self, template_name: str, template_inputs: Dict[str, Any]
    ) -> List[str]:
        """Validate user-provided templateInputs against the template schema.

        Performs three checks:
            1. **Unknown keys** — every key in ``template_inputs`` must
               correspond to a parameter ``name`` in the template definition.
            2. **Missing required parameters** — every parameter where
               ``optional`` is ``False`` AND ``defaultValue`` is empty/null
               must be supplied by the user.
            3. **Basic type validation** — lightweight format checks for
               common ``parameterType`` values (boolean, Integer, ipV4Address,
               etc.). Values that fail these checks are reported as warnings,
               not hard failures, because the controller's own validation is
               authoritative.

        Args:
            template_name: Template name for fetching parameter definitions.
            template_inputs: User-provided ``templateInputs`` dict.

        Returns:
            List of validation error message strings. Empty list means all
            inputs are valid.
        """
        self.log.debug(
            f"ENTER: _validate_template_inputs(template={template_name}, "
            f"input_keys={list(template_inputs.keys())})"
        )

        params = self._fetch_template_params(template_name)
        if not params:
            self.log.debug("No template params available, skipping validation")
            return []

        errors: List[str] = []

        # Build lookup: param_name -> param_def
        # Filter out internal parameters (annotations.IsInternal == "true")
        # that the controller auto-populates (e.g., SERIAL_NUMBER, POLICY_ID,
        # SOURCE, FABRIC_NAME). Users should never need to set these.
        param_map: Dict[str, Dict] = {}
        internal_names: set = set()
        for p in params:
            name = p.get("name")
            if not name:
                continue
            annotations = p.get("annotations") or {}
            if str(annotations.get("IsInternal", "")).lower() == "true":
                internal_names.add(name)
            else:
                param_map[name] = p

        self.log.debug(
            f"Template '{template_name}': {len(param_map)} user params, "
            f"{len(internal_names)} internal params ({sorted(internal_names)})"
        )

        # ------------------------------------------------------------------
        # Check 1: Unknown keys (skip internal params — they are allowed
        # but not advertised to users)
        # ------------------------------------------------------------------
        valid_names = set(param_map.keys()) | internal_names
        user_facing_names = set(param_map.keys())
        for user_key in template_inputs:
            if user_key not in valid_names:
                errors.append(
                    f"Unknown templateInput key '{user_key}' for template "
                    f"'{template_name}'. Valid keys: {sorted(user_facing_names)}"
                )

        # ------------------------------------------------------------------
        # Check 2: Missing required parameters
        # ------------------------------------------------------------------
        for pname, pdef in param_map.items():
            is_optional = pdef.get("optional", True)
            default_val = pdef.get("defaultValue")
            has_default = default_val is not None and str(default_val).strip() != ""

            if not is_optional and not has_default and pname not in template_inputs:
                errors.append(
                    f"Required templateInput '{pname}' (type={pdef.get('parameterType', '?')}) "
                    f"is missing for template '{template_name}'"
                )

        # ------------------------------------------------------------------
        # Check 3: Basic type validation (soft checks)
        # ------------------------------------------------------------------
        for user_key, user_val in template_inputs.items():
            pdef = param_map.get(user_key)
            if not pdef:
                continue  # Already flagged as unknown above

            ptype = (pdef.get("parameterType") or "").lower()
            val_str = str(user_val)

            if ptype == "boolean":
                if val_str.lower() not in ("true", "false"):
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects boolean (true/false), got '{val_str}'"
                    )

            elif ptype == "integer":
                try:
                    int(val_str)
                except ValueError:
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects integer, got '{val_str}'"
                    )

            elif ptype == "long":
                try:
                    int(val_str)
                except ValueError:
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects long integer, got '{val_str}'"
                    )

            elif ptype == "float":
                try:
                    float(val_str)
                except ValueError:
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects float, got '{val_str}'"
                    )

            elif ptype in ("ipv4address", "ipaddress"):
                # Basic IPv4 check
                ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
                if not re.match(ipv4_pattern, val_str):
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects IPv4 address (e.g., 192.168.1.1), got '{val_str}'"
                    )

            elif ptype == "ipv4addresswithsubnet":
                ipv4_subnet_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"
                if not re.match(ipv4_subnet_pattern, val_str):
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects IPv4 address with subnet (e.g., 192.168.1.1/24), got '{val_str}'"
                    )

            elif ptype == "macaddress":
                mac_pattern = r"^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$|^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$"
                if not re.match(mac_pattern, val_str):
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects MAC address, got '{val_str}'"
                    )

            elif ptype == "enum":
                # If metaProperties contains 'validValues', check against them
                meta = pdef.get("metaProperties") or {}
                valid_values_str = meta.get("validValues")
                if valid_values_str:
                    # validValues format is typically "val1,val2,val3"
                    valid_values = [v.strip() for v in valid_values_str.split(",")]
                    if val_str not in valid_values:
                        errors.append(
                            f"templateInput '{user_key}' for template '{template_name}' "
                            f"expects one of {valid_values}, got '{val_str}'"
                        )

        if errors:
            self.log.warning(
                f"Template input validation found {len(errors)} errors "
                f"for template '{template_name}': {errors}"
            )
        else:
            self.log.debug(
                f"Template input validation passed for template '{template_name}'"
            )

        self.log.debug("EXIT: _validate_template_inputs()")
        return errors

    def _build_have(self, want: Dict) -> Tuple[List[Dict], Optional[str]]:
        """Query the controller to find existing policies matching the want.

        Handles all lookup strategies:
            - Case A: Policy ID given → direct lookup
            - Case B: use_desc_as_key=false, templateName given → switchId + templateName
            - Case C: use_desc_as_key=true, templateName given → switchId + description
            - Case D: Switch-only (no templateName or policyId) → all policies on switch

        Args:
            want: Want dict produced by ``_build_want``.

        Returns:
            Tuple of (have_list, error_msg).
        """
        self.log.debug("ENTER: _build_have()")

        # Exclude markDeleted policies to avoid false idempotency matches.
        incl_md = False

        # Case A: Policy ID given directly
        if "policyId" in want:
            self.log.debug(f"Case A: Direct policy ID lookup: {want['policyId']}")
            policy = self._query_policy_by_id(want["policyId"], include_mark_deleted=incl_md)
            if policy:
                self.log.info(f"Policy {want['policyId']} found")
                return [policy], None
            self.log.info(f"Policy {want['policyId']} not found")
            return [], None

        # Case D: Switch-only — no name or policyId given
        if "templateName" not in want:
            self.log.debug(f"Case D: Switch-only lookup for {want['switchId']}")
            lucene = self._build_lucene_filter(switchId=want["switchId"])
            policies = self._query_policies(lucene, include_mark_deleted=incl_md)
            self.log.info(f"Found {len(policies)} policies on switch {want['switchId']}")
            return policies, None

        # Case B: use_desc_as_key=false, search by switchId + templateName
        if not self.use_desc_as_key:
            self.log.debug(
                f"Case B: Lookup by switchId={want['switchId']} + "
                f"templateName={want['templateName']}"
            )
            lucene = self._build_lucene_filter(
                switchId=want["switchId"],
                templateName=want["templateName"],
            )
            policies = self._query_policies(lucene, include_mark_deleted=incl_md)

            # If description is provided, use it as an additional post-filter
            want_desc = want.get("description", "")
            if want_desc:
                pre_filter_count = len(policies)
                policies = [
                    p for p in policies
                    if (p.get("description", "") or "") == want_desc
                ]
                self.log.debug(
                    f"Post-filtered by description: {len(policies)} of {pre_filter_count}"
                )

            self.log.info(f"Case B matched {len(policies)} policies")
            return policies, None

        # Case C: use_desc_as_key=true, search by switchId + description
        want_desc = want.get("description", "") or ""
        self.log.debug(
            f"Case C: Lookup by switchId={want['switchId']} + "
            f"description='{want_desc}'"
        )
        # For merged/deleted states, Pydantic enforces that description
        # is non-empty.  This guard covers gathered state where
        # Pydantic intentionally skips the check.
        if not want_desc:
            self.log.warning("Case C: description is required but not provided")
            return [], "description is required when use_desc_as_key=true and name is a template name"

        lucene = self._build_lucene_filter(
            switchId=want["switchId"],
            description=want_desc,
        )
        policies = self._query_policies(lucene, include_mark_deleted=incl_md)

        # IMPORTANT: Lucene does tokenized matching, not exact match.
        # Post-filter to ensure exact description match.
        exact_matches = [
            p for p in policies
            if (p.get("description", "") or "") == want_desc
        ]
        self.log.debug(
            f"Exact description match: {len(exact_matches)} of {len(policies)}"
        )

        self.log.info(f"Case C matched {len(exact_matches)} policies")
        self.log.debug("EXIT: _build_have()")
        return exact_matches, None

    # =========================================================================
    # Diff: Merged State (16 cases)
    # =========================================================================

    def _get_diff_merged_single(self, want: Dict, have_list: List[Dict]) -> Dict:
        """Compute the diff and determine the action for a single config entry.

        Args:
            want: Desired policy state dict.
            have_list: Matching policies from the controller.

        Returns:
            Dict with keys: action, want, have, diff, policy_id, error_msg.
        """
        result = {
            "action": None,
            "want": want,
            "have": None,
            "diff": None,
            "policy_id": None,
            "error_msg": None,
        }

        match_count = len(have_list)

        # =================================================================
        # CASES 1-6: Template name given, use_desc_as_key=false
        #
        # Template names are not unique — multiple policies can share the
        # same template.  Therefore, existing policies are never updated
        # in-place when identified by template name alone.  A new policy
        # is always created.  To update a specific policy, the user must
        # provide its policy ID.
        # create_additional_policy controls whether an identical (no-diff)
        # policy is duplicated.
        # =================================================================
        create_additional = want.get("create_additional_policy", True)

        if not self.use_desc_as_key and "templateName" in want:
            if match_count == 0:
                # Case 1: No match → CREATE
                result["action"] = "create"
                return result

            if match_count == 1:
                have = have_list[0]
                diff = self._policies_differ(want, have)
                result["have"] = have
                result["policy_id"] = have.get("policyId")

                if not diff:
                    if create_additional:
                        # Case 2a: Exact match, create_additional=true → CREATE duplicate
                        result["action"] = "create"
                        return result
                    # Case 2b: Exact match, create_additional=false → SKIP
                    result["action"] = "skip"
                    return result

                # Case 3/4: Diff exists — template name cannot uniquely
                # identify a policy, so always CREATE a new one.
                result["action"] = "create"
                result["diff"] = diff
                return result

            # match_count >= 2
            if create_additional:
                # Case 5: Multiple matches, create_additional=true → CREATE another
                result["action"] = "create"
                return result

            # Case 6: Multiple matches, create_additional=false → SKIP
            result["action"] = "skip"
            return result

        # =================================================================
        # CASES 7-11: Policy ID given
        # =================================================================
        if "policyId" in want:
            if match_count == 0:
                # Case 7: Policy ID not found → SKIP
                result["action"] = "skip"
                result["error_msg"] = (
                    f"Policy {want['policyId']} not found. "
                    "Cannot create a policy with a specific ID."
                )
                return result

            have = have_list[0]
            diff = self._policies_differ(want, have)
            result["have"] = have
            result["policy_id"] = have.get("policyId")

            # Carry forward templateName from existing policy for update payload
            if "templateName" not in want and "templateName" in have:
                want["templateName"] = have["templateName"]

            if not diff:
                if create_additional:
                    # Case 8a: Exact match, create_additional=true → CREATE duplicate
                    # Strip policyId so create doesn't fail with "not unique"
                    want.pop("policyId", None)
                    result["action"] = "create"
                    return result
                # Case 8b: Match, no diff → SKIP
                result["action"] = "skip"
                return result

            # Case 10/11: Match, has diff → UPDATE (policy ID uniquely
            # identifies the policy, so in-place update is safe)
            result["action"] = "update"
            result["diff"] = diff
            return result

        # =================================================================
        # CASES 12-16: use_desc_as_key=true
        # =================================================================
        if self.use_desc_as_key:
            if match_count == 0:
                # Case 12: No match → CREATE
                result["action"] = "create"
                return result

            if match_count == 1:
                have = have_list[0]
                result["have"] = have
                result["policy_id"] = have.get("policyId")

                # Check if template matches
                templates_match = want.get("templateName") == have.get("templateName")

                if templates_match:
                    diff = self._policies_differ(want, have)
                    if not diff:
                        # Case 13: Same template, no diff → SKIP
                        result["action"] = "skip"
                        return result

                    # Case 14: Same template, fields differ → UPDATE
                    result["action"] = "update"
                    result["diff"] = diff
                    return result

                # Case 15: Different template → DELETE old + CREATE new
                result["action"] = "delete_and_create"
                result["diff"] = {
                    "templateName": {
                        "want": want.get("templateName"),
                        "have": have.get("templateName"),
                    }
                }
                return result

            # Case 16: Multiple matches → hard FAIL (ambiguous)
            # Abort the entire task atomically — no partial changes.
            self.module.fail_json(
                msg=(
                    f"Multiple policies ({match_count}) found with description "
                    f"'{want.get('description')}' on switch {want.get('switchId')}. "
                    "Cannot determine which policy to update when "
                    "use_desc_as_key=true. Remove the duplicate policies from "
                    "NDFC or use a policy ID directly."
                )
            )

        # Should not reach here
        result["action"] = "fail"
        result["error_msg"] = "Unable to determine action for policy config."
        return result

    # =========================================================================
    # Execute: Merged State
    # =========================================================================

    def _execute_merged(self, diff_results: List[Dict]) -> List[str]:
        """Execute the computed actions for all config entries using bulk APIs.

        Instead of making one API call per entry, this method collects all
        create/update/delete_and_create entries into batches and executes
        them with minimal API calls:

            1. Register skip/fail results immediately (no API call).
            2. Collect ``delete_and_create`` removals → single bulk remove.
            3. Collect all creates (``create`` + ``delete_and_create``) →
               single bulk POST via ``_api_bulk_create_policies``.
            4. Execute updates individually (PUT has no bulk API).

        Args:
            diff_results: List of diff result dicts from _get_diff_merged_single.

        Returns:
            List of policy IDs to deploy (if deploy=true).
        """
        self.log.debug("ENTER: _execute_merged()")
        self.log.debug(f"Processing {len(diff_results)} diff entries")
        policy_ids_to_deploy = []

        # Batches for bulk execution
        # Each item is (diff_entry_index, diff_entry) to preserve ordering
        create_batch: List[Dict] = []
        update_batch: List[Dict] = []
        delete_and_create_batch: List[Dict] = []

        # ── Phase 1: Classify entries, register skip/fail immediately ───
        for diff_entry in diff_results:
            action = diff_entry["action"]
            want = diff_entry["want"]
            have = diff_entry["have"]
            error_msg = diff_entry["error_msg"]

            self.log.info(
                f"Classifying action={action} for "
                f"{want.get('templateName', want.get('policyId', 'unknown'))}"
            )

            if action == "fail":
                self._proposed.append(want)
                self._register_result(
                    action="policy_merged",
                    operation_type=OperationType.QUERY,
                    return_code=-1,
                    message=error_msg,
                    success=False,
                    found=False,
                    diff={"action": action, "want": want, "error": error_msg},
                )
                continue

            if action == "skip":
                self._proposed.append(want)
                if have:
                    self._before.append(have)
                    self._after.append(have)
                diff_payload = {"action": action, "want": want}
                if error_msg:
                    diff_payload["warning"] = error_msg
                self._register_result(
                    action="policy_merged",
                    operation_type=OperationType.QUERY,
                    return_code=200,
                    message="No changes needed",
                    data=have or {},
                    success=True,
                    found=have is not None,
                    diff=diff_payload,
                )
                continue

            if action == "create":
                create_batch.append(diff_entry)
                continue

            if action == "update":
                update_batch.append(diff_entry)
                continue

            if action == "delete_and_create":
                delete_and_create_batch.append(diff_entry)
                continue

        self.log.info(
            f"Batch summary: create={len(create_batch)}, "
            f"update={len(update_batch)}, "
            f"delete_and_create={len(delete_and_create_batch)}"
        )

        # ── Phase 2: Check mode — register all as would-be changes ──────
        if self.check_mode:
            for diff_entry in create_batch:
                want = diff_entry["want"]
                self._proposed.append(want)
                self._after.append(want)
                self._register_result(
                    action="policy_create",
                    operation_type=OperationType.CREATE,
                    return_code=200,
                    message="OK (check_mode)",
                    success=True,
                    found=False,
                    diff={"action": "create", "want": want, "diff": diff_entry["diff"]},
                )

            for diff_entry in update_batch:
                want, have = diff_entry["want"], diff_entry["have"]
                self._proposed.append(want)
                self._before.append(have)
                self._after.append({**have, **want})
                self._register_result(
                    action="policy_update",
                    operation_type=OperationType.UPDATE,
                    return_code=200,
                    message="OK (check_mode)",
                    success=True,
                    found=True,
                    diff={
                        "action": "update", "before": have,
                        "after": {**have, **want}, "want": want,
                        "have": have, "diff": diff_entry["diff"],
                        "policy_id": diff_entry["policy_id"],
                    },
                )

            for diff_entry in delete_and_create_batch:
                want, have = diff_entry["want"], diff_entry["have"]
                self._proposed.append(want)
                self._before.append(have)
                self._after.append(want)
                self._register_result(
                    action="policy_replace",
                    operation_type=OperationType.UPDATE,
                    return_code=200,
                    message="OK (check_mode)",
                    success=True,
                    found=True,
                    diff={
                        "action": "delete_and_create", "before": have,
                        "after": want, "want": want, "have": have,
                        "diff": diff_entry["diff"],
                        "delete_policy_id": diff_entry["policy_id"],
                    },
                )

            self.log.info("Check mode: all batches registered")
            self.log.debug("EXIT: _execute_merged()")
            return policy_ids_to_deploy

        # ── Phase 3: Execute delete_and_create removals ─────────────────
        #
        # We must fully remove old policies BEFORE creating replacements.
        # This follows the same delete logic as _execute_deleted:
        #
        #   1. markDelete → try for all old policies
        #   2. PYTHON-type fallback → direct DELETE /policies/{policyId}
        #   3. deploy=true → pushConfig (markDeleted) or switchActions/deploy
        #      (direct-deleted) to push config removal to the switch
        #   4. remove → hard-delete markDeleted policy records
        #
        # If the old policy's config isn't removed from the switch first,
        # the old template's config lines will remain on the device even
        # after the new template is deployed (different templates produce
        # different config — the new one won't negate the old one).
        #
        # If any removal fails, we must NOT create a replacement for that
        # entry — otherwise we'd create a duplicate.
        remove_failed_ids: set = set()
        if delete_and_create_batch:
            remove_ids = [
                d["policy_id"] for d in delete_and_create_batch if d["policy_id"]
            ]
            if remove_ids:
                self.log.info(
                    f"Phase 3: Removing {len(remove_ids)} old policies "
                    f"for delete_and_create: {remove_ids}"
                )

                # Build policy→switch map for switchActions/deploy
                dac_switch_map: Dict[str, str] = {}
                for d in delete_and_create_batch:
                    pid = d.get("policy_id", "")
                    have = d.get("have") or {}
                    sw = have.get("switchId", d.get("want", {}).get("switchId", ""))
                    if pid and sw:
                        dac_switch_map[pid] = sw

                # Step 3a: Attempt markDelete for all old policies
                self.log.info(
                    f"Phase 3a: markDelete for {len(remove_ids)} old policies"
                )
                mark_delete_data = self._api_mark_delete(remove_ids)

                mark_succeeded = []
                mark_failed_python = []
                mark_failed_other = []

                if isinstance(mark_delete_data, dict):
                    policies_response = mark_delete_data.get("policies", [])
                    failed_ids_set: set = set()
                    for p in policies_response:
                        pid = p.get("policyId", "")
                        status = str(p.get("status", "")).lower()
                        if status != "success":
                            failed_ids_set.add(pid)
                            msg = p.get("message", "")
                            if "content type PYTHON" in msg:
                                mark_failed_python.append(pid)
                                self.log.info(
                                    f"markDelete failed for {pid} "
                                    "(PYTHON content type) — will use "
                                    "direct DELETE"
                                )
                            else:
                                mark_failed_other.append(pid)
                                self.log.error(
                                    f"markDelete failed for {pid} "
                                    f"(status={p.get('status')!r}): {msg}"
                                )

                    mark_succeeded = [
                        pid for pid in remove_ids if pid not in failed_ids_set
                    ]

                    if not policies_response and remove_ids:
                        self.log.warning(
                            "markDelete returned empty 'policies' list — "
                            "treating all as succeeded (ambiguous response)"
                        )
                        mark_succeeded = list(remove_ids)
                else:
                    self.log.warning(
                        "markDelete returned non-dict response — "
                        "treating all as succeeded"
                    )
                    mark_succeeded = list(remove_ids)

                self.log.info(
                    f"Phase 3a results: {len(mark_succeeded)} markDeleted, "
                    f"{len(mark_failed_python)} PYTHON-type, "
                    f"{len(mark_failed_other)} other failures"
                )

                # Track truly failed (non-PYTHON) as remove failures
                remove_failed_ids.update(mark_failed_other)

                # Step 3b: Direct DELETE for PYTHON-type policies
                if mark_failed_python:
                    self.log.info(
                        f"Phase 3b: Direct DELETE for "
                        f"{len(mark_failed_python)} PYTHON-type policies"
                    )
                    direct_deleted = []
                    for pid in mark_failed_python:
                        try:
                            self._api_delete_policy(pid)
                            direct_deleted.append(pid)
                        except Exception:  # noqa: BLE001
                            self.log.error(
                                f"Direct DELETE also failed for {pid}"
                            )
                            remove_failed_ids.add(pid)

                    # Deploy to affected switches to push config removal
                    if direct_deleted and self.deploy:
                        affected_switches = list({
                            dac_switch_map[pid]
                            for pid in direct_deleted
                            if pid in dac_switch_map
                        })
                        if affected_switches:
                            self.log.info(
                                f"Phase 3b: switchActions/deploy for "
                                f"{len(affected_switches)} switch(es)"
                            )
                            self._api_deploy_switches(affected_switches)

                # Step 3c: pushConfig for markDeleted policies (deploy=true)
                if mark_succeeded and self.deploy:
                    self.log.info(
                        f"Phase 3c: pushConfig for "
                        f"{len(mark_succeeded)} markDeleted policies"
                    )
                    deploy_success = self._deploy_policies(
                        mark_succeeded, state="merged"
                    )
                    if not deploy_success:
                        self.log.error(
                            "pushConfig failed during delete_and_create — "
                            "old policy config may not be removed from switch"
                        )

                # Step 3d: remove markDeleted policy records
                if mark_succeeded:
                    self.log.info(
                        f"Phase 3d: remove {len(mark_succeeded)} "
                        f"markDeleted policy records"
                    )
                    remove_data = self._api_remove_policies(mark_succeeded)
                    rm_ok, rm_fail = self._inspect_207_policies(remove_data)

                    if not rm_ok and not rm_fail and mark_succeeded:
                        self.log.warning(
                            "remove returned no per-policy results — "
                            "treating as success (ambiguous response)"
                        )

                    if rm_fail:
                        for p in rm_fail:
                            pid = p.get("policyId", "")
                            if pid:
                                remove_failed_ids.add(pid)
                        fail_msgs = [
                            f"{p.get('policyId', '?')}: "
                            f"{p.get('message', 'unknown')}"
                            for p in rm_fail
                        ]
                        self.log.error(
                            f"remove failed for {len(rm_fail)} policy(ies): "
                            + "; ".join(fail_msgs)
                        )

        # ── Phase 4: Bulk create ────────────────────────────────────────
        #
        # We issue SEPARATE bulk create calls for pure creates vs
        # delete_and_create replacements.  This is important because:
        #
        #   - Pure creates are safe to fail: no data loss, user re-runs.
        #   - DAC replacements have already deleted the old policy in
        #     Phase 3.  If the create fails, the policy is ORPHANED
        #     (old one gone, new one not created).  Keeping them in a
        #     separate call prevents a pure-create failure from causing
        #     a bulk 4xx/5xx that takes down DAC entries with it.
        #
        # Within each batch, per-policy 207 failures are handled
        # individually — a single policy failure does not affect others
        # in the same batch.
        #
        # NOTE: The orphan risk for DAC entries is inherent — NDFC has
        # no atomic "replace policy" API.  Re-running the playbook
        # will re-create the policy (it will be seen as
        # "not found" → create).

        # Filter out DAC entries whose old policy failed to be removed
        eligible_dac = []
        for d in delete_and_create_batch:
            if d["policy_id"] in remove_failed_ids:
                want = d["want"]
                self._proposed.append(want)
                if d.get("have"):
                    self._before.append(d["have"])
                self._register_result(
                    action="policy_replace",
                    operation_type=OperationType.UPDATE,
                    return_code=207,
                    message=(
                        f"Cannot replace policy: removal of old policy "
                        f"{d['policy_id']} failed. Skipping create to "
                        f"avoid duplicates."
                    ),
                    success=False,
                    found=True,
                    diff={
                        "action": "replace_failed",
                        "want": want,
                        "have": d.get("have"),
                        "error": f"Old policy {d['policy_id']} removal failed",
                        "failed_policy_id": d["policy_id"],
                    },
                )
            else:
                eligible_dac.append(d)

        for batch_label, batch_entries in [
            ("create", create_batch),
            ("replace", eligible_dac),
        ]:
            if not batch_entries:
                continue

            want_list = [d["want"] for d in batch_entries]
            self.log.info(
                f"Bulk creating {len(want_list)} policies "
                f"(batch={batch_label})"
            )

            try:
                created_ids = self._api_bulk_create_policies(want_list)
            except NDModuleError as bulk_err:
                self.log.error(
                    f"Bulk {batch_label} failed entirely: {bulk_err.msg}"
                )
                for diff_entry in batch_entries:
                    want = diff_entry["want"]
                    action_label = (
                        "policy_replace"
                        if diff_entry["action"] == "delete_and_create"
                        else "policy_create"
                    )
                    self._proposed.append(want)
                    if diff_entry.get("have"):
                        self._before.append(diff_entry["have"])
                    self._register_result(
                        action=action_label,
                        operation_type=OperationType.CREATE,
                        return_code=bulk_err.status or -1,
                        message=bulk_err.msg,
                        data=bulk_err.response_payload or {},
                        success=False,
                        found=False,
                        diff={
                            "action": "fail",
                            "want": want,
                            "error": bulk_err.msg,
                        },
                    )
                continue  # Skip per-entry registration for this batch

            # Register per-entry results from bulk response
            for idx, diff_entry in enumerate(batch_entries):
                want = diff_entry["want"]
                have = diff_entry.get("have")
                field_diff = diff_entry["diff"]
                is_replace = diff_entry["action"] == "delete_and_create"

                entry_result = (
                    created_ids[idx] if idx < len(created_ids)
                    else {"policy_id": None, "ndfc_error": "No response entry from NDFC"}
                )
                created_id = entry_result["policy_id"]
                ndfc_error = entry_result["ndfc_error"]
                per_policy_error = None

                # created_id is None when per-policy response had status!=success
                if created_id is None:
                    per_policy_error = (
                        f"Policy creation failed for "
                        f"{want.get('templateName')} on "
                        f"{want.get('switchId')}: {ndfc_error}"
                    )

                self._proposed.append(want)
                if have:
                    self._before.append(have)

                if per_policy_error:
                    action_label = (
                        "policy_replace" if is_replace else "policy_create"
                    )
                    self._register_result(
                        action=action_label,
                        operation_type=OperationType.CREATE,
                        return_code=207,
                        message=per_policy_error,
                        success=False,
                        found=False,
                        diff={
                            "action": "fail",
                            "want": want,
                            "error": per_policy_error,
                        },
                    )
                    continue

                policy_ids_to_deploy.append(created_id)
                self._after.append({**want, "policyId": created_id})

                if is_replace:
                    self._register_result(
                        action="policy_replace",
                        operation_type=OperationType.UPDATE,
                        return_code=200,
                        message="OK",
                        success=True,
                        found=True,
                        diff={
                            "action": "delete_and_create",
                            "before": have,
                            "after": {**want, "policyId": created_id},
                            "want": want, "have": have, "diff": field_diff,
                            "deleted_policy_id": diff_entry["policy_id"],
                            "created_policy_id": created_id,
                        },
                    )
                else:
                    self._register_result(
                        action="policy_create",
                        operation_type=OperationType.CREATE,
                        return_code=200,
                        message="OK",
                        success=True,
                        found=False,
                        diff={
                            "action": "create",
                            "before": None,
                            "after": {**want, "policyId": created_id},
                            "want": want, "diff": field_diff,
                            "created_policy_id": created_id,
                        },
                    )

        # ── Phase 5: Execute updates (PUT has no bulk API) ──────────────
        for diff_entry in update_batch:
            want = diff_entry["want"]
            have = diff_entry["have"]
            policy_id = diff_entry["policy_id"]
            field_diff = diff_entry["diff"]

            self._proposed.append(want)
            self._before.append(have)

            try:
                self._api_update_policy(want, have, policy_id)
            except NDModuleError as update_err:
                self.log.error(
                    f"Update failed for {policy_id}: {update_err.msg}"
                )
                self._register_result(
                    action="policy_update",
                    operation_type=OperationType.UPDATE,
                    return_code=update_err.status or -1,
                    message=update_err.msg,
                    data=update_err.response_payload or {},
                    success=False,
                    found=True,
                    diff={
                        "action": "update_failed",
                        "want": want, "have": have, "diff": field_diff,
                        "policy_id": policy_id,
                        "error": update_err.msg,
                    },
                )
                continue

            policy_ids_to_deploy.append(policy_id)

            after_merged = {**have, **want, "policyId": policy_id}
            self._after.append(after_merged)

            self._register_result(
                action="policy_update",
                operation_type=OperationType.UPDATE,
                return_code=200,
                message="OK",
                success=True,
                found=True,
                diff={
                    "action": "update",
                    "before": have, "after": after_merged,
                    "want": want, "have": have, "diff": field_diff,
                    "policy_id": policy_id,
                },
            )

        self.log.info(f"Merged execute complete: {len(policy_ids_to_deploy)} policies to deploy")
        self.log.debug("EXIT: _execute_merged()")
        return policy_ids_to_deploy

    # =========================================================================
    # Diff: Deleted State (16 cases)
    # =========================================================================

    def _get_diff_deleted_single(self, want: Dict, have_list: List[Dict]) -> Dict:
        """Compute the delete result for a single config entry.

        Args:
            want: Desired delete filter dict.
            have_list: Matching policies from the controller.

        Returns:
            Dict with keys: action, want, policies, policy_ids, match_count,
            warning, error_msg.
        """
        policy_ids = [p.get("policyId") for p in have_list if p.get("policyId")]
        result = {
            "action": None,
            "want": want,
            "policies": have_list,
            "policy_ids": policy_ids,
            "match_count": len(have_list),
            "warning": None,
            "error_msg": None,
        }

        match_count = len(have_list)

        # D-7, D-8: Policy ID given
        if "policyId" in want:
            if match_count == 0:
                result["action"] = "skip"
            else:
                result["action"] = "delete"
            return result

        # D-13 to D-16: Switch-only (no name given)
        if "templateName" not in want:
            if match_count == 0:
                result["action"] = "skip"
            else:
                result["action"] = "delete_all"
            return result

        # D-1 to D-6: Template name given, use_desc_as_key=false
        if not self.use_desc_as_key:
            if match_count == 0:
                result["action"] = "skip"
            elif match_count == 1:
                result["action"] = "delete"
            else:
                result["action"] = "delete_all"
            return result

        # D-9 to D-12: Template name given, use_desc_as_key=true
        if self.use_desc_as_key:
            # Note: description-empty is already caught by Pydantic
            # (state=deleted) and _build_have Case C upstream.
            want_desc = want.get("description", "")

            if match_count == 0:
                result["action"] = "skip"
                return result

            if match_count == 1:
                result["action"] = "delete"
                return result

            # D-12: Multiple matches → hard FAIL (ambiguous)
            # Abort the entire task atomically — do not silently delete
            # multiple policies when descriptions should be unique.
            self.module.fail_json(
                msg=(
                    f"Multiple policies ({match_count}) found with description "
                    f"'{want_desc}' on switch {want.get('switchId')}. "
                    "Descriptions must be unique per switch when "
                    "use_desc_as_key=true. Remove the duplicate policies from "
                    "NDFC or use a policy ID directly."
                )
            )

        # Should not reach here
        result["action"] = "skip"
        return result

    # =========================================================================
    # Execute: Deleted State
    # =========================================================================

    def _execute_deleted(self, diff_results: List[Dict]) -> None:
        """Execute the computed actions for all deleted config entries.

        Collects all policy IDs to delete across all config entries, then
        performs bulk API calls.  PYTHON content-type templates (e.g.
        ``switch_freeform``) use direct DELETE; everything else uses the
        normal markDelete → pushConfig → remove flow.

            - deploy=true:  markDelete → pushConfig → remove (3-step)
            - deploy=false: markDelete only                  (1-step)
            - PYTHON-type:  direct DELETE (1-step, regardless of deploy)

        Args:
            diff_results: List of diff result dicts from ``_get_diff_deleted_single``.

        Returns:
            None.
        """
        self.log.debug("ENTER: _execute_deleted()")
        self.log.debug(f"Processing {len(diff_results)} delete entries")

        # Phase A: Register per-entry results and collect all policy IDs
        all_policy_ids_to_delete = []
        all_switch_ids = []
        # Map policy ID → templateName so Phase B can route switch_freeform
        # policies through a direct DELETE instead of markDelete.
        policy_template_map: Dict[str, str] = {}
        # Map policy ID → switchId so we know which switches to deploy after
        # direct DELETE of PYTHON-type policies.
        policy_switch_map: Dict[str, str] = {}

        for diff_entry in diff_results:
            action = diff_entry["action"]
            want = diff_entry["want"]
            policies = diff_entry["policies"]
            policy_ids = diff_entry["policy_ids"]
            match_count = diff_entry["match_count"]
            warning = diff_entry["warning"]
            error_msg = diff_entry["error_msg"]

            self.log.debug(
                f"Delete action={action} for "
                f"{want.get('templateName', want.get('policyId', 'switch-only'))}, "
                f"policy_ids={policy_ids}"
            )

            # --- FAIL ---
            if action == "fail":
                self.log.warning(f"Delete failed: {error_msg}")
                self._proposed.append(want)
                self._register_result(
                    action="policy_deleted",
                    state="deleted",
                    operation_type=OperationType.QUERY,
                    return_code=-1,
                    message=error_msg,
                    success=False,
                    found=False,
                    diff={"action": action, "want": want, "error": error_msg},
                )
                continue

            # --- SKIP ---
            if action == "skip":
                self.log.info(
                    f"Policy not found for deletion: "
                    f"{want.get('templateName', want.get('policyId', 'switch-only'))}"
                )
                self._proposed.append(want)
                self._register_result(
                    action="policy_deleted",
                    state="deleted",
                    operation_type=OperationType.QUERY,
                    return_code=200,
                    message="Policy not found — already absent",
                    success=True,
                    found=False,
                    diff={"action": action, "want": want, "before": None, "after": None},
                )
                continue

            # --- DELETE / DELETE_ALL ---
            if action in ("delete", "delete_all"):
                self.log.info(
                    f"Collecting {len(policy_ids)} policy(ies) for deletion: {policy_ids}"
                )
                self._proposed.append(want)
                self._before.extend(policies)  # what existed before deletion
                all_policy_ids_to_delete.extend(policy_ids)

                # Track templateName and switchId per policy
                for p in policies:
                    pid = p.get("policyId", "")
                    tname = p.get("templateName", "")
                    sw = p.get("switchId", "")
                    if pid:
                        policy_template_map[pid] = tname
                        if sw:
                            policy_switch_map[pid] = sw

                # Collect switch IDs for result tracking
                for p in policies:
                    sw = p.get("switchId", "")
                    if sw and sw not in all_switch_ids:
                        all_switch_ids.append(sw)

                if self.check_mode:
                    self.log.info(f"Check mode: would delete {len(policy_ids)} policy(ies)")
                    diff_payload = {
                        "action": action,
                        "want": want,
                        "before": policies,
                        "after": None,
                        "policy_ids": policy_ids,
                        "match_count": match_count,
                    }
                    if warning:
                        diff_payload["warning"] = warning
                    self._register_result(
                        action="policy_deleted",
                        state="deleted",
                        operation_type=OperationType.DELETE,
                        return_code=200,
                        message="OK (check_mode)",
                        success=True,
                        found=True,
                        diff=diff_payload,
                    )
                    continue

                # Register intent — actual API calls happen in bulk below
                diff_payload = {
                    "action": action,
                    "want": want,
                    "before": policies,
                    "after": None,
                    "policy_ids": policy_ids,
                    "match_count": match_count,
                }
                if warning:
                    diff_payload["warning"] = warning
                self._register_result(
                    action="policy_deleted",
                    state="deleted",
                    operation_type=OperationType.DELETE,
                    return_code=200,
                    message="Pending bulk delete",
                    success=True,
                    found=True,
                    diff=diff_payload,
                )
                continue

        # Phase B: Execute bulk API calls (skip if check_mode or nothing to delete)
        if self.check_mode or not all_policy_ids_to_delete:
            self.log.info(
                "Skipping bulk delete: "
                f"{'check_mode' if self.check_mode else 'no policies to delete'}"
            )
            self.log.debug("EXIT: _execute_deleted()")
            return

        # Deduplicate policy IDs (same policy could match multiple config entries)
        unique_policy_ids = list(dict.fromkeys(all_policy_ids_to_delete))
        self.log.info(
            f"Total policies to delete: {len(unique_policy_ids)} "
            f"(deduplicated from {len(all_policy_ids_to_delete)})"
        )

        # ---------------------------------------------------------------------
        # Delete strategy: markDelete-first with automatic fallback
        #
        # Rather than trying to predict which templates are PYTHON content-type
        # upfront, we send ALL policies through markDelete and inspect the
        # 207 Multi-Status response for per-policy failures.  Any policy that
        # fails with "content type PYTHON" is automatically retried via
        # direct DELETE /policies/{policyId}.
        #
        # This is more robust than maintaining a hardcoded set of template
        # names, since the content type is an NDFC-internal property that
        # varies across templates and NDFC versions.
        # ---------------------------------------------------------------------

        # Step 1: Attempt markDelete for all policies
        self.log.info(
            f"{'Step 1/3' if self.deploy else 'Step 1/1'}: "
            f"markDelete for {len(unique_policy_ids)} policies"
        )
        mark_delete_data = self._api_mark_delete(unique_policy_ids)

        # Inspect 207 response for per-policy results
        mark_succeeded = []
        mark_failed = []
        mark_failed_python = []  # Failed specifically due to PYTHON content type

        if isinstance(mark_delete_data, dict):
            policies_response = mark_delete_data.get("policies", [])
            # Build a set of policy IDs that explicitly failed.
            # Any status that is NOT "success" (case-insensitive) is
            # treated as failure (defensive against future values
            # and potential case variations like "SUCCESS").
            failed_ids = set()
            for p in policies_response:
                pid = p.get("policyId", "")
                status = str(p.get("status", "")).lower()
                if status != "success":
                    failed_ids.add(pid)
                    msg = p.get("message", "")
                    if "content type PYTHON" in msg:
                        mark_failed_python.append(pid)
                        self.log.info(
                            f"markDelete failed for {pid} (PYTHON content type) "
                            "— will retry via direct DELETE"
                        )
                    else:
                        mark_failed.append(pid)
                        self.log.error(
                            f"markDelete failed for {pid} "
                            f"(status={p.get('status')!r}): {msg}"
                        )

            # Policies not in the failed set are considered successful
            mark_succeeded = [pid for pid in unique_policy_ids if pid not in failed_ids]

            # Warn if NDFC returned empty policies list (ambiguous)
            if not policies_response and unique_policy_ids:
                self.log.warning(
                    "markDelete returned empty 'policies' list for "
                    f"{len(unique_policy_ids)} policy IDs — "
                    "treating all as succeeded (ambiguous response)"
                )
                mark_succeeded = list(unique_policy_ids)
        else:
            # No structured response — assume all succeeded (pre-existing behavior)
            self.log.warning(
                "markDelete returned non-dict response — "
                "treating all as succeeded"
            )
            mark_succeeded = list(unique_policy_ids)

        self.log.info(
            f"markDelete results: {len(mark_succeeded)} succeeded, "
            f"{len(mark_failed_python)} failed (PYTHON-type, will retry), "
            f"{len(mark_failed)} failed (other errors)"
        )

        # Register markDelete result
        if mark_succeeded:
            self._register_result(
                action="policy_mark_delete",
                state="deleted",
                operation_type=OperationType.DELETE,
                return_code=200,
                message=f"Marked {len(mark_succeeded)} policies for deletion",
                success=True,
                found=True,
                diff={
                    "action": "mark_delete",
                    "policy_ids": mark_succeeded,
                },
            )

        if mark_failed:
            self._register_result(
                action="policy_mark_delete",
                state="deleted",
                operation_type=OperationType.DELETE,
                return_code=207,
                message=(
                    f"markDelete failed for {len(mark_failed)} policy(ies): "
                    f"{mark_failed}"
                ),
                success=False,
                found=True,
                diff={
                    "action": "mark_delete_failed",
                    "policy_ids": mark_failed,
                },
            )

        # Step 1b: Fallback — direct DELETE for PYTHON-type policies
        if mark_failed_python:
            self.log.info(
                f"Falling back to direct DELETE for {len(mark_failed_python)} "
                f"PYTHON-type policies: {mark_failed_python}"
            )
            deleted_direct = []
            failed_direct = []
            for pid in mark_failed_python:
                try:
                    self._api_delete_policy(pid)
                    deleted_direct.append(pid)
                except Exception:  # noqa: BLE001
                    self.log.error(f"Direct DELETE also failed for {pid}")
                    failed_direct.append(pid)

            if deleted_direct:
                tpl_names = list({
                    policy_template_map.get(pid, "unknown")
                    for pid in deleted_direct
                })
                self._register_result(
                    action="policy_direct_delete",
                    state="deleted",
                    operation_type=OperationType.DELETE,
                    return_code=200,
                    message=(
                        f"Directly deleted {len(deleted_direct)} PYTHON-type "
                        f"policy(ies) ({', '.join(tpl_names)}). "
                        "These templates use content type PYTHON and cannot "
                        "be markDeleted — direct DELETE is used instead."
                    ),
                    success=True,
                    found=True,
                    diff={
                        "action": "direct_delete",
                        "policy_ids": deleted_direct,
                        "templates": tpl_names,
                    },
                )
            if failed_direct:
                self._register_result(
                    action="policy_direct_delete",
                    state="deleted",
                    operation_type=OperationType.DELETE,
                    return_code=-1,
                    message=(
                        f"Direct DELETE failed for {len(failed_direct)} "
                        f"policy(ies): {failed_direct}"
                    ),
                    success=False,
                    found=True,
                    diff={
                        "action": "direct_delete_failed",
                        "policy_ids": failed_direct,
                    },
                )

            # Deploy to affected switches so NDFC pushes the config removal
            # to the devices.  Direct DELETE removes the policy record but
            # the device still has the running config until we deploy.
            if deleted_direct and self.deploy:
                affected_switches = list({
                    policy_switch_map[pid]
                    for pid in deleted_direct
                    if pid in policy_switch_map
                })
                if affected_switches:
                    self.log.info(
                        f"Deploying config to {len(affected_switches)} switch(es) "
                        f"after direct DELETE: {affected_switches}"
                    )
                    deploy_data = self._api_deploy_switches(affected_switches)

                    # Inspect switchActions/deploy response.
                    #
                    # The /fabrics/{fabricName}/switchActions/deploy endpoint
                    # has a DIFFERENT response shape from policy actions.
                    # Per the OpenAPI spec it returns a single object:
                    #   {"status": "Configuration deployment completed for [...]"}
                    #
                    # In practice NDFC may return an empty body {} with 207.
                    # This endpoint does NOT use the per-item
                    # policyBaseGeneralResponse schema, so we cannot use
                    # _inspect_207_policies() here.
                    #
                    # We inspect the top-level "status" string:
                    #   - Present and contains "completed" → success
                    #   - Present but other text → log warning, treat as success
                    #   - Missing (empty body {}) → ambiguous, log warning,
                    #     treat as success (NDFC often returns {} on success)
                    deploy_ok = True
                    if isinstance(deploy_data, dict) and deploy_data:
                        status_str = deploy_data.get("status", "")
                        if status_str:
                            self.log.info(
                                f"switchActions/deploy status: {status_str}"
                            )
                        else:
                            self.log.warning(
                                "switchActions/deploy returned non-empty body "
                                f"but no 'status' field: {deploy_data}"
                            )
                    else:
                        self.log.warning(
                            "switchActions/deploy returned empty body — "
                            "treating as success (NDFC commonly returns {} "
                            "for this endpoint)"
                        )

                    self._register_result(
                        action="policy_switch_deploy",
                        state="deleted",
                        operation_type=OperationType.DELETE,
                        return_code=207,
                        message=(
                            f"Deployed config to {len(affected_switches)} "
                            f"switch(es) to push removal of directly-deleted "
                            f"PYTHON-type policies"
                        ),
                        success=deploy_ok,
                        found=True,
                        diff={
                            "action": "switch_deploy",
                            "switch_ids": affected_switches,
                            "policy_ids": deleted_direct,
                            "deploy_success": deploy_ok,
                        },
                    )

        # If nothing succeeded at all, bail out
        if not mark_succeeded and not mark_failed_python:
            self.log.info("No policies were successfully deleted — done")
            self.log.debug("EXIT: _execute_deleted()")
            return

        # Only mark_succeeded policies continue through the
        # pushConfig → remove flow below.  If none succeeded via
        # markDelete, there's nothing left for pushConfig/remove.
        normal_delete_ids = mark_succeeded
        if not normal_delete_ids:
            self.log.info(
                "No policies were successfully markDeleted — "
                "skipping pushConfig/remove"
            )
            self.log.debug("EXIT: _execute_deleted()")
            return

        # Step 2 (deploy=true only): pushConfig
        deploy_success = True
        if self.deploy:
            self.log.info(
                f"Step 2/3: pushConfig for {len(normal_delete_ids)} policies"
            )
            deploy_success = self._deploy_policies(
                normal_delete_ids, state="deleted"
            )

        # deploy=false: stop after markDelete
        if not self.deploy:
            self.log.info(
                "Deploy=false: skipping pushConfig/remove; "
                "policies remain marked for deletion"
            )
            self.log.debug("EXIT: _execute_deleted()")
            return

        # If pushConfig failed, do NOT proceed to remove.
        if not deploy_success:
            self.log.error(
                "pushConfig failed — aborting remove. "
                "Policies remain in markDeleted state."
            )
            self._register_result(
                action="policy_deploy_abort",
                state="deleted",
                operation_type=OperationType.DELETE,
                return_code=-1,
                message=(
                    "pushConfig failed for one or more policies. "
                    "Aborting remove — policies remain marked for deletion "
                    "with negative priority. Fix device connectivity and re-run."
                ),
                success=False,
                found=True,
                diff={
                    "action": "deploy_abort",
                    "policy_ids": normal_delete_ids,
                    "reason": "pushConfig per-policy failure",
                },
            )
            self.log.debug("EXIT: _execute_deleted()")
            return

        # Step 3: remove — hard-delete policy records from NDFC
        self.log.info(
            f"Step 3/3: remove {len(normal_delete_ids)} policies"
        )
        remove_data = self._api_remove_policies(normal_delete_ids)

        # Inspect 207 response for per-policy failures
        rm_ok, rm_fail = self._inspect_207_policies(remove_data)
        remove_success = len(rm_fail) == 0

        # Warn if NDFC returned no per-policy detail at all
        if not rm_ok and not rm_fail and normal_delete_ids:
            self.log.warning(
                f"remove returned no per-policy results for "
                f"{len(normal_delete_ids)} policy IDs — treating as success "
                "(ambiguous response)"
            )

        if rm_fail:
            fail_msgs = [
                f"{p.get('policyId', '?')}: {p.get('message', 'unknown')}"
                for p in rm_fail
            ]
            self.log.error(
                f"remove failed for {len(rm_fail)} policy(ies): "
                + "; ".join(fail_msgs)
            )

        self._register_result(
            action="policy_remove",
            state="deleted",
            operation_type=OperationType.DELETE,
            return_code=200 if remove_success else 207,
            message=(
                f"Removed {len(normal_delete_ids)} policies"
                if remove_success
                else (
                    f"Remove partially failed: "
                    f"{len(rm_ok)} succeeded, {len(rm_fail)} failed"
                )
            ),
            success=remove_success,
            found=True,
            diff={
                "action": "remove",
                "policy_ids": normal_delete_ids,
                "remove_success": remove_success,
                "failed_policies": [
                    p.get("policyId") for p in rm_fail
                ],
            },
        )

        self.log.debug("EXIT: _execute_deleted()")

    # =========================================================================
    # Deploy: pushConfig
    # =========================================================================

    def _deploy_policies(
        self,
        policy_ids: List[str],
        state: str = "merged",
    ) -> bool:
        """Deploy policies by calling pushConfig.

        Inspects the 207 Multi-Status response body for per-policy
        failures (e.g., device connectivity issues).  If any policy
        has ``status: "failed"``, the deploy is considered failed.

        Args:
            policy_ids: List of policy IDs to deploy.
            state: Module state for result reporting.

        Returns:
            True if all policies deployed successfully, False if any failed.
        """
        if not policy_ids:
            self.log.debug("No policy IDs to deploy, skipping")
            return True

        self.log.info(f"Deploying {len(policy_ids)} policies via pushConfig")

        self.results.action = "policy_deploy"
        self.results.state = state
        self.results.check_mode = self.check_mode
        self.results.operation_type = OperationType.UPDATE

        if self.check_mode:
            self.log.info(f"Check mode: would deploy {len(policy_ids)} policies")
            self.results.response_current = {
                "RETURN_CODE": 200,
                "MESSAGE": "OK (check_mode)",
                "DATA": {},
            }
            self.results.result_current = {"success": True, "found": True}
            self.results.diff_current = {
                "action": "deploy",
                "policy_ids": policy_ids,
            }
            self.results.register_api_call()
            return True

        push_body = PolicyIds(policy_ids=policy_ids)

        ep = EpManagePolicyActionsPushConfigPost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        # NOTE: pushConfig does NOT accept ticketId per manage.json spec

        data = self.nd.request(ep.path, ep.verb, push_body.to_request_dict())

        # Inspect 207 body for per-policy failures
        succeeded_policies, failed_policies = self._inspect_207_policies(data)

        # Warn if NDFC returned no per-policy detail at all
        if not succeeded_policies and not failed_policies and policy_ids:
            self.log.warning(
                f"pushConfig returned no per-policy results for "
                f"{len(policy_ids)} policy IDs — treating as success "
                "(ambiguous response)"
            )

        deploy_success = len(failed_policies) == 0

        if failed_policies:
            failed_msgs = [f"{p.get('policyId', '?')}: {p.get('message', 'unknown error')}" for p in failed_policies]
            self.log.error(
                f"pushConfig failed for {len(failed_policies)} policy(ies): "
                + "; ".join(failed_msgs)
            )

        self.results.response_current = self.nd.rest_send.response_current
        self.results.result_current = {
            "success": deploy_success,
            "found": True,
            "changed": deploy_success,
        }
        self.results.diff_current = {
            "action": "deploy",
            "policy_ids": policy_ids,
            "deploy_success": deploy_success,
            "failed_policies": [p.get("policyId") for p in failed_policies],
        }
        self.results.register_api_call()
        return deploy_success

    # =========================================================================
    # 207 Multi-Status Response Inspection
    # =========================================================================

    @staticmethod
    def _inspect_207_policies(
        data: Any,
        key: str = "policies",
    ) -> Tuple[List[Dict], List[Dict]]:
        """Inspect a 207 Multi-Status response for per-item success/failure.

        NDFC returns HTTP 207 for most bulk policy actions (create,
        markDelete, pushConfig, remove).  The response body contains
        a list of per-item results under a top-level key (``policies``),
        each with a required ``status`` field (``"success"`` or
        ``"failed"``) and an optional ``message`` field.

        The per-item schema is ``policyBaseGeneralResponse``::

            {
                "status": "success" | "failed",   # REQUIRED
                "message": "...",                   # optional
                "policyId": "POLICY-...",           # optional
                "entityName": "SWITCH",             # optional
                "entityType": "switch",             # optional
                "templateName": "...",              # optional
                "switchId": "FDO..."                # optional
            }

        An item is considered **failed** when ``status`` is anything
        other than ``"success"`` (defensive against future values
        like ``"error"``, ``"warning"``, or ``"partial"``).

        Comparison is **case-insensitive**: ``"success"``,
        ``"SUCCESS"``, and ``"Success"`` are all treated as success.

        If the response body is empty (``{}``) or does not contain
        the expected key, both returned lists will be empty.  The
        caller should treat this as an ambiguous result (NDFC did
        not report per-item status) and decide accordingly.

        Args:
            data: Response DATA dict from NDFC (or None/non-dict).
            key: Top-level key holding the items list.
                 ``"policies"`` for policy action endpoints.

        Returns:
            Tuple of (succeeded, failed) lists of per-item dicts.
        """
        if not isinstance(data, dict):
            return [], []
        items = data.get(key, [])
        if not isinstance(items, list):
            return [], []
        succeeded = []
        failed = []
        for item in items:
            status = str(item.get("status", "")).lower()
            if status == "success":
                succeeded.append(item)
            else:
                # Any non-"success" status is treated as failure.
                # Known values: "failed", "warning".
                failed.append(item)
        return succeeded, failed

    # =========================================================================
    # API Helpers (low-level CRUD)
    # =========================================================================

    def _api_bulk_create_policies(self, want_list: List[Dict]) -> List[Dict]:
        """Create multiple policies via a single bulk POST.

        Builds one ``PolicyCreateBulk`` containing all entries and sends
        a single POST request.  The controller returns a per-policy
        response in the same order as the request.

        Args:
            want_list: List of want dicts, each with all policy fields.

        Returns:
            List of dicts (same length as want_list), each with::

                {
                    "policy_id": str or None,   # created ID, None on failure
                    "ndfc_error": str or None,  # NDFC error message on failure
                }

        Raises:
            NDModuleError: If the entire API call fails (e.g., network error).
                Per-policy failures within a 207 response are returned
                with ``policy_id=None`` and do NOT raise.
        """
        if not want_list:
            return []

        self.log.info(f"Bulk creating {len(want_list)} policies")

        policy_models = []
        for want in want_list:
            policy_models.append(
                PolicyCreate(
                    switch_id=want["switchId"],
                    template_name=want["templateName"],
                    entity_type="switch",
                    entity_name="SWITCH",
                    description=want.get("description", ""),
                    priority=want.get("priority", 500),
                    source=want.get("source", ""),
                    template_inputs=want.get("templateInputs"),
                )
            )

        bulk = PolicyCreateBulk(policies=policy_models)
        payload = bulk.to_request_dict()

        ep = EpManagePoliciesPost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id

        data = self.nd.request(ep.path, ep.verb, payload)

        # Parse per-policy results from the 207 response.
        # The controller returns policies in the same order as sent.
        created_policies = data.get("policies", []) if isinstance(data, dict) else []
        results: List[Dict] = []

        for idx, want in enumerate(want_list):
            if idx < len(created_policies):
                entry = created_policies[idx]
                entry_status = str(entry.get("status", "")).lower()
                if entry_status != "success":
                    ndfc_msg = entry.get("message", "Policy creation failed")
                    self.log.error(
                        f"Bulk create: policy {idx} failed "
                        f"(status={entry.get('status')!r}) — "
                        f"template={want.get('templateName')}, "
                        f"switch={want.get('switchId')}: {ndfc_msg}"
                    )
                    results.append({"policy_id": None, "ndfc_error": ndfc_msg})
                else:
                    pid = entry.get("policyId")
                    self.log.info(f"Bulk create: policy {idx} created — {pid}")
                    results.append({"policy_id": pid, "ndfc_error": None})
            else:
                self.log.warning(f"Bulk create: no response entry for policy {idx}")
                results.append({"policy_id": None, "ndfc_error": "No response entry from NDFC"})

        self.log.info(
            f"Bulk create complete: "
            f"{sum(1 for r in results if r['policy_id'])} succeeded, "
            f"{sum(1 for r in results if r['policy_id'] is None)} failed"
        )
        return results

    def _api_update_policy(self, want: Dict, have: Dict, policy_id: str) -> None:
        """Update an existing policy via PUT.

        For templateInputs, merge user-specified keys on top of the
        controller's existing values.  This prevents accidentally
        wiping template inputs when the user only wants to change
        description or priority.

        Args:
            want: The want dict with desired policy fields.
            have: The existing policy dict from the controller.
            policy_id: The policy ID to update.

        Returns:
            None.
        """
        self.log.info(f"Updating policy: {policy_id}")
        merged_inputs = dict(have.get("templateInputs") or {})
        for k, v in (want.get("templateInputs") or {}).items():
            merged_inputs[k] = v
        self.log.debug(f"Merged templateInputs: {len(merged_inputs)} keys")

        update_model = PolicyUpdate(
            switch_id=want["switchId"],
            template_name=want.get("templateName", have.get("templateName")),
            entity_type="switch",
            entity_name="SWITCH",
            description=want.get("description", ""),
            priority=want.get("priority", 500),
            source=want.get("source", have.get("source", "")),
            template_inputs=merged_inputs,
        )
        payload = update_model.to_request_dict()

        ep = EpManagePoliciesPut()
        ep.fabric_name = self.fabric_name
        ep.policy_id = policy_id
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id

        self.nd.request(ep.path, ep.verb, payload)

    def _api_mark_delete(self, policy_ids: List[str]) -> Dict:
        """Mark policies for deletion via POST /policyActions/markDelete.

        NDFC returns HTTP 207 Multi-Status with per-policy results.
        Policies with content type PYTHON (e.g. ``switch_freeform``,
        ``Ext_VRF_Lite_SVI``) will fail with::

            "Policies with content type PYTHON or without generated
             config can't be mark deleted."

        The caller must inspect the returned dict for per-policy
        failures and fall back to direct DELETE for those.

        Args:
            policy_ids: List of policy IDs to mark-delete.

        Returns:
            Response DATA dict from NDFC.  Typically contains a
            ``policies`` list with per-policy ``status`` and
            ``message`` fields.
        """
        self.log.info(f"Marking {len(policy_ids)} policies for deletion: {policy_ids}")
        body = PolicyIds(policy_ids=policy_ids)

        ep = EpManagePolicyActionsMarkDeletePost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id

        data = self.nd.request(ep.path, ep.verb, body.to_request_dict())
        return data if isinstance(data, dict) else {}

    def _api_remove_policies(self, policy_ids: List[str]) -> Dict:
        """Hard-delete policies via POST /policyActions/remove.

        NDFC returns HTTP 207 Multi-Status with per-policy results.
        The caller should inspect the returned dict for per-policy
        ``status: "failed"`` entries.

        Args:
            policy_ids: List of policy IDs to remove from NDFC.

        Returns:
            Response DATA dict from NDFC.  Typically contains a
            ``policies`` list with per-policy ``status`` and
            ``message`` fields.
        """
        self.log.info(f"Removing {len(policy_ids)} policies: {policy_ids}")
        body = PolicyIds(policy_ids=policy_ids)

        ep = EpManagePolicyActionsRemovePost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id

        data = self.nd.request(ep.path, ep.verb, body.to_request_dict())
        return data if isinstance(data, dict) else {}

    def _api_delete_policy(self, policy_id: str) -> None:
        """Delete a single policy via DELETE /policies/{policyId}.

        Used for PYTHON content-type templates (e.g. ``switch_freeform``)
        that cannot go through the markDelete flow, and for cleaning up
        stale markDeleted policies.

        Args:
            policy_id: Policy ID to delete (e.g., "POLICY-12345").

        Returns:
            None.
        """
        self.log.info(f"Deleting individual policy: {policy_id}")

        ep = EpManagePoliciesDelete()
        ep.fabric_name = self.fabric_name
        ep.policy_id = policy_id
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id

        self.nd.request(ep.path, ep.verb)

    def _api_deploy_switches(self, switch_ids: List[str]) -> dict:
        """Deploy fabric config to specific switches.

        Used after direct DELETE of PYTHON content-type policies to push
        the config removal to the actual devices.  Unlike ``pushConfig``
        (which operates on policy IDs), this endpoint operates on switch
        serial numbers.

        API: ``POST /fabrics/{fabricName}/switchActions/deploy``

        Args:
            switch_ids: List of switch serial numbers to deploy to.

        Returns:
            Response DATA dict from NDFC.  Typically contains a ``status``
            field like ``"Configuration deployment completed for [...]"``.
        """
        self.log.info(
            f"Deploying config to {len(switch_ids)} switch(es): {switch_ids}"
        )
        body = SwitchIds(switch_ids=switch_ids)

        ep = EpManageSwitchActionsDeployPost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name

        data = self.nd.request(ep.path, ep.verb, body.to_request_dict())
        return data if isinstance(data, dict) else {}

    # =========================================================================
    # Results Helper
    # =========================================================================

    def _register_result(
        self,
        action: str,
        operation_type: OperationType,
        return_code: int,
        message: str,
        success: bool,
        found: bool,
        diff: Dict,
        data: Any = None,
        state: Optional[str] = None,
    ) -> None:
        """Register a single task result into the Results aggregator.

        Convenience wrapper to avoid repeating the same boilerplate
        for every action/state combination.

        Args:
            action: Action label (e.g., "policy_create", "policy_query").
            operation_type: OperationType enum value.
            return_code: HTTP return code (or -1 for errors).
            message: Human-readable message.
            success: Whether the operation succeeded.
            found: Whether the policy was found.
            diff: Diff payload dict.
            data: Optional response data.
            state: Override state (defaults to self.state).

        Returns:
            None.
        """
        self.results.action = action
        self.results.state = state or self.state
        self.results.check_mode = self.check_mode
        self.results.operation_type = operation_type
        self.results.response_current = {
            "RETURN_CODE": return_code,
            "MESSAGE": message,
            "DATA": data if data is not None else {},
        }
        result_dict = {"success": success, "found": found}
        if not success:
            result_dict["changed"] = False
        self.results.result_current = result_dict
        self.results.diff_current = diff
        self.results.register_api_call()
