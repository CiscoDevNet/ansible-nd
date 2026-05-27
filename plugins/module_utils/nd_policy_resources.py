# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Policy Resource Module.

Provides all business logic for switch policy management on ND:
    - Policy CRUD (create, read, update, delete)
    - Idempotency diff calculation for merged, deleted states
    - Deploy orchestration (pushConfig for create/update, switchActions/deploy for delete)
    - Conditional delete flow:
      deploy=true  → markDelete → switchActions/deploy
      deploy=false → markDelete only (policy left in markDeleted state on controller;
                     running config remains on the switch until the next deploy)

The module file ``nd_policy.py`` contains only DOCUMENTATION, argument_spec,
and a thin ``main()`` that instantiates this class and calls ``manage_state()``.

Models (from ``models.nd_manage_policies``):
    - ``PolicyCreate``      - single policy create payload
    - ``PolicyCreateBulk``  - bulk policy create wrapper
    - ``PolicyUpdate``      - policy update payload (extends PolicyCreate)
    - ``PolicyIds``         - list of policy IDs for actions
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.constants import (
    SYSTEM_INJECTED_TEMPLATE_KEYS,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_config_templates import (
    EpManageConfigTemplateParametersGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policies import (
    EpManagePoliciesDelete,
    EpManagePoliciesGet,
    EpManagePoliciesPost,
    EpManagePoliciesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_actions import (
    EpManagePolicyActionsMarkDeletePost,
    EpManagePolicyActionsPushConfigPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
)
from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory import (
    FabricSwitchInventory,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.config_models import (
    PlaybookPolicyConfig,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.gathered_models import (
    GatheredPolicy,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_actions import (
    PolicyIds,
    SwitchIds,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_base import (
    PolicyCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_crud import (
    PolicyCreateBulk,
    PolicyUpdate,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import (
    SwitchDataModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    NDModuleError,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results

# pylint: disable=logging-fstring-interpolation


# pylint: disable=logging-fstring-interpolation,logging-not-lazy,f-string-without-interpolation,unnecessary-comprehension,implicit-str-concat


# =============================================================================
# Module-level pre-compiled regex patterns
# =============================================================================
#
# Used by _validate_template_inputs() for soft type-checks of user-supplied
# template inputs.  Compiled once at import time to avoid repeated parsing
# cost in tight loops (P3).

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_IPV4_SUBNET_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
_MAC_RE = re.compile(r"^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$" r"|^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


# =============================================================================
# Module-level helpers (stateless, used by NDPolicyModule)
# =============================================================================


def _needs_resolution(value) -> bool:
    """Return True if the switch identifier needs IP/hostname → serial resolution.

    Serial numbers are alphanumeric strings (e.g. ``FDO25031SY4``) and contain
    no dots.  IPv4 addresses and hostnames/FQDNs always contain dots, so a
    simple dot-presence check is a sufficient (and inexpensive) gate to avoid
    an unnecessary fabric inventory API call when every identifier is already
    a serial number.  Actual IP-vs-hostname resolution is delegated to
    :class:`FabricSwitchInventory` lookups (``by_ip()`` / hostname map).

    Args:
        value: Switch identifier string to inspect.

    Returns:
        True if the value contains a ``.`` (IP/hostname), False otherwise.
    """
    if not value:
        return False
    return "." in str(value).strip()


class NDPolicyModule:
    """Specialized module for switch policy lifecycle management.

    Provides policy-specific operations on top of NDModule:
        - Query and match existing policies (switchId-only Lucene narrowing,
          templateName/source/markDeleted filtered in code)
        - Idempotent diff calculation across 16 merged / 16 deleted cases
        - Create, update, delete_and_create actions
        - Bulk deploy via pushConfig (create/update) or switchActions/deploy (delete)
        - Conditional delete flow:
          deploy=true  → markDelete → switchActions/deploy
          deploy=false → markDelete only (policy left in markDeleted state on controller;
                         running config remains on the switch until the next deploy)

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
        logger: logging.Logger | None = None,
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
                raise NDModuleError(msg=f"'config' element is mandatory for state '{self.state}'.")
            # For gathered without config, initialise to empty list so
            # downstream code can iterate safely.
            self.config = []

        # Template parameter cache used by _validate_template_inputs().
        # Keyed by templateName; populated lazily by _fetch_template_params().
        self._template_params_cache: dict[str, list[dict]] = {}

        # Before/after snapshot lists — populated during _execute_* methods.
        # Merged into exit_json output so the caller sees what changed.
        self._before: list[dict] = []
        self._after: list[dict] = []
        self._proposed: list[dict] = []
        self._gathered: list[dict] = []

        # Accumulator for ND "warning"-status messages surfaced from 207
        # Multi-Status responses (markDelete, pushConfig, bulk create).
        # ND uses status="warning" for non-fatal partial outcomes (e.g.,
        # "already in markDeleted state", "deployment skipped — already in
        # sync"). These do NOT count toward task failure but are surfaced
        # to the user via module.warn() and the top-level ``warnings_nd``
        # key in exit_json so the operator can audit ND-side state.
        self._warnings: list[str] = []

        # Sticky stash for the path/verb/payload of the most recent (or
        # would-be) HTTP request.  _record_call() is invoked by the _api_*
        # helpers (and check-mode would-be sites) immediately before the
        # request is built; _register_result() reads this stash and stamps
        # Results.{path,verb,payload}_current so the final output's
        # ``path`` / ``payload`` arrays are populated alongside ``response``.
        # The stash is intentionally NOT auto-cleared after stamping so a
        # single bulk POST can be associated with multiple per-entry result
        # rows.  Synthetic register sites (no preceding API call) call
        # _clear_call() to avoid inheriting stale values.
        self._call_path: str | None = None
        self._call_verb: HttpVerbEnum | None = None
        self._call_payload: dict | None = None

        # Lazily-populated fabric switch inventory (shared by
        # resolve_switch_identifiers and _get_fabric_switches so a single
        # GET /fabrics/{name}/switches serves the whole module run).
        self._inventory: FabricSwitchInventory | None = None

        # Policy cache populated by _prefetch_all_policies() at the start of
        # _handle_merged_state / _handle_deleted_state / _handle_gathered_state.
        # When populated, _build_have() filters from this cache (O(1) in-memory
        # lookups) instead of making per-entry HTTP GETs.  None means cache is
        # not yet loaded (any call to _build_have() in that state is a bug).
        self._policies_cache: list[dict] | None = None
        self._policies_by_id_cache: dict[str, dict] = {}
        self._policies_by_switch_cache: dict[str, list[dict]] = {}
        # Composite (switchId, templateName) index for O(1) Case B/C lookups.
        self._policies_by_switch_template_cache: dict[tuple[str, str], list[dict]] = {}

        self.log.info(f"Initialized NDPolicyModule for fabric: {self.fabric_name}, state: {self.state}")

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

        # Surface ND-side warnings (status="warning" entries from 207
        # responses) to the operator. Each message is emitted as an
        # Ansible-visible warning (yellow ``[WARNING]:`` line in the CLI)
        # and also attached to the result under ``warnings_nd`` so that
        # downstream tasks using ``register:`` can react programmatically.
        if self._warnings:
            # De-duplicate while preserving order so identical warnings
            # from a bulk response are not shown N times.
            seen: set = set()
            unique_warnings: list = []
            for w in self._warnings:
                if w not in seen:
                    seen.add(w)
                    unique_warnings.append(w)
            for w in unique_warnings:
                try:
                    self.module.warn(w)
                except Exception:  # pragma: no cover — defensive only
                    pass
            final["warnings_nd"] = unique_warnings

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

        # Detect gathered output format: every named entry already has its own
        # embedded switch list. Flatten directly — no global/switch separation needed.
        #
        # Three shapes are recognised:
        #   Shape 1 (legacy two-level): policy entries (no `switch`) plus a
        #     single switch entry (no `name`, has `switch: [...]`).
        #   Shape 2 (self-contained / gathered round-trip): every named entry
        #     carries its own embedded `switch: [...]` list.
        #   Shape 3 (mixed): a forbidden combination of Shape 1 and Shape 2
        #     in the same config list. In the legacy path, the self-contained
        #     entries would be silently misinterpreted as the global switch
        #     entry, dropping their policy fields on the floor — so we reject
        #     this combination explicitly.
        has_self_contained = False
        legacy_named_entries: list = []  # named entries WITHOUT embedded switch
        for entry in config:
            name = entry.get("name")
            sw = entry.get("switch")
            if name and isinstance(sw, list):
                has_self_contained = True
            elif name:
                legacy_named_entries.append(name)

        all_self_contained = not legacy_named_entries

        if has_self_contained and not all_self_contained:
            raise NDModuleError(
                msg=(
                    "Invalid config shape: cannot mix self-contained policy "
                    "entries (with embedded `switch:` list, e.g., gathered "
                    "output) with legacy global policy entries (no `switch:` "
                    "key) in the same `config` list. "
                    f"Offending legacy entries: {legacy_named_entries}. "
                    "Either (a) feed the gathered output back unchanged for "
                    "round-trip use, or (b) remove the embedded `switch:` "
                    "lists from the self-contained entries and add a single "
                    "top-level `- switch: [...]` entry listing all target "
                    "switches (legacy two-level shape)."
                )
            )

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
            1. If the value does NOT look like an IP or hostname (no ``.``)
               it is assumed to be a serial number already → pass through.
            2. Otherwise the fabric switch inventory is consulted via
               :class:`FabricSwitchInventory` to map management IP or
               hostname → switch serial number.
            3. If resolution fails, raise ``NDModuleError`` with a clear
               message.

        Args:
            config: Flat config list from ``translate_config()``.

        Returns:
            The config list with all switch identifiers resolved to serials.
        """
        if config is None:
            return []

        # Cheap gate — skip the fabric inventory GET when every identifier
        # already looks like a serial number.
        needs_any = False
        for entry in config:
            sv = entry.get("switch")
            if isinstance(sv, list):
                for se in sv:
                    val = se.get("serial_number") or se.get("ip") or ""
                    if _needs_resolution(val):
                        needs_any = True
                        break
            elif isinstance(sv, str) and _needs_resolution(sv):
                needs_any = True
            if needs_any:
                break

        if not needs_any:
            return config

        inventory = self._get_inventory()
        ip_map = inventory.by_ip()
        hostname_map = {sw.hostname.strip().lower(): sw for sw in inventory.switches if sw.hostname}

        def _resolve(identifier):
            if identifier is None:
                return None
            value = str(identifier).strip()
            if not value:
                return value
            sw = ip_map.get(value) or hostname_map.get(value.lower())
            return sw.switch_id if sw is not None else None

        for entry in config:
            switch_value = entry.get("switch")

            if isinstance(switch_value, list):
                for switch_entry in switch_value:
                    original = switch_entry.get("serial_number") or switch_entry.get("ip")
                    if not _needs_resolution(original):
                        continue
                    resolved = _resolve(original)
                    if resolved is None:
                        raise NDModuleError(
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
                    raise NDModuleError(
                        msg=(
                            f"Unable to resolve switch identifier '{switch_value}' to a serial number "
                            f"in fabric '{self.fabric_name}'. Provide a valid switch serial_number, "
                            "management IP, or hostname from the fabric inventory."
                        )
                    )
                entry["switch"] = resolved

        return config

    def _get_inventory(self) -> FabricSwitchInventory:
        """Fetch (once) and cache the fabric switch inventory.

        Delegates to :meth:`FabricSwitchInventory.from_fabric` which performs
        the ``GET /fabrics/{name}/switches`` call and parses results into
        typed ``SwitchDataModel`` instances.  Uses RestSend save/restore so
        the GET always hits the controller even in Ansible check mode.

        The result is memoised on ``self._inventory`` so multiple callers
        share a single API round-trip per module run.

        Returns:
            Populated :class:`FabricSwitchInventory` instance.
        """
        if self._inventory is not None:
            return self._inventory

        # Stamp the path/verb stash so any synthetic register that follows
        # an empty switch list still reflects the inventory GET.
        ep = EpManageFabricsSwitchesGet()
        ep.fabric_name = self.fabric_name
        self._record_call(ep, None)

        rest_send = self.nd._get_rest_send()
        rest_send.save_settings()
        rest_send.check_mode = False
        try:
            self._inventory = FabricSwitchInventory.from_fabric(self.nd, self.fabric_name, self.log, SwitchDataModel)
        finally:
            rest_send.restore_settings()
        return self._inventory

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
            NDModuleError: If any entry is missing a switch serial number.
        """
        for idx, entry in enumerate(translated_config):
            if not entry.get("switch"):
                raise NDModuleError(msg=f"config[{idx}]: every policy entry must have a switch serial number after translation.")

    # =========================================================================
    # Public API - State Management
    # =========================================================================

    def validate_and_prepare_config(self) -> None:
        """Validate, normalize, resolve, and flatten the playbook config.

        Full pipeline executed before state dispatch:
            1. **Pydantic validation** — each ``config[]`` entry is validated
               against ``PlaybookPolicyConfig``.  Also applies defaults
               (priority=500, description="", etc.)
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
        validation_context = {
            "state": self.state,
            "use_desc_as_key": self.use_desc_as_key,
        }
        normalized_config = []
        for idx, entry in enumerate(self.config):
            try:
                validated = PlaybookPolicyConfig.model_validate(entry, context=validation_context)
                normalized_config.append(validated.model_dump(by_alias=False, exclude_none=False))
            except ValidationError as ve:
                raise NDModuleError(msg=f"Input validation failed for config[{idx}]: {ve}") from ve
            except ValueError as ve:
                raise NDModuleError(msg=f"Input validation failed for config[{idx}]: {ve}") from ve
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
            - **deleted** - deploy=true: markDelete → switchActions/deploy
                          - deploy=false: markDelete only (policy left in markDeleted
                            state on controller; running config remains on the switch
                            until the next deploy)

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
            raise NDModuleError(msg=f"Unsupported state: {self.state}")

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
            ``validate_and_prepare_config()``.  In particular, the
            ``use_desc_as_key=true`` + empty-description rule is
            enforced by ``PlaybookPolicyConfig.validate_state_requirements``
            (see ``models/manage_policies/config_models.py``), which
            raises a ``ValueError`` for any template-name entry without
            a description in merged/deleted states.  This method only
            validates cross-entry constraints that Pydantic cannot
            enforce because it sees one entry at a time.

        Returns:
            None.
        """
        if not self.use_desc_as_key:
            return

        self.log.debug("ENTER: _validate_config() [use_desc_as_key=true]")

        desc_switch_counts: dict[str, int] = {}

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
            # Empty descriptions for template-name entries are already
            # rejected upstream by PlaybookPolicyConfig Pydantic validation
            # (config_models.validate_state_requirements), so reaching this
            # point with an empty description means name is a policy ID
            # (skipped above) or the entry is switch-only.
            if description:
                key = f"{description}|{switch}"
                desc_switch_counts[key] = desc_switch_counts.get(key, 0) + 1

        # Report all duplicates at once
        duplicates = [f"description='{k.split('|')[0]}', switch='{k.split('|')[1]}'" for k, count in desc_switch_counts.items() if count > 1]
        if duplicates:
            raise NDModuleError(
                msg=(
                    "Duplicate description+switch combinations found in the "
                    "playbook config (use_desc_as_key=true requires each "
                    "description to be unique per switch): " + "; ".join(duplicates)
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

        # Phase 0: Prefetch all fabric policies in a single GET call.
        # Subsequent _build_have() calls will use the in-memory cache
        # instead of making per-entry HTTP GETs.
        self._prefetch_all_policies(config_entries=self.config)

        # Phase 1: Build want and have for each config entry
        diff_results = []
        for config_entry in self.config:
            want = self._build_want(config_entry, state="merged")

            # Phase 1a: Validate templateInputs against template schema
            template_name = want.get("templateName")
            template_inputs = want.get("templateInputs") or {}
            if template_name and not self._is_policy_id(template_name):
                validation_errors = self._validate_template_inputs(template_name, template_inputs)
                if validation_errors:
                    error_msg = f"Template input validation failed for '{template_name}': " + "; ".join(validation_errors)
                    self.log.error(error_msg)
                    diff_results.append(
                        {
                            "action": "fail",
                            "want": want,
                            "have": None,
                            "diff": None,
                            "policy_id": None,
                            "error_msg": error_msg,
                        }
                    )
                    continue

            have_list, error_msg = self._build_have(want)

            if error_msg:
                self.log.error(f"Build have failed: {error_msg}")
                diff_results.append(
                    {
                        "action": "fail",
                        "want": want,
                        "have": None,
                        "diff": None,
                        "policy_id": None,
                        "error_msg": error_msg,
                    }
                )
                continue

            # Phase 2: Compute diff
            diff_entry = self._get_diff_merged_single(want, have_list)
            self.log.debug(f"Diff result for {want.get('templateName', want.get('policyId', 'unknown'))}: " f"action={diff_entry['action']}")
            diff_results.append(diff_entry)

        self.log.info(f"Computed {len(diff_results)} diff results")

        # Phase 3: Execute actions
        policy_ids_to_deploy = self._execute_merged(diff_results)

        # Phase 4: Deploy if requested
        if self.deploy and policy_ids_to_deploy:
            # Determine if any actual changes occurred (create/update)
            # vs only no-diff deploys.  No-diff deploys should not mark changed.
            has_actual_changes = any(dr.get("action") not in ("skip", None) for dr in diff_results)
            self.log.info(f"Deploying {len(policy_ids_to_deploy)} policies (has_actual_changes={has_actual_changes})")
            deploy_success = self._deploy_policies(policy_ids_to_deploy, changed=has_actual_changes)
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
        """Handle state=deleted: remove policies from ND.

        Returns:
            None.
        """
        self.log.debug("ENTER: _handle_deleted_state()")
        self.log.info("Handling deleted state")
        self.log.debug(f"Config entries: {len(self.config)}")

        # Phase 0: Prefetch all fabric policies in a single GET call.
        self._prefetch_all_policies(config_entries=self.config)

        # Phase 1: Build want and have for each config entry
        diff_results = []
        for config_entry in self.config:
            want = self._build_want(config_entry, state="deleted")
            have_list, error_msg = self._build_have(want)

            if error_msg:
                self.log.error(f"Build have failed: {error_msg}")
                diff_results.append(
                    {
                        "action": "fail",
                        "want": want,
                        "policies": [],
                        "policy_ids": [],
                        "match_count": 0,
                        "warning": None,
                        "error_msg": error_msg,
                    }
                )
                continue

            # Phase 2: Compute delete result
            diff_entry = self._get_diff_deleted_single(want, have_list)
            # Capture the GET stash from _build_have so Phase 3 can stamp
            # skip/fail rows with the actual lookup path/verb (payload=None).
            diff_entry["query_path"] = self._call_path
            diff_entry["query_verb"] = self._call_verb
            self.log.debug(f"Delete diff for {want.get('templateName', want.get('policyId', 'switch-only'))}: " f"action={diff_entry['action']}")
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

        # Phase 0: Prefetch all (or narrowed) fabric policies in one GET.
        # Subsequent _build_have() / per-switch iteration uses the
        # in-memory cache instead of N per-entry/per-switch HTTP GETs.
        self._prefetch_all_policies(config_entries=self.config if self.config else None)

        policies: list[dict] = []

        if self.config:
            # --- With config: query matching policies per entry ---
            self.log.info(f"Gathered with config: {len(self.config)} entries")
            for config_entry in self.config:
                want = self._build_want(config_entry, state="gathered")
                have_list, error_msg = self._build_have(want)

                if error_msg:
                    self.log.warning(f"Gathered: build_have error: {error_msg}")
                    # Keep the GET stash from _build_have so the failed
                    # lookup path/verb is reflected on the result row.
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
                # Keep the GET stash from _get_inventory so the
                # "no switches" row carries the actual lookup path/verb.
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

            # Use the prefetched cache instead of one GET per switch.
            # Cache already excludes markDeleted and source!="" entries.
            for switch_sn in switches:
                switch_policies = self._policies_by_switch_cache.get(switch_sn, [])
                self.log.info(f"Found {len(switch_policies)} policies on switch {switch_sn}")
                policies.extend(switch_policies)

        if not policies:
            self.log.info("Gathered: no policies found")
            # Keep the most recent GET stash (from _build_have or the
            # prefetch call) so the row reflects a real lookup that
            # returned empty.
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

        # De-duplicate by policyId using NDConfigCollection.
        # GatheredPolicy uses policyId as its single identifier, so
        # adding a policy with a duplicate policyId is silently skipped.
        gathered_collection = NDConfigCollection(model_class=GatheredPolicy)
        skipped = 0
        for pol in policies:
            pid = pol.get("policyId")
            if not pid:
                self.log.warning("Skipping policy without policyId in gathered results")
                skipped += 1
                continue
            try:
                model = GatheredPolicy.from_api_policy(pol)
            except Exception as exc:
                self.log.warning(f"Failed to parse policy {pid} for gathered output: {exc}")
                skipped += 1
                continue
            # NDConfigCollection.add() raises ValueError on duplicate key;
            # use get() first to skip duplicates gracefully.
            if gathered_collection.get(pid) is not None:
                self.log.debug(f"Gathered: skipping duplicate policy {pid}")
                skipped += 1
                continue
            gathered_collection.add(model)

        self.log.info(f"Gathered {len(gathered_collection)} unique policies " f"(from {len(policies)} total, {skipped} skipped)")

        # Convert each policy to playbook-ready config, applying
        # _clean_template_inputs to strip ND-injected keys.
        for model in gathered_collection:
            config_entry = model.to_gathered_config()
            # Clean template inputs using the template parameter API
            template_name = config_entry.get("name", "")
            raw_inputs = config_entry.get("template_inputs") or {}
            if template_name and raw_inputs:
                config_entry["template_inputs"] = self._clean_template_inputs(template_name, raw_inputs)
            self._gathered.append(config_entry)

        # Keep the most recent GET stash so the success row carries the
        # last lookup path/verb (no payload for GETs).
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

    def _get_fabric_switches(self) -> list[str]:
        """Fetch all switch serial numbers in the current fabric.

        Delegates to :meth:`_get_inventory` and projects the typed
        ``SwitchDataModel`` instances down to their serial-number strings.

        Returns:
            List of serial number strings.
        """
        self.log.debug("ENTER: _get_fabric_switches()")

        try:
            inventory = self._get_inventory()
        except Exception as exc:
            self.log.warning(f"Failed to fetch fabric switches: {exc}")
            return []

        switches = [sw.switch_id for sw in inventory.switches if sw.switch_id]

        self.log.info(f"Found {len(switches)} switches in fabric '{self.fabric_name}'")
        self.log.debug(f"EXIT: _get_fabric_switches() -> {switches}")
        return switches

    def _clean_template_inputs(self, template_name: str, raw_inputs: dict[str, Any]) -> dict[str, Any]:
        """Remove system-injected keys from template inputs.

        Strips keys listed in ``SYSTEM_INJECTED_TEMPLATE_KEYS`` (defined in
        ``constants.py`` and shared with policy-group resources) and keeps
        everything else as a real template variable.

        Args:
            template_name: Template name (for logging context).
            raw_inputs:    Raw ``templateInputs`` dict from the controller.

        Returns:
            Cleaned dict with system-injected keys removed.
        """
        self.log.debug(f"ENTER: _clean_template_inputs(template={template_name}, " f"keys={list(raw_inputs.keys())})")

        cleaned = {}
        stripped_keys = []
        for k, v in raw_inputs.items():
            if k in SYSTEM_INJECTED_TEMPLATE_KEYS:
                stripped_keys.append(k)
            else:
                cleaned[k] = v

        if stripped_keys:
            self.log.debug(f"Stripped {len(stripped_keys)} system-injected keys: " f"{sorted(stripped_keys)}")

        self.log.debug(f"EXIT: _clean_template_inputs() -> {len(cleaned)} keys " f"(removed {len(raw_inputs) - len(cleaned)})")
        return cleaned

    # =========================================================================
    # Helpers: Classification & Filtering
    # =========================================================================

    # Internal control flags carried on `want` dicts that are NOT real
    # policy attributes on the controller.  Stripped before any user-facing
    # projection (after, diff.after, _after).
    _INTERNAL_WANT_KEYS: ClassVar[frozenset] = frozenset({"create_additional_policy"})

    @classmethod
    def _strip_internal(cls, d: dict | None) -> dict:
        """Return a shallow copy of *d* with internal control keys removed.

        Internal keys (e.g. ``create_additional_policy``) are carried on the
        ``want`` dict so the diff classifier can read them, but they must not
        leak into ``after`` / ``diff.after`` / ``gathered`` outputs because
        they are not real attributes of the policy on the controller.
        """
        if not d:
            return {} if d is None else dict(d)
        return {k: v for k, v in d.items() if k not in cls._INTERNAL_WANT_KEYS}

    @staticmethod
    def _is_policy_id(name: str) -> bool:
        """Return True if name looks like a policy ID (starts with POLICY-).

        Args:
            name: Policy name or ID string to check.

        Returns:
            True if the name starts with ``POLICY-``, False otherwise.
        """
        return name.upper().startswith("POLICY-")

    @classmethod
    def _escape_lucene_value(cls, value: str) -> str:
        """Escape a value for safe inclusion in a Lucene filter term.

        ND's Lucene implementation does **not** support double-quoted
        phrase syntax (e.g. ``description:"hello world"`` returns zero
        results).  Instead, individual special characters are escaped
        with a backslash while spaces are left unescaped so that the
        Lucene tokenizer can match on individual words.  Callers that
        need exact-match semantics must post-filter the results.

        Args:
            value: Raw string value.

        Returns:
            Lucene-safe string with special chars backslash-escaped.
        """
        s = str(value)
        if not s:
            return s
        # Escape individual Lucene special characters with backslash.
        # Spaces are intentionally left unescaped — ND performs
        # tokenized (word-level) matching on spaces.
        chars_to_escape = set(r'+-!(){}[]^"~*?:\/')
        out: list = []
        for ch in s:
            if ch in chars_to_escape:
                out.append(f"\\{ch}")
            else:
                out.append(ch)
        return "".join(out)

    @classmethod
    def _build_lucene_filter(cls, **kwargs: Any) -> str:
        """Build a Lucene filter string from keyword arguments.

        Values containing Lucene special characters are automatically
        escaped/quoted so that descriptions like ``"policy: enable"``
        do not break the query syntax.

        Example::

            _build_lucene_filter(switchId="FDO123", templateName="feature_enable")
            # Returns: "switchId:FDO123 AND templateName:feature_enable"

            _build_lucene_filter(description="policy: enable (v2)")
            # Returns: 'description:"policy: enable (v2)"'

        Args:
            **kwargs: Key-value pairs to include in the Lucene filter.
                None values are skipped.

        Returns:
            Lucene filter string with terms joined by ``AND``.
        """
        parts = []
        for key, value in kwargs.items():
            if value is not None:
                parts.append(f"{key}:{cls._escape_lucene_value(str(value))}")
        return " AND ".join(parts)

    @staticmethod
    def _policies_differ(want: dict, have: dict) -> dict:
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
            # Normalize both sides to lowercase strings to handle:
            #   - Python bool True → "True" vs ND string "true"
            #   - Python int 100 → "100" vs ND string "100"
            # Also strip trailing whitespace/newlines to avoid false
            # diffs from multiline template inputs (e.g., CONF blocks).
            want_val = str(want_inputs[key]).strip().lower()
            have_val = str(have_inputs.get(key, "")).strip().lower()
            if want_val != have_val:
                input_diff[key] = {
                    "want": want_inputs[key],
                    "have": have_inputs.get(key),
                }
        if input_diff:
            diff["templateInputs"] = input_diff

        return diff

    # =========================================================================
    # API Query Helpers
    # =========================================================================

    def _prefetch_all_policies(self, config_entries: list[dict] | None = None) -> None:
        """Fetch fabric policies in a single GET call and build lookup indexes.

        Drastically reduces API call count for bulk operations:
            - Before: N config entries -> N GET calls in _build_have
            - After:  N config entries -> 1 GET call upfront, all lookups in memory

        When ``config_entries`` is provided and every entry resolves to a
        ``(switchId, templateName)`` pair (i.e. no policy-id-only and no
        switch-only entries), the GET is narrowed with a Lucene
        ``switchId:VALUE`` or ``switchId:(S1 OR S2 ...)`` filter to shrink
        the response body.  In all other cases the fetch is unfiltered (1 GET,
        full list) to guarantee that subsequent in-memory lookups find
        every policy the caller may ask for — preserving the exact
        semantics of the per-entry slow path.

        Populates four caches:
            - self._policies_cache:                    full list of valid policies
            - self._policies_by_id_cache:              {policyId: policy}
            - self._policies_by_switch_cache:          {switchId: [policies]}
            - self._policies_by_switch_template_cache: {(switchId, templateName): [policies]}

        After fetching, filters in Python code (not via the API) to exclude
        internal sub-policies (``source != ""``) and ``markDeleted`` policies.
        These fields are not supported as Lucene filter parameters by ND.
        """
        lucene_filter = self._build_prefetch_filter(config_entries)
        if lucene_filter:
            self.log.info(f"Prefetching policies with narrowed filter ({lucene_filter[:120]}...)")
        else:
            self.log.info("Prefetching all fabric policies (single unfiltered GET)")

        raw = self._query_policies_raw(lucene_filter=lucene_filter)

        self._policies_cache = []
        excluded = 0
        for p in raw:
            if p.get("source", "") != "":
                excluded += 1
                continue
            if p.get("markDeleted", False):
                excluded += 1
                continue
            self._policies_cache.append(p)

        # Build O(1) lookup indexes
        self._policies_by_id_cache = {}
        self._policies_by_switch_cache = {}
        self._policies_by_switch_template_cache = {}
        for p in self._policies_cache:
            pid = p.get("policyId")
            if pid:
                self._policies_by_id_cache[pid] = p
            sw = p.get("switchId") or p.get("serialNumber")
            if sw:
                self._policies_by_switch_cache.setdefault(sw, []).append(p)
                tn = p.get("templateName")
                if tn:
                    self._policies_by_switch_template_cache.setdefault((sw, tn), []).append(p)

        self.log.info(
            f"Policy cache populated: {len(self._policies_cache)} active policies "
            f"({excluded} excluded as internal/markDeleted) across "
            f"{len(self._policies_by_switch_cache)} switches, "
            f"{len(self._policies_by_switch_template_cache)} (switch,template) groups"
        )

    def _build_prefetch_filter(self, config_entries: list[dict] | None) -> str | None:
        """Build a narrowed Lucene filter for prefetch, or None if not safe.

        Returns one of:

        - ``switchId:VALUE`` when exactly one unique switch is referenced
          (the form the legacy per-switch ``_query_policies`` loop used,
          empirically reliable on the supported controller build).
        - ``switchId:(S1 OR S2 OR ...)`` when 2+ unique switches are referenced.
        - ``None`` when **any** entry lacks ``switch`` or references a policy id
          by ``name``.  Caller must then fetch unfiltered to preserve correctness
          for policy-id and switch-less entries.

        Note: only ``switchId`` is used in the Lucene filter.
        ``templateName`` filtering via Lucene is unreliable on the supported
        controller build — conjunctions that include ``templateName`` silently
        return zero results even when matching policies exist.  Similarly,
        ``source != ""`` cannot be expressed as a server-side filter (only
        positive equality on ``source`` works, and negation is rejected).
        Both are applied as client-side post-filters on the prefetched list.

        # TODO: Re-evaluate ``templateName`` and ``source`` Lucene filtering
        #       on newer ND controller builds.  If supported, narrowing on
        #       templateName would reduce the response body further for
        #       template-specific operations, and server-side source filtering
        #       would eliminate the post-filter pass.
        """
        if not config_entries:
            return None

        switches: set[str] = set()
        for entry in config_entries:
            switch = entry.get("switch")
            name = entry.get("name")
            # Any entry that can't be expressed via switchId narrowing
            # disqualifies the narrowed query -- we must fetch the full set.
            if not switch or not name or self._is_policy_id(name):
                return None
            switches.add(switch)

        if not switches:
            return None

        # Single-switch: use the plain ``switchId:VALUE`` form.  Empirical
        # testing against ND showed the single-element group-disjunction
        # form ``switchId:(VALUE)`` silently returns zero results on the
        # supported controller build, while the plain form works.
        if len(switches) == 1:
            return f"switchId:{self._escape_lucene_value(next(iter(switches)))}"

        switch_group = " OR ".join(self._escape_lucene_value(sw) for sw in sorted(switches))
        return f"switchId:({switch_group})"

    def _query_policies_raw(self, lucene_filter: str | None = None) -> list[dict]:
        """Query policies from the controller using GET /policies.

        Returns **all** matching policies including ``markDeleted`` and
        internal (``source != ""``) entries — the API does not support
        filtering on these fields.  Callers must filter them in Python
        code (this is what :meth:`_prefetch_all_policies` does).

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
        # set max to retrieve all matching policies.
        # Default page size is 10 which causes missed matches.
        ep.lucene_params.max = 10000

        self._record_call(ep, None)
        data = self.nd.request(ep.path, ep.verb)
        if isinstance(data, dict):
            policies = data.get("policies", [])
            self.log.debug(f"Raw query returned {len(policies)} policies")
            return policies
        self.log.debug("Query returned non-dict response, returning empty list")
        return []

    # =========================================================================
    # Core: Build want / have
    # =========================================================================

    def _build_want(self, config_entry: dict, state: str = "merged") -> dict:
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

    def _fetch_template_params(self, template_name: str) -> list[dict]:
        """Fetch and cache parameter definitions for a config template.

        Calls ``GET /api/v1/manage/configTemplates/{templateName}`` and
        extracts the ``parameters`` array. Results are cached per
        ``template_name`` so multiple config entries sharing the same
        template incur only one API call.

        Args:
            template_name: The ND template name (e.g., ``switch_freeform``).

        Returns:
            List of parameter dicts, each with at minimum ``name``,
            ``parameterType``, ``optional``, and ``defaultValue`` keys.
            Returns an empty list if the template has no parameters or
            the API call fails.
        """
        self.log.debug(f"ENTER: _fetch_template_params(template_name={template_name})")

        if template_name in self._template_params_cache:
            self.log.debug(f"Template params cache hit for '{template_name}': " f"{len(self._template_params_cache[template_name])} params")
            return self._template_params_cache[template_name]

        ep = EpManageConfigTemplateParametersGet()
        ep.template_name = template_name

        try:
            self._record_call(ep, None)
            data = self.nd.request(ep.path, ep.verb)
        except Exception as exc:
            self.log.warning(f"Failed to fetch template '{template_name}' parameters: {exc}. " "Skipping template input validation.")
            self._template_params_cache[template_name] = []
            return []

        # The response is a templateData object with 'parameters' key.
        # 'parameters' is a list of templateParameter objects.
        params = data.get("parameters") if isinstance(data, dict) else []
        if params is None:
            params = []

        self._template_params_cache[template_name] = params
        self.log.info(f"Fetched {len(params)} parameter definitions for template '{template_name}'")
        self.log.debug(f"Template '{template_name}' param names: " f"{[p.get('name') for p in params]}")
        self.log.debug(f"EXIT: _fetch_template_params()")
        return params

    def _validate_template_inputs(self, template_name: str, template_inputs: dict[str, Any]) -> list[str]:
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
        self.log.debug(f"ENTER: _validate_template_inputs(template={template_name}, " f"input_keys={list(template_inputs.keys())})")

        params = self._fetch_template_params(template_name)
        if not params:
            self.log.debug("No template params available, skipping validation")
            return []

        errors: list[str] = []

        # Build lookup: param_name -> param_def
        # Filter out internal parameters (annotations.IsInternal == "true")
        # that the controller auto-populates (e.g., SERIAL_NUMBER, POLICY_ID,
        # SOURCE, FABRIC_NAME). Users should never need to set these.
        param_map: dict[str, dict] = {}
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

        self.log.debug(f"Template '{template_name}': {len(param_map)} user params, " f"{len(internal_names)} internal params ({sorted(internal_names)})")

        # ------------------------------------------------------------------
        # Check 1: Unknown keys (skip internal params — they are allowed
        # but not advertised to users)
        # ------------------------------------------------------------------
        valid_names = set(param_map.keys()) | internal_names
        user_facing_names = set(param_map.keys())
        for user_key in template_inputs:
            if user_key not in valid_names:
                errors.append(f"Unknown templateInput key '{user_key}' for template " f"'{template_name}'. Valid keys: {sorted(user_facing_names)}")

        # ------------------------------------------------------------------
        # Check 2: Missing required parameters
        # ------------------------------------------------------------------
        for pname, pdef in param_map.items():
            is_optional = pdef.get("optional", True)
            default_val = pdef.get("defaultValue")
            has_default = default_val is not None and str(default_val).strip() != ""

            if not is_optional and not has_default and pname not in template_inputs:
                errors.append(f"Required templateInput '{pname}' (type={pdef.get('parameterType', '?')}) " f"is missing for template '{template_name}'")

        # ------------------------------------------------------------------
        # Check 3: Basic type validation (soft checks)
        # Empty strings are treated as "not set" — the controller accepts
        # them for optional fields, so we skip validation for them.  This
        # is especially important for the gathered → merged roundtrip
        # where the controller returns "" for unset optional parameters.
        # ------------------------------------------------------------------
        for user_key, user_val in template_inputs.items():
            pdef = param_map.get(user_key)
            if not pdef:
                continue  # Already flagged as unknown above

            ptype = (pdef.get("parameterType") or "").lower()
            val_str = str(user_val)

            # Skip type validation for empty/blank values — they mean "not set"
            if val_str.strip() == "":
                continue

            if ptype == "boolean":
                if val_str.lower() not in ("true", "false"):
                    errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects boolean (true/false), got '{val_str}'")

            elif ptype == "integer":
                try:
                    int(val_str)
                except ValueError:
                    errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects integer, got '{val_str}'")

            elif ptype == "long":
                try:
                    int(val_str)
                except ValueError:
                    errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects long integer, got '{val_str}'")

            elif ptype == "float":
                try:
                    float(val_str)
                except ValueError:
                    errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects float, got '{val_str}'")

            elif ptype in ("ipv4address", "ipaddress"):
                # Basic IPv4 check
                if not _IPV4_RE.match(val_str):
                    errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects IPv4 address (e.g., 192.168.1.1), got '{val_str}'")

            elif ptype == "ipv4addresswithsubnet":
                if not _IPV4_SUBNET_RE.match(val_str):
                    errors.append(
                        f"templateInput '{user_key}' for template '{template_name}' "
                        f"expects IPv4 address with subnet (e.g., 192.168.1.1/24), got '{val_str}'"
                    )

            elif ptype == "macaddress":
                if not _MAC_RE.match(val_str):
                    errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects MAC address, got '{val_str}'")

            elif ptype == "enum":
                # If metaProperties contains 'validValues', check against them
                meta = pdef.get("metaProperties") or {}
                valid_values_str = meta.get("validValues")
                if valid_values_str:
                    # validValues format is typically "val1,val2,val3"
                    valid_values = [v.strip() for v in valid_values_str.split(",")]
                    if val_str not in valid_values:
                        errors.append(f"templateInput '{user_key}' for template '{template_name}' " f"expects one of {valid_values}, got '{val_str}'")

        if errors:
            self.log.warning(f"Template input validation found {len(errors)} errors " f"for template '{template_name}': {errors}")
        else:
            self.log.debug(f"Template input validation passed for template '{template_name}'")

        self.log.debug("EXIT: _validate_template_inputs()")
        return errors

    def _build_have(self, want: dict) -> tuple[list[dict], str | None]:
        """Query existing policies matching the want, in-memory against the cache.

        Dispatches to :meth:`_build_have_from_cache`:
            - Case A: Policy ID given -> O(1) policyId index lookup
            - Case B: use_desc_as_key=false, templateName given -> O(1) (switchId, templateName) index
            - Case C: use_desc_as_key=true,  templateName given -> O(1) (switchId, templateName) index + exact description post-filter
            - Case D: Switch-only (no templateName or policyId) -> O(1) switchId index

        :meth:`_prefetch_all_policies` **must** be called by every state
        handler before this method is invoked.  A missing prefetch is a
        programming error -- we fail loudly here rather than silently
        falling back to N per-entry HTTP GETs (which is the perf
        regression the cache was introduced to prevent).

        Note on intentional behavioural differences vs. the legacy
        per-id ``GET /policies/{policyId}`` endpoint:
            - Internal ND sub-policies (``source != ""``) are excluded
              in Python code after the bulk GET (the API does not support
              filtering on ``source``).
            - ``markDeleted`` policies are excluded in Python code after
              the bulk GET (the API does not support filtering on
              ``markDeleted``).
            - Policy-id lookups are bounded by the prefetch's bulk-list
              page size (``max=10000``).  The same cap applied to the
              slow path's switch/template queries, so this is not a
              regression.  Fabrics with >10K policies require
              pagination in :meth:`_prefetch_all_policies`.

        Args:
            want: Want dict produced by ``_build_want``.

        Returns:
            Tuple of (have_list, error_msg).
        """
        if self._policies_cache is None:
            raise RuntimeError("_build_have() called before _prefetch_all_policies(); " "every state handler must prefetch the policy cache first.")
        return self._build_have_from_cache(want)

    def _build_have_from_cache(self, want: dict) -> tuple[list[dict], str | None]:
        """Cache-backed equivalent of _build_have -- pure in-memory filtering.

        Used when ``self._policies_cache`` has been populated by
        :meth:`_prefetch_all_policies`.  Performs no HTTP calls.

        Args:
            want: Want dict produced by ``_build_want``.

        Returns:
            Tuple of (have_list, error_msg).
        """
        # Case A: Policy ID given directly -- O(1) hash lookup
        if "policyId" in want:
            policy = self._policies_by_id_cache.get(want["policyId"])
            if policy:
                self.log.debug(f"[cache] Case A: Policy {want['policyId']} found")
                return [policy], None
            self.log.debug(f"[cache] Case A: Policy {want['policyId']} not found")
            return [], None

        # All other cases need switch-scoped list
        switch_id = want.get("switchId")
        switch_policies = self._policies_by_switch_cache.get(switch_id, [])

        # Case D: Switch-only -- return all policies on switch
        if "templateName" not in want:
            self.log.debug(f"[cache] Case D: {len(switch_policies)} policies on switch {switch_id}")
            return list(switch_policies), None

        template_name = want["templateName"]

        # Case B: use_desc_as_key=false, filter by templateName.
        # O(1) composite-index lookup instead of linear scan of switch_policies.
        if not self.use_desc_as_key:
            matches = list(self._policies_by_switch_template_cache.get((switch_id, template_name), []))

            want_desc = want.get("description", "")
            if want_desc:
                pre = len(matches)
                matches = [p for p in matches if (p.get("description", "") or "") == want_desc]
                self.log.debug(f"[cache] Case B: post-filter by description: {len(matches)}/{pre}")

            self.log.debug(f"[cache] Case B: matched {len(matches)} policies")
            return matches, None

        # Case C: use_desc_as_key=true, filter by templateName + exact description.
        # O(1) composite-index lookup, then exact-match post-filter on description.
        want_desc = want.get("description", "") or ""
        if not want_desc:
            return [], "description is required when use_desc_as_key=true and name is a template name"

        candidates = self._policies_by_switch_template_cache.get((switch_id, template_name), [])
        matches = [p for p in candidates if (p.get("description", "") or "") == want_desc]
        self.log.debug(f"[cache] Case C: matched {len(matches)} policies")
        return matches, None

    # =========================================================================
    # Diff: Merged State (16 cases)
    # =========================================================================

    def _get_diff_merged_single(self, want: dict, have_list: list[dict]) -> dict:
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
                # Case 7: Policy ID not found → FAIL
                #
                # When the user supplies an explicit policy ID, they are
                # asserting that this exact policy exists and should be
                # updated. If it doesn't exist, the user's intent cannot
                # be satisfied (we cannot create a policy with a caller-
                # specified ID — ND assigns IDs). Reporting "skip/success"
                # here would silently mask typos and out-of-band deletions,
                # so we hard-fail instead.
                result["action"] = "fail"
                result["error_msg"] = (
                    f"Policy {want['policyId']} not found on switch "
                    f"{want.get('switchId')}. Cannot update a non-existent "
                    "policy by ID — policy IDs are assigned by ND and "
                    "cannot be created by the caller. Verify the policy ID, "
                    "or use a template name to create a new policy."
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
            raise NDModuleError(
                msg=(
                    f"Multiple policies ({match_count}) found with description "
                    f"'{want.get('description')}' on switch {want.get('switchId')}. "
                    "Cannot determine which policy to update when "
                    "use_desc_as_key=true. Remove the duplicate policies from "
                    "the controller or use a policy ID directly."
                )
            )

        # Should not reach here
        result["action"] = "fail"
        result["error_msg"] = "Unable to determine action for policy config."
        return result

    # =========================================================================
    # Execute: Merged State
    # =========================================================================

    def _execute_merged(self, diff_results: list[dict]) -> list[str]:
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
            diff_results: list of diff result dicts from _get_diff_merged_single.

        Returns:
            List of policy IDs to deploy (if deploy=true).
        """
        self.log.debug("ENTER: _execute_merged()")
        self.log.debug(f"Processing {len(diff_results)} diff entries")
        policy_ids_to_deploy = []

        # Batches for bulk execution
        # Each item is (diff_entry_index, diff_entry) to preserve ordering
        create_batch: list[dict] = []
        update_batch: list[dict] = []
        delete_and_create_batch: list[dict] = []

        # ── Phase 1: Classify entries, register skip/fail immediately ───
        for diff_entry in diff_results:
            action = diff_entry["action"]
            want = diff_entry["want"]
            have = diff_entry["have"]
            error_msg = diff_entry["error_msg"]

            self.log.info(f"Classifying action={action} for " f"{want.get('templateName', want.get('policyId', 'unknown'))}")

            if action == "fail":
                self._proposed.append(want)
                self._clear_call()
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
                    # Even when no diff, if deploy=true we still deploy the
                    # existing policy to ensure it's pushed to the switch.
                    if self.deploy:
                        existing_pid = have.get("policyId")
                        if existing_pid:
                            policy_ids_to_deploy.append(existing_pid)
                            self.log.info(f"No diff but deploy=true: will deploy existing policy {existing_pid}")
                diff_payload = {"action": action, "want": want}
                if error_msg:
                    diff_payload["warning"] = error_msg
                self._clear_call()
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

        self.log.info(f"Batch summary: create={len(create_batch)}, " f"update={len(update_batch)}, " f"delete_and_create={len(delete_and_create_batch)}")

        # ── Phase 2: Check mode — register all as would-be changes ──────
        if self.check_mode:
            for diff_entry in create_batch:
                want = diff_entry["want"]
                self._proposed.append(want)
                self._after.append(self._strip_internal(want))
                self._record_call(
                    self._wouldbe_create_ep(),
                    {"policies": [self._strip_internal(want)]},
                )
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
                after_proj = self._strip_internal({**have, **want})
                self._after.append(after_proj)
                self._record_call(self._wouldbe_update_ep(diff_entry["policy_id"]), after_proj)
                self._register_result(
                    action="policy_update",
                    operation_type=OperationType.UPDATE,
                    return_code=200,
                    message="OK (check_mode)",
                    success=True,
                    found=True,
                    diff={
                        "action": "update",
                        "before": have,
                        "after": after_proj,
                        "want": want,
                        "have": have,
                        "diff": diff_entry["diff"],
                        "policy_id": diff_entry["policy_id"],
                    },
                )

            for diff_entry in delete_and_create_batch:
                want, have = diff_entry["want"], diff_entry["have"]
                self._proposed.append(want)
                self._before.append(have)
                after_proj = self._strip_internal(want)
                self._after.append(after_proj)
                self._record_call(self._wouldbe_create_ep(), {"policies": [after_proj]})
                self._register_result(
                    action="policy_replace",
                    operation_type=OperationType.UPDATE,
                    return_code=200,
                    message="OK (check_mode)",
                    success=True,
                    found=True,
                    diff={
                        "action": "delete_and_create",
                        "before": have,
                        "after": after_proj,
                        "want": want,
                        "have": have,
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
        #   3. deploy=true → switchActions/deploy to push config removal
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
            remove_ids = [d["policy_id"] for d in delete_and_create_batch if d["policy_id"]]
            if remove_ids:
                self.log.info(f"Phase 3: Removing {len(remove_ids)} old policies " f"for delete_and_create: {remove_ids}")

                # Build policy→switch map for switchActions/deploy
                dac_switch_map: dict[str, str] = {}
                for d in delete_and_create_batch:
                    pid = d.get("policy_id", "")
                    have = d.get("have") or {}
                    sw = have.get("switchId", d.get("want", {}).get("switchId", ""))
                    if pid and sw:
                        dac_switch_map[pid] = sw

                # Step 3a: Attempt markDelete for all old policies
                self.log.info(f"Phase 3a: markDelete for {len(remove_ids)} old policies")
                mark_delete_data = self._api_mark_delete(remove_ids)

                # Classify the 207 response into the three buckets.
                # ``warning`` entries are surfaced via self._warnings by
                # the helper and DO NOT appear in any failure bucket.
                mark_succeeded, mark_failed_python, mark_failed_other = self._parse_mark_delete_response(
                    mark_delete_data,
                    remove_ids,
                    context_label="markDelete (delete_and_create)",
                )

                self.log.info(
                    f"Phase 3a results: {len(mark_succeeded)} markDeleted, "
                    f"{len(mark_failed_python)} PYTHON-type, "
                    f"{len(mark_failed_other)} other failures"
                )

                # Track truly failed (non-PYTHON) as remove failures
                remove_failed_ids.update(mark_failed_other)

                # Step 3b: switch-level deploy to push removal config
                if mark_succeeded and self.deploy:
                    dac_switches = list({dac_switch_map[pid] for pid in mark_succeeded if pid in dac_switch_map})
                    if dac_switches:
                        self.log.info(f"Phase 3b: switchActions/deploy for " f"{len(dac_switches)} switch(es) to push removal config")
                        self._api_deploy_switches(dac_switches)
                    else:
                        self.log.warning("Phase 3b: No switch IDs found for markDeleted policies — skipping switch deploy")

                # Step 3c: Direct DELETE for PYTHON-type policies
                if mark_failed_python:
                    self.log.info(f"Phase 3d: Direct DELETE for " f"{len(mark_failed_python)} PYTHON-type policies")
                    direct_deleted, direct_failed = self._direct_delete_policies(mark_failed_python)
                    # Direct-DELETE exceptions are terminal removal failures
                    # for this entry — the caller will skip the create to
                    # avoid producing a duplicate alongside the un-removed
                    # old policy.
                    remove_failed_ids.update(direct_failed)

                    # Deploy to affected switches to push config removal
                    if direct_deleted and self.deploy:
                        affected_switches = list({dac_switch_map[pid] for pid in direct_deleted if pid in dac_switch_map})
                        if affected_switches:
                            self.log.info(f"Phase 3d: switchActions/deploy for " f"{len(affected_switches)} switch(es)")
                            self._api_deploy_switches(affected_switches)

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
        # NOTE: The orphan risk for DAC entries is inherent — ND has
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
                self._clear_call()
                self._register_result(
                    action="policy_replace",
                    operation_type=OperationType.UPDATE,
                    return_code=207,
                    message=(f"Cannot replace policy: removal of old policy " f"{d['policy_id']} failed. Skipping create to " f"avoid duplicates."),
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
            self.log.info(f"Bulk creating {len(want_list)} policies " f"(batch={batch_label})")

            try:
                created_ids = self._api_bulk_create_policies(want_list)
            except NDModuleError as bulk_err:
                self.log.error(f"Bulk {batch_label} failed entirely: {bulk_err.msg}")
                for diff_entry in batch_entries:
                    want = diff_entry["want"]
                    action_label = "policy_replace" if diff_entry["action"] == "delete_and_create" else "policy_create"
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

                entry_result = created_ids[idx] if idx < len(created_ids) else {"policy_id": None, "nd_error": "No response entry from ND"}
                created_id = entry_result["policy_id"]
                nd_error = entry_result["nd_error"]
                per_policy_error = None

                # created_id is None when per-policy response had status!=success
                if created_id is None:
                    per_policy_error = f"Policy creation failed for " f"{want.get('templateName')} on " f"{want.get('switchId')}: {nd_error}"

                self._proposed.append(want)
                if have:
                    self._before.append(have)

                if per_policy_error:
                    action_label = "policy_replace" if is_replace else "policy_create"
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
                after_proj = self._strip_internal({**want, "policyId": created_id})
                self._after.append(after_proj)

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
                            "after": after_proj,
                            "want": want,
                            "have": have,
                            "diff": field_diff,
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
                            "after": after_proj,
                            "want": want,
                            "diff": field_diff,
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
                self.log.error(f"Update failed for {policy_id}: {update_err.msg}")
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
                        "want": want,
                        "have": have,
                        "diff": field_diff,
                        "policy_id": policy_id,
                        "error": update_err.msg,
                    },
                )
                continue

            policy_ids_to_deploy.append(policy_id)

            after_merged = self._strip_internal({**have, **want, "policyId": policy_id})
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
                    "before": have,
                    "after": after_merged,
                    "want": want,
                    "have": have,
                    "diff": field_diff,
                    "policy_id": policy_id,
                },
            )

        self.log.info(f"Merged execute complete: {len(policy_ids_to_deploy)} policies to deploy")
        self.log.debug("EXIT: _execute_merged()")
        return policy_ids_to_deploy

    # =========================================================================
    # Diff: Deleted State (16 cases)
    # =========================================================================

    def _get_diff_deleted_single(self, want: dict, have_list: list[dict]) -> dict:
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
            if self.use_desc_as_key and want.get("description"):
                want_desc = want["description"]
                filtered = [p for p in have_list if (p.get("description") or "") == want_desc]
                policy_ids = [p.get("policyId") for p in filtered if p.get("policyId")]
                result["policies"] = filtered
                result["policy_ids"] = policy_ids
                result["match_count"] = len(filtered)
                if len(filtered) == 0:
                    result["action"] = "skip"
                elif len(filtered) == 1:
                    result["action"] = "delete"
                else:
                    raise NDModuleError(
                        msg=(
                            f"Multiple policies ({len(filtered)}) found with description "
                            f"'{want_desc}' on switch {want.get('switchId')}. "
                            "Descriptions must be unique per switch when "
                            "use_desc_as_key=true. Remove the duplicate policies from "
                            "the controller manually."
                        )
                    )
                return result

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
            raise NDModuleError(
                msg=(
                    f"Multiple policies ({match_count}) found with description "
                    f"'{want_desc}' on switch {want.get('switchId')}. "
                    "Descriptions must be unique per switch when "
                    "use_desc_as_key=true. Remove the duplicate policies from "
                    "the controller or use a policy ID directly."
                )
            )

        # Should not reach here
        result["action"] = "skip"
        return result

    # =========================================================================
    # Execute: Deleted State
    # =========================================================================

    def _execute_deleted(self, diff_results: list[dict]) -> None:
        """Execute the computed actions for all deleted config entries.

        Collects all policy IDs to delete across all config entries, then
        performs bulk API calls.  PYTHON content-type templates (e.g.
        ``switch_freeform``) use direct DELETE; everything else uses the
        normal markDelete (+ optional switch deploy) flow.

            - deploy=true:  markDelete → switchActions/deploy           (2-step)
            - deploy=false: markDelete only                              (1-step;
                            policy left in markDeleted state on controller,
                            running config remains on switch until next deploy)
            - PYTHON-type:  direct DELETE (+ switchActions/deploy when deploy=true)

        Args:
            diff_results: list of diff result dicts from ``_get_diff_deleted_single``.

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
        policy_template_map: dict[str, str] = {}
        # Map policy ID → switchId so we know which switches to deploy after
        # direct DELETE of PYTHON-type policies.
        policy_switch_map: dict[str, str] = {}

        for diff_entry in diff_results:
            action = diff_entry["action"]
            want = diff_entry["want"]
            policies = diff_entry["policies"]
            policy_ids = diff_entry["policy_ids"]
            match_count = diff_entry["match_count"]
            warning = diff_entry["warning"]
            error_msg = diff_entry["error_msg"]

            self.log.debug(f"Delete action={action} for " f"{want.get('templateName', want.get('policyId', 'switch-only'))}, " f"policy_ids={policy_ids}")

            # --- FAIL ---
            if action == "fail":
                self.log.warning(f"Delete failed: {error_msg}")
                self._proposed.append(want)
                # Restore the GET path/verb captured in Phase 1 so the row
                # reflects the actual lookup that surfaced this failure.
                self._clear_call()
                self._call_path = diff_entry.get("query_path")
                self._call_verb = diff_entry.get("query_verb")
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
                self.log.info(f"Policy not found for deletion: " f"{want.get('templateName', want.get('policyId', 'switch-only'))}")
                self._proposed.append(want)
                # Restore the GET path/verb captured in Phase 1 so the
                # "already absent" row shows the actual lookup we made.
                self._clear_call()
                self._call_path = diff_entry.get("query_path")
                self._call_verb = diff_entry.get("query_verb")
                self._register_result(
                    action="policy_deleted",
                    state="deleted",
                    operation_type=OperationType.QUERY,
                    return_code=200,
                    message="Policy not found — already absent",
                    success=True,
                    found=False,
                    diff={
                        "action": action,
                        "want": want,
                        "before": None,
                        "after": None,
                    },
                )
                continue

            # --- DELETE / DELETE_ALL ---
            if action in ("delete", "delete_all"):
                self.log.info(f"Collecting {len(policy_ids)} policy(ies) for deletion: {policy_ids}")
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
                    self._record_call(self._wouldbe_mark_delete_ep(), {"policyIds": policy_ids})
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

                # Real mode: do NOT register a per-entry intent row here. The
                # bulk markDelete in Phase B emits a single authoritative row
                # (with the deduplicated policyIds and the real path/payload);
                # an extra per-entry row would just duplicate that information.
                continue

        # Phase B: Execute bulk API calls (skip if check_mode or nothing to delete)
        if self.check_mode or not all_policy_ids_to_delete:
            self.log.info("Skipping bulk delete: " f"{'check_mode' if self.check_mode else 'no policies to delete'}")
            self.log.debug("EXIT: _execute_deleted()")
            return

        # Deduplicate policy IDs (same policy could match multiple config entries)
        unique_policy_ids = list(dict.fromkeys(all_policy_ids_to_delete))
        self.log.info(f"Total policies to delete: {len(unique_policy_ids)} " f"(deduplicated from {len(all_policy_ids_to_delete)})")

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
        # names, since the content type is an ND-internal property that
        # varies across templates and ND versions.
        # ---------------------------------------------------------------------

        # Step 1: Attempt markDelete for all policies
        self.log.info(f"{'Step 1/3' if self.deploy else 'Step 1/1'}: " f"markDelete for {len(unique_policy_ids)} policies")
        mark_delete_data = self._api_mark_delete(unique_policy_ids)

        # Classify the 207 response into the three buckets.
        # NOTE: the local var ``mark_failed`` corresponds to the helper's
        # ``mark_failed_other`` return (i.e. failures NOT due to PYTHON
        # content type).  The shorter name is preserved because it is
        # referenced by the result-registration block below.
        mark_succeeded, mark_failed_python, mark_failed = self._parse_mark_delete_response(
            mark_delete_data,
            unique_policy_ids,
            context_label="markDelete",
        )

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
                message=(f"markDelete failed for {len(mark_failed)} policy(ies): " f"{mark_failed}"),
                success=False,
                found=True,
                diff={
                    "action": "mark_delete_failed",
                    "policy_ids": mark_failed,
                },
            )

        # ── Step 2: switch deploy for markDeleted (non-PYTHON) ──
        #
        # After markDelete, a switch-level deploy pushes the removal
        # (negative) config to the affected switches.

        normal_delete_ids = mark_succeeded

        deploy_success = True
        if normal_delete_ids and self.deploy:
            # Step 2a: switch-level deploy to push removal config
            normal_switches = list({policy_switch_map[pid] for pid in normal_delete_ids if pid in policy_switch_map})
            if normal_switches:
                self.log.info(f"Step 2/3: switchActions/deploy for {len(normal_switches)} switch(es) " f"to push removal config: {normal_switches}")
                deploy_data = self._api_deploy_switches(normal_switches)

                if isinstance(deploy_data, dict) and deploy_data:
                    status_str = deploy_data.get("status", "")
                    if status_str:
                        self.log.info(f"switchActions/deploy status: {status_str}")
                else:
                    self.log.warning("switchActions/deploy returned empty body — " "treating as success (ND commonly returns {} for this endpoint)")

                self._register_result(
                    action="policy_switch_deploy",
                    state="deleted",
                    operation_type=OperationType.DELETE,
                    return_code=200,
                    message=(f"Deployed removal config to {len(normal_switches)} switch(es) " f"for {len(normal_delete_ids)} markDeleted policies"),
                    success=True,
                    found=True,
                    diff={
                        "action": "switch_deploy",
                        "switch_ids": normal_switches,
                        "policy_ids": normal_delete_ids,
                    },
                )
            else:
                self.log.warning("No switch IDs found for markDeleted policies — " "skipping switch deploy")

        elif normal_delete_ids and not self.deploy:
            # deploy=false: markDelete already happened; switch-level deploy
            # is skipped so config remains on device but policy is marked
            # for deletion on the controller.  No remove needed — the
            # next switch-level deploy (manual or via future playbook run
            # with deploy=true) will clean up.
            self.log.info(f"Deploy=false: {len(normal_delete_ids)} policies markDeleted but not deployed")

        # ── Step 3: direct DELETE + switchActions/deploy for PYTHON-type ──
        #
        # PYTHON content-type templates cannot be markDeleted.  We use
        # direct DELETE to remove the record, then switch-level deploy
        # to push the config removal to the devices.
        if mark_failed_python:
            self.log.info(f"Falling back to direct DELETE for {len(mark_failed_python)} " f"PYTHON-type policies: {mark_failed_python}")
            deleted_direct, failed_direct = self._direct_delete_policies(mark_failed_python)

            if deleted_direct:
                tpl_names = list({policy_template_map.get(pid, "unknown") for pid in deleted_direct})
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
                    message=(f"Direct DELETE failed for {len(failed_direct)} " f"policy(ies): {failed_direct}"),
                    success=False,
                    found=True,
                    diff={
                        "action": "direct_delete_failed",
                        "policy_ids": failed_direct,
                    },
                )

            # Deploy to affected switches so ND pushes the config removal
            # to the devices.  Direct DELETE removes the policy record but
            # the device still has the running config until we deploy.
            # This MUST be last — switchActions/deploy is fabric-wide and
            # would also push any pending markDeleted policy removals.
            if deleted_direct and self.deploy:
                affected_switches = list({policy_switch_map[pid] for pid in deleted_direct if pid in policy_switch_map})
                if affected_switches:
                    self.log.info(f"Deploying config to {len(affected_switches)} switch(es) " f"after direct DELETE: {affected_switches}")
                    deploy_data = self._api_deploy_switches(affected_switches)

                    deploy_ok = True
                    if isinstance(deploy_data, dict) and deploy_data:
                        status_str = deploy_data.get("status", "")
                        if status_str:
                            self.log.info(f"switchActions/deploy status: {status_str}")
                        else:
                            self.log.warning("switchActions/deploy returned non-empty body " f"but no 'status' field: {deploy_data}")
                    else:
                        self.log.warning("switchActions/deploy returned empty body — " "treating as success (ND commonly returns {} " "for this endpoint)")

                    self._register_result(
                        action="policy_switch_deploy",
                        state="deleted",
                        operation_type=OperationType.DELETE,
                        return_code=207,
                        message=(f"Deployed config to {len(affected_switches)} " f"switch(es) to push removal of directly-deleted " f"PYTHON-type policies"),
                        success=deploy_ok,
                        found=True,
                        diff={
                            "action": "switch_deploy",
                            "switch_ids": affected_switches,
                            "policy_ids": deleted_direct,
                            "deploy_success": deploy_ok,
                        },
                    )

        # If nothing succeeded at all, we're done
        if not mark_succeeded and not mark_failed_python:
            self.log.info("No policies were successfully deleted — done")

        self.log.debug("EXIT: _execute_deleted()")

    # =========================================================================
    # Deploy: pushConfig
    # =========================================================================

    def _deploy_policies(
        self,
        policy_ids: list[str],
        state: str = "merged",
        changed: bool = True,
    ) -> bool:
        """Deploy policies by calling pushConfig.

        Inspects the 207 Multi-Status response body for per-policy
        failures (e.g., device connectivity issues).  If any policy
        has ``status: "failed"``, the deploy is considered failed.

        Args:
            policy_ids: list of policy IDs to deploy.
            state: Module state for result reporting.
            changed: Whether to report this deploy as a change.
                Set to False when deploying already-in-sync policies
                (no-diff deploy) to preserve idempotence.

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

        # Build the pushConfig endpoint + payload up front so both check-mode
        # (would-be) and real branches can stamp Results.{path,verb,payload}_current.
        push_body = PolicyIds(policy_ids=policy_ids)
        push_payload = push_body.to_request_dict()

        ep = EpManagePolicyActionsPushConfigPost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        # NOTE: pushConfig does NOT accept ticketId per ND API specification

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
            self.results.path_current = ep.path
            self.results.verb_current = ep.verb
            self.results.payload_current = push_payload
            self.results.register_api_call()
            return True

        self._record_call(ep, push_payload)
        data = self.nd.request(ep.path, ep.verb, push_payload)

        # Inspect 207 body for per-policy success/warning/failure.
        # Warnings (e.g., "already in sync", "deployment skipped") are
        # NOT treated as failures — they are surfaced separately via
        # self._warnings so the operator sees them without the task
        # being marked failed.
        succeeded_policies, warning_policies, failed_policies = self._inspect_207_policies(data)

        # Warn if ND returned no per-policy detail at all
        if not succeeded_policies and not warning_policies and not failed_policies and policy_ids:
            self.log.warning(f"pushConfig returned no per-policy results for " f"{len(policy_ids)} policy IDs — treating as success " "(ambiguous response)")

        # Collect warnings for surfacing in exit_json.
        for p in warning_policies:
            pid = p.get("policyId", "?")
            msg = p.get("message", "")
            wmsg = f"pushConfig: ND warning for {pid}: {msg}"
            self.log.warning(wmsg)
            self._warnings.append(wmsg)

        deploy_success = len(failed_policies) == 0

        if failed_policies:
            failed_msgs = [f"{p.get('policyId', '?')}: {p.get('message', 'unknown error')}" for p in failed_policies]
            self.log.error(f"pushConfig failed for {len(failed_policies)} policy(ies): " + "; ".join(failed_msgs))

        self.results.response_current = self.nd.rest_send.response_current
        self.results.result_current = {
            "success": deploy_success,
            "found": True,
            "changed": deploy_success and changed,
        }
        self.results.diff_current = {
            "action": "deploy",
            "policy_ids": policy_ids,
            "deploy_success": deploy_success,
            "failed_policies": [p.get("policyId") for p in failed_policies],
            "warning_policies": [p.get("policyId") for p in warning_policies],
        }
        self._apply_stashed_call()
        self.results.register_api_call()
        return deploy_success

    # =========================================================================
    # 207 Multi-Status Response Inspection
    # =========================================================================

    @staticmethod
    def _inspect_207_policies(
        data: Any,
        key: str = "policies",
    ) -> tuple[list[dict], list[dict], list[dict]]:
        """Inspect a 207 Multi-Status response for per-item success/warning/failure.

        ND returns HTTP 207 for most bulk policy actions (create,
        markDelete, pushConfig, remove).  The response body contains
        a list of per-item results under a top-level key (``policies``),
        each with a required ``status`` field (``"success"``,
        ``"warning"``, or ``"failed"``) and an optional ``message``
        field.

        The per-item schema is ``policyBaseGeneralResponse``::

            {
                "status": "success" | "warning" | "failed",  # REQUIRED
                "message": "...",                              # optional
                "policyId": "POLICY-...",                      # optional
                "entityName": "SWITCH",                        # optional
                "entityType": "switch",                        # optional
                "templateName": "...",                         # optional
                "switchId": "FDO..."                           # optional
            }

        Classification rules:
            - ``status == "success"``  → succeeded bucket.
            - ``status == "warning"``  → warnings bucket. Non-fatal
              partial outcomes (e.g., "policy already in markDeleted
              state", "deployment skipped — already in sync"). The
              caller must NOT count these toward task failure, but
              SHOULD surface them to the operator (see
              :attr:`NDPolicyModule._warnings`).
            - Anything else (``"failed"``, ``"error"``, unknown values,
              missing status) → failed bucket. Defensive: an unknown
              future value is treated as failure rather than silently
              passing.

        Comparison is **case-insensitive**: ``"WARNING"`` is treated
        identically to ``"warning"``.

        If the response body is empty (``{}``) or does not contain
        the expected key, all three returned lists will be empty.  The
        caller should treat this as an ambiguous result (ND did
        not report per-item status) and decide accordingly.

        Args:
            data: Response DATA dict from ND (or None/non-dict).
            key: Top-level key holding the items list.
                 ``"policies"`` for policy action endpoints.

        Returns:
            Tuple of (succeeded, warnings, failed) lists of per-item dicts.
        """
        if not isinstance(data, dict):
            return [], [], []
        items = data.get(key, [])
        if not isinstance(items, list):
            return [], [], []
        succeeded: list = []
        warnings: list = []
        failed: list = []
        for item in items:
            status = str(item.get("status", "")).lower()
            if status == "success":
                succeeded.append(item)
            elif status == "warning":
                warnings.append(item)
            else:
                # "failed", "error", unknown values, or missing status.
                failed.append(item)
        return succeeded, warnings, failed

    # =========================================================================
    # API Helpers (low-level CRUD)
    # =========================================================================

    def _api_bulk_create_policies(self, want_list: list[dict]) -> list[dict]:
        """Create multiple policies via a single bulk POST.

        Builds one ``PolicyCreateBulk`` containing all entries and sends
        a single POST request.  The controller returns a per-policy
        response in the same order as the request.

        Args:
            want_list: list of want dicts, each with all policy fields.

        Returns:
            List of dicts (same length as want_list), each with::

                {
                    "policy_id": str or None,   # created ID, None on failure
                    "nd_error": str or None,  # ND error message on failure
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

        self.log.info(f"Bulk create payload templateInputs: " f"{[{k: v for k, v in (w.get('templateInputs') or {}).items()} for w in want_list]}")

        ep = EpManagePoliciesPost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id

        self._record_call(ep, payload)
        data = self.nd.request(ep.path, ep.verb, payload)

        # Parse per-policy results from the 207 response.
        # The controller returns policies in the same order as sent.
        created_policies = data.get("policies", []) if isinstance(data, dict) else []
        results: list[dict] = []

        for idx, want in enumerate(want_list):
            if idx < len(created_policies):
                entry = created_policies[idx]
                entry_status = str(entry.get("status", "")).lower()
                nd_msg = entry.get("message", "")
                pid = entry.get("policyId")
                if entry_status == "warning":
                    # Non-fatal: ND created/recognised the policy but flagged
                    # something noteworthy (e.g., "already exists, reused").
                    # Treat as success but surface the message via _warnings.
                    wmsg = (
                        f"Bulk create: ND warning for "
                        f"template={want.get('templateName')}, "
                        f"switch={want.get('switchId')}, "
                        f"policy_id={pid}: {nd_msg}"
                    )
                    self.log.warning(wmsg)
                    self._warnings.append(wmsg)
                    results.append({"policy_id": pid, "nd_error": None})
                elif entry_status != "success":
                    nd_msg = nd_msg or "Policy creation failed"
                    self.log.error(
                        f"Bulk create: policy {idx} failed "
                        f"(status={entry.get('status')!r}) — "
                        f"template={want.get('templateName')}, "
                        f"switch={want.get('switchId')}: {nd_msg}"
                    )
                    results.append({"policy_id": None, "nd_error": nd_msg})
                else:
                    self.log.info(f"Bulk create: policy {idx} created — {pid}")
                    results.append({"policy_id": pid, "nd_error": None})
            else:
                self.log.warning(f"Bulk create: no response entry for policy {idx}")
                results.append({"policy_id": None, "nd_error": "No response entry from ND"})

        self.log.info(
            f"Bulk create complete: " f"{sum(1 for r in results if r['policy_id'])} succeeded, " f"{sum(1 for r in results if r['policy_id'] is None)} failed"
        )
        return results

    def _api_update_policy(self, want: dict, have: dict, policy_id: str) -> None:
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
        self.log.info(f"Update payload templateInputs for {policy_id}: {merged_inputs}")

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

        self._record_call(ep, payload)
        self.nd.request(ep.path, ep.verb, payload)

    def _api_mark_delete(self, policy_ids: list[str]) -> dict:
        """Mark policies for deletion via POST /policyActions/markDelete.

        ND returns HTTP 207 Multi-Status with per-policy results.
        Policies with content type PYTHON (e.g. ``switch_freeform``,
        ``Ext_VRF_Lite_SVI``) will fail with::

            "Policies with content type PYTHON or without generated
             config can't be mark deleted."

        The caller must inspect the returned dict for per-policy
        failures and fall back to direct DELETE for those.

        Args:
            policy_ids: list of policy IDs to mark-delete.

        Returns:
            Response DATA dict from ND.  Typically contains a
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

        mark_payload = body.to_request_dict()
        self._record_call(ep, mark_payload)
        data = self.nd.request(ep.path, ep.verb, mark_payload)
        return data if isinstance(data, dict) else {}

    def _api_delete_policy(self, policy_id: str) -> None:
        """Delete a single policy via DELETE /policies/{policyId}.

        Used as a fallback for PYTHON content-type policies that cannot
        go through the markDelete flow.

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

        self._record_call(ep, None)
        self.nd.request(ep.path, ep.verb)

    def _api_deploy_switches(self, switch_ids: list[str]) -> dict:
        """Deploy fabric config to specific switches.

        Used after direct DELETE of PYTHON content-type policies to push
        the config removal to the actual devices.  Unlike ``pushConfig``
        (which operates on policy IDs), this endpoint operates on switch
        serial numbers.

        API: ``POST /fabrics/{fabricName}/switchActions/deploy``

        Args:
            switch_ids: list of switch serial numbers to deploy to.

        Returns:
            Response DATA dict from ND.  Typically contains a ``status``
            field like ``"Configuration deployment completed for [...]"``.
        """
        self.log.info(f"Deploying config to {len(switch_ids)} switch(es): {switch_ids}")
        body = SwitchIds(switch_ids=switch_ids)

        ep = EpManageSwitchActionsDeployPost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name

        deploy_payload = body.to_request_dict()
        self._record_call(ep, deploy_payload)
        data = self.nd.request(ep.path, ep.verb, deploy_payload)
        return data if isinstance(data, dict) else {}

    # =========================================================================
    # Shared delete helpers (used by _execute_merged Phase 3 and _execute_deleted Phase B)
    # =========================================================================

    def _parse_mark_delete_response(
        self,
        mark_delete_data: Any,
        requested_ids: list[str],
        *,
        context_label: str,
    ) -> tuple[list[str], list[str], list[str]]:
        """Classify a markDelete 207 response into success / python-fallback / other-fail.

        Centralises the per-entry classification logic that was previously
        duplicated between ``_execute_merged`` Phase 3 (``delete_and_create``
        removals) and ``_execute_deleted`` Phase B.

        Behaviour preserved from the duplicated implementations:

        - **Non-dict response** → log warning, treat ALL ``requested_ids``
          as succeeded (returns ``(list(requested_ids), [], [])``).  This
          matches ND's known behaviour of occasionally returning a non-dict
          body on success.
        - **Empty ``policies`` list in the dict** → log warning, treat ALL
          ``requested_ids`` as succeeded.  Same rationale.
        - **status == ``"warning"``** → emit a warning message via
          ``self.log.warning`` and ``self._warnings``, but DO NOT add the
          policy to any failure bucket.  Warning entries are soft-successes
          (the policy is in the desired ND state).
        - **status == ``"success"``** → succeeded bucket (implicitly: not in
          ``failed_ids`` set).
        - **Other non-success status** with message containing
          ``"content type PYTHON"`` → ``mark_failed_python`` bucket
          (caller should retry these via direct DELETE).
        - **Other non-success status** otherwise → ``mark_failed_other``
          bucket (terminal failure).

        ``mark_succeeded`` is derived as ``[pid for pid in requested_ids
        if pid not in failed_ids]`` so request order is preserved.

        Args:
            mark_delete_data: Raw response DATA from ``_api_mark_delete``
                (may be ``None``, a non-dict, an empty dict, or a dict
                with a ``policies`` list).
            requested_ids: The exact list of policy IDs that was sent.
                Used to derive ``mark_succeeded`` and for the
                ambiguous-response fallback.
            context_label: Short label included in the warning-message
                prefix so each caller's warnings are distinguishable
                (e.g. ``"markDelete"`` vs.
                ``"markDelete (delete_and_create)"``).

        Returns:
            Tuple of ``(mark_succeeded, mark_failed_python,
            mark_failed_other)``.
        """
        mark_failed_python: list[str] = []
        mark_failed_other: list[str] = []

        if not isinstance(mark_delete_data, dict):
            self.log.warning("markDelete returned non-dict response — " "treating all as succeeded")
            return list(requested_ids), mark_failed_python, mark_failed_other

        policies_response = mark_delete_data.get("policies", [])

        if not policies_response and requested_ids:
            self.log.warning(
                "markDelete returned empty 'policies' list for " f"{len(requested_ids)} policy IDs — " "treating all as succeeded (ambiguous response)"
            )
            return list(requested_ids), mark_failed_python, mark_failed_other

        failed_ids: set = set()
        for p in policies_response:
            pid = p.get("policyId", "")
            status = str(p.get("status", "")).lower()
            msg = p.get("message", "")
            if status == "warning":
                # Non-fatal: treat as success (pid stays out of
                # failed_ids set) and surface for operator audit.
                wmsg = f"{context_label}: ND warning for {pid}: {msg}"
                self.log.warning(wmsg)
                self._warnings.append(wmsg)
            elif status != "success":
                failed_ids.add(pid)
                if "content type PYTHON" in msg:
                    mark_failed_python.append(pid)
                    self.log.info(f"markDelete failed for {pid} (PYTHON content type) " "— will retry via direct DELETE")
                else:
                    mark_failed_other.append(pid)
                    self.log.error(f"markDelete failed for {pid} " f"(status={p.get('status')!r}): {msg}")

        mark_succeeded = [pid for pid in requested_ids if pid not in failed_ids]
        return mark_succeeded, mark_failed_python, mark_failed_other

    def _direct_delete_policies(
        self,
        python_pids: list[str],
    ) -> tuple[list[str], list[str]]:
        """Direct-DELETE the given policy IDs one by one (PYTHON-type fallback).

        Centralises the per-policy ``_api_delete_policy`` loop that was
        previously duplicated between ``_execute_merged`` Phase 3 and
        ``_execute_deleted`` Phase B.  Each call is wrapped in a broad
        ``except`` so a single bad ID does not abort the rest of the
        batch — exceptions are logged and the offending ID is reported
        back to the caller, which decides how to react (skip create vs.
        register a failure row).

        Args:
            python_pids: Policy IDs that failed ``markDelete`` with
                ``"content type PYTHON"`` and must be removed via the
                direct ``DELETE /policies/{policyId}`` endpoint.

        Returns:
            Tuple of ``(deleted_direct, failed_direct)``.
        """
        deleted_direct: list[str] = []
        failed_direct: list[str] = []
        for pid in python_pids:
            try:
                self._api_delete_policy(pid)
                deleted_direct.append(pid)
            except Exception:  # noqa: BLE001
                self.log.error(f"Direct DELETE also failed for {pid}")
                failed_direct.append(pid)
        return deleted_direct, failed_direct

    # =========================================================================
    # Results Helper
    # =========================================================================

    def _record_call(self, ep: Any, payload: dict | None = None) -> None:
        """Stash the path/verb/payload of the call about to be (or just) made.

        Called by every mutating ``_api_*`` helper immediately before
        ``self.nd.request(...)``, and by check-mode would-be branches
        that need to surface what *would* have been sent.  The stash is
        consumed by ``_register_result()`` (and the inline registers in
        ``_deploy_policies``) which copy it into
        ``Results.{path,verb,payload}_current``.

        Args:
            ep:      Endpoint instance exposing ``.path`` and ``.verb``.
            payload: Optional request body (DELETE-style calls pass None).
        """
        try:
            self._call_path = ep.path
            self._call_verb = ep.verb
        except AttributeError:
            self._call_path = None
            self._call_verb = None
        self._call_payload = payload if isinstance(payload, dict) else None

    def _clear_call(self) -> None:
        """Drop any stashed path/verb/payload.

        Called immediately before a synthetic ``_register_result()`` site
        (i.e., one that is NOT preceded by a real or would-be HTTP call)
        so that the result row does not inherit stale call info from a
        previous iteration.
        """
        self._call_path = None
        self._call_verb = None
        self._call_payload = None

    def _apply_stashed_call(self) -> None:
        """Stamp the currently-stashed call info onto Results.*_current.

        No-op if nothing is stashed.  Safe to invoke from any register
        site.  Does NOT clear the stash so that one bulk call can be
        attributed to multiple per-entry register rows.
        """
        if self._call_path is not None:
            self.results.path_current = self._call_path
        if self._call_verb is not None:
            self.results.verb_current = self._call_verb
        # payload_current setter accepts None — only stamp when we have one
        if self._call_payload is not None:
            self.results.payload_current = self._call_payload

    # -------------------------------------------------------------------------
    # Would-be endpoint builders (used by check-mode register sites so the
    # output's path/verb/payload arrays reflect what *would* have been sent).
    # -------------------------------------------------------------------------

    def _wouldbe_create_ep(self) -> Any:
        """Return a configured EpManagePoliciesPost for check-mode would-be."""
        ep = EpManagePoliciesPost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id
        return ep

    def _wouldbe_update_ep(self, policy_id: str) -> Any:
        """Return a configured EpManagePoliciesPut for check-mode would-be."""
        ep = EpManagePoliciesPut()
        ep.fabric_name = self.fabric_name
        ep.policy_id = policy_id
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id
        return ep

    def _wouldbe_mark_delete_ep(self) -> Any:
        """Return a configured EpManagePolicyActionsMarkDeletePost for check-mode would-be."""
        ep = EpManagePolicyActionsMarkDeletePost()
        ep.fabric_name = self.fabric_name
        if self.cluster_name:
            ep.endpoint_params.cluster_name = self.cluster_name
        if self.ticket_id:
            ep.endpoint_params.ticket_id = self.ticket_id
        return ep

    def _register_result(
        self,
        action: str,
        operation_type: OperationType,
        return_code: int,
        message: str,
        success: bool,
        found: bool,
        diff: dict,
        data: Any = None,
        state: str | None = None,
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
        self._apply_stashed_call()
        self.results.register_api_call()
