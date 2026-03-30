# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Utility helpers for nd_manage_switches: exceptions, fabric operations,
payload construction, credential grouping, bootstrap queries, and
multi-phase switch wait utilities.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import time
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_bootstrap import (
    EpManageFabricsBootstrapGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_inventory import (
    EpManageFabricsInventoryDiscoverGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switchactions import (
    EpManageFabricsSwitchActionsRediscoverPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.utils import (
    FabricUtils,
    SwitchOperationError,
)

# =========================================================================
# Payload Utilities
# =========================================================================


def mask_password(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep copy of *payload* with password fields masked.

    Useful for safe logging of API payloads that contain credentials.

    Args:
        payload: API payload dict (may contain ``password`` keys).

    Returns:
        Copy with every ``password`` value replaced by ``"********"``.
    """
    masked = deepcopy(payload)
    if "password" in masked:
        masked["password"] = "********"
    if isinstance(masked.get("switches"), list):
        for switch in masked["switches"]:
            if isinstance(switch, dict) and "password" in switch:
                switch["password"] = "********"
    return masked


class PayloadUtils:
    """Stateless helper for building ND Switch Resource API request payloads."""

    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize PayloadUtils.

        Args:
            logger: Optional logger; defaults to ``nd.PayloadUtils``.
        """
        self.log = logger or logging.getLogger("nd.PayloadUtils")

    def build_credentials_payload(
        self,
        serial_numbers: List[str],
        username: str,
        password: str,
    ) -> Dict[str, Any]:
        """Build payload for saving switch credentials.

        Args:
            serial_numbers: Switch serial numbers.
            username:       Switch username.
            password:       Switch password.

        Returns:
            Credentials API payload dict.
        """
        return {
            "switchIds": serial_numbers,
            "username": username,
            "password": password,
        }

    def build_switch_ids_payload(
        self,
        serial_numbers: List[str],
    ) -> Dict[str, Any]:
        """Build payload with switch IDs for remove / batch operations.

        Args:
            serial_numbers: Switch serial numbers.

        Returns:
            ``{"switchIds": [...]}`` payload dict.
        """
        return {"switchIds": serial_numbers}


# =========================================================================
# Switch Helpers
# =========================================================================


def get_switch_field(
    switch,
    field_names: List[str],
) -> Optional[Any]:
    """Extract a field value from a switch config, trying multiple names.

    Supports Pydantic models and plain dicts with both snake_case and
    camelCase key lookups.

    Args:
        switch:      Switch model or dict to extract from.
        field_names: Candidate field names to try, in priority order.

    Returns:
        First non-``None`` value found, or ``None``.
    """
    for name in field_names:
        if hasattr(switch, name):
            value = getattr(switch, name)
            if value is not None:
                return value
        elif isinstance(switch, dict):
            if name in switch and switch[name] is not None:
                return switch[name]
            # Try camelCase variant
            camel = "".join(
                word.capitalize() if i > 0 else word
                for i, word in enumerate(name.split("_"))
            )
            if camel in switch and switch[camel] is not None:
                return switch[camel]
    return None


def determine_operation_type(switch) -> str:
    """Determine the operation type from switch configuration.

    Args:
        switch: A ``SwitchConfigModel``, ``SwitchDiscoveryModel``,
            or raw dict.

    Returns:
        ``'normal'``, ``'poap'``, or ``'rma'``.
    """
    # Pydantic model with .operation_type attribute
    if hasattr(switch, "operation_type"):
        return switch.operation_type

    if isinstance(switch, dict):
        if "poap" in switch or "bootstrap" in switch:
            return "poap"
        if "rma" in switch or "old_serial" in switch or "oldSerial" in switch:
            return "rma"

    return "normal"


def group_switches_by_credentials(
    switches,
    log: logging.Logger,
) -> Dict[Tuple, list]:
    """Group switches by shared credentials for bulk API operations.

    Args:
        switches: Validated ``SwitchConfigModel`` instances.
        log:      Logger.

    Returns:
        Dict mapping a ``(username, password_hash, auth_proto,
        platform_type, preserve_config)`` tuple to the list of switches
        sharing those credentials.
    """
    groups: Dict[Tuple, list] = {}

    for switch in switches:
        password_hash = hash(switch.password)
        group_key = (
            switch.username,
            password_hash,
            switch.auth_proto,
            switch.platform_type,
            switch.preserve_config,
        )
        groups.setdefault(group_key, []).append(switch)

    log.info(
        "Grouped %s switches into %s credential group(s)",
        len(switches),
        len(groups),
    )

    for idx, (key, group_switches) in enumerate(groups.items(), 1):
        username, _pw_hash, auth_proto, platform_type, preserve_config = key
        auth_value = (
            auth_proto.value if hasattr(auth_proto, "value") else str(auth_proto)
        )
        platform_value = (
            platform_type.value
            if hasattr(platform_type, "value")
            else str(platform_type)
        )
        log.debug(
            f"Group {idx}: {len(group_switches)} switches with "
            f"username={username}, auth={auth_value}, "
            f"platform={platform_value}, "
            f"preserve_config={preserve_config}"
        )

    return groups


# =========================================================================
# Bootstrap Utilities
# =========================================================================


def query_bootstrap_switches(
    nd,
    fabric: str,
    log: logging.Logger,
) -> List[Dict[str, Any]]:
    """GET switches currently in the bootstrap (POAP / PnP) loop.

    Args:
        nd:     NDModule instance (REST client).
        fabric: Fabric name.
        log:    Logger.

    Returns:
        List of raw switch dicts from the bootstrap API.
    """
    log.debug("ENTER: query_bootstrap_switches()")

    endpoint = EpManageFabricsBootstrapGet()
    endpoint.fabric_name = fabric
    log.debug("Bootstrap endpoint: %s", endpoint.path)

    try:
        result = nd.request(
            path=endpoint.path,
            verb=endpoint.verb,
        )
    except Exception as e:
        msg = f"Failed to query bootstrap switches for " f"fabric '{fabric}': {e}"
        log.error(msg)
        nd.module.fail_json(msg=msg)

    if isinstance(result, dict):
        switches = result.get("switches", [])
    elif isinstance(result, list):
        switches = result
    else:
        switches = []

    log.info("Bootstrap API returned %s switch(es) in POAP loop", len(switches))
    log.debug("EXIT: query_bootstrap_switches()")
    return switches


def build_bootstrap_index(
    bootstrap_switches: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Build a serial-number-keyed index from bootstrap API data.

    Args:
        bootstrap_switches: Raw switch dicts from the bootstrap API.

    Returns:
        Dict mapping ``serial_number`` -> switch dict.
    """
    return {
        sw.get("serialNumber", sw.get("serial_number", "")): sw
        for sw in bootstrap_switches
    }


def build_poap_data_block(poap_cfg) -> Optional[Dict[str, Any]]:
    """Build optional data block for bootstrap and pre-provision models.

    Args:
        poap_cfg: ``POAPConfigModel`` from the user playbook.

    Returns:
        Data block dict, or ``None`` if no ``config_data`` is present.
    """
    if not poap_cfg.config_data:
        return None
    data_block: Dict[str, Any] = {}
    gateway = poap_cfg.config_data.gateway
    if gateway:
        data_block["gatewayIpMask"] = gateway
    if poap_cfg.config_data.models:
        data_block["models"] = poap_cfg.config_data.models
    return data_block or None


# =========================================================================
# Switch Wait Utilities
# =========================================================================


class SwitchWaitUtils:
    """Multi-phase wait utilities for switch lifecycle operations.

    Polls the fabric switches API until target switches reach a manageable state,
    handling migration mode, greenfield/brownfield shortcuts, and rediscovery.
    """

    # Default wait parameters
    DEFAULT_MAX_ATTEMPTS: int = 300
    DEFAULT_WAIT_INTERVAL: int = 10  # seconds

    # Status values indicating the switch is ready
    MANAGEABLE_STATUSES = frozenset({"ok", "manageable"})

    # Status values indicating an operation is still in progress
    IN_PROGRESS_STATUSES = frozenset(
        {
            "inProgress",
            "migration",
            "discovering",
            "rediscovering",
        }
    )

    # Status values indicating failure
    FAILED_STATUSES = frozenset(
        {
            "failed",
            "unreachable",
            "authenticationFailed",
            "timeout",
            "discoveryTimeout",
            "notReacheable",  # Note: typo matches the API spec
            "notAuthorized",
            "unknownUserPassword",
            "connectionError",
            "sshSessionError",
        }
    )

    # Sleep multipliers for each phase
    _MIGRATION_SLEEP_FACTOR: float = 2.0
    _REDISCOVERY_SLEEP_FACTOR: float = 3.5

    def __init__(
        self,
        nd_module,
        fabric: str,
        logger: Optional[logging.Logger] = None,
        max_attempts: Optional[int] = None,
        wait_interval: Optional[int] = None,
        fabric_utils: Optional["FabricUtils"] = None,
    ):
        """Initialize SwitchWaitUtils.

        Args:
            nd_module:     Parent module instance (must expose ``.nd``).
            fabric:        Fabric name.
            logger:        Optional logger; defaults to ``nd.SwitchWaitUtils``.
            max_attempts:  Max polling iterations (default ``300``).
            wait_interval: Override interval in seconds (default ``5``).
            fabric_utils:  Optional ``FabricUtils`` instance for fabric
                           info queries. Created internally if not provided.
        """
        self.nd = nd_module.nd
        self.fabric = fabric
        self.log = logger or logging.getLogger("nd.SwitchWaitUtils")
        self.max_attempts = max_attempts or self.DEFAULT_MAX_ATTEMPTS
        self.wait_interval = wait_interval or self.DEFAULT_WAIT_INTERVAL
        self.fabric_utils = fabric_utils or FabricUtils(nd_module, fabric, self.log)

        # Pre-configure endpoints
        self.ep_switches_get = EpManageFabricsSwitchesGet()
        self.ep_switches_get.fabric_name = fabric

        self.ep_inventory_discover = EpManageFabricsInventoryDiscoverGet()
        self.ep_inventory_discover.fabric_name = fabric

        self.ep_rediscover = EpManageFabricsSwitchActionsRediscoverPost()
        self.ep_rediscover.fabric_name = fabric

        # Cached greenfield flag
        self._greenfield_debug_enabled: Optional[bool] = None

    # =====================================================================
    # Public API – Wait Methods
    # =====================================================================

    def wait_for_switch_manageable(
        self,
        serial_numbers: List[str],
        all_preserve_config: bool = False,
        skip_greenfield_check: bool = False,
    ) -> bool:
        """Wait for switches to exit migration mode and become manageable.

        Runs a multi-phase poll: migration-mode exit, normal-mode entry,
        brownfield shortcut, greenfield shortcut, unreachable detection,
        and final rediscovery to ok status.

        Args:
            serial_numbers:      Switch serial numbers to monitor.
            all_preserve_config: Set to ``True`` when all switches in the
                batch are brownfield (``preserve_config=True``). Skips
                reload detection, as brownfield switches never reload.
            skip_greenfield_check: Set to ``True`` to bypass the greenfield
                debug flag shortcut (required for POAP bootstrap where
                the device always reboots).

        Returns:
            ``True`` if all switches are manageable, ``False`` on timeout.
        """
        self.log.info("Waiting for switches to become manageable: %s", serial_numbers)

        # Phase 1 + 2: migration → normal
        if not self._wait_for_system_mode(serial_numbers):
            return False

        # Phase 3: brownfield shortcut — no reload expected
        if all_preserve_config:
            self.log.info(
                "All switches are brownfield (preserve_config=True) — "
                "skipping reload detection (phases 5-6)"
            )
            return True

        # Phase 4: greenfield shortcut (skipped for POAP bootstrap)
        if not skip_greenfield_check and self._is_greenfield_debug_enabled():
            self.log.info("Greenfield debug flag enabled — skipping reload detection")
            return True

        if skip_greenfield_check:
            self.log.info(
                "Greenfield debug check skipped "
                "(POAP bootstrap — device always reboots)"
            )

        # Phase 5: wait for "unreachable" (switch is reloading)
        if not self._wait_for_discovery_state(serial_numbers, "unreachable"):
            return False

        # Phase 6: wait for "ok" (switch is ready)
        return self._wait_for_discovery_state(serial_numbers, "ok")

    def wait_for_rma_switch_ready(
        self,
        serial_numbers: List[str],
    ) -> bool:
        """Wait for RMA replacement switches to become manageable.

        RMA replacement switches come up via POAP bootstrap and never enter
        migration mode.  Three phases are run in order:

        1. Wait for each new serial to appear in the fabric inventory.
           The controller registers the switch after ``provisionRMA``
           completes, but it may take a few polling cycles.
        2. Wait for discovery status ``ok``.

        Args:
            serial_numbers: New (replacement) switch serial numbers to monitor.

        Returns:
            ``True`` if all switches reach ``ok`` status, ``False`` on timeout.
        """
        self.log.info(
            f"Waiting for RMA replacement switch(es) to become ready "
            f"(skipping migration-mode phase): {serial_numbers}"
        )

        # Phase 1: wait until all new serials appear in the fabric inventory.
        # Rediscovery triggers will 400 until the switch is registered.
        if not self._wait_for_switches_in_fabric(serial_numbers):
            return False

        # Phase 2: wait for ok discovery status.
        return self._wait_for_discovery_state(serial_numbers, "ok")

    def wait_for_discovery(
        self,
        seed_ip: str,
        max_attempts: Optional[int] = None,
        wait_interval: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Poll until a single switch discovery completes.

        Args:
            seed_ip:       IP address of the switch being discovered.
            max_attempts:  Override max attempts (default ``30``).
            wait_interval: Override interval in seconds (default ``5``).

        Returns:
            Discovery data dict on success, ``None`` on failure or timeout.
        """
        attempts = max_attempts or 30
        interval = wait_interval or self.wait_interval

        self.log.info("Waiting for discovery of: %s", seed_ip)

        for attempt in range(attempts):
            status = self._get_discovery_status(seed_ip)

            if status and status.get("status") in self.MANAGEABLE_STATUSES:
                self.log.info("Discovery completed for %s", seed_ip)
                return status

            if status and status.get("status") in self.FAILED_STATUSES:
                self.log.error("Discovery failed for %s: %s", seed_ip, status)
                return None

            self.log.debug(
                "Discovery attempt %s/%s for %s",
                attempt + 1,
                attempts,
                seed_ip,
            )
            time.sleep(interval)

        self.log.warning("Discovery timeout for %s", seed_ip)
        return None

    # =====================================================================
    # Phase Helpers – System Mode
    # =====================================================================

    def _wait_for_system_mode(self, serial_numbers: List[str]) -> bool:
        """Poll until all switches transition from migration mode to normal mode.

        Args:
            serial_numbers: Switch serial numbers to monitor.

        Returns:
            ``True`` when all switches are in ``normal`` mode,
            ``False`` on timeout or API failure.
        """
        # Sub-phase A: exit "migration" mode
        pending = self._poll_system_mode(
            serial_numbers,
            target_mode="migration",
            expect_match=True,
        )
        if pending is None:
            return False

        # Sub-phase B: enter "normal" mode
        pending = self._poll_system_mode(
            serial_numbers,
            target_mode="normal",
            expect_match=False,
        )
        if pending is None:
            return False

        self.log.info("All switches in normal system mode — proceeding to discovery checks")
        return True

    def _poll_system_mode(
        self,
        serial_numbers: List[str],
        target_mode: str,
        expect_match: bool,
    ) -> Optional[List[str]]:
        """Poll until no switches remain in (or outside) ``target_mode``.

        Args:
            serial_numbers: Switches to check.
            target_mode:    System mode string (e.g. ``"migration"``).
            expect_match:   When ``True``, waits for switches to leave
                            ``target_mode``. When ``False``, waits for
                            switches to enter ``target_mode``.

        Returns:
            Empty list on success, ``None`` on timeout or API error.
        """
        pending = list(serial_numbers)
        label = f"exit '{target_mode}'" if expect_match else f"enter '{target_mode}'"

        for attempt in range(1, self.max_attempts + 1):
            if not pending:
                return pending

            switch_data = self._fetch_switch_data()
            if switch_data is None:
                return None

            remaining = self._filter_by_system_mode(
                pending, switch_data, target_mode, expect_match
            )

            if not remaining:
                self.log.info("All switches %s mode (attempt %s)", label, attempt)
                return remaining

            pending = remaining
            self.log.debug(
                "Attempt %s/%s: %s switch(es) waiting to %s: %s",
                attempt,
                self.max_attempts,
                len(pending),
                label,
                pending,
            )
            time.sleep(self.wait_interval * self._MIGRATION_SLEEP_FACTOR)

        self.log.warning("Timeout waiting for switches to %s: %s", label, pending)
        return None

    # =====================================================================
    # Filtering (static, pure-logic helpers)
    # =====================================================================

    @staticmethod
    def _filter_by_system_mode(
        serial_numbers: List[str],
        switch_data: List[Dict[str, Any]],
        target_mode: str,
        expect_match: bool,
    ) -> List[str]:
        """Return serial numbers that have NOT yet satisfied the mode check.

        Args:
            serial_numbers: Switches to inspect.
            switch_data:    Raw switch dicts from the GET API.
            target_mode:    e.g. ``"migration"`` or ``"normal"``.
            expect_match:   When ``True``, waits for switches to leave
                            ``target_mode``. When ``False``, waits for
                            switches to enter ``target_mode``.

        Returns:
            Serial numbers still waiting.
        """
        switch_index = {sw.get("serialNumber"): sw for sw in switch_data}
        remaining: List[str] = []
        for sn in serial_numbers:
            sw = switch_index.get(sn)
            if sw is None:
                remaining.append(sn)
                continue
            mode = sw.get("additionalData", {}).get("systemMode", "").lower()
            # expect_match=True:  "still in target_mode" → not done
            # expect_match=False: "not yet in target_mode" → not done
            still_waiting = (
                (mode == target_mode) if expect_match else (mode != target_mode)
            )
            if still_waiting:
                remaining.append(sn)
        return remaining

    @staticmethod
    def _filter_by_discovery_status(
        serial_numbers: List[str],
        switch_data: List[Dict[str, Any]],
        target_state: str,
    ) -> List[str]:
        """Return serial numbers not yet at ``target_state``.

        Args:
            serial_numbers: Switches to inspect.
            switch_data:    Raw switch dicts from the GET API.
            target_state:   e.g. ``"unreachable"`` or ``"ok"``.

        Returns:
            Serial numbers still waiting.
        """
        switch_index = {sw.get("serialNumber"): sw for sw in switch_data}
        remaining: List[str] = []
        for sn in serial_numbers:
            sw = switch_index.get(sn)
            if sw is None:
                remaining.append(sn)
                continue
            status = sw.get("additionalData", {}).get("discoveryStatus", "").lower()
            if status != target_state:
                remaining.append(sn)
        return remaining

    # =====================================================================
    # Phase Helpers – Discovery Status
    # =====================================================================

    def _wait_for_discovery_state(
        self,
        serial_numbers: List[str],
        target_state: str,
    ) -> bool:
        """Poll until all switches reach the given discovery status.

        Triggers rediscovery on each iteration for switches that have not
        yet reached the target state.

        Args:
            serial_numbers: Switch serial numbers to monitor.
            target_state:   Expected discovery status, e.g. ``"unreachable"``
                            or ``"ok"``.

        Returns:
            ``True`` when all switches reach ``target_state``,
            ``False`` on timeout.
        """
        pending = list(serial_numbers)

        for attempt in range(1, self.max_attempts + 1):
            if not pending:
                return True

            switch_data = self._fetch_switch_data()
            if switch_data is None:
                return False

            pending = self._filter_by_discovery_status(
                pending, switch_data, target_state
            )

            if not pending:
                self.log.info(
                    f"All switches reached '{target_state}' state "
                    f"(attempt {attempt})"
                )
                return True

            self._trigger_rediscovery(pending)
            self.log.debug(
                "Attempt %s/%s: %s switch(es) not yet '%s': %s",
                attempt,
                self.max_attempts,
                len(pending),
                target_state,
                pending,
            )
            time.sleep(self.wait_interval * self._REDISCOVERY_SLEEP_FACTOR)

        self.log.warning(
            "Timeout waiting for '%s' state: %s", target_state, serial_numbers
        )
        return False

    # =====================================================================
    # API Helpers
    # =====================================================================

    def _wait_for_switches_in_fabric(
        self,
        serial_numbers: List[str],
    ) -> bool:
        """Poll until all serial numbers appear in the fabric inventory.

        After ``provisionRMA`` the controller registers the new switch
        asynchronously.  Rediscovery requests will fail with 400
        "Switch not found" until the switch is registered, so we must
        wait for it to appear before triggering any rediscovery.

        Args:
            serial_numbers: Switch serial numbers to wait for.

        Returns:
            ``True`` when all serials are present, ``False`` on timeout.
        """
        pending = list(serial_numbers)
        self.log.info(
            f"Waiting for {len(pending)} switch(es) to appear in "
            f"fabric inventory: {pending}"
        )

        for attempt in range(1, self.max_attempts + 1):
            if not pending:
                return True

            switch_data = self._fetch_switch_data()
            if switch_data is None:
                # API error — keep waiting
                time.sleep(self.wait_interval)
                continue

            known_serials = {sw.get("serialNumber") for sw in switch_data}
            pending = [sn for sn in pending if sn not in known_serials]

            if not pending:
                self.log.info(
                    f"All RMA switch(es) now visible in fabric inventory "
                    f"(attempt {attempt})"
                )
                return True

            self.log.debug(
                "Attempt %s/%s: %s switch(es) not yet in fabric: %s",
                attempt,
                self.max_attempts,
                len(pending),
                pending,
            )
            time.sleep(self.wait_interval)

        self.log.warning("Timeout waiting for switches to appear in fabric: %s", pending)
        return False

    def _fetch_switch_data(
        self,
    ) -> Optional[List[Dict[str, Any]]]:
        """GET current switch data for the fabric.

        Returns:
            List of switch dicts, or ``None`` on failure.
        """
        try:
            response = self.nd.request(
                self.ep_switches_get.path,
                verb=self.ep_switches_get.verb,
            )
            switch_data = response.get("switches", [])
            if not switch_data:
                self.log.error("No switch data returned for fabric")
                return None
            return switch_data
        except Exception as e:
            self.log.error("Failed to fetch switch data: %s", e)
            return None

    def _trigger_rediscovery(self, serial_numbers: List[str]) -> None:
        """POST a rediscovery request for the given switches.

        Args:
            serial_numbers: Switch serial numbers to rediscover.
        """
        if not serial_numbers:
            return

        payload = {"switchIds": serial_numbers}
        self.log.info("Triggering rediscovery for: %s", serial_numbers)
        try:
            self.nd.request(
                self.ep_rediscover.path,
                verb=self.ep_rediscover.verb,
                data=payload,
            )
        except Exception as e:
            self.log.warning("Failed to trigger rediscovery: %s", e)

    def _get_discovery_status(
        self,
        seed_ip: str,
    ) -> Optional[Dict[str, Any]]:
        """GET discovery status for a single switch by IP.

        Args:
            seed_ip: IP address of the switch.

        Returns:
            Switch dict from the discovery API, or ``None``.
        """
        try:
            response = self.nd.request(
                self.ep_inventory_discover.path,
                verb=self.ep_inventory_discover.verb,
            )
            for switch in response.get("switches", []):
                if switch.get("ip") == seed_ip or switch.get("ipaddr") == seed_ip:
                    return switch
            return None
        except Exception as e:
            self.log.debug("Discovery status check failed: %s", e)
            return None

    def _is_greenfield_debug_enabled(self) -> bool:
        """Check whether the fabric has the greenfield debug flag enabled.

        Uses the ``FabricUtils`` instance. Result is cached for the
        lifetime of the instance.

        Returns:
            ``True`` if the flag is ``"enable"``, ``False`` otherwise.
        """
        if self._greenfield_debug_enabled is not None:
            return self._greenfield_debug_enabled

        try:
            fabric_info = self.fabric_utils.get_fabric_info()
            self.log.debug(
                f"Fabric info retrieved for greenfield check: " f"{fabric_info}"
            )
            flag = (
                fabric_info.get("management", {}).get("greenfieldDebugFlag", "").lower()
            )
            self.log.debug("Greenfield debug flag value: '%s'", flag)
            self._greenfield_debug_enabled = flag == "enable"
        except Exception as e:
            self.log.debug("Failed to get greenfield debug flag: %s", e)
            self._greenfield_debug_enabled = False

        return self._greenfield_debug_enabled


__all__ = [
    "SwitchOperationError",
    "PayloadUtils",
    "FabricUtils",
    "SwitchWaitUtils",
    "mask_password",
    "get_switch_field",
    "determine_operation_type",
    "group_switches_by_credentials",
    "query_bootstrap_switches",
    "build_bootstrap_index",
    "build_poap_data_block",
]
