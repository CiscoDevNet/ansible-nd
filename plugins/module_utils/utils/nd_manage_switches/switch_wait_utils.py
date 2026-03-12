# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Multi-phase wait utilities for switch lifecycle operations."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import time
from typing import Any, Dict, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.nd_manage_switches.fabric_config import (
    V1ManageFabricInventoryDiscoverGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.nd_manage_switches.fabric_switches import (
    V1ManageFabricSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.nd_manage_switches.fabric_switch_actions import (
    V1ManageFabricSwitchActionsRediscoverPost,
)

from .fabric_utils import FabricUtils


class SwitchWaitUtils:
    """Multi-phase wait utilities for switch lifecycle operations.

    Polls the fabric switches API until target switches reach a manageable state,
    handling migration mode, greenfield/brownfield shortcuts, and rediscovery.
    """

    # Default wait parameters
    DEFAULT_MAX_ATTEMPTS: int = 300
    DEFAULT_WAIT_INTERVAL: int = 5  # seconds

    # Status values indicating the switch is ready
    MANAGEABLE_STATUSES = frozenset({"ok", "manageable"})

    # Status values indicating an operation is still in progress
    IN_PROGRESS_STATUSES = frozenset({
        "inProgress", "migration", "discovering", "rediscovering",
    })

    # Status values indicating failure
    FAILED_STATUSES = frozenset({
        "failed",
        "unreachable",
        "authenticationFailed",
        "timeout",
        "discoveryTimeout",
        "notReacheable",       # Note: typo matches the API spec
        "notAuthorized",
        "unknownUserPassword",
        "connectionError",
        "sshSessionError",
    })

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
            wait_interval: Seconds between polls (default ``5``).
            fabric_utils:  Optional ``FabricUtils`` instance for fabric
                           info queries. Created internally if not provided.
        """
        self.nd = nd_module.nd
        self.fabric = fabric
        self.log = logger or logging.getLogger("nd.SwitchWaitUtils")
        self.max_attempts = max_attempts or self.DEFAULT_MAX_ATTEMPTS
        self.wait_interval = wait_interval or self.DEFAULT_WAIT_INTERVAL
        self.fabric_utils = (
            fabric_utils or FabricUtils(nd_module, fabric, self.log)
        )

        # Pre-configure endpoints
        self.ep_switches_get = V1ManageFabricSwitchesGet()
        self.ep_switches_get.fabric_name = fabric

        self.ep_inventory_discover = V1ManageFabricInventoryDiscoverGet()
        self.ep_inventory_discover.fabric_name = fabric

        self.ep_rediscover = V1ManageFabricSwitchActionsRediscoverPost()
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
        self.log.info(
            f"Waiting for switches to become manageable: {serial_numbers}"
        )

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
        if (
            not skip_greenfield_check
            and self._is_greenfield_debug_enabled()
        ):
            self.log.info(
                "Greenfield debug flag enabled — "
                "skipping reload detection"
            )
            return True

        if skip_greenfield_check:
            self.log.info(
                "Greenfield debug check skipped "
                "(POAP bootstrap — device always reboots)"
            )

        # Phase 5: wait for "unreachable" (switch is reloading)
        if not self._wait_for_discovery_state(
            serial_numbers, "unreachable"
        ):
            return False

        # Phase 6: wait for "ok" (switch is ready)
        return self._wait_for_discovery_state(
            serial_numbers, "ok"
        )

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

        self.log.info(f"Waiting for discovery of: {seed_ip}")

        for attempt in range(attempts):
            status = self._get_discovery_status(seed_ip)

            if (
                status
                and status.get("status") in self.MANAGEABLE_STATUSES
            ):
                self.log.info(f"Discovery completed for {seed_ip}")
                return status

            if (
                status
                and status.get("status") in self.FAILED_STATUSES
            ):
                self.log.error(
                    f"Discovery failed for {seed_ip}: {status}"
                )
                return None

            self.log.debug(
                f"Discovery attempt {attempt + 1}/{attempts} "
                f"for {seed_ip}"
            )
            time.sleep(interval)

        self.log.warning(f"Discovery timeout for {seed_ip}")
        return None

    # =====================================================================
    # Phase Helpers – System Mode
    # =====================================================================

    def _wait_for_system_mode(
        self, serial_numbers: List[str]
    ) -> bool:
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

        self.log.info(
            "All switches in normal system mode — "
            "proceeding to discovery checks"
        )
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
        label = (
            f"exit '{target_mode}'"
            if expect_match
            else f"enter '{target_mode}'"
        )

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
                self.log.info(
                    f"All switches {label} mode (attempt {attempt})"
                )
                return remaining

            pending = remaining
            self.log.debug(
                f"Attempt {attempt}/{self.max_attempts}: "
                f"{len(pending)} switch(es) waiting to "
                f"{label}: {pending}"
            )
            time.sleep(
                self.wait_interval * self._MIGRATION_SLEEP_FACTOR
            )

        self.log.warning(
            f"Timeout waiting for switches to {label}: {pending}"
        )
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
        switch_index = {
            sw.get("serialNumber"): sw for sw in switch_data
        }
        remaining: List[str] = []
        for sn in serial_numbers:
            sw = switch_index.get(sn)
            if sw is None:
                remaining.append(sn)
                continue
            mode = (
                sw.get("additionalData", {})
                .get("systemMode", "")
                .lower()
            )
            # expect_match=True:  "still in target_mode" → not done
            # expect_match=False: "not yet in target_mode" → not done
            still_waiting = (
                (mode == target_mode)
                if expect_match
                else (mode != target_mode)
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
        switch_index = {
            sw.get("serialNumber"): sw for sw in switch_data
        }
        remaining: List[str] = []
        for sn in serial_numbers:
            sw = switch_index.get(sn)
            if sw is None:
                remaining.append(sn)
                continue
            status = (
                sw.get("additionalData", {})
                .get("discoveryStatus", "")
                .lower()
            )
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
                f"Attempt {attempt}/{self.max_attempts}: "
                f"{len(pending)} switch(es) not yet "
                f"'{target_state}': {pending}"
            )
            time.sleep(
                self.wait_interval * self._REDISCOVERY_SLEEP_FACTOR
            )

        self.log.warning(
            f"Timeout waiting for '{target_state}' state: "
            f"{serial_numbers}"
        )
        return False

    # =====================================================================
    # API Helpers
    # =====================================================================

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
                self.log.error(
                    "No switch data returned for fabric"
                )
                return None
            return switch_data
        except Exception as e:
            self.log.error(f"Failed to fetch switch data: {e}")
            return None

    def _trigger_rediscovery(
        self, serial_numbers: List[str]
    ) -> None:
        """POST a rediscovery request for the given switches.

        Args:
            serial_numbers: Switch serial numbers to rediscover.
        """
        if not serial_numbers:
            return

        payload = {"switchIds": serial_numbers}
        self.log.info(
            f"Triggering rediscovery for: {serial_numbers}"
        )
        try:
            self.nd.request(
                self.ep_rediscover.path,
                verb=self.ep_rediscover.verb,
                data=payload,
            )
        except Exception as e:
            self.log.warning(
                f"Failed to trigger rediscovery: {e}"
            )

    def _get_discovery_status(
        self, seed_ip: str,
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
                if (
                    switch.get("ip") == seed_ip
                    or switch.get("ipaddr") == seed_ip
                ):
                    return switch
            return None
        except Exception as e:
            self.log.debug(
                f"Discovery status check failed: {e}"
            )
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
                f"Fabric info retrieved for greenfield check: "
                f"{fabric_info}"
            )
            flag = (
                fabric_info
                .get("management", {})
                .get("greenfieldDebugFlag", "")
                .lower()
            )
            self.log.debug(
                f"Greenfield debug flag value: '{flag}'"
            )
            self._greenfield_debug_enabled = flag == "enable"
        except Exception as e:
            self.log.debug(
                f"Failed to get greenfield debug flag: {e}"
            )
            self._greenfield_debug_enabled = False

        return self._greenfield_debug_enabled


__all__ = [
    "SwitchWaitUtils",
]
