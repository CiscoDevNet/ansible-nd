# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""API payload builders for ND Switch Resource operations."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from copy import deepcopy
from typing import Any, Dict, List, Optional


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


__all__ = [
    "mask_password",
    "PayloadUtils",
]
