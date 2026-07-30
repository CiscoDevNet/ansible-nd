# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Enumerations for Policy Operations.

Extracted from the ND API specification for Nexus Dashboard Manage APIs.
"""

from __future__ import annotations

from enum import Enum

# =============================================================================
# ENUMS - Extracted from OpenAPI Schema components/schemas
# =============================================================================


class PolicyEntityType(str, Enum):
    """
    Valid entity types for policies.

    Based on: components/schemas/policyEntityType
    Description: Type of entity the policy is attached to.
    """

    SWITCH = "switch"
    CONFIG_PROFILE = "configProfile"
    INTERFACE = "interface"

    @classmethod
    def choices(cls) -> list[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]

    @classmethod
    def from_user_input(cls, value: str) -> PolicyEntityType:
        """
        Convert user-friendly input to enum value.
        Accepts underscore-separated values like 'config_profile' -> 'configProfile'
        """
        if not value:
            return cls.SWITCH
        # Try direct match first
        try:
            return cls(value)
        except ValueError:
            pass
        # Try converting underscore to camelCase
        parts = value.lower().split("_")
        camel_case = parts[0] + "".join(word.capitalize() for word in parts[1:])
        try:
            return cls(camel_case)
        except ValueError:
            raise ValueError(f"Invalid entity type: {value}. Valid options: {cls.choices()}")

    @classmethod
    def normalize(cls, value: str | PolicyEntityType | None) -> PolicyEntityType:
        """
        Normalize input to enum value (case-insensitive).
        Accepts: SWITCH, switch, config_profile, configProfile, etc.
        """
        if value is None:
            return cls.SWITCH
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            v_lower = value.lower()
            for et in cls:
                if et.value.lower() == v_lower:
                    return et
            # Try converting underscore to camelCase
            parts = v_lower.split("_")
            if len(parts) > 1:
                camel_case = parts[0] + "".join(word.capitalize() for word in parts[1:])
                for et in cls:
                    if et.value == camel_case:
                        return et
        raise ValueError(f"Invalid PolicyEntityType: {value}. Valid: {cls.choices()}")
