# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Switch-specific validators.

Domain-specific validators for switch models. Generic validators for IP, MAC,
hostname, etc. are imported from common.validators and re-exported for convenience.
"""

from __future__ import annotations

import re

# Import and re-export generic validators from common module
from ...common.validators import (
    _normalize_optional_string,
    _require_field,
    validate_ip_address,
    validate_cidr,
    validate_ip_or_cidr_as_cidr,
    validate_hostname,
    validate_mac_address,
    require_ip_address,
    require_ip_or_cidr_as_cidr,
    require_hostname,
    require_mac_address,
    validate_cidr_optional,
    check_credentials_pair,
)

# ------------------------------------------------------------------
# Switch-specific validators
# ------------------------------------------------------------------


def validate_serial_number(v: str | None) -> str | None:
    """Validate switch serial number format.

    Args:
        v: Raw serial number value.

    Returns:
        Validated serial number, or ``None`` if input is None/empty.

    Raises:
        ValueError: When the serial number contains invalid characters.
    """
    v = _normalize_optional_string(v)
    if v is None:
        return None
    # Serial numbers are typically alphanumeric with optional hyphens
    if not re.match(r"^[A-Za-z0-9_-]+$", v):
        raise ValueError(f"Serial number must be alphanumeric with optional hyphens/underscores: {v}")
    return v


def require_serial_number(v: str, field_name: str = "serial_number") -> str:
    """Validate and require a non-empty serial number.

    Args:
        v: Raw serial number value.
        field_name: Field name used in the error message.

    Returns:
        Validated serial number string.

    Raises:
        ValueError: When the value is empty or contains invalid characters.
    """
    return _require_field(v, validate_serial_number, field_name)


def validate_vpc_domain(v: int | None) -> int | None:
    """Validate VPC domain ID (1-1000).

    Args:
        v: VPC domain ID.

    Returns:
        Validated VPC domain ID, or ``None`` if input is None.

    Raises:
        ValueError: When the value is out of valid range.
    """
    if v is None:
        return None
    if not 1 <= v <= 1000:
        raise ValueError(f"VPC domain must be between 1 and 1000: {v}")
    return v


def check_discovery_credentials_pair(username: str | None, password: str | None) -> None:
    """Enforce mutual-presence of discovery credentials.

    Both ``discovery_username`` and ``discovery_password`` must either be
    absent together or present together.

    Args:
        username: discovery_username value (may be ``None``).
        password: discovery_password value (may be ``None``).

    Raises:
        ValueError: When exactly one of the two is provided.
    """
    check_credentials_pair(username, password, "discovery_username", "discovery_password")
