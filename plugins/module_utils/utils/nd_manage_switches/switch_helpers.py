# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

"""Stateless utility helpers for switch field extraction, operation-type detection, and credential grouping."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict, List, Optional, Tuple, Union


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
            camel = ''.join(
                word.capitalize() if i > 0 else word
                for i, word in enumerate(name.split('_'))
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
    if hasattr(switch, 'operation_type'):
        return switch.operation_type

    if isinstance(switch, dict):
        if 'poap' in switch or 'bootstrap' in switch:
            return 'poap'
        if (
            'rma' in switch
            or 'old_serial' in switch
            or 'oldSerial' in switch
        ):
            return 'rma'

    return 'normal'


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
            switch.user_name,
            password_hash,
            switch.auth_proto,
            switch.platform_type,
            switch.preserve_config,
        )
        groups.setdefault(group_key, []).append(switch)

    log.info(
        f"Grouped {len(switches)} switches into "
        f"{len(groups)} credential group(s)"
    )

    for idx, (key, group_switches) in enumerate(groups.items(), 1):
        username, _, auth_proto, platform_type, preserve_config = key
        auth_value = (
            auth_proto.value
            if hasattr(auth_proto, 'value')
            else str(auth_proto)
        )
        platform_value = (
            platform_type.value
            if hasattr(platform_type, 'value')
            else str(platform_type)
        )
        log.debug(
            f"Group {idx}: {len(group_switches)} switches with "
            f"username={username}, auth={auth_value}, "
            f"platform={platform_value}, "
            f"preserve_config={preserve_config}"
        )

    return groups


__all__ = [
    "get_switch_field",
    "determine_operation_type",
    "group_switches_by_credentials",
]
