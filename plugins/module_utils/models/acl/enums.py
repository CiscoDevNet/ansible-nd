# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Enumerations for Access Control List (ACL) management.

Design note on port-action values
----------------------------------
The Nexus Dashboard Manage API represents port-match operators in camelCase
(``equalTo``, ``greaterThan``, ``lessThan``, ``notEqualTo``, ``portRange``),
while the Ansible-facing argument spec exposes the more idiomatic snake_case
(``equal_to``, ``greater_than`` ...). ``PortActionEnum`` therefore stores the
*wire* (camelCase) value, and ``PORT_ACTION_SNAKE_TO_WIRE`` lets the model's
``mode="before"`` validator accept snake_case input and normalise it to the
wire value before enum validation. API responses (already camelCase) validate
directly. Module output consequently reflects the controller's camelCase form.
"""

from __future__ import annotations

from enum import Enum


class AclTypeEnum(str, Enum):
    """IP address family discriminator for an ACL."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"


class AclActionEnum(str, Enum):
    """Action for an ACL entry."""

    PERMIT = "permit"
    DENY = "deny"
    REMARK = "remark"


class AclProtocolEnum(str, Enum):
    """
    Layer-3/4 protocol matched by an ACL entry.

    Ansible value equals the API wire value for every member, so no
    translation is required.
    """

    IP = "ip"
    IPV6 = "ipv6"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IGMP = "igmp"
    EIGRP = "eigrp"
    OSPF = "ospf"
    PIM = "pim"
    CUSTOM = "custom"


class PortActionEnum(str, Enum):
    """
    Port-match operator for an ACL entry (TCP/UDP).

    Members store the API *wire* (camelCase) value. Snake_case argument-spec
    input is normalised via ``PORT_ACTION_SNAKE_TO_WIRE`` before validation.
    """

    NONE = "none"
    EQUAL_TO = "equalTo"
    GREATER_THAN = "greaterThan"
    LESS_THAN = "lessThan"
    NOT_EQUAL_TO = "notEqualTo"
    PORT_RANGE = "portRange"


# Maps Ansible snake_case port-action input to the API camelCase wire value.
PORT_ACTION_SNAKE_TO_WIRE: dict[str, str] = {
    "none": "none",
    "equal_to": "equalTo",
    "greater_than": "greaterThan",
    "less_than": "lessThan",
    "not_equal_to": "notEqualTo",
    "port_range": "portRange",
}
