# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic models for Access Control List (ACL) management via Nexus Dashboard.

## Models Overview

- ``AclEntryModel`` - A single ACL entry (sequenceNumber + action + match
  criteria, port operators, and protocol options).
- ``AclModel``      - Complete ACL (type + name + description + entries).

## Design Notes

IPv4 and IPv6 ACLs share a single API namespace
(``/fabrics/{fabricName}/accessControlLists``) and are distinguished by the
``type`` *body* field (``"ipv4"`` / ``"ipv6"``). Unlike prefix lists, ``type``
is therefore part of the API payload (not an Ansible-only discriminator), and
the identifier is the bare ACL ``name``.

``fabric_name`` is not a model field; it is a top-level module option read by
the orchestrator from ``rest_send.params`` and used only as a path parameter.

Port-match operators are stored in the API wire form (camelCase) by
``PortActionEnum``; snake_case argument-spec input is normalised by a
``mode="before"`` validator. ``"none"`` (and omitted) collapses to ``None`` so
it is excluded from both payload and diff, keeping idempotency symmetric with
controller responses that omit inactive port operators.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.enums import (
    AclActionEnum,
    AclProtocolEnum,
    AclTypeEnum,
    PortActionEnum,
    PORT_ACTION_SNAKE_TO_WIRE,
)

# Allowed characters for ACL names (from OpenAPI pattern). The ``~`` separates
# an optional tenant qualifier from the ACL name (e.g. ``tenant1~acl3``) for
# tenant-scoped ACLs, so it is part of the permitted character set.
_NAME_RE = re.compile(r"^[a-zA-Z0-9_~-]+$")

# Maximum ACL name length permitted by the OpenAPI schema. Tenant-qualified
# names (``<tenant>~<name>``) are longer than plain names, hence 115.
_NAME_MAX_LENGTH = 115

# Argument-spec choices for port operators (Ansible snake_case).
_PORT_ACTION_CHOICES = ["none", "equal_to", "greater_than", "less_than", "not_equal_to", "port_range"]

# Protocol choices for the argument spec.
_PROTOCOL_CHOICES = ["ip", "ipv6", "tcp", "udp", "icmp", "igmp", "eigrp", "ospf", "pim", "ahp", "gre", "nos", "esp", "custom"]


class AclEntryModel(NDNestedModel):
    """
    A single entry in an ACL.

    Required fields: ``sequence_number`` and ``action``. ``remark`` entries
    carry only ``remark_comment``; ``permit``/``deny`` entries carry
    ``protocol``, ``src``, ``dst`` and optional port/protocol options.
    """

    sequence_number: int = Field(
        alias="sequenceNumber",
        ge=1,
        le=4294967294,
        description="Sequence number of the entry (1-4294967294).",
    )

    action: AclActionEnum = Field(
        alias="action",
        description="Action for the entry: permit, deny, or remark.",
    )

    remark_comment: Optional[str] = Field(
        default=None,
        alias="remarkComment",
        description="Remark text (required when action is 'remark').",
    )

    protocol: Optional[AclProtocolEnum] = Field(
        default=None,
        alias="protocol",
        description="Matched protocol (required for permit/deny entries).",
    )

    custom_protocol: Optional[int] = Field(
        default=None,
        alias="customProtocol",
        description="Custom IP protocol number (required when protocol is 'custom').",
    )

    src: Optional[str] = Field(
        default=None,
        alias="src",
        description="Source match (address/CIDR or 'any').",
    )

    dst: Optional[str] = Field(
        default=None,
        alias="dst",
        description="Destination match (address/CIDR or 'any').",
    )

    src_port_action: Optional[PortActionEnum] = Field(
        default=None,
        alias="srcPortAction",
        description="Source port operator (tcp/udp).",
    )

    src_port: Optional[int] = Field(default=None, alias="srcPort", description="Source port value.")
    src_port_range_start: Optional[int] = Field(default=None, alias="srcPortRangeStart", description="Source port range start.")
    src_port_range_end: Optional[int] = Field(default=None, alias="srcPortRangeEnd", description="Source port range end.")

    dst_port_action: Optional[PortActionEnum] = Field(
        default=None,
        alias="dstPortAction",
        description="Destination port operator (tcp/udp).",
    )

    dst_port: Optional[int] = Field(default=None, alias="dstPort", description="Destination port value.")
    dst_port_range_start: Optional[int] = Field(default=None, alias="dstPortRangeStart", description="Destination port range start.")
    dst_port_range_end: Optional[int] = Field(default=None, alias="dstPortRangeEnd", description="Destination port range end.")

    icmp_option: Optional[str] = Field(default=None, alias="icmpOption", description="ICMP option (icmp protocol only).")
    tcp_option: Optional[str] = Field(default=None, alias="tcpOption", description="TCP option (tcp protocol only).")

    # --- Field Validators ---

    @field_validator("src_port_action", "dst_port_action", mode="before")
    @classmethod
    def normalize_port_action(cls, value: Any) -> Any:
        """
        Accept snake_case argument-spec input and normalise to the API wire
        (camelCase) value. ``"none"`` (and ``None``) collapses to ``None`` so it
        is excluded from payload and diff.
        """
        if value is None:
            return None
        if isinstance(value, PortActionEnum):
            value = value.value
        wire = PORT_ACTION_SNAKE_TO_WIRE.get(value, value)
        if wire == "none":
            return None
        return wire


class AclModel(NDBaseModel):
    """
    Access Control List configuration for a Nexus Dashboard fabric.

    ## Identifier

    ``single`` strategy keyed on ``name``. The fabric scope is provided
    out-of-band via the top-level ``fabric_name`` module option.

    ## Serialization Notes

    - ``type`` is a real API body field (ipv4/ipv6) and is included in payloads.
    - ``last_update_timestamp`` is read-only and excluded from payloads/diffs.
    - ``description`` is accepted by the controller but, on ND 4.1.1, is neither
      persisted nor returned by the ACL GET endpoints. It is still sent in
      payloads (forward-compatible) but excluded from diff comparison so that a
      user-supplied description does not break idempotency against responses
      that always omit it.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[Set[str]] = {"last_update_timestamp", "description"}
    payload_exclude_fields: ClassVar[Set[str]] = {"last_update_timestamp"}
    unwanted_keys: ClassVar[List] = []

    # --- Fields ---

    name: str = Field(
        alias="name",
        min_length=1,
        max_length=_NAME_MAX_LENGTH,
        description="Name of the ACL (pattern: ^[a-zA-Z0-9_~-]+$).",
    )

    type: Optional[AclTypeEnum] = Field(
        default=None,
        alias="type",
        description="IP address family of the ACL: 'ipv4' or 'ipv6'. Required for all states except 'deleted'.",
    )

    description: Optional[str] = Field(
        default=None,
        alias="description",
        max_length=90,
        description="Description of the ACL.",
    )

    last_update_timestamp: Optional[str] = Field(
        default=None,
        alias="lastUpdateTimestamp",
        description="Timestamp of the last update (read-only, set by ND).",
    )

    entries: Optional[List[AclEntryModel]] = Field(
        default=None,
        alias="entries",
        description="List of ACL entries.",
    )

    # --- Field Validators ---

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        """Enforce API name pattern: ^[a-zA-Z0-9_~-]+$."""
        if not _NAME_RE.match(value):
            raise ValueError(f"ACL name '{value}' is invalid. Only alphanumeric characters, '_', '-', and '~' are allowed.")
        return value

    # --- Model Validators (cross-field) ---

    @model_validator(mode="after")
    def validate_entries(self) -> "AclModel":
        """
        Validate semantic correctness of every entry and enforce unique
        sequence numbers within the ACL.
        """
        entries = self.entries or []
        seen_sequence_numbers: Set[int] = set()

        for idx, entry in enumerate(entries):
            if entry.sequence_number in seen_sequence_numbers:
                raise ValueError(f"entries[{idx}].sequenceNumber '{entry.sequence_number}' is duplicated. Sequence numbers must be unique within an ACL.")
            seen_sequence_numbers.add(entry.sequence_number)
            self._validate_entry(idx, entry)

        return self

    @staticmethod
    def _validate_entry(idx: int, entry: "AclEntryModel") -> None:
        """Validate a single ACL entry's field combination."""
        action = str(entry.action)

        if action == "remark":
            if not entry.remark_comment:
                raise ValueError(f"entries[{idx}]: 'remark_comment' is required when action is 'remark'.")
            return

        for field_name in ("protocol", "src", "dst"):
            if getattr(entry, field_name) is None:
                raise ValueError(f"entries[{idx}]: '{field_name}' is required for permit/deny entries.")

        protocol = str(entry.protocol)
        if protocol == "custom" and entry.custom_protocol is None:
            raise ValueError(f"entries[{idx}]: 'custom_protocol' is required when protocol is 'custom'.")

        if protocol in ("tcp", "udp"):
            AclModel._validate_port_options(idx, entry, "src")
            AclModel._validate_port_options(idx, entry, "dst")

        if entry.icmp_option is not None and protocol != "icmp":
            raise ValueError(f"entries[{idx}]: 'icmp_option' is only valid when protocol is 'icmp'.")
        if entry.tcp_option is not None and protocol != "tcp":
            raise ValueError(f"entries[{idx}]: 'tcp_option' is only valid when protocol is 'tcp'.")

    @staticmethod
    def _validate_port_options(idx: int, entry: "AclEntryModel", prefix: str) -> None:
        """Validate port operator and range consistency for one direction."""
        action = getattr(entry, f"{prefix}_port_action")
        if action is None:
            return
        action = str(action)

        if action == "portRange":
            start = getattr(entry, f"{prefix}_port_range_start")
            end = getattr(entry, f"{prefix}_port_range_end")
            if start is None or end is None:
                raise ValueError(
                    f"entries[{idx}]: '{prefix}_port_range_start' and '{prefix}_port_range_end' are required when {prefix}_port_action is 'port_range'."
                )
            if start > end:
                raise ValueError(f"entries[{idx}]: '{prefix}_port_range_start' must be less than or equal to '{prefix}_port_range_end'.")
        else:
            if getattr(entry, f"{prefix}_port") is None:
                raise ValueError(f"entries[{idx}]: '{prefix}_port' is required when {prefix}_port_action is set.")

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        entry_spec = dict(
            sequence_number=dict(type="int", required=True, aliases=["sequenceNumber"]),
            action=dict(type="str", required=True, choices=["permit", "deny", "remark"]),
            remark_comment=dict(type="str", aliases=["remarkComment"]),
            protocol=dict(type="str", choices=_PROTOCOL_CHOICES),
            custom_protocol=dict(type="int", aliases=["customProtocol"]),
            src=dict(type="str"),
            dst=dict(type="str"),
            src_port_action=dict(type="str", choices=_PORT_ACTION_CHOICES, aliases=["srcPortAction"]),
            src_port=dict(type="int", aliases=["srcPort"]),
            src_port_range_start=dict(type="int", aliases=["srcPortRangeStart"]),
            src_port_range_end=dict(type="int", aliases=["srcPortRangeEnd"]),
            dst_port_action=dict(type="str", choices=_PORT_ACTION_CHOICES, aliases=["dstPortAction"]),
            dst_port=dict(type="int", aliases=["dstPort"]),
            dst_port_range_start=dict(type="int", aliases=["dstPortRangeStart"]),
            dst_port_range_end=dict(type="int", aliases=["dstPortRangeEnd"]),
            icmp_option=dict(type="str", aliases=["icmpOption"]),
            tcp_option=dict(type="str", aliases=["tcpOption"]),
        )

        acl_spec = dict(
            name=dict(type="str", required=True),
            type=dict(type="str", choices=["ipv4", "ipv6"]),
            description=dict(type="str"),
            entries=dict(type="list", elements="dict", required=False, options=entry_spec),
        )

        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(type="list", elements="dict", required=True, options=acl_spec),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
