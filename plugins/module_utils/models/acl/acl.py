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
from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    ValidationInfo,
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
_PROTOCOL_CHOICES = ["ip", "ipv6", "tcp", "udp", "icmp", "igmp", "eigrp", "ospf", "pim", "custom"]


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

    remark_comment: str | None = Field(
        default=None,
        alias="remarkComment",
        description="Remark text (required when action is 'remark').",
    )

    protocol: AclProtocolEnum | None = Field(
        default=None,
        alias="protocol",
        description="Matched protocol (required for permit/deny entries).",
    )

    custom_protocol: int | None = Field(
        default=None,
        alias="customProtocol",
        description="Custom IP protocol number (required when protocol is 'custom').",
    )

    src: str | None = Field(
        default=None,
        alias="src",
        description="Source match (address/CIDR or 'any').",
    )

    dst: str | None = Field(
        default=None,
        alias="dst",
        description="Destination match (address/CIDR or 'any').",
    )

    src_port_action: PortActionEnum | None = Field(
        default=None,
        alias="srcPortAction",
        description="Source port operator (tcp/udp).",
    )

    src_port: str | None = Field(default=None, alias="srcPort", description="Source port value (number or service name, e.g. 'www').")
    src_port_range_start: str | None = Field(default=None, alias="srcPortRangeStart", description="Source port range start (number or service name).")
    src_port_range_end: str | None = Field(default=None, alias="srcPortRangeEnd", description="Source port range end (number or service name).")

    dst_port_action: PortActionEnum | None = Field(
        default=None,
        alias="dstPortAction",
        description="Destination port operator (tcp/udp).",
    )

    dst_port: str | None = Field(default=None, alias="dstPort", description="Destination port value (number or service name, e.g. 'ftp').")
    dst_port_range_start: str | None = Field(default=None, alias="dstPortRangeStart", description="Destination port range start (number or service name).")
    dst_port_range_end: str | None = Field(default=None, alias="dstPortRangeEnd", description="Destination port range end (number or service name).")

    icmp_option: str | None = Field(default=None, alias="icmpOption", description="ICMP option (icmp protocol only).")
    tcp_option: str | None = Field(default=None, alias="tcpOption", description="TCP option (tcp protocol only).")

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

    @field_validator(
        "src_port",
        "src_port_range_start",
        "src_port_range_end",
        "dst_port",
        "dst_port_range_start",
        "dst_port_range_end",
        mode="before",
    )
    @classmethod
    def normalize_port(cls, value: Any) -> Any:
        """
        Accept both integer and string port input and normalise to the API wire
        (string) form. The ACL API models port fields as strings and permits
        service names such as ``www`` and ``ftp`` in addition to numeric values,
        so an integer like ``443`` is coerced to ``"443"``.
        """
        if value is None:
            return None
        if isinstance(value, bool):
            # Guard against YAML coercing bare true/false into a port value.
            raise ValueError(f"invalid port value: {value!r}")
        if isinstance(value, int):
            return str(value)
        return value


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

    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[set[str]] = {"last_update_timestamp", "description"}
    payload_exclude_fields: ClassVar[set[str]] = {"last_update_timestamp"}
    unwanted_keys: ClassVar[list] = []

    # --- Fields ---

    name: str = Field(
        alias="name",
        min_length=1,
        max_length=_NAME_MAX_LENGTH,
        description="Name of the ACL (pattern: ^[a-zA-Z0-9_~-]+$).",
    )

    type: AclTypeEnum | None = Field(
        default=None,
        alias="type",
        description="IP address family of the ACL: 'ipv4' or 'ipv6'. Required for all states except 'deleted'.",
    )

    description: str | None = Field(
        default=None,
        alias="description",
        max_length=90,
        description="Description of the ACL.",
    )

    last_update_timestamp: str | None = Field(
        default=None,
        alias="lastUpdateTimestamp",
        description="Timestamp of the last update (read-only, set by ND).",
    )

    entries: list[AclEntryModel] | None = Field(
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
    def validate_required_for_write_states(self, info: ValidationInfo) -> "AclModel":
        """
        Enforce state-aware required fields.

        ``type`` and ``entries`` are required for the write states (``merged``,
        ``replaced``, ``overridden``); identifier-only items (``name`` only) are
        accepted for ``deleted``. The active state is read from the pydantic
        validation context threaded by ``NDStateMachine``
        (``context={"state": ...}``). When no context is present -- e.g. models
        built from controller responses via ``from_response`` -- the check is
        skipped so existing state parses unconditionally.
        """
        state = (info.context or {}).get("state") if info else None
        if state in ("merged", "replaced", "overridden"):
            missing = [name for name in ("type", "entries") if getattr(self, name) is None]
            if missing:
                verb = "is" if len(missing) == 1 else "are"
                raise ValueError(f"ACL '{self.name}': '{', '.join(missing)}' {verb} required for state '{state}'.")
        return self

    @model_validator(mode="after")
    def validate_entries(self) -> "AclModel":
        """
        Validate semantic correctness of every entry and enforce unique
        sequence numbers within the ACL.

        All problems are collected and reported together in a single error. 
        The complete set of duplicated sequence numbers is reported,
        not just the first collision.
        """
        entries = self.entries or []
        errors: list[str] = []
        seen_sequence_numbers: set[int] = set()
        duplicate_sequence_numbers: set[int] = set()
        for entry in entries:
            if entry.sequence_number in seen_sequence_numbers:
                duplicate_sequence_numbers.add(entry.sequence_number)
            seen_sequence_numbers.add(entry.sequence_number)
        if duplicate_sequence_numbers:
            duplicates = ", ".join(str(number) for number in sorted(duplicate_sequence_numbers))
            errors.append(f"sequenceNumber values {duplicates} are duplicated. Sequence numbers must be unique within an ACL.")

        # Collect every entry's semantic errors instead of stopping at the first.
        for idx, entry in enumerate(entries):
            errors.extend(self._validate_entry(idx, entry))

        if errors:
            raise ValueError("; ".join(errors))

        return self

    @staticmethod
    def _validate_entry(idx: int, entry: "AclEntryModel") -> list[str]:
        """
        Validate a single ACL entry's field combination and return a list of
        error messages (empty when the entry is valid). Collecting rather than
        raising lets the caller aggregate errors across all entries.
        """
        errors: list[str] = []
        action = str(entry.action)

        if action == "remark":
            if not entry.remark_comment:
                errors.append(f"entries[{idx}]: 'remark_comment' is required when action is 'remark'.")
            return errors

        for field_name in ("protocol", "src", "dst"):
            if getattr(entry, field_name) is None:
                errors.append(f"entries[{idx}]: '{field_name}' is required for permit/deny entries.")

        # Protocol-dependent checks only apply when a protocol was supplied; when
        # it is missing the 'required for permit/deny' error above already covers it.
        if entry.protocol is not None:
            protocol = str(entry.protocol)
            if protocol == "custom" and entry.custom_protocol is None:
                errors.append(f"entries[{idx}]: 'custom_protocol' is required when protocol is 'custom'.")

            if protocol in ("tcp", "udp"):
                errors.extend(AclModel._validate_port_options(idx, entry, "src"))
                errors.extend(AclModel._validate_port_options(idx, entry, "dst"))

            if entry.icmp_option is not None and protocol != "icmp":
                errors.append(f"entries[{idx}]: 'icmp_option' is only valid when protocol is 'icmp'.")
            if entry.tcp_option is not None and protocol != "tcp":
                errors.append(f"entries[{idx}]: 'tcp_option' is only valid when protocol is 'tcp'.")

        return errors

    @staticmethod
    def _validate_port_options(idx: int, entry: "AclEntryModel", prefix: str) -> list[str]:
        """
        Validate port operator and range consistency for one direction and
        return a list of error messages (empty when valid).
        """
        errors: list[str] = []
        action = getattr(entry, f"{prefix}_port_action")
        if action is None:
            return errors
        action = str(action)

        if action == "portRange":
            start = getattr(entry, f"{prefix}_port_range_start")
            end = getattr(entry, f"{prefix}_port_range_end")
            if start is None or end is None:
                errors.append(
                    f"entries[{idx}]: '{prefix}_port_range_start' and '{prefix}_port_range_end' are required when {prefix}_port_action is 'port_range'."
                )
            # Ports may be numeric or service names (e.g. 'www'); only enforce
            # start <= end ordering when both endpoints are numeric.
            elif str(start).isdigit() and str(end).isdigit() and int(start) > int(end):
                errors.append(f"entries[{idx}]: '{prefix}_port_range_start' must be less than or equal to '{prefix}_port_range_end'.")
        else:
            if getattr(entry, f"{prefix}_port") is None:
                errors.append(f"entries[{idx}]: '{prefix}_port' is required when {prefix}_port_action is set.")
        return errors

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        entry_spec = dict(
            sequence_number=dict(type="int", required=True, aliases=["sequenceNumber"]),
            action=dict(type="str", required=True, choices=["permit", "deny", "remark"]),
            remark_comment=dict(type="str", aliases=["remarkComment"]),
            protocol=dict(type="str", choices=_PROTOCOL_CHOICES),
            custom_protocol=dict(type="int", aliases=["customProtocol"]),
            src=dict(type="str"),
            dst=dict(type="str"),
            src_port_action=dict(type="str", choices=_PORT_ACTION_CHOICES, aliases=["srcPortAction"]),
            src_port=dict(type="str", aliases=["srcPort"]),
            src_port_range_start=dict(type="str", aliases=["srcPortRangeStart"]),
            src_port_range_end=dict(type="str", aliases=["srcPortRangeEnd"]),
            dst_port_action=dict(type="str", choices=_PORT_ACTION_CHOICES, aliases=["dstPortAction"]),
            dst_port=dict(type="str", aliases=["dstPort"]),
            dst_port_range_start=dict(type="str", aliases=["dstPortRangeStart"]),
            dst_port_range_end=dict(type="str", aliases=["dstPortRangeEnd"]),
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
