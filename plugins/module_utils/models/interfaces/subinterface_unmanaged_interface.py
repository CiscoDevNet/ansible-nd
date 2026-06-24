# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unmanaged L3 subinterface Pydantic models for Nexus Dashboard.

This module defines nested Pydantic models that mirror the ND Manage Interfaces API payload structure for the
unmanaged variant of L3 subinterfaces (`interfaceType: "subInterface"`, `mode: "unmanaged"`,
`policyType: "monitorSubinterface"`). The policy body carries only the `policyType` discriminator; no L3 fields
are configurable. All scaffolding fields are hardcoded via `Literal[...] + Field(frozen=True)` and excluded from
the user-facing argument spec.

The managed variant lives in `subinterface_managed_interface.py`.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SubinterfaceUnmanagedPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class SubinterfaceUnmanagedPolicyModel(NDNestedModel):
    """
    # Summary

    Policy fields for an unmanaged L3 subinterface. The body carries only the `policyType` discriminator. Extra
    fields returned by ND on GET (for instance the `userDefined` discriminator branch's `templateName` /
    `templateConfig`) are silently discarded via `extra="ignore"`.

    ## Raises

    None
    """

    model_config = ConfigDict(extra="ignore")

    policy_type: SubinterfaceUnmanagedPolicyTypeEnum = Field(
        default=SubinterfaceUnmanagedPolicyTypeEnum.MONITOR_SUBINTERFACE,
        alias="policyType",
        frozen=True,
        description="Interface policy type (hardcoded for this module)",
    )


class SubinterfaceUnmanagedNetworkOSModel(NDNestedModel):
    """
    # Summary

    Network OS container for an unmanaged subinterface. Maps to `configData.networkOS` in the ND API.

    ## Raises

    None
    """

    network_os_type: Literal["nx-os"] = Field(default="nx-os", alias="networkOSType", frozen=True)
    policy: SubinterfaceUnmanagedPolicyModel = Field(default_factory=SubinterfaceUnmanagedPolicyModel, alias="policy")


class SubinterfaceUnmanagedConfigDataModel(NDNestedModel):
    """
    # Summary

    Config data container for an unmanaged subinterface. Maps to `configData` in the ND API. `mode` is always
    `"unmanaged"` for this module and is required by the API as a discriminator.

    ## Raises

    None
    """

    mode: Literal["unmanaged"] = Field(default="unmanaged", alias="mode", frozen=True)
    network_os: SubinterfaceUnmanagedNetworkOSModel = Field(default_factory=SubinterfaceUnmanagedNetworkOSModel, alias="networkOS")


class SubinterfaceUnmanagedOperDataModel(NDNestedModel):
    """
    # Summary

    Operational state container returned by GET on an unmanaged subinterface. Server-populated and read-only.
    Excluded from payloads via `SubinterfaceUnmanagedInterfaceModel.payload_exclude_fields`.

    ## Raises

    None
    """

    admin_status: str | None = Field(default=None, alias="adminStatus")
    operational_description: str | None = Field(default=None, alias="operationalDescription")
    operational_status: str | None = Field(default=None, alias="operationalStatus")
    switch_name: str | None = Field(default=None, alias="switchName")


class SubinterfaceUnmanagedInterfaceModel(NDBaseModel):
    """
    # Summary

    Unmanaged L3 subinterface configuration for Nexus Dashboard.

    Uses a composite identifier (`switch_ip`, `interface_name`). The nested model structure mirrors the ND
    Manage Interfaces API payload, so `to_payload()` and `from_response()` work via standard Pydantic
    serialization. The policy body carries only the `policyType` discriminator.

    `interface_type` is required by the ND API on both POST and PUT. The per-interface PUT (`updateInterface`) uses
    `interfaceType` as the request-body discriminator (mapping `subInterface` -> `interfaceSubInterface`) and lists it
    in `required`, so `to_payload()` always serializes it for both verbs (verified against the ND 4.2.1 OpenAPI spec).

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[list[str] | None] = ["switch_ip", "interface_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set[str]] = {"switch_ip", "oper_data"}

    # --- Fields ---

    switch_ip: str = Field(alias="switchIp")
    interface_name: str = Field(alias="interfaceName")
    interface_type: Literal["subInterface"] = Field(default="subInterface", alias="interfaceType", frozen=True)
    config_data: SubinterfaceUnmanagedConfigDataModel = Field(default_factory=SubinterfaceUnmanagedConfigDataModel, alias="configData")
    oper_data: SubinterfaceUnmanagedOperDataModel | None = Field(default=None, alias="operData")

    @field_validator("interface_name", mode="before")
    @classmethod
    def normalize_interface_name(cls, value):
        """
        # Summary

        Validate that `interface_name` is a dotted subinterface form on either an Ethernet or Port-channel
        parent (e.g. `Ethernet1/3.2`, `Port-channel10.5`). The parent kind is inferred from the prefix; no
        separate `parent_interface` argument is needed. The sub-id portion (`.<n>`) is required.

        Accepts any case for the parent prefix and normalizes to canonical capitalization (`Ethernet...`,
        `Port-channel...`) so user input, POST payloads, and GET responses all compare equal.

        ## Raises

        ### ValueError

        - If `value` is a string without a `.<sub>` segment.
        - If `value` does not start with `Ethernet` or `Port-channel` (case-insensitive).
        """
        if not isinstance(value, str) or not value:
            return value
        stripped = value.strip()
        if "." not in stripped:
            raise ValueError(f"interface_name must include a dot-separated subinterface id (e.g. 'Ethernet1/3.2'); got {value!r}")
        parent, sub = stripped.rsplit(".", 1)
        parent_lower = parent.lower()
        # ND echoes interface names lowercased on GET; normalize to canonical case so idempotency comparisons work.
        if parent_lower.startswith("ethernet"):
            canonical_parent = "Ethernet" + parent[len("ethernet") :]
        elif parent_lower.startswith("port-channel"):
            canonical_parent = "Port-channel" + parent[len("port-channel") :]
        else:
            raise ValueError(f"interface_name parent must be 'Ethernet...' or 'Port-channel...'; got parent={parent!r}")
        return f"{canonical_parent}.{sub}"

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> dict:
        """
        # Summary

        Return the Ansible argument spec for the `nd_interface_subinterface_unmanaged` module.

        The user supplies only `switch_ip` and `interface_name` per item. Every field under `config_data` is
        hardcoded scaffolding (interface_type, mode, network_os_type, policy_type) and is intentionally hidden
        from the arg spec.

        ## Raises

        None
        """
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    switch_ip=dict(type="str", required=True),
                    interface_name=dict(type="str", required=True),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
