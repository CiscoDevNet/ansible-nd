# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ResourceManagerConfigModel - Ansible playbook input validation model.

Validates a single config entry for the nd_manage_resource_manager module.

Fields map directly to the module's config suboptions:
  entity_name      → entityName      (unique name identifying the resource allocation)
  pool_type        → poolType        (ID | IP | SUBNET)
  pool_name        → poolName        (name of the resource pool)
  scope_type       → scopeType       (fabric | device | device_interface | device_pair | link)
  resource         → resourceValue   (value to allocate; integer/IP/CIDR based on pool_type)
  is_pre_allocated → isPreAllocated  (True to reserve a specific value; False for auto-assignment)
  vrf_name         → vrfName         (VRF name; use 'default' for the global VRF)
  switch           → switch          (list of switch IPs/serials; required for non-fabric scopes)

State-aware validation is supported when model_validate() is called with
context={"state": "merged|deleted|query|gathered"}.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Any, ClassVar, Dict, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.constants import (
    POOL_SCOPE_MAP,
    PoolType,
    ScopeType,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)


class ResourceManagerConfigModel(NDBaseModel):
    """
    Input validation model for a single nd_manage_resource_manager config entry.

    Provides full per-field and cross-field validation for resource allocation
    configuration. Supports state-aware validation when model_validate() is
    called with context={"state": "merged|deleted|query|gathered"}.

    Field requirements by state:
      merged:          entity_name, pool_type, pool_name, scope_type required;
                       switch required for non-fabric scopes.
      deleted:         entity_name, pool_type, pool_name, scope_type required;
                       switch required for non-fabric scopes.
      query/gathered:  all fields optional (used as filters).

    Note: The nd_manage_resource_manager module performs its own mandatory field
    checks before calling from_config(). This model adds per-field normalization
    and cross-field validation on top of those checks.
    """

    identifiers: ClassVar[List[str]] = []

    # Fields excluded from diff — operational input flags not present in gathered state.
    # entity_name, pool_type, pool_name, scope_type, resource and vrf_name
    # are all meaningful for comparison; is_pre_allocated is a request-time allocation
    # control flag (analogous to preserve_config for switches) and is omitted from diffs.
    exclude_from_diff: ClassVar[List[str]] = ["is_pre_allocated", "switch"]

    entity_name: Optional[str] = Field(
        default=None,
        description=(
            "Unique name identifying the entity to which the resource is allocated. "
            "Format depends on scope_type: "
            "fabric/device → free-form string; "
            "device_pair → 1 or 2 tildes (~), e.g. 'SER1~SER2' or 'SER1~SER2~label'; "
            "device_interface → exactly 1 tilde (~), e.g. 'SER~Ethernet1/13'; "
            "link → exactly 3 tildes (~), e.g. 'SER1~Eth1/3~SER2~Eth1/3'."
        ),
    )
    pool_type: Optional[PoolType] = Field(
        default=None,
        description=(
            "Type of resource pool. One of: ID (integer ID), IP (IP address), SUBNET (CIDR block). Determines the expected format for the 'resource' field."
        ),
    )
    pool_name: Optional[str] = Field(
        default=None,
        description=(
            "Name of the resource pool to use (e.g. 'L3_VNI', 'LOOPBACK_ID', 'SUBNET'). "
            "For known pool names the scope_type must match the allowed scopes in POOL_SCOPE_MAP. "
            "Custom pool names not in POOL_SCOPE_MAP are unrestricted."
        ),
    )
    scope_type: Optional[ScopeType] = Field(
        default=None,
        description=("Scope level for the resource allocation. One of: fabric, device, device_interface, device_pair, link."),
    )
    resource: Optional[str] = Field(
        default=None,
        description=(
            "Value of the resource being allocated. "
            "Integer string for ID pools (e.g. '101'); "
            "IPv4 or IPv6 address for IP pools (e.g. '110.1.1.1' or 'fe80::1'); "
            "CIDR notation for SUBNET pools (e.g. '10.1.1.0/24'). "
            "Required when is_pre_allocated is True."
        ),
    )
    is_pre_allocated: Optional[bool] = Field(
        default=None,
        description=(
            "Whether the resource value is explicitly pre-allocated. "
            "Set to True to reserve a specific resource value; "
            "False to let the system auto-assign. "
            "When True, the 'resource' field must also be provided."
        ),
    )
    vrf_name: Optional[str] = Field(
        default=None,
        description=("VRF name associated with the resource allocation. Use 'default' for the global default VRF. When omitted, the default VRF is assumed."),
    )
    switch: Optional[List[str]] = Field(
        default=None,
        description=("List of switch management IP addresses or serial numbers to which the resource is assigned. Required when scope_type is not 'fabric'."),
    )

    # -------------------------------------------------------------------------
    # Per-field validators
    # -------------------------------------------------------------------------

    @field_validator("entity_name", mode="before")
    @classmethod
    def validate_entity_name(cls, v: Any) -> Optional[str]:
        """Validate entity_name is a non-empty string when provided."""
        if v is None:
            return None
        if not isinstance(v, str) or not str(v).strip():
            raise ValueError("entity_name must be a non-empty string")
        return str(v).strip()

    @field_validator("pool_type", mode="before")
    @classmethod
    def normalize_pool_type(cls, v: Any) -> Optional[str]:
        """Normalize pool_type to uppercase and validate against PoolType enum."""
        if v is None:
            return None
        if isinstance(v, str):
            normalized = v.strip().upper()
            valid_values = [pt.value for pt in PoolType]
            if normalized not in valid_values:
                raise ValueError("pool_type '{0}' is invalid. Valid choices: {1}".format(v, valid_values))
            return normalized
        return v

    @field_validator("pool_name", mode="before")
    @classmethod
    def validate_pool_name(cls, v: Any) -> Optional[str]:
        """Validate pool_name is a non-empty string when provided."""
        if v is None:
            return None
        if not isinstance(v, str) or not str(v).strip():
            raise ValueError("pool_name must be a non-empty string")
        return str(v).strip()

    @field_validator("scope_type", mode="before")
    @classmethod
    def normalize_scope_type(cls, v: Any) -> Optional[str]:
        """Normalize scope_type to lowercase and validate against ScopeType enum."""
        if v is None:
            return None
        if isinstance(v, str):
            normalized = v.strip().lower()
            valid_values = [st.value for st in ScopeType]
            if normalized not in valid_values:
                raise ValueError("scope_type '{0}' is invalid. Valid choices: {1}".format(v, valid_values))
            return normalized
        return v

    @field_validator("resource", mode="before")
    @classmethod
    def validate_resource_not_empty(cls, v: Any) -> Optional[str]:
        """Validate resource is a non-empty string when provided."""
        if v is None:
            return None
        if not isinstance(v, str) or not str(v).strip():
            raise ValueError("resource must be a non-empty string when provided")
        return str(v).strip()

    @field_validator("is_pre_allocated", mode="before")
    @classmethod
    def coerce_is_pre_allocated(cls, v: Any) -> Optional[bool]:
        """Coerce string and integer representations to bool when provided."""
        if v is None:
            return None
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            lower = v.strip().lower()
            if lower in ("true", "yes", "1"):
                return True
            if lower in ("false", "no", "0"):
                return False
        if isinstance(v, int) and v in (0, 1):
            return bool(v)
        raise ValueError("is_pre_allocated must be a boolean (true/false), got: {0!r}".format(v))

    @field_validator("vrf_name", mode="before")
    @classmethod
    def validate_vrf_name(cls, v: Any) -> Optional[str]:
        """Validate vrf_name is a non-empty string when provided."""
        if v is None:
            return None
        if not isinstance(v, str) or not str(v).strip():
            raise ValueError("vrf_name must be a non-empty string when provided")
        return str(v).strip()

    @field_validator("switch", mode="before")
    @classmethod
    def validate_switch_entries(cls, v: Any) -> Optional[List[str]]:
        """Validate each switch entry is a non-empty string.

        Accepts IPv4, IPv6, or serial number strings. Format validation
        (IP-to-serial resolution) is deferred to the module at runtime.
        """
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError("switch must be a list of IP addresses or serial numbers")
        if len(v) == 0:
            raise ValueError("switch list must not be empty when provided")
        validated = []
        for entry in v:
            entry_str = str(entry).strip()
            if not entry_str:
                raise ValueError("switch list entries must be non-empty strings")
            validated.append(entry_str)
        return validated

    # -------------------------------------------------------------------------
    # Cross-field validators
    # -------------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_resource_format(self) -> "ResourceManagerConfigModel":
        """Validate the resource value format matches the pool_type.

        - pool_type=ID:     resource must be a non-negative integer string (e.g. '101')
        - pool_type=IP:     resource must be a valid IPv4 or IPv6 address
        - pool_type=SUBNET: resource must be CIDR notation (e.g. '10.1.1.0/24')
        """
        if self.resource is None or self.pool_type is None:
            return self
        resource = self.resource
        pool_type = self.pool_type
        if pool_type == PoolType.ID:
            if not re.match(r"^\d+$", resource):
                raise ValueError("resource must be an integer string when pool_type is 'ID', got: '{0}'".format(resource))
        elif pool_type == PoolType.IP:
            try:
                ip_address(resource)
            except ValueError:
                raise ValueError("resource must be a valid IPv4 or IPv6 address when pool_type is 'IP', got: '{0}'".format(resource))
        elif pool_type == PoolType.SUBNET:
            if "/" not in resource:
                raise ValueError("resource must be CIDR notation (IP/prefix) when pool_type is 'SUBNET', got: '{0}'".format(resource))
            try:
                ip_network(resource, strict=False)
            except ValueError:
                raise ValueError("resource '{0}' is not a valid CIDR network".format(resource))
        return self

    @model_validator(mode="after")
    def validate_entity_name_format(self) -> "ResourceManagerConfigModel":
        """Validate entity_name tilde (~) count matches the required scope_type format.

        Tilde conventions:
          device_pair:      1 or 2 tildes  e.g. 'SER1~SER2' or 'SER1~SER2~label'
          device_interface: exactly 1 tilde   e.g. 'SER~Ethernet1/13'
          link:             exactly 3 tildes  e.g. 'SER1~Eth1/3~SER2~Eth1/3'
          fabric/device:    no tilde constraint
        """
        if self.entity_name is None or self.scope_type is None:
            return self
        entity_name = self.entity_name
        scope_type = self.scope_type
        tilde_count = entity_name.count("~")
        if scope_type == ScopeType.DEVICE_PAIR:
            if tilde_count not in (1, 2):
                raise ValueError(
                    "entity_name for scope_type 'device_pair' must contain 1 or 2 tildes (~), "
                    "e.g. 'SER1~SER2' or 'SER1~SER2~label', got: '{0}' ({1} tilde(s))".format(entity_name, tilde_count)
                )
        elif scope_type == ScopeType.DEVICE_INTERFACE:
            if tilde_count != 1:
                raise ValueError(
                    "entity_name for scope_type 'device_interface' must contain exactly 1 tilde (~), "
                    "e.g. 'SER~Ethernet1/13', got: '{0}' ({1} tilde(s))".format(entity_name, tilde_count)
                )
        elif scope_type == ScopeType.LINK:
            if tilde_count != 3:
                raise ValueError(
                    "entity_name for scope_type 'link' must contain exactly 3 tildes (~), "
                    "e.g. 'SER1~Eth1/3~SER2~Eth1/3', got: '{0}' ({1} tilde(s))".format(entity_name, tilde_count)
                )
        return self

    @model_validator(mode="after")
    def validate_pool_name_scope_combination(self) -> "ResourceManagerConfigModel":
        """Validate pool_name and scope_type are a known-valid combination via POOL_SCOPE_MAP.

        For IP pool types, 'IP_POOL' is used as the POOL_SCOPE_MAP lookup key.
        For SUBNET pool types, 'SUBNET' is used as the POOL_SCOPE_MAP lookup key.
        For ID pool types, the pool_name itself is used as the lookup key.
        Custom / user-defined pool names not present in POOL_SCOPE_MAP are unrestricted.
        """
        if self.pool_name is None or self.scope_type is None:
            return self
        pool_name = self.pool_name
        scope_type = self.scope_type
        pool_type = self.pool_type
        # Determine the POOL_SCOPE_MAP lookup key based on pool_type
        if pool_type == PoolType.IP:
            check_key = "IP_POOL"
        elif pool_type == PoolType.SUBNET:
            check_key = "SUBNET"
        else:
            check_key = pool_name
        allowed_scopes = POOL_SCOPE_MAP.get(check_key)
        if allowed_scopes is not None and scope_type not in allowed_scopes:
            raise ValueError("scope_type '{0}' is not valid for pool_name '{1}'. Allowed scope_types: {2}".format(scope_type, pool_name, allowed_scopes))
        return self

    @model_validator(mode="after")
    def validate_pre_allocated_requires_resource(self) -> "ResourceManagerConfigModel":
        """Require 'resource' when 'is_pre_allocated' is True."""
        if self.is_pre_allocated is True and self.resource is None:
            raise ValueError("'resource' must be provided when 'is_pre_allocated' is True")
        return self

    @model_validator(mode="after")
    def validate_scope_and_switch(self) -> "ResourceManagerConfigModel":
        """Require 'switch' when scope_type is not 'fabric'.

        For the fabric scope, switch IDs are not applicable. For all other
        scopes (device, device_interface, device_pair, link), at least one
        switch must be specified to identify the target device(s).
        """
        if self.scope_type is not None and self.scope_type != ScopeType.FABRIC:
            if not self.switch:
                raise ValueError("'switch' is required when scope_type is '{0}' (entity_name: '{1}')".format(self.scope_type, self.entity_name))
        return self

    @model_validator(mode="after")
    def apply_state_validation(self, info: Any) -> "ResourceManagerConfigModel":
        """Apply state-aware mandatory field enforcement using validation context.

        When model_validate(context={"state": "merged"}) or
        model_validate(context={"state": "deleted"}) is passed, the model
        enforces that entity_name, pool_type, pool_name, and scope_type are
        all provided. For 'query' / 'gathered' state (or no context), all
        fields remain optional and serve as filters.
        """
        state = (info.context or {}).get("state") if info else None
        if state in ("merged", "deleted"):
            missing = []
            if self.entity_name is None:
                missing.append("entity_name")
            if self.pool_type is None:
                missing.append("pool_type")
            if self.pool_name is None:
                missing.append("pool_name")
            if self.scope_type is None:
                missing.append("scope_type")
            if state == "merged" and self.resource is None:
                missing.append("resource")
            if missing:
                raise ValueError(
                    "Mandatory parameter(s) missing for state='{0}': {1}".format(
                        state,
                        ", ".join("'{0}'".format(m) for m in missing),
                    )
                )
        return self

    # -------------------------------------------------------------------------
    # Serialization helpers
    # -------------------------------------------------------------------------

    def to_gathered_dict(self) -> Dict[str, Any]:
        """Return a config dict suitable for gathered output.

        Returns all non-None fields serialised with Python field names
        (i.e. the same keys used in Ansible playbook config blocks).
        No credential masking is required for this model.
        """
        return self.to_config()

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        """Return the Ansible argument spec for nd_manage_resource_manager."""
        return dict(
            fabric=dict(type="str", required=True),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "deleted", "gathered"],
            ),
            config=dict(type="list", elements="dict"),
        )


__all__ = ["ResourceManagerConfigModel"]
