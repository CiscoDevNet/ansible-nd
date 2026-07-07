# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Abstract base class for all fabric models.

Provides the shared field definitions, validators, ClassVars, and argument spec
that are identical across eBGP, iBGP, External Connectivity, and Campus fabrics.
Subclasses only need to define:

- `_fabric_type` — the `FabricTypeEnum` value for this fabric kind
- `management` field — typed to the specific management model

Optionally override `_post_validate_consistency()` for type-specific logic
(e.g. site_id propagation from BGP ASN).
"""

from __future__ import annotations

import enum
import types
import typing
from typing import Any, ClassVar, Dict, Literal, Set, get_args, get_origin

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import NdFabricName
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    HAS_PYDANTIC,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    AlertSuspendEnum,
    FabricTypeEnum,
    LicenseTierEnum,
    TelemetryCollectionTypeEnum,
    TelemetryStreamingProtocolEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    ExternalStreamingSettingsModel,
    LocationModel,
    TelemetrySettingsModel,
)


def _is_single_literal(annotation) -> bool:
    """Return True if annotation is Literal[single_value]."""
    origin = get_origin(annotation)
    if origin is Literal:
        return len(get_args(annotation)) == 1
    return False


def _get_enum_choices(annotation) -> tuple | None:
    """If annotation is an enum class, return (choices_list, ansible_type_str)."""
    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        choices = [e.value for e in annotation]
        if issubclass(annotation, int):
            return choices, "int"
        return choices, "str"
    return None


def _get_literal_choices(annotation) -> list | None:
    """If annotation is Literal[...] with multiple values, return them as choices."""
    origin = get_origin(annotation)
    if origin is Literal:
        args = get_args(annotation)
        if len(args) > 1:
            return list(args)
    return None


def _unwrap_optional(annotation):
    """Unwrap Optional[X] / X | None to get X and whether it's optional."""
    origin = get_origin(annotation)
    # Handle typing.Union (Python 3.9 Optional[X]) and types.UnionType (Python 3.10+ X | None)
    if origin is typing.Union or isinstance(annotation, types.UnionType):
        args = [a for a in get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
    return annotation, False


def _is_pydantic_model(annotation) -> bool:
    """Check if annotation is a pydantic BaseModel subclass."""
    return isinstance(annotation, type) and issubclass(annotation, BaseModel)


def _python_type_to_ansible(annotation) -> str:
    """Map a Python type annotation to an Ansible argument spec type string."""
    if annotation is bool:
        return "bool"
    if annotation is int:
        return "int"
    if annotation is float:
        return "float"
    if annotation is str:
        return "str"
    if _is_pydantic_model(annotation):
        return "dict"
    return "str"


def _build_options_from_model(model_cls, exclude_fields: Set[str] | None = None) -> Dict[str, Any]:
    """
    Build Ansible argument spec options dict from a pydantic model's fields.

    Recursively handles nested models and list[Model] fields.
    Auto-excludes single-value Literal fields.
    Respects _argspec_exclude_fields ClassVar on model classes.
    """
    if not HAS_PYDANTIC:
        return {}

    options = {}
    excludes = exclude_fields or set()

    # Merge model-level excludes if defined
    model_excludes = getattr(model_cls, "_argspec_exclude_fields", set())
    excludes = excludes | model_excludes

    for field_name, field_info in model_cls.model_fields.items():
        if field_name in excludes:
            continue

        annotation = field_info.annotation
        if annotation is None:
            continue

        # Unwrap Optional
        inner_type, is_optional = _unwrap_optional(annotation)

        # Skip single-value Literal fields (not user-configurable)
        if _is_single_literal(inner_type):
            continue

        spec: Dict[str, Any] = {}

        # Determine if it's a list type
        list_origin = get_origin(inner_type)
        if list_origin is list:
            list_args = get_args(inner_type)
            spec["type"] = "list"
            if list_args:
                element_type = list_args[0]
                if _is_pydantic_model(element_type):
                    spec["elements"] = "dict"
                    nested_options = _build_options_from_model(element_type)
                    if nested_options:
                        spec["options"] = nested_options
                elif element_type is int:
                    spec["elements"] = "int"
                elif element_type is float:
                    spec["elements"] = "float"
                else:
                    spec["elements"] = "str"
            else:
                spec["elements"] = "str"
        elif _is_pydantic_model(inner_type):
            # Nested model → dict with options
            spec["type"] = "dict"
            nested_options = _build_options_from_model(inner_type)
            if nested_options:
                spec["options"] = nested_options
        else:
            # Check for enum choices (returns tuple of (choices, type_str) or None)
            enum_result = _get_enum_choices(inner_type)
            if enum_result is not None:
                choices, ansible_type = enum_result
                spec["type"] = ansible_type
                spec["choices"] = choices
            else:
                choices = _get_literal_choices(inner_type)
                if choices:
                    spec["type"] = "str"
                    spec["choices"] = choices
                else:
                    spec["type"] = _python_type_to_ansible(inner_type)

        # Handle required fields only.
        # Non-required fields intentionally have NO default in the arg spec.
        # Ansible will pass None for unspecified options, which from_config()
        # strips before pydantic validation. This ensures:
        # - Pydantic uses its own defaults (not Ansible-injected values)
        # - Fields not provided by the user stay out of model_fields_set
        # - Merged state only diffs/merges user-specified fields
        if field_info.is_required():
            if not is_optional:
                spec["required"] = True

        options[field_name] = spec

    return options


class FabricBaseModel(NDBaseModel):
    """
    # Summary

    Abstract base for all fabric models (eBGP, iBGP, External, Campus, etc.).

    Subclasses **must** define:
    - ``_fabric_type: ClassVar[FabricTypeEnum]`` — discriminator value
    - ``management`` field typed to the concrete management model

    Subclasses **may** override:
    - ``_post_validate_consistency()`` — for extra post-validation logic
    - ``to_diff_dict()`` — for custom diff exclusions

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "_fabric_type"):
            raise TypeError(f"{cls.__name__} must define a '_fabric_type' ClassVar with a FabricTypeEnum value")

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # ── ClassVars (shared across all fabric models) ──
    identifiers: ClassVar[list[str] | None] = ["fabric_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    # Subclass must set this to the appropriate FabricTypeEnum member
    _fabric_type: ClassVar[FabricTypeEnum]

    # ── Basic Fabric Properties ──
    category: Literal["fabric"] = Field(description="Resource category", default="fabric")
    fabric_name: NdFabricName
    location: LocationModel | None = Field(description="Geographic location of the fabric", default=None)

    # ── License, Telemetry, and Operations ──
    license_tier: LicenseTierEnum = Field(alias="licenseTier", description="License Tier for fabric.", default=LicenseTierEnum.ESSENTIALS)
    alert_suspend: AlertSuspendEnum = Field(
        alias="alertSuspend", description="Alert Suspend state configured on the fabric.", default=AlertSuspendEnum.DISABLED
    )
    telemetry_collection: bool = Field(alias="telemetryCollection", description="Enable telemetry collection.", default=False)
    telemetry_collection_type: TelemetryCollectionTypeEnum = Field(
        alias="telemetryCollectionType", description="Telemetry collection method.", default=TelemetryCollectionTypeEnum.IN_BAND
    )
    telemetry_streaming_protocol: TelemetryStreamingProtocolEnum = Field(
        alias="telemetryStreamingProtocol", description="Telemetry Streaming Protocol.", default=TelemetryStreamingProtocolEnum.IPV4
    )
    telemetry_source_interface: str = Field(
        alias="telemetrySourceInterface",
        description="Telemetry Source Interface Loopback ID, only valid if Telemetry Collection is set to inBand.",
        default="loopback0",
    )
    telemetry_source_vrf: str = Field(
        alias="telemetrySourceVrf", description="VRF over which telemetry is streamed, valid only if Telemetry Collection is set to inBand.", default="default"
    )
    security_domain: str = Field(alias="securityDomain", description="Security Domain associated with the fabric.", default="all")

    # ── Optional Advanced Settings ──
    # NOTE: `management` is intentionally NOT defined here — subclasses define it
    # with their specific management model type.
    telemetry_settings: TelemetrySettingsModel | None = Field(alias="telemetrySettings", description="Telemetry configuration", default=None)
    external_streaming_settings: ExternalStreamingSettingsModel = Field(
        alias="externalStreamingSettings", description="External streaming settings", default_factory=ExternalStreamingSettingsModel
    )

    # ── Validators ──

    @model_validator(mode="after")
    def validate_fabric_consistency(self):
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        Checks the management type matches ``_fabric_type``, propagates fabric_name
        into the management model, auto-creates telemetry settings, then delegates
        to ``_post_validate_consistency()`` for subclass-specific logic.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        if self.management is not None and self.management.type != self._fabric_type:
            raise ValueError(f"Management type must be {self._fabric_type}")

        # Propagate fabric name to management model
        if self.management is not None:
            self.management.name = self.fabric_name

        # Auto-create default telemetry settings if collection is enabled
        if self.telemetry_collection and self.telemetry_settings is None:
            self.telemetry_settings = TelemetrySettingsModel()

        # Subclass hook for additional validation
        self._post_validate_consistency()

        return self

    def _post_validate_consistency(self) -> None:
        """Subclass hook for post-validation logic.

        Subclasses that override this method MUST call
        ``super()._post_validate_consistency()`` to ensure any future
        shared validation in the base class is not silently skipped.
        """
        pass

    @classmethod
    def get_argument_spec(cls) -> dict:
        """Auto-generate Ansible argument spec from pydantic model fields.

        Introspects the model's field definitions to produce a complete
        argument spec with proper types, defaults, choices, and nested options.
        Single-value Literal fields and fields listed in _argspec_exclude_fields
        are automatically excluded.
        """
        config_options = _build_options_from_model(cls)
        return dict(
            state={
                "type": "str",
                "default": "merged",
                "choices": ["merged", "replaced", "deleted", "overridden"],
            },
            config={
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": config_options,
            },
            config_actions={
                "type": "dict",
                "required": False,
                "options": {
                    "save": {"type": "bool", "default": False},
                    "deploy": {"type": "bool", "default": False},
                    "type": {"type": "str", "default": "switch", "choices": ["switch", "global"]},
                },
            },
        )
