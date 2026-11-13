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
from collections.abc import Mapping
from typing import Any, ClassVar, Literal, get_args, get_origin

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import NDMinimumVersion
from ansible_collections.cisco.nd.plugins.module_utils.models.types import NdFabricName
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    HAS_PYDANTIC,
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
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
        args = [a for a in get_args(annotation) if a is not types.NoneType]
        if len(args) == 1:
            return args[0], True
    return annotation, False


def _is_pydantic_model(annotation) -> bool:
    """Check if annotation is a pydantic BaseModel subclass."""
    return isinstance(annotation, type) and issubclass(annotation, BaseModel)


def _is_mapping_type(annotation) -> bool:
    """Return whether an annotation represents a generic mapping."""
    origin = get_origin(annotation)
    candidate = origin or annotation
    return isinstance(candidate, type) and issubclass(candidate, Mapping)


def _is_secret_field(field_info, inner_type) -> bool:
    """True when a field is declared secret via metadata (authoritative) or typed as SecretStr (backstop)."""
    extra = getattr(field_info, "json_schema_extra", None)
    if isinstance(extra, dict) and extra.get("secret") is True:
        return True
    return inner_type is SecretStr


def serialize_secret_value(value, info):
    """Serialize a secret field: real value only for the API payload, masked everywhere else.

    Accepts a ``SecretStr`` or a plain string (empty-string defaults are stored as-is).
    """
    if value is None:
        return None
    raw = value.get_secret_value() if hasattr(value, "get_secret_value") else value
    if raw == "":
        return ""
    mode = (info.context or {}).get("mode")
    if mode == "payload":
        return raw
    return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


def _python_type_to_ansible(annotation) -> str:
    """Map a Python type annotation to an Ansible argument spec type string."""
    if get_origin(annotation) is typing.Annotated:
        return _python_type_to_ansible(get_args(annotation)[0])
    if annotation is bool:
        return "bool"
    if annotation is int:
        return "int"
    if annotation is float:
        return "float"
    if annotation is str:
        return "str"
    if _is_mapping_type(annotation):
        return "dict"
    if _is_pydantic_model(annotation):
        return "dict"
    return "str"


def _project_value_to_argument_spec(value: Any, spec: dict[str, Any]) -> Any:
    """Project config output through one generated Ansible option specification.

    A dict with nested ``options`` is a closed public model surface, so response-
    only fields and retained pydantic extras must be removed recursively. A dict
    without ``options`` is an intentionally opaque mapping and must retain its
    complete structure. The same rules apply to lists whose elements are dicts.
    """
    option_type = spec.get("type")
    nested_options = spec.get("options")

    if option_type == "dict" and isinstance(value, Mapping):
        if not isinstance(nested_options, dict):
            return dict(value)
        return {key: _project_value_to_argument_spec(value[key], nested_options[key]) for key in nested_options if key in value}

    if option_type == "list" and isinstance(value, list):
        if spec.get("elements") != "dict" or not isinstance(nested_options, dict):
            return value
        return [(_project_value_to_argument_spec(item, {"type": "dict", "options": nested_options}) if isinstance(item, Mapping) else item) for item in value]

    return value


def _project_config_to_argument_spec(config: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Return only replayable fields declared by the public config options."""
    return {key: _project_value_to_argument_spec(config[key], options[key]) for key in options if key in config}


def _omit_unset_release_gated_defaults(model: NDBaseModel, config: dict[str, Any]) -> None:
    """Keep model defaults for gated fields out of gathered replay when absent in the response."""
    for field_name, field_info in type(model).model_fields.items():
        if field_name not in config:
            continue
        has_release_gate = any(isinstance(metadata, NDMinimumVersion) for metadata in getattr(field_info, "metadata", ()))
        if has_release_gate and field_name not in model.model_fields_set:
            config.pop(field_name, None)
            continue

        value = getattr(model, field_name, None)
        config_value = config.get(field_name)
        if isinstance(value, NDBaseModel) and isinstance(config_value, dict):
            _omit_unset_release_gated_defaults(value, config_value)
        elif isinstance(value, list) and isinstance(config_value, list):
            for child, child_config in zip(value, config_value):
                if isinstance(child, NDBaseModel) and isinstance(child_config, dict):
                    _omit_unset_release_gated_defaults(child, child_config)


def _declared_fabric_secret_values(model: NDBaseModel) -> set[str]:
    """Collect modeled response secrets for Ansible's value scrubber."""
    values: set[str] = set()
    for name in type(model).secret_field_keys():
        values.update(model._secret_strings(getattr(model, name, None)))
    for name in type(model).model_fields:
        value = getattr(model, name, None)
        if isinstance(value, NDBaseModel):
            values.update(_declared_fabric_secret_values(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, NDBaseModel):
                    values.update(_declared_fabric_secret_values(item))
    return values


def _normalize_unreported_release_defaults(model: NDBaseModel) -> None:
    """Keep newer defaults absent from API responses out of merged payloads."""
    for name, field in type(model).model_fields.items():
        value = getattr(model, name, None)
        if name not in model.model_fields_set and any(isinstance(item, NDMinimumVersion) for item in field.metadata):
            if value is not None:
                if type(None) not in get_args(field.annotation):
                    raise ValueError(f"Release-gated field {name!r} must allow omission from controller responses")
                object.__setattr__(model, name, None)
        elif isinstance(value, NDBaseModel):
            _normalize_unreported_release_defaults(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, NDBaseModel):
                    _normalize_unreported_release_defaults(item)


def _release_defaults_for_comparison(model: NDBaseModel, data: dict[str, Any]) -> None:
    """Compare absent release defaults without adding them to model/payload state."""
    secret_names = type(model).secret_field_keys()
    for name, field in type(model).model_fields.items():
        if name in secret_names:
            continue
        alias = field.alias or name
        value = getattr(model, name, None)
        if (
            alias not in data
            and name not in model.model_fields_set
            and not field.is_required()
            and field.default_factory is None
            and field.default is not None
            and any(isinstance(item, NDMinimumVersion) for item in field.metadata)
        ):
            data[alias] = field.default
        elif isinstance(value, NDBaseModel) and isinstance(data.get(alias), dict):
            _release_defaults_for_comparison(value, data[alias])
        elif isinstance(value, list) and isinstance(data.get(alias), list):
            for item, item_data in zip(value, data[alias]):
                if isinstance(item, NDBaseModel) and isinstance(item_data, dict):
                    _release_defaults_for_comparison(item, item_data)


def _complete_supplied_model_list_items(model: NDBaseModel, data: dict[str, Any]) -> None:
    """Compare supplied typed lists with the item defaults their PUT sends.

    Fabric merge replaces a supplied list as a whole. An unset item default is
    therefore outbound state, even though ``exclude_unset`` correctly keeps
    omitted scalar fields and whole lists out of the merged comparison. Dump
    these items through the normal comparison serializer so aliases and secret
    masks match the existing model. Release-default projections stay confined
    to comparison data; the item and its version-filtered payload are unchanged.
    """
    for name, field in type(model).model_fields.items():
        alias = field.alias or name
        if alias not in data:
            continue
        value = getattr(model, name, None)
        if isinstance(value, NDBaseModel) and isinstance(data[alias], dict):
            _complete_supplied_model_list_items(value, data[alias])
            continue
        annotation, _ = _unwrap_optional(field.annotation)
        if get_origin(annotation) is not list:
            continue
        item_type, _ = _unwrap_optional(get_args(annotation)[0])
        if not isinstance(item_type, type) or not issubclass(item_type, NDBaseModel):
            continue
        if not isinstance(value, list) or not isinstance(data[alias], list) or len(value) != len(data[alias]):
            continue
        complete_items = []
        for item, serialized in zip(value, data[alias]):
            if isinstance(item, NDBaseModel):
                serialized = item.model_dump(by_alias=True, exclude_none=True, mode="json")
                _release_defaults_for_comparison(item, serialized)
            complete_items.append(serialized)
        data[alias] = complete_items


def _controller_default_field_owner(model: NDBaseModel, path: tuple[str, ...]) -> NDBaseModel | None:
    """Find a declared object-field owner without materializing absent objects."""
    owner = model
    for name in path[:-1]:
        if not isinstance(owner, NDBaseModel):
            return None
        owner = getattr(owner, name, None)
    return owner if isinstance(owner, NDBaseModel) else None


def _build_options_from_model(model_cls, exclude_fields: set[str] | None = None) -> dict[str, Any]:
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

        spec: dict[str, Any] = {}

        # Determine if it's a list type
        list_origin = get_origin(inner_type)
        if list_origin is list:
            list_args = get_args(inner_type)
            spec["type"] = "list"
            if list_args:
                element_type = list_args[0]
                while get_origin(element_type) is typing.Annotated:
                    element_type = get_args(element_type)[0]
                if _is_pydantic_model(element_type):
                    spec["elements"] = "dict"
                    nested_options = _build_options_from_model(element_type)
                    if nested_options:
                        spec["options"] = nested_options
                elif _is_mapping_type(element_type):
                    spec["elements"] = "dict"
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

        # Secrets: metadata {"secret": True} is authoritative; SecretStr is a backstop.
        # no_log lets Ansible scrub the real value from task args, results, and error text.
        if _is_secret_field(field_info, inner_type):
            spec["no_log"] = True

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

    # Resolved by fabric release preflight; never serialized as configuration.
    _nd_controller_default_comparisons: dict[tuple[str, ...], Any] = PrivateAttr(default_factory=dict)

    # ── ClassVars (shared across all fabric models) ──
    identifiers: ClassVar[list[str] | None] = ["fabric_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "location": {"latitude": 37.33939, "longitude": -121.89496},
    }

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

    def prepare_for_replacement(self, existing: NDBaseModel) -> NDBaseModel:
        """Materialize telemetry only when opaque writable state needs preserving.

        ``telemetry_settings`` is optional in public configuration.  If an
        exact-state proposal omits it, normal recursive preservation cannot
        reach writable-but-unexposed roots nested below ``flow_collection``.
        Create the default public telemetry shape only when the existing
        response actually contains one of those declared opaque roots.  The
        base implementation then copies only the allowlisted descendants;
        public telemetry values retain normal exact-state reset semantics.
        """
        candidate = self
        if isinstance(existing, type(self)) and self.telemetry_settings is None and existing.telemetry_settings is not None:
            existing_flow = existing.telemetry_settings.flow_collection
            existing_extras = existing_flow.model_extra or {}
            if existing_flow.replacement_preserve_fields.intersection(existing_extras):
                candidate = self.model_copy(deep=True)
                candidate.telemetry_settings = TelemetrySettingsModel()
        return NDBaseModel.prepare_for_replacement(candidate, existing)

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
            **config_actions_spec(FABRIC_CONFIG_ACTIONS),
        )

    def to_gathered_config(self, **kwargs) -> dict[str, Any]:
        """Return configuration limited recursively to public Ansible options."""
        config = self.to_config(**kwargs)
        _omit_unset_release_gated_defaults(self, config)
        options = type(self).get_argument_spec()["config"]["options"]
        return _project_config_to_argument_spec(config, options)

    def collect_replacement_secret_values(self) -> set[str]:
        """Register public and opaque controller-returned secrets for masking."""
        return super().collect_replacement_secret_values() | _declared_fabric_secret_values(self)

    @classmethod
    def from_response(cls, response: dict[str, Any], **kwargs) -> NDBaseModel:
        """Preserve API omission of release-gated defaults in the stored state."""
        model = super().from_response(response, **kwargs)
        _normalize_unreported_release_defaults(model)
        return model

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """Compare outbound typed-list defaults and full-state release defaults."""
        data = super().to_diff_dict(**kwargs)
        if kwargs.get("exclude_unset", False):
            _complete_supplied_model_list_items(self, data)
        else:
            _release_defaults_for_comparison(self, data)
        return data

    def get_diff(self, other: NDBaseModel, exclude_unset: bool = False) -> bool:
        """Ignore an omitted controller-owned field only at its resolved default.

        Exact-state omission still resets nondefault values. Matching default
        echoes are removed only from a temporary comparison copy; neither the
        original controller model nor the proposed payload is changed.
        """
        if exclude_unset or not isinstance(other, type(self)):
            return super().get_diff(other, exclude_unset=exclude_unset)
        matching_paths = []
        for path, expected in other._nd_controller_default_comparisons.items():
            proposed_owner = _controller_default_field_owner(other, path)
            existing_owner = _controller_default_field_owner(self, path)
            if proposed_owner is None or existing_owner is None:
                continue
            name = path[-1]
            if name in proposed_owner.model_fields_set or getattr(proposed_owner, name, None) is not None:
                continue
            if getattr(existing_owner, name, None) == expected:
                matching_paths.append(path)
        if not matching_paths:
            return super().get_diff(other, exclude_unset=False)
        comparison_existing = self.model_copy(deep=True)
        for path in matching_paths:
            owner = _controller_default_field_owner(comparison_existing, path)
            object.__setattr__(owner, path[-1], None)
            owner.model_fields_set.discard(path[-1])
        return NDBaseModel.get_diff(comparison_existing, other, exclude_unset=False)
