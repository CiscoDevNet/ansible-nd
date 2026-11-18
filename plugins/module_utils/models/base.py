# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from abc import ABC
from copy import deepcopy
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple, Union, get_args, get_origin
import types

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    SerializationInfo,
    model_serializer,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.utils import NO_LOG_PLACEHOLDER, has_removals, issubset


def _strip_none_values(data):
    """Recursively remove keys with None values from dicts.

    This ensures Ansible's implicit None defaults (for unspecified options)
    are not passed to pydantic, allowing default_factory and model defaults
    to take effect without polluting model_fields_set.
    """
    if isinstance(data, dict):
        return {k: _strip_none_values(v) for k, v in data.items() if v is not None}
    if isinstance(data, list):
        return [_strip_none_values(item) for item in data]
    return data


class NDBaseModel(BaseModel, ABC):
    """
    Base model for all Nexus Dashboard API objects.

    Class-level configuration attributes:
        identifiers: List of field names used to uniquely identify this object.
        identifier_strategy: How identifiers are interpreted.
        exclude_from_diff: Fields excluded from diff comparisons.
        unwanted_keys: Keys to strip from API responses before processing.
        payload_nested_fields: Mapping of {payload_key: [field_names]} for fields
            that should be grouped under a nested key in payload mode but remain
            flat in config mode.
        payload_exclude_fields: Fields to exclude from payload output
            (e.g., because they are restructured into nested keys).
        config_exclude_fields: Fields to exclude from config output
            (e.g., computed payload-only structures).
        replacement_preserve_fields: Wire aliases copied from the existing
            object when omitted from a replaced/overridden proposal.
        replacement_preserve_secret_fields: Preserved wire aliases whose
            controller-returned values must also be registered for no-log
            scrubbing.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        arbitrary_types_allowed=True,
        extra="ignore",
    )

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = None
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "singleton"

    # --- Gathered Filtering Configuration ---

    supports_gathered_filtering: ClassVar[bool] = False
    gathered_filter_properties: ClassVar[tuple[str, ...]] = ()

    @classmethod
    def normalize_gathered_filter(cls, filter_item: dict) -> dict:
        """
        Normalize one gathered-state filter item.

        The base implementation makes no changes. Models can override this
        when filter values require module-specific normalization.
        """
        return filter_item

    @classmethod
    def matches_gathered_filter(
        cls,
        criteria: dict,
        candidate: dict,
    ) -> bool:
        """Return whether a gathered candidate matches one filter item."""
        return issubset(criteria, candidate)

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        """Return the Ansible argument spec for this model's module.

        Used by the state machine to derive gathered output pruning. Models
        that support gathered state should override this to return the full
        module argument spec including ``config.options``.
        """
        return {}

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[Set[str]] = set()
    unwanted_keys: ClassVar[List] = []

    # Declarative nested-field grouping for payload mode
    # e.g., {"passwordPolicy": ["reuse_limitation", "time_interval_limitation"]}
    # means: in payload mode, remove these fields from top level and nest them
    # under "passwordPolicy" with their alias names.
    payload_nested_fields: ClassVar[Dict[str, List[str]]] = {}

    # Fields to explicitly exclude per mode
    payload_exclude_fields: ClassVar[Set[str]] = set()
    config_exclude_fields: ClassVar[Set[str]] = set()

    # Wire aliases that a full replacement PUT must carry forward from the
    # existing object when the user omitted them. This is for dynamic,
    # controller-assigned values and intentionally unsupported writable fields;
    # deterministic controller defaults belong in reverse_diff_defaults instead.
    replacement_preserve_fields: ClassVar[Set[str]] = set()

    # Subset of replacement_preserve_fields whose values contain secret
    # material. Unlike public secret fields, opaque response extras have no
    # Field metadata from which secret handling can be inferred. The state
    # machine recursively registers these controller-returned values with
    # Ansible's value-based no-log scrubber before producing module output.
    replacement_preserve_secret_fields: ClassVar[Set[str]] = set()

    # Opt-in for `_treat_empty_string_as_unset`. Off by default: for most models "" is a
    # legitimate value that clears a field, so coercing it to unset would silently drop the
    # user's intent. Fabric families enable it because ND 4.3.1 rejects "" on schema-
    # constrained fields with HTTP 400 (see the validator docstring).
    empty_string_means_unset: ClassVar[bool] = False

    # Evidence-backed controller defaults for the reverse pass of `get_diff` (issue #410), keyed by field ALIAS
    # (wire key). OpenAPI defaults are contract candidates, not proof of live controller behavior: add a value
    # only after omit/read-back and explicit-value probes establish a deterministic value for every supported
    # release/fabric in scope. Dynamic, conditional, release-divergent, or otherwise unresolved values must be
    # preserved or omitted instead. A wrong value here breaks replaced/overridden idempotency.
    # Values MUST be in the model's DUMPED form, not an unnormalized controller echo: when a validator coerces a field
    # on read (e.g. a numeric-string loopback `routeMapTag` to integer 12345), the table must hold the coerced value
    # or the default never matches and the field silently reopens issue #410 for that model.
    reverse_diff_defaults: ClassVar[Dict[str, Any]] = {}

    # Keys (field ALIASES / wire keys) stripped from this model's level of the reverse-pass dump regardless of
    # value. For server-populated fields the proposed config can never express (e.g. the orchestrator-injected
    # `peerSwitchId` on vPC policy models): their presence on the existing side is not a pending reset, and
    # unlike `reverse_diff_defaults` they have no single constant value to match against. Applies at the
    # declaring model's own nesting level, so nested models scope their own exclusions.
    reverse_diff_exclude: ClassVar[Set[str]] = set()

    # ND template defaults the WIRE body must always carry, keyed by field ALIAS (wire key). ND 4.3.1 rejects create/update
    # bodies that omit certain template fields 4.2.1 silently defaulted (issue #564; vault `ethernet-create-required-fields-431`
    # and `vpc-trunk-allowedvlans-required-431`). Only `to_payload` injects these (`_apply_payload_defaults`, gated on the
    # payload serialization context): config and diff dumps carry no payload context, so before/after output and diff
    # classification are unchanged, and the read side already normalizes the echoed default via `reverse_diff_defaults`.
    # Values MUST be the template default in wire form so the body is version-agnostic (4.2.1 stores the same value whether
    # or not it is sent). Applies at the declaring model's own nesting level. A model that declares its own wrap-mode
    # `model_serializer` replaces `_serialize_with_payload_defaults` and must call `_apply_payload_defaults` itself.
    payload_defaults: ClassVar[Dict[str, Any]] = {}

    # --- Subclass Validation ---

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Skip enforcement for nested models
        if cls.__name__ == "NDNestedModel" or any(base.__name__ == "NDNestedModel" for base in cls.__mro__):
            return

        if not hasattr(cls, "identifiers") or cls.identifiers is None:
            raise ValueError(f"Class {cls.__name__} must define 'identifiers'. " f"Example: identifiers: ClassVar[Optional[List[str]]] = ['login_id']")
        if not hasattr(cls, "identifier_strategy") or cls.identifier_strategy is None:
            raise ValueError(f"Class {cls.__name__} must define 'identifier_strategy'. " f"Example: identifier_strategy: ClassVar[...] = 'single'")

    # --- Core Serialization ---

    def _build_payload_nested(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply payload_nested_fields: pull specified fields out of the top-level
        dict and group them under their declared parent key.
        """
        if not self.payload_nested_fields:
            return data

        result = dict(data)

        for nested_key, field_names in self.payload_nested_fields.items():
            nested_dict = {}
            for field_name in field_names:
                # Resolve the alias for this field
                field_info = self.__class__.model_fields.get(field_name)
                if field_info is None:
                    continue

                alias = field_info.alias or field_name

                # Pull value from the serialized data (which uses aliases in payload mode)
                if alias in result:
                    nested_dict[alias] = result.pop(alias)

            if nested_dict:
                result[nested_key] = nested_dict

        return result

    @classmethod
    def _direct_tagged_field_keys(cls, tag: str, by_alias: bool = False) -> set[str]:
        """Field names on this class whose ``json_schema_extra`` sets ``tag``."""
        keys: set[str] = set()
        for field_name, field_info in cls.model_fields.items():
            extra = field_info.json_schema_extra
            if isinstance(extra, dict) and extra.get(tag):
                keys.add((field_info.alias or field_name) if by_alias else field_name)
        return keys

    @classmethod
    def _direct_secret_field_keys(cls, by_alias: bool = False) -> set[str]:
        """Secret field names declared on this class only (not nested models)."""
        return cls._direct_tagged_field_keys("secret", by_alias=by_alias)

    @classmethod
    def _direct_sensitive_container_keys(cls, by_alias: bool = False) -> set[str]:
        """CLI/template container names declared on this class only."""
        return cls._direct_tagged_field_keys("sensitive_container", by_alias=by_alias)

    @classmethod
    def secret_field_keys(cls, by_alias: bool = False) -> set[str]:
        """Names of fields tagged ``json_schema_extra={"secret": True}``.

        Aliases when ``by_alias`` is True (payload shape), else Python field
        names (config/input shape). Includes nested model fields. The single
        source of truth for which fields are secret, used both to keep them
        out of output and to register their values for ``no_log`` masking.
        """
        keys = set(cls._direct_secret_field_keys(by_alias=by_alias))
        for _field_name, _field_info, nested_cls, _is_list in cls._nested_model_fields():
            keys.update(nested_cls.secret_field_keys(by_alias=by_alias))
        return keys

    @classmethod
    def sensitive_container_keys(cls, by_alias: bool = False) -> set[str]:
        """Names of fields tagged ``json_schema_extra={"sensitive_container": True}``.

        These are opaque CLI/template blobs, not named passwords. Display dumps
        replace the whole value with the no-log placeholder; ``to_diff_dict()``
        and ``to_payload()`` keep the original so a blob change is still a change.
        """
        keys = set(cls._direct_sensitive_container_keys(by_alias=by_alias))
        for _field_name, _field_info, nested_cls, _is_list in cls._nested_model_fields():
            keys.update(nested_cls.sensitive_container_keys(by_alias=by_alias))
        return keys

    @classmethod
    def _nested_model_fields(cls):
        """Yield ``(field_name, field_info, nested_model_cls, is_list)`` for typed nested models."""
        nested = []
        for field_name, field_info in cls.model_fields.items():
            nested_cls, is_list = cls._nested_model_type(field_info.annotation)
            if nested_cls is not None:
                nested.append((field_name, field_info, nested_cls, is_list))
        return nested

    @staticmethod
    def _nested_model_type(annotation) -> tuple:
        """Return ``(NDBaseModel subclass, is_list)`` for a field annotation, else ``(None, False)``."""
        origin = get_origin(annotation)
        if origin is Union or origin is getattr(types, "UnionType", None):
            args = [arg for arg in get_args(annotation) if arg is not type(None)]
            annotation = args[0] if len(args) == 1 else annotation
            origin = get_origin(annotation)
        if origin in (list, List):
            args = get_args(annotation)
            element = args[0] if args else None
            try:
                if isinstance(element, type) and issubclass(element, NDBaseModel):
                    return element, True
            except TypeError:
                return None, False
            return None, False
        try:
            if isinstance(annotation, type) and issubclass(annotation, NDBaseModel):
                return annotation, False
        except TypeError:
            return None, False
        return None, False

    @classmethod
    def collect_secret_values(cls, config_item: dict[str, Any]) -> set[str]:
        """Secret string values in a raw Ansible config item, for no_log masking.

        Ansible auto-masks ``no_log`` argument-spec params, but not values in
        free-form/nested dicts it does not statically model. ``NDStateMachine``
        registers whatever this returns with ``module.no_log_values`` so the
        value-based scrubber strips them from the invocation echo and result.

        Walks typed nested models and lists of models. Collects both snake_case
        names and API aliases. Models with secrets nested in a free-form dict
        (e.g. links ``template_inputs``, VRF ``fabric_data``) override to add those.
        """
        values: set[str] = set()
        if not isinstance(config_item, dict):
            return values
        for key in cls._direct_secret_field_keys(by_alias=False) | cls._direct_secret_field_keys(by_alias=True):
            cls._add_secret_value(values, config_item.get(key))
        for key in cls._direct_sensitive_container_keys(by_alias=False) | cls._direct_sensitive_container_keys(by_alias=True):
            values.update(cls._secret_strings(config_item.get(key)))
        for field_name, field_info, nested_cls, is_list in cls._nested_model_fields():
            raw = config_item.get(field_name)
            if raw is None:
                raw = config_item.get(field_info.alias or field_name)
            if is_list and isinstance(raw, list):
                for item in raw:
                    values.update(nested_cls.collect_secret_values(item) if isinstance(item, dict) else set())
            elif isinstance(raw, dict):
                values.update(nested_cls.collect_secret_values(raw))
        return values

    @staticmethod
    def _add_secret_value(values: set[str], value: Any) -> None:
        """Register a non-empty secret, including controller-echoed non-string forms."""
        if hasattr(value, "get_secret_value"):
            value = value.get_secret_value()
        if value is None or value == "":
            return
        if isinstance(value, str):
            values.add(value)
            return
        values.add(str(value))

    def collect_replacement_secret_values(self) -> set[str]:
        """Return secret strings held in opaque replacement-preserved fields.

        These values originate in a controller response rather than the
        Ansible argument specification, so Ansible cannot discover them from a
        ``no_log`` option declaration. Collection is recursive because fabric
        replacement fields are declared on the nested management model.
        """
        values: set[str] = set()
        fields_by_wire_key = {field_info.alias or field_name: field_name for field_name, field_info in type(self).model_fields.items()}

        for wire_key in self.replacement_preserve_secret_fields:
            field_name = fields_by_wire_key.get(wire_key)
            if field_name is not None:
                value = getattr(self, field_name, None)
            else:
                value = (self.model_extra or {}).get(wire_key)
            values.update(self._secret_strings(value))

        for field_name in type(self).model_fields:
            value = getattr(self, field_name, None)
            if isinstance(value, NDBaseModel):
                values.update(value.collect_replacement_secret_values())
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, NDBaseModel):
                        values.update(child.collect_replacement_secret_values())
        return values

    def collect_model_secret_values(self) -> set[str]:
        """Tagged secret strings held on this instance, including nested models.

        Used for controller-returned values that Ansible did not see as task
        arguments. Typed nested models are walked here; free-form dict containers
        (VRF ``fabric_data``) are added by the resource model.
        """
        values: set[str] = set()
        for field_name in type(self)._direct_secret_field_keys(by_alias=False):
            self._add_secret_value(values, getattr(self, field_name, None))
        for field_name in type(self)._direct_sensitive_container_keys(by_alias=False):
            values.update(self._secret_strings(getattr(self, field_name, None)))
        for field_name, _field_info, _nested_cls, _is_list in type(self)._nested_model_fields():
            value = getattr(self, field_name, None)
            if isinstance(value, NDBaseModel):
                values.update(value.collect_model_secret_values())
            elif isinstance(value, list):
                for child in value:
                    if isinstance(child, NDBaseModel):
                        values.update(child.collect_model_secret_values())
        return values

    @staticmethod
    def _secret_strings(value: Any) -> set[str]:
        """Recursively extract non-empty secret strings without collecting keys."""
        if hasattr(value, "get_secret_value"):
            value = value.get_secret_value()
        if isinstance(value, str):
            return {value} if value else set()
        if isinstance(value, dict):
            return {secret for child in value.values() for secret in NDBaseModel._secret_strings(child)}  # pylint: disable=protected-access
        if isinstance(value, (list, tuple, set)):
            return {secret for child in value for secret in NDBaseModel._secret_strings(child)}  # pylint: disable=protected-access
        return set()

    def _apply_payload_defaults(self, data: Dict[str, Any], info: SerializationInfo) -> Dict[str, Any]:
        """
        # Summary

        Inject each `payload_defaults` entry whose key is absent from `data`, but only for a payload-mode dump (serialization
        context `mode == "payload"`, set by `to_payload`). Every other dump (config, diff, contextless) returns `data` unchanged,
        so a wrap serializer that defaults a missing context to payload mode (e.g. the vPC per-peer fan-out) still never injects
        into a diff. Models that declare their own wrap-mode `model_serializer` call this from it, since the subclass serializer
        replaces `_serialize_with_payload_defaults`.

        ## Raises

        None
        """
        if not self.payload_defaults or (info.context or {}).get("mode") != "payload":
            return data
        for key, value in self.payload_defaults.items():
            data.setdefault(key, value)
        return data

    @model_serializer(mode="wrap")
    def _serialize_with_payload_defaults(self, handler, info: SerializationInfo) -> Any:
        """
        # Summary

        Default wrap-mode serializer: run the standard serialization, then apply `payload_defaults` (`_apply_payload_defaults`)
        when the dump is a payload. A no-op for every model that declares no defaults.

        ## Raises

        None
        """
        data = handler(self)
        if isinstance(data, dict):
            return self._apply_payload_defaults(data, info)
        return data

    def to_payload(self, **kwargs) -> Dict[str, Any]:
        """Convert model to API payload format (aliased keys, nested structures)."""
        data = self.model_dump(
            by_alias=True,
            exclude_none=True,
            mode="json",
            context={"mode": "payload"},
            exclude=self.payload_exclude_fields or None,
            **kwargs,
        )
        return self._build_payload_nested(data)

    def to_internal_config(self, **kwargs) -> Dict[str, Any]:
        """Return the Ansible config shape with real secret values.

        Coordinators and request builders must use this dump, not ``to_config()``.
        ``to_config()`` is the user-visible copy and replaces tagged secrets with
        ``NO_LOG_PLACEHOLDER``; feeding that placeholder back into
        ``prepare_config_data()`` would send it to Nexus Dashboard.
        """
        return self._dump_config(mask_secrets=False, **kwargs)

    def to_config(self, **kwargs) -> Dict[str, Any]:
        """Convert model to Ansible config format (Python field names, flat structure).

        Secret-tagged fields and sensitive CLI/template containers are masked
        to ``NO_LOG_PLACEHOLDER`` in output (after/before/proposed): the key
        stays visible so callers see the field is set, but the value is never
        shown. The real value remains in ``to_payload()`` and
        ``to_internal_config()``.
        """
        return self._dump_config(mask_secrets=True, **kwargs)

    def _dump_config(self, *, mask_secrets: bool, **kwargs) -> Dict[str, Any]:
        """Dump snake_case config; optionally replace tagged secrets for display."""
        data = self.model_dump(
            by_alias=False,
            exclude_none=True,
            context={"mode": "config" if mask_secrets else "internal"},
            exclude=self.config_exclude_fields or None,
            **kwargs,
        )
        if mask_secrets:
            self._mask_secrets_in_mapping(data)
        self._apply_config_exclude_scope(data)
        return data

    def _mask_secrets_in_mapping(self, data: Dict[str, Any]) -> None:
        """Replace tagged secrets in a snake_case config mapping, including nested models."""
        if not isinstance(data, dict):
            return
        type(self).mask_secrets_in_mapping(data)
        for field_name, _field_info, nested_cls, is_list in type(self)._nested_model_fields():
            nested = data.get(field_name)
            value = getattr(self, field_name, None)
            if is_list and isinstance(nested, list):
                children = value if isinstance(value, list) else []
                for index, child_data in enumerate(nested):
                    if not isinstance(child_data, dict):
                        continue
                    child = children[index] if index < len(children) else None
                    if isinstance(child, NDBaseModel):
                        child._mask_secrets_in_mapping(child_data)  # pylint: disable=protected-access
                    else:
                        nested_cls.mask_secrets_in_mapping(child_data)
            elif isinstance(nested, dict):
                if isinstance(value, NDBaseModel):
                    value._mask_secrets_in_mapping(nested)  # pylint: disable=protected-access
                else:
                    nested_cls.mask_secrets_in_mapping(nested)

    @classmethod
    def mask_secrets_in_mapping(cls, data: Dict[str, Any]) -> None:
        """Mask this class's direct secret and sensitive-container keys."""
        if not isinstance(data, dict):
            return
        keys = (
            cls._direct_secret_field_keys(by_alias=False)
            | cls._direct_secret_field_keys(by_alias=True)
            | cls._direct_sensitive_container_keys(by_alias=False)
            | cls._direct_sensitive_container_keys(by_alias=True)
        )
        for key in keys:
            if key in data and data[key] not in (None, ""):
                data[key] = NO_LOG_PLACEHOLDER

    def _apply_config_exclude_scope(self, data: Dict[str, Any]) -> None:
        """Apply each nested model's config exclusions to a config-mode dump.

        ``model_dump(exclude=...)`` only applies the root model's exclusion
        declaration. This recursive pass lets nested models hide their own
        declared fields and retained ``extra="allow"`` keys without excluding
        those values from API payloads.
        """
        for configured_key in self.config_exclude_fields:
            data.pop(configured_key, None)
            for field_name, field_info in type(self).model_fields.items():
                if configured_key in {field_name, field_info.alias or field_name}:
                    data.pop(field_name, None)

        for field_name in type(self).model_fields:
            value = getattr(self, field_name, None)
            nested = data.get(field_name)
            if isinstance(value, NDBaseModel) and isinstance(nested, dict):
                value._apply_config_exclude_scope(nested)  # pylint: disable=protected-access
            elif isinstance(value, list) and isinstance(nested, list):
                for child, child_data in zip(value, nested):
                    if isinstance(child, NDBaseModel) and isinstance(child_data, dict):
                        child._apply_config_exclude_scope(child_data)  # pylint: disable=protected-access

    def to_gathered_config(self, **kwargs) -> Dict[str, Any]:
        """Convert the model to replay-safe gathered configuration.

        Most resources use the normal Ansible config representation. Models
        containing write-only fields may override this method to omit values that
        cannot be read back from the controller and therefore cannot safely be
        replayed as declarative input. Sensitive CLI/template containers are
        omitted because replaying the display placeholder would send it to ND.
        """
        data = self.to_config(**kwargs)
        self._omit_sensitive_containers_in_mapping(data)
        return data

    def _omit_sensitive_containers_in_mapping(self, data: Dict[str, Any]) -> None:
        """Drop sensitive CLI/template containers from a gathered mapping."""
        if not isinstance(data, dict):
            return
        type(self).omit_sensitive_containers_in_mapping(data)
        for field_name, _field_info, nested_cls, is_list in type(self)._nested_model_fields():
            nested = data.get(field_name)
            value = getattr(self, field_name, None)
            if is_list and isinstance(nested, list):
                children = value if isinstance(value, list) else []
                for index, child_data in enumerate(nested):
                    if not isinstance(child_data, dict):
                        continue
                    child = children[index] if index < len(children) else None
                    if isinstance(child, NDBaseModel):
                        child._omit_sensitive_containers_in_mapping(child_data)  # pylint: disable=protected-access
                    else:
                        nested_cls.omit_sensitive_containers_in_mapping(child_data)
            elif isinstance(nested, dict):
                if isinstance(value, NDBaseModel):
                    value._omit_sensitive_containers_in_mapping(nested)  # pylint: disable=protected-access
                else:
                    nested_cls.omit_sensitive_containers_in_mapping(nested)

    @classmethod
    def omit_sensitive_containers_in_mapping(cls, data: Dict[str, Any]) -> None:
        """Remove this class's sensitive-container keys from a dict."""
        if not isinstance(data, dict):
            return
        for key in cls._direct_sensitive_container_keys(by_alias=False) | cls._direct_sensitive_container_keys(by_alias=True):
            data.pop(key, None)

    # --- Core Deserialization ---

    @model_validator(mode="before")
    @classmethod
    def _treat_empty_string_as_unset(cls, data: Any, info: Any) -> Any:
        """Drop empty-string config input for fields declared ``Optional[...] = None``.

        A field defaulting to ``None`` is declaring "when unset, omit me from the
        payload". Ansible playbooks and vars files routinely spell "unset" as ``""``,
        so both spellings must mean the same thing. This matters because ND 4.3.1
        enforces request-body schema validation: fields carrying ``minLength``,
        ``pattern`` or ``format`` (for example ``dhcpStartAddress``) reject ``""``
        with HTTP 400, whereas omitting them lets ND apply its own default.

        Only applied to config input on models that opt in via ``empty_string_means_unset``.
        Fields that legitimately accept "" declare a ``str = ""`` default instead and are
        therefore untouched.
        """
        if not cls.empty_string_means_unset:
            return data
        if not isinstance(data, dict):
            return data
        context = getattr(info, "context", None) or {}
        if context.get("mode") != "config":
            return data
        nullable_keys = cls._nullable_default_keys()
        if not nullable_keys:
            return data
        return {key: value for key, value in data.items() if not (value == "" and key in nullable_keys)}

    @classmethod
    def _nullable_default_keys(cls) -> set[str]:
        """Field names and aliases whose declared default is None."""
        keys: set[str] = set()
        for field_name, field_info in getattr(cls, "model_fields", {}).items():
            # Fields with no declared default carry PydanticUndefined here, so an
            # identity check against None selects only explicit ``= None`` defaults.
            if field_info.default is not None:
                continue
            if getattr(field_info, "default_factory", None) is not None:
                continue
            keys.add(field_name)
            alias = getattr(field_info, "alias", None)
            if alias:
                keys.add(alias)
        return keys

    @classmethod
    def from_response(cls, response: dict[str, Any], **kwargs) -> "NDBaseModel":
        """Create model instance from API response dict.

        Marks the validation context with both ``mode="response"`` (resource-manager
        convention) and ``source="response"`` (links tolerant-read convention) so
        models can be lenient about controller-only shapes (e.g. links tolerate
        policy types they cannot model) without relaxing validation of user input.
        """
        context = {"mode": "response", **(kwargs.pop("context", None) or {}), "source": "response"}
        return cls.model_validate(response, by_alias=True, context=context, **kwargs)

    @classmethod
    def from_config(cls, ansible_config: dict[str, Any], **kwargs) -> "NDBaseModel":
        """Create model instance from Ansible config dict.

        Strips None values recursively before validation so that Ansible's
        default None for unspecified options does not override pydantic
        default_factory values or pollute model_fields_set. Validation runs with
        context ``mode=config`` so config-only validators (e.g. the storm-control
        percentage/pps mutex) fire on config input but not on ND responses.
        """
        cleaned = _strip_none_values(ansible_config)
        context = {"mode": "config", **(kwargs.pop("context", None) or {})}
        return cls.model_validate(cleaned, by_name=True, context=context, **kwargs)

    # --- Identifier Access ---

    def get_identifier_value(self) -> Optional[Union[str, int, Tuple[Any, ...]]]:
        """
        Extract identifier value(s) based on the configured strategy.

        Returns:
            - single: The field value
            - composite: Tuple of all field values
            - hierarchical: Tuple of (field_name, value) for first non-None field
            - singleton: None
        """
        strategy = self.identifier_strategy

        if strategy == "singleton":
            return None

        if not self.identifiers:
            raise ValueError(f"{self.__class__.__name__} has strategy '{strategy}' but no identifiers defined.")

        if strategy == "single":
            value = getattr(self, self.identifiers[0], None)
            if value is None:
                raise ValueError(f"Single identifier field '{self.identifiers[0]}' is None")
            return value

        elif strategy == "composite":
            values = []
            missing = []
            for field in self.identifiers:
                value = getattr(self, field, None)
                if value is None:
                    missing.append(field)
                values.append(value)
            if missing:
                raise ValueError(f"Composite identifier fields {missing} are None. " f"All required: {self.identifiers}")
            return tuple(values)

        elif strategy == "hierarchical":
            for field in self.identifiers:
                value = getattr(self, field, None)
                if value is not None:
                    return (field, value)
            raise ValueError(f"No non-None value in hierarchical fields {self.identifiers}")

        else:
            raise ValueError(f"Unknown identifier strategy: {strategy}")

    # --- Diff & Merge ---

    def prepare_for_replacement(self, existing: "NDBaseModel") -> "NDBaseModel":
        """Return the exact-state candidate with allowlisted values preserved.

        Replaced and overridden states issue full payloads. Some controller
        values cannot safely be reconstructed from user input: they may be
        dynamically allocated or intentionally unsupported by the module. Each
        model declares the corresponding wire aliases in
        ``replacement_preserve_fields``. Omitted values are copied recursively
        from ``existing`` before both diffing and payload construction; explicit
        proposed values always win.
        """
        if not isinstance(existing, type(self)):
            raise TypeError(f"Cannot prepare {type(self).__name__} from {type(existing).__name__}. " "Both must be the same type.")

        candidate = self.model_copy(deep=True)
        if candidate._preserve_replacement_fields(existing):  # pylint: disable=protected-access
            return candidate
        return self

    def _preserve_replacement_fields(self, existing: "NDBaseModel") -> bool:
        """Copy omitted allowlisted values from ``existing`` into ``self``."""
        changed = False
        fields_by_wire_key = {field_info.alias or field_name: field_name for field_name, field_info in type(self).model_fields.items()}

        for wire_key in self.replacement_preserve_fields:
            field_name = fields_by_wire_key.get(wire_key)
            if field_name is not None:
                if field_name in self.model_fields_set:
                    continue
                existing_value = getattr(existing, field_name, None)
                if existing_value is not None:
                    setattr(self, field_name, deepcopy(existing_value))
                    changed = True
                continue

            proposed_extras = self.model_extra or {}
            existing_extras = existing.model_extra or {}
            if wire_key not in proposed_extras and wire_key in existing_extras:
                setattr(self, wire_key, deepcopy(existing_extras[wire_key]))
                changed = True

        for field_name in type(self).model_fields:
            proposed_value = getattr(self, field_name, None)
            existing_value = getattr(existing, field_name, None)
            if isinstance(proposed_value, NDBaseModel) and isinstance(existing_value, type(proposed_value)):
                if proposed_value._preserve_replacement_fields(existing_value):  # pylint: disable=protected-access
                    changed = True

        return changed

    def to_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """Export for diff comparison, excluding sensitive fields.

        Secret-tagged fields are excluded from the comparison so a change to
        only a secret is not (and cannot be) detected as a diff, keeping runs
        idempotent when the controller does not echo secrets back on read.
        """
        exclude = set(self.exclude_from_diff) | self.secret_field_keys(by_alias=False)
        return self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude=exclude or None,
            mode="json",
            **kwargs,
        )

    def to_reverse_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """
        # Summary

        Export for the reverse pass of `get_diff` (issue #410), scoped to payload shape: fields in `exclude_from_diff` or
        `payload_exclude_fields` are excluded, so only fields the PUT body can express participate in removal detection.
        The dump is then scrubbed recursively, each nested model applying its own declarations: values equal to their
        `reverse_diff_defaults` entry are stripped (ND echoes template defaults for unset fields), keys in
        `reverse_diff_exclude` are stripped unconditionally (server-populated fields the proposed config can never
        express), and keys retained by `extra="allow"` are stripped (undeclared server keys are not expressible in
        config and must not count as removals). Like `to_diff_dict`, the top-level exclusion sets apply at the top
        level only; nested exclusions are declared on the nested model via `reverse_diff_exclude`.

        Derived from `to_diff_dict` (one dump, then in-place scoping) rather than a second `model_dump`, so subclass
        `to_diff_dict` overrides scope the reverse pass too, and `get_diff` can reuse its forward dumps instead of
        re-dumping both models.

        ## Raises

        None
        """
        data = self.to_diff_dict(**kwargs)
        self._apply_reverse_diff_scope(data)
        return data

    def _apply_reverse_diff_scope(self, data: Dict[str, Any]) -> None:
        """
        # Summary

        Convert a `to_diff_dict` export into the reverse-pass shape, in place: pop the aliases of top-level
        `payload_exclude_fields` (already absent when a field is also in `exclude_from_diff`), then run
        `_scrub_reverse_diff_dict` so each nested model applies its own exclusions/extras/defaults declarations.

        ## Raises

        None
        """
        for field_name in self.payload_exclude_fields:
            field_info = type(self).model_fields.get(field_name)
            data.pop(field_info.alias if field_info is not None and field_info.alias else field_name, None)
        self._scrub_reverse_diff_dict(data)

    def _scrub_reverse_diff_dict(self, data: Dict[str, Any]) -> None:
        """
        # Summary

        Scrub `data` (an aliased dump of `self`) for removal detection: drop keys listed in `reverse_diff_exclude`, keys
        retained only via `extra="allow"` (undeclared server keys), and keys whose value equals the model's declared
        `reverse_diff_defaults` entry, then recurse into nested `NDBaseModel` fields so each nested model applies its own
        declarations.

        ## Raises

        None
        """
        for alias in self.reverse_diff_exclude:
            data.pop(alias, None)
        # `model_extra` keys are stored under their wire spelling, matching the aliased dump.
        for extra_key in getattr(self, "model_extra", None) or {}:
            data.pop(extra_key, None)
        for alias, default in self.reverse_diff_defaults.items():
            if alias in data and data[alias] == default:
                del data[alias]
        for field_name, field_info in type(self).model_fields.items():
            value = getattr(self, field_name, None)
            if isinstance(value, NDBaseModel):
                alias = field_info.alias or field_name
                nested = data.get(alias)
                if isinstance(nested, dict):
                    # Same-class recursion; pylint cannot infer `value` is an NDBaseModel from getattr.
                    value._scrub_reverse_diff_dict(nested)  # pylint: disable=protected-access

    def get_diff(self, other: "NDBaseModel", exclude_unset: bool = False) -> bool:
        """Diff comparison.

        Args:
            other: The model to compare against.
            exclude_unset: When True, only compare fields explicitly set in
                ``other`` (via Pydantic's ``exclude_unset``). This prevents
                default values from triggering false diffs during merge
                operations. This is the merge-path comparison, so a subset
                match is additionally cross-checked with ``merge_would_change``
                to catch merge side effects the one-way subset test cannot see
                (e.g. mutually exclusive counterpart fields that the merge
                would clear).

                When False (the ``replaced``/``overridden`` path), a subset
                match is additionally cross-checked with ``has_removals`` over
                the payload-scoped dumps (issue #410): a field present on
                ``self`` (device) but absent from ``other`` (proposed) means
                the full-payload PUT would reset it, so it must classify as a
                difference. Empty existing values (``""``, ``[]``, ``{}``) are
                normalized to absent so ND-echoed empty markers keep runs
                idempotent.

        Raises:
            TypeError: If ``other`` is not an instance of this model's type
                (same contract as ``merge``). The reverse pass applies
                ``other``'s own ``reverse_diff_*`` declarations, so a
                cross-type comparison is a programming error, not a diff.
        """
        if not isinstance(other, type(self)):
            raise TypeError(f"Cannot diff {type(other).__name__} against {type(self).__name__}. Both must be the same type.")

        self_data = self.to_diff_dict()
        other_data = other.to_diff_dict(exclude_unset=exclude_unset)
        is_subset = issubset(other_data, self_data)
        if is_subset and exclude_unset and self.merge_would_change(other):
            return False
        if is_subset and not exclude_unset:
            # Reuse the forward dumps for the reverse pass (they are not read again): scoping them in place
            # avoids a second full model_dump per side (PR #422 review, efficiency finding).
            self._apply_reverse_diff_scope(self_data)
            # Same-class access; pylint cannot infer `other` shares this NDBaseModel API.
            other._apply_reverse_diff_scope(other_data)  # pylint: disable=protected-access
            if has_removals(self_data, other_data):
                return False
        return is_subset

    def merge_would_change(self, other: "NDBaseModel") -> bool:
        """
        # Summary

        Return True when `merge(other)` would mutate `self` in a way the one-way dict-subset comparison in `get_diff`
        cannot detect. The default implementation has no such side effects itself; it only recurses into nested
        `NDBaseModel` fields explicitly set on `other` so that nested models overriding `merge` (e.g.
        `StormControlMutexMixin`, which clears the counterpart of a mutually exclusive pair) can surface their
        merge side effects to the top-level diff.

        ## Raises

        None
        """
        for field_name in other.model_fields_set:
            value = getattr(other, field_name, None)
            if value is None:
                continue
            current = getattr(self, field_name, None)
            if isinstance(current, NDBaseModel) and isinstance(value, NDBaseModel):
                if current.merge_would_change(value):
                    return True
        return False

    def merge(self, other: "NDBaseModel") -> "NDBaseModel":
        """
        # Summary

        Merge another model's explicitly set, non-None values into this instance. Recursively merges nested `NDBaseModel` fields. Only fields present in
        `other.model_fields_set` are applied so that Pydantic default values do not overwrite existing configuration. Returns `self` for chaining.

        ## Raises

        ### TypeError

        - If `other` is not an instance of `type(self)`

        ### ValueError

        - If merging would change the discriminator value of a nested discriminated-union field (e.g. `policy_type`). Two union branches have disjoint
          field sets, so a field-by-field merge across them is undefined; the transition is rejected with a message pointing at `state: replaced`
        """
        if not isinstance(other, type(self)):
            raise TypeError(f"Cannot merge {type(other).__name__} into {type(self).__name__}. " f"Both must be the same type.")

        for field_name, value in other:
            if value is None:
                continue

            # Only merge fields that were explicitly provided, not defaults
            if field_name not in other.model_fields_set:
                continue

            current = getattr(self, field_name)
            if isinstance(current, NDBaseModel) and isinstance(value, NDBaseModel):
                if type(current) is not type(value):
                    discriminator = type(self).model_fields[field_name].discriminator
                    if isinstance(discriminator, str):
                        raise ValueError(
                            f"Cannot change {discriminator} from '{getattr(current, discriminator)}' to '{getattr(value, discriminator)}' "
                            f"with state: merged. Use state: replaced (or delete and re-create the resource) to change {discriminator}."
                        )
                current.merge(value)
            else:
                setattr(self, field_name, value)

        return self
