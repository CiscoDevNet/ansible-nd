# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from abc import ABC
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple, Union

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict
from ansible_collections.cisco.nd.plugins.module_utils.utils import has_removals, issubset


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

    # ND template defaults for the reverse pass of `get_diff` (issue #410), keyed by field ALIAS (wire key).
    # ND echoes the schema-declared template default for every field the user never set, so an existing-side
    # value equal to its declared default is normalized to absent during removal detection -- omitting it from
    # proposed config is not a pending reset. Source the values from the ND OpenAPI template schema for the
    # model's policyType (see the `nd-openapi` MCP); a wrong value here breaks replaced/overridden idempotency.
    reverse_diff_defaults: ClassVar[Dict[str, Any]] = {}

    # Keys (field ALIASES / wire keys) stripped from this model's level of the reverse-pass dump regardless of
    # value. For server-populated fields the proposed config can never express (e.g. the orchestrator-injected
    # `peerSwitchId` on vPC policy models): their presence on the existing side is not a pending reset, and
    # unlike `reverse_diff_defaults` they have no single constant value to match against. Applies at the
    # declaring model's own nesting level, so nested models scope their own exclusions.
    reverse_diff_exclude: ClassVar[Set[str]] = set()

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

    def to_config(self, **kwargs) -> Dict[str, Any]:
        """Convert model to Ansible config format (Python field names, flat structure)."""
        return self.model_dump(
            by_alias=False,
            exclude_none=True,
            context={"mode": "config"},
            exclude=self.config_exclude_fields or None,
            **kwargs,
        )

    # --- Core Deserialization ---

    @classmethod
    def from_response(cls, response: Dict[str, Any], **kwargs) -> "NDBaseModel":
        """Create model instance from API response dict (validation context ``mode=response``)."""
        context = {"mode": "response", **(kwargs.pop("context", None) or {})}
        return cls.model_validate(response, by_alias=True, context=context, **kwargs)

    @classmethod
    def from_config(cls, ansible_config: Dict[str, Any], **kwargs) -> "NDBaseModel":
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

    def to_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """Export for diff comparison, excluding sensitive fields."""
        return self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude=self.exclude_from_diff or None,
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
        """
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
        Merge another model's explicitly set, non-None values into this instance.
        Recursively merges nested NDBaseModel fields.
        Only fields present in ``other.model_fields_set`` are applied so that
        Pydantic default values do not overwrite existing configuration.

        Returns self for chaining.
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
                current.merge(value)
            else:
                setattr(self, field_name, value)

        return self
