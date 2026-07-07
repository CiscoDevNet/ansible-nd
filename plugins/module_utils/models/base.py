# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from abc import ABC
from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple, Union

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict
from ansible_collections.cisco.nd.plugins.module_utils.utils import issubset


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

    # --- Gathered Filtering Configuration ---

    supports_gathered_filtering: ClassVar[bool] = False

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
    def secret_field_keys(cls, by_alias: bool = False) -> Set[str]:
        """Names of fields tagged ``json_schema_extra={"secret": True}``.

        Aliases when ``by_alias`` is True (payload shape), else Python field
        names (config/input shape). The single source of truth for which fields
        are secret, used both to keep them out of output and to register their
        values for ``no_log`` masking.
        """
        keys: Set[str] = set()
        for field_name, field_info in cls.model_fields.items():
            extra = field_info.json_schema_extra
            if isinstance(extra, dict) and extra.get("secret"):
                keys.add((field_info.alias or field_name) if by_alias else field_name)
        return keys

    @classmethod
    def collect_secret_values(cls, config_item: Dict[str, Any]) -> Set[str]:
        """Secret string values in a raw Ansible config item, for no_log masking.

        Ansible auto-masks ``no_log`` argument-spec params, but not values in
        free-form/nested dicts it does not statically model. ``NDStateMachine``
        registers whatever this returns with ``module.no_log_values`` so the
        value-based scrubber strips them from the invocation echo and result.

        Default: top-level fields tagged secret. Models with secrets nested in a
        free-form dict (e.g. links ``template_inputs``) override to add those.
        """
        values: Set[str] = set()
        if not isinstance(config_item, dict):
            return values
        for key in cls.secret_field_keys(by_alias=False):
            value = config_item.get(key)
            if value:
                values.add(value)
        return values

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
        """Convert model to Ansible config format (Python field names, flat structure).

        Secret-tagged fields are excluded so they never surface in output
        (after/before/proposed/gathered); they remain only in to_payload().
        """
        exclude = set(self.config_exclude_fields) | self.secret_field_keys(by_alias=False)
        return self.model_dump(
            by_alias=False,
            exclude_none=True,
            context={"mode": "config"},
            exclude=exclude or None,
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
        """
        self_data = self.to_diff_dict()
        other_data = other.to_diff_dict(exclude_unset=exclude_unset)
        is_subset = issubset(other_data, self_data)
        if is_subset and exclude_unset and self.merge_would_change(other):
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
