# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from abc import ABC
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict
from typing import List, Dict, Any, ClassVar, Set, Tuple, Union, Literal, Optional
from ansible_collections.cisco.nd.plugins.module_utils.utils import issubset


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
        """Create model instance from API response dict."""
        return cls.model_validate(response, by_alias=True, **kwargs)

    @classmethod
    def from_config(cls, ansible_config: Dict[str, Any], **kwargs) -> "NDBaseModel":
        """Create model instance from Ansible config dict."""
        return cls.model_validate(ansible_config, by_name=True, **kwargs)

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

    def _to_set_fields_diff_dict(self) -> Dict[str, Any]:
        """Build diff dict containing only explicitly set fields, recursively.

        Used for merge-state diff comparison where only user-provided fields
        should be compared against existing configuration. Fields that received
        their value from model defaults are excluded.
        """
        full_dump = self.to_diff_dict()
        return self._filter_set_fields(full_dump)

    def _filter_set_fields(self, full_dump: Dict[str, Any]) -> Dict[str, Any]:
        """Filter a serialized dict to only include explicitly set fields."""
        result = {}
        exclude = self.exclude_from_diff or set()

        for field_name in self.model_fields_set:
            if field_name in exclude:
                continue

            value = getattr(self, field_name)
            if value is None:
                continue

            field_info = self.__class__.model_fields.get(field_name)
            alias = field_info.alias if field_info and field_info.alias else field_name

            if alias not in full_dump:
                continue

            if isinstance(value, NDBaseModel):
                result[alias] = value._to_set_fields_diff_dict()
            else:
                result[alias] = full_dump[alias]

        return result

    def get_diff(self, other: "NDBaseModel", only_set_fields: bool = False) -> bool:
        """Diff comparison.

        Args:
            other: The model to compare against.
            only_set_fields: When True, only compare fields explicitly set in
                ``other`` (via model_fields_set). This prevents default values
                from triggering false diffs during merge operations.
        """
        self_data = self.to_diff_dict()
        if only_set_fields:
            other_data = other._to_set_fields_diff_dict()
        else:
            other_data = other.to_diff_dict()
        return issubset(other_data, self_data)

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
