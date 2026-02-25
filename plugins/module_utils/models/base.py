# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABC, abstractmethod
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, ClassVar, Tuple, Union, Literal, Optional
from typing_extensions import Self


# TODO: Revisit identifiers strategy (low priority)
# TODO: add kwargs to every sub method
class NDBaseModel(BaseModel, ABC):
    """
    Base model for all Nexus Dashboard API objects.
    
    Supports three identifier strategies:
    - single: One unique required field (e.g., ["login_id"])
    - composite: Multiple required fields as tuple (e.g., ["device", "interface"])
    - hierarchical: Priority-ordered fields (e.g., ["uuid", "name"])
    - none: no identifiers required (e.g., only a single instance can exist in Nexus Dasboard)
    """
    # TODO: revisit initial Model Configurations (low priority)
    # TODO: enable extra
    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra='ignore'
    )

    # TODO: Revisit identifiers strategy (low priority)
    identifiers: ClassVar[Optional[List[str]]] = None
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "none"]]] = "none"
    
    # Optional: fields to exclude from diffs (e.g., passwords)
    exclude_from_diff: ClassVar[List[str]] = []
    unwanted_keys: ClassVar[List] = []

    # TODO: Revisit it with identifiers strategy (low priority)
    def __init_subclass__(cls, **kwargs):
        """
        Enforce configuration for identifiers definition.
        """
        super().__init_subclass__(**kwargs)
        
        # Skip enforcement for nested models
        # TODO: Remove if `NDNestedModel` is a separated BaseModel (low priority)
        if cls.__name__ in ["NDNestedModel"] or any(base.__name__ == "NDNestedModel" for base in cls.__mro__):
            return

        if not hasattr(cls, "identifiers") or cls.identifiers is None:
            raise ValueError(
                f"Class {cls.__name__} must define 'identifiers' and 'identifier_strategy'."
                f"Example: `identifiers: ClassVar[Optional[List[str]]] = ['login_id']`"
            )
        if not hasattr(cls, "identifier_strategy") or cls.identifier_strategy is None:
            raise ValueError(
                f"Class {cls.__name__} must define 'identifiers' and 'identifier_strategy'."
                f"Example: `identifier_strategy: ClassVar[Optional[Literal['single', 'composite', 'hierarchical', 'none']]] = 'single'`"
            )
    
    # NOTE: Might not need to make them absractmethod because of the Pydantic built-in methods (low priority)
    # NOTE: Should we use keyword arguments?
    @abstractmethod
    def to_payload(self, **kwargs) -> Dict[str, Any]:
        """
        Convert model to API payload format.
        """
        pass
    
    @classmethod
    @abstractmethod
    def from_response(cls, response: Dict[str, Any], **kwargs) -> Self:
        """
        Create model instance from API response.
        """
        pass
    
    # TODO: Revisit this function when revisiting identifier strategy (low priority)
    # TODO: Add condition when there is no identifiers (high priority)
    def get_identifier_value(self) -> Union[str, int, Tuple[Any, ...]]:
        """
        Extract identifier value(s) from this instance:
        - single identifier: Returns field value.
        - composite identifiers: Returns tuple of all field values.
        - hierarchical identifiers: Returns tuple of (field_name, value) for first non-None field.
        """
        if not self.identifiers:
            raise ValueError(f"{self.__class__.__name__} has no identifiers defined")
        
        if self.identifier_strategy == "single":
            value = getattr(self, self.identifiers[0], None)
            if value is None:
                raise ValueError(
                    f"Single identifier field '{self.identifiers[0]}' is None"
                )
            return value
        
        elif self.identifier_strategy == "composite":
            values = []
            missing = []
            
            for field in self.identifiers:
                value = getattr(self, field, None)
                if value is None:
                    missing.append(field)
                values.append(value)
            
            # NOTE: might be redefined with Pydantic (low priority)
            if missing:
                raise ValueError(
                    f"Composite identifier fields {missing} are None. "
                    f"All required: {self.identifiers}"
                )
            
            return tuple(values)
        
        elif self.identifier_strategy == "hierarchical":
            for field in self.identifiers:
                value = getattr(self, field, None)
                if value is not None:
                    return (field, value)
            
            raise ValueError(
                f"No non-None value in hierarchical fields {self.identifiers}"
            )
        
        else:
            raise ValueError(f"Unknown identifier strategy: {self.identifier_strategy}")
    

    def to_diff_dict(self) -> Dict[str, Any]:
        """
        Export for diff comparison (excludes sensitive fields).
        """
        return self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude=set(self.exclude_from_diff)
        )
    
    # NOTE: initialize and return a deep copy of the instance?
    # TODO: Might be missing a proper merge on fields of type `List[NDNestedModel]`? -> similar to NDCOnfigCollection... -> add argument to make it optional either replace
    def merge(self, other_model: "NDBaseModel") -> Self:
        if not isinstance(other_model, type(self)):
            # TODO: Change error message
            return TypeError("models are not of the same type.")
        
        for field, value in other_model:
            if value is None:
                continue
            
            current_value = getattr(self, field)
            if isinstance(current_value, NDBaseModel) and isinstance(value, NDBaseModel):
                setattr(self, field, current_value.merge(value))

            else:
                setattr(self, field, value)
        return self

# TODO: Make it a seperated BaseModel (low priority)
class NDNestedModel(NDBaseModel):
    """
    Base for nested models without identifiers.
    """

    # TODO: Configuration Fields to be clearly defined here (low priority)
    identifiers: ClassVar[List[str]] = []

    def to_payload(self) -> Dict[str, Any]:
        """
        Convert model to API payload format.
        """
        return self.model_dump(by_alias=True, exclude_none=True)
    
    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        """
        Create model instance from API response.
        """
        return cls.model_validate(response, by_alias=True)
