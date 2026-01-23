# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABC, abstractmethod
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, ClassVar, Tuple, Union, Literal
from typing_extensions import Self


class NDBaseModel(BaseModel, ABC):
    """
    Base model for all Nexus Dashboard API objects.
    
    Supports three identifier strategies:
    - single: One unique required field (e.g., ["login_id"])
    - composite: Multiple required fields as tuple (e.g., ["device", "interface"])
    - hierarchical: Priority-ordered fields (e.g., ["uuid", "name"])
    """
    
    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        extra='ignore'
    )
    
    # Subclasses MUST define these
    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical"]] = "single"
    
    # Optional: fields to exclude from diffs (e.g., passwords)
    exclude_from_diff: ClassVar[List[str]] = []
    
    @abstractmethod
    def to_payload(self) -> Dict[str, Any]:
        """
        Convert model to API payload format.
        """
        pass
    
    @classmethod
    @abstractmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        """
        Create model instance from API response.
        """
        pass
    
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
            
            # NOTE: might not be needed in the future with field_validator
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

# NOTE: Maybe make it a seperate BaseModel
class NDNestedModel(NDBaseModel):
    """
    Base for nested models without identifiers.
    """

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
        return cls.model_validate(response)
