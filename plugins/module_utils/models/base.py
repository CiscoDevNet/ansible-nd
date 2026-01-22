# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABC, abstractmethod
from pydantic import BaseModel, ConfigDict
from typing import List, Dict, Any, Optional, ClassVar
from typing_extensions import Self


class NDBaseModel(BaseModel, ABC):

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    # TODO: find ways to redifine these var in every future NDBaseModels
    identifiers: ClassVar[List[str]] = []
    use_composite_identifiers: ClassVar[bool] = False

    @abstractmethod
    def to_payload(self) -> Dict[str, Any]:
        pass
    
    @classmethod
    @abstractmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        pass
    
    def get(self, field: str, default: Any = None) -> Any:
        """Custom get method to mimic dictionary behavior."""
        return getattr(self, field, default)

    # TODO: Modify to make it more generic and Pydantic | might change and be moved in different Generic Class/Model
    # TODO: add a method to get nested keys, ex: get("spec", {}).get("onboardUrl")
    def get_identifier_value(self) -> Any:
        """Generates the internal map key based on the selected mode."""
        if self.use_composite_identifiers:
            # Mode: Composite (Tuple of ALL keys)
            values = []
            for identifier in self.identifiers:
                value = self.get(identifier)
                if value is None:
                    return None # Missing a required part | Add Error Handling method here
                values.append(value)
            return tuple(values)
        else:
            # Mode: Priority (First available key)
            for identifier in self.identifiers:
                return self.get(identifier)
            return None
