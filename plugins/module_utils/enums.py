# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
# pylint: disable=missing-module-docstring
# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

Enum definitions for Nexus Dashboard Ansible modules.

## Enums

- HttpVerbEnum: Enum for HTTP verb values used in endpoints.
- OperationType: Enum for operation types used by Results to determine if changes have occurred.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from enum import Enum

class BooleanStringEnum(str, Enum):
    """
    # Summary

    Enum for boolean string values used in query parameters.

    ## Members

    - TRUE: Represents the string "true".
    - FALSE: Represents the string "false".
    """

    TRUE = "true"
    FALSE = "false"
class HttpVerbEnum(str, Enum):
    """
    # Summary

    Enum for HTTP verb values used in endpoints.

    ## Members

    - GET: Represents the HTTP GET method.
    - POST: Represents the HTTP POST method.
    - PUT: Represents the HTTP PUT method.
    - DELETE: Represents the HTTP DELETE method.
    - PATCH: Represents the HTTP PATCH method.
    """

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"

    @classmethod
    def values(cls) -> list[str]:
        """
        # Summary

        Returns a list of all enum values.

        ## Returns

        - A list of string values representing the enum members.
        """
        return sorted([member.value for member in cls])
class OperationType(Enum):
    """
    # Summary

    Enumeration for operation types.

    Used by Results to determine if changes have occurred based on the operation type.

    - QUERY: Represents a query operation which does not change state.
    - CREATE: Represents a create operation which adds new resources.
    - UPDATE: Represents an update operation which modifies existing resources.
    - DELETE: Represents a delete operation which removes resources.

    # Usage

    ```python
    from plugins.module_utils.enums import OperationType
    class MyModule:
        def __init__(self):
            self.operation_type = OperationType.QUERY
    ```

    The above informs the Results class that the current operation is a query, and thus
    no changes should be expected.

    Specifically, Results.has_anything_changed() will return False for QUERY operations,
    while it will evaluate CREATE, UPDATE, and DELETE operations in more detail to
    determine if any changes have occurred.
    """

    QUERY = "query"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"

    def changes_state(self) -> bool:
        """
        # Summary

        Return True if this operation type can change controller state.

        ## Returns

        - `bool`: True if operation can change state, False otherwise

        ## Examples

        ```python
        OperationType.QUERY.changes_state()  # Returns False
        OperationType.CREATE.changes_state()  # Returns True
        OperationType.DELETE.changes_state()  # Returns True
        ```
        """
        return self in (
            OperationType.CREATE,
            OperationType.UPDATE,
            OperationType.DELETE,
        )

    def is_read_only(self) -> bool:
        """
        # Summary

        Return True if this operation type is read-only.

        ## Returns

        - `bool`: True if operation is read-only, False otherwise

        ## Examples

        ```python
        OperationType.QUERY.is_read_only()  # Returns True
        OperationType.CREATE.is_read_only()  # Returns False
        ```
        """
        return self == OperationType.QUERY
