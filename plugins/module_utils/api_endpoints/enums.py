# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Enums used in api_endpoints.
"""
from enum import Enum


class VerbEnum(str, Enum):
    """
    # Summary

    Enum for HTTP verb values used in endpoints.

    ## Members

    - GET: Represents the HTTP GET method.
    - POST: Represents the HTTP POST method.
    - PUT: Represents the HTTP PUT method.
    - DELETE: Represents the HTTP DELETE method.
    """

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


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
