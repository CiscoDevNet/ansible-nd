# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Centralized base paths for ND API endpoints.

This module provides a single location to manage all API base paths using
a type-safe Enum pattern, allowing easy modification when API paths change
and preventing invalid path usage through compile-time checking.

## Usage

```python
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base_path import ApiPath

# Recommended: Use enum for type safety
base_url = ApiPath.INFRA.value

# Type-safe function parameters
def build_endpoint(api_base: ApiPath, path: str) -> str:
    return f"{api_base.value}/{path}"

# IDE autocomplete works
endpoint = build_endpoint(ApiPath.INFRA, "aaa/localUsers")
```
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from enum import Enum


class ApiPath(str, Enum):
    """
    # Summary

    Base API path constants for ND REST API.

    ## Description

    String-based enum providing type-safe API base paths shared across
    all endpoint versions (v1, v2, etc.).

    ## Raises

    None
    """

    ANALYZE = "/api/v1/analyze"
    INFRA = "/api/v1/infra"
    MANAGE = "/api/v1/manage"
    ONEMANAGE = "/api/v1/onemanage"
