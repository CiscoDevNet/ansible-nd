# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

ND Endpoint infrastructure (smart endpoints).

## Description

Provides Pydantic-based endpoint models that bundle URL paths with HTTP verbs,
enabling type-safe API endpoint definitions.

## Current Stable API Version

v1 (ND 3.0+, NDFC 12+)

## Usage

Import from top-level for current stable version:

```python
from ansible_collections.cisco.nd.plugins.module_utils.endpoints import (
    EpInfraAaaLocalUsersGet,
    BasePathInfra,
)
```

Or import explicitly from version directory:

```python
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1 import (
    EpInfraAaaLocalUsersGet,
)
```

## Version Management

When v2 is released, this module will re-export the latest stable version.
Legacy code can continue importing from version-specific subdirectories:

- `ep.v1.*` - ND API v1 endpoints
- `ep.v2.*` - ND API v2 endpoints (future)
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

# Re-export v1 as current stable
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1 import (
    BasePathInfra,
    BasePathManage,
    ClusterHealthConfigEndpointParams,
    ClusterHealthStatusEndpointParams,
    EpInfraAaaLocalUsersDelete,
    EpInfraAaaLocalUsersGet,
    EpInfraAaaLocalUsersPost,
    EpInfraAaaLocalUsersPut,
    EpInfraClusterhealthConfigGet,
    EpInfraClusterhealthStatusGet,
    EpManageSwitchesGet,
    SwitchesEndpointParams,
)

__all__ = [
    # BasePath helpers
    "BasePathInfra",
    "BasePathManage",
    # Infra AAA
    "EpInfraAaaLocalUsersGet",
    "EpInfraAaaLocalUsersPost",
    "EpInfraAaaLocalUsersPut",
    "EpInfraAaaLocalUsersDelete",
    # Infra ClusterHealth
    "EpInfraClusterhealthConfigGet",
    "EpInfraClusterhealthStatusGet",
    "ClusterHealthConfigEndpointParams",
    "ClusterHealthStatusEndpointParams",
    # Manage Switches
    "EpManageSwitchesGet",
    "SwitchesEndpointParams",
]
