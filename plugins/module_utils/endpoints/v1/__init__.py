# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND API v1 endpoint definitions.

This module provides all endpoint classes and helpers for ND API v1
(ND 3.0+, NDFC 12+).

Import from this module to explicitly use v1 endpoints:

```python
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1 import (
    EpInfraAaaLocalUsersGet,
    BasePathInfra,
)
```

Or import from the parent ep module for current stable version:

```python
from ansible_collections.cisco.nd.plugins.module_utils.endpoints import (
    EpInfraAaaLocalUsersGet,
    BasePathInfra,
)
```
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.base_paths_infra import BasePath as BasePathInfra
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.base_paths_manage import BasePath as BasePathManage
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra_aaa import (
    EpInfraAaaLocalUsersDelete,
    EpInfraAaaLocalUsersGet,
    EpInfraAaaLocalUsersPost,
    EpInfraAaaLocalUsersPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra_clusterhealth import (
    ClusterHealthConfigEndpointParams,
    ClusterHealthStatusEndpointParams,
    EpInfraClusterhealthConfigGet,
    EpInfraClusterhealthStatusGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra_login import (
    EpInfraLoginPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage_switches import (
    EpManageSwitchesGet,
    SwitchesEndpointParams,
)

__all__ = [
    # BasePath helpers
    "BasePathInfra",
    "BasePathManage",
    # Infra AAA endpoints
    "EpInfraAaaLocalUsersGet",
    "EpInfraAaaLocalUsersPost",
    "EpInfraAaaLocalUsersPut",
    "EpInfraAaaLocalUsersDelete",
    # Infra ClusterHealth endpoints
    "EpInfraClusterhealthConfigGet",
    "EpInfraClusterhealthStatusGet",
    "ClusterHealthConfigEndpointParams",
    "ClusterHealthStatusEndpointParams",
    # Infra Login endpoint
    "EpInfraLoginPost",
    # Manage Switches endpoints
    "EpManageSwitchesGet",
    "SwitchesEndpointParams",
]
