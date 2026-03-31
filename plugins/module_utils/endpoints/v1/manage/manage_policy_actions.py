# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Manage Policy Actions endpoint models.

This module contains endpoint definitions for policy action operations
in the ND Manage API.

Endpoints covered:
- POST /fabrics/{fabricName}/policyActions/markDelete  - Mark-delete policies
- POST /fabrics/{fabricName}/policyActions/pushConfig   - Deploy policy configs
- POST /fabrics/{fabricName}/policyActions/remove       - Remove policies in bulk
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

__author__ = "L Nikhil Sri Krishna"

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)


# ============================================================================
# Query parameter classes
# ============================================================================


class PolicyActionMutationEndpointParams(EndpointQueryParams):
    """
    # Summary

    Shared query parameters for policy action mutation endpoints.

    ## Description

    Per manage.json, the following policy action endpoints accept
    ``clusterName`` and ``ticketId``:

    - POST /policyActions/markDelete
    - POST /policyActions/remove

    ## Parameters

    - cluster_name → clusterName
    - ticket_id   → ticketId
    """

    model_config = ConfigDict(extra="forbid")

    cluster_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )
    ticket_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z][a-zA-Z0-9_-]+$",
        description="Change Control Ticket Id",
    )


class PolicyPushConfigEndpointParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for the pushConfig endpoint.

    ## Description

    Per manage.json, ``POST /policyActions/pushConfig`` accepts only
    ``clusterName`` (no ``ticketId``).

    ## Parameters

    - cluster_name → clusterName
    """

    model_config = ConfigDict(extra="forbid")

    cluster_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )


# ============================================================================
# Base class for /fabrics/{fabricName}/policyActions/{action}
# ============================================================================


class _EpManagePolicyActionsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Policy Actions endpoints.

    Provides the common base path builder for all HTTP methods on the
    ``/api/v1/manage/fabrics/{fabricName}/policyActions/{action}`` endpoints.
    """

    def _action_path(self, action: str) -> str:
        """Build the base endpoint path for a specific action."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "policyActions", action)


# ============================================================================
# POST /fabrics/{fabricName}/policyActions/markDelete
# ============================================================================


class EpManagePolicyActionsMarkDeletePost(_EpManagePolicyActionsBase):
    """
    # Summary

    ND Manage Policy Actions — Mark Delete Endpoint

    ## Description

    Mark-delete policies in bulk.  This flags policies for deletion
    without immediately removing them from the controller.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyActions/markDelete

    ## Verb

    - POST

    ## Usage

    ```python
    ep = EpManagePolicyActionsMarkDeletePost()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    ```

    ## Request Body Example

    ```json
    {
        "policyIds": ["POLICY-121110", "POLICY-121120"]
    }
    ```
    """

    class_name: Literal["EpManagePolicyActionsMarkDeletePost"] = Field(
        default="EpManagePolicyActionsMarkDeletePost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyActionMutationEndpointParams = Field(
        default_factory=PolicyActionMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        base = self._action_path("markDelete")
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# POST /fabrics/{fabricName}/policyActions/pushConfig
# ============================================================================


class EpManagePolicyActionsPushConfigPost(_EpManagePolicyActionsBase):
    """
    # Summary

    ND Manage Policy Actions — Push Config Endpoint

    ## Description

    Push (deploy) configuration for policies in bulk.  This deploys
    the policy configurations to the target switches.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyActions/pushConfig

    ## Verb

    - POST

    ## Usage

    ```python
    ep = EpManagePolicyActionsPushConfigPost()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    ```

    ## Note

    pushConfig does NOT accept ``ticketId`` per manage.json spec.

    ## Request Body Example

    ```json
    {
        "policyIds": ["POLICY-121110", "POLICY-121120"]
    }
    ```
    """

    class_name: Literal["EpManagePolicyActionsPushConfigPost"] = Field(
        default="EpManagePolicyActionsPushConfigPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyPushConfigEndpointParams = Field(
        default_factory=PolicyPushConfigEndpointParams,
        description="Query parameters: clusterName only (no ticketId)",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        base = self._action_path("pushConfig")
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# POST /fabrics/{fabricName}/policyActions/remove
# ============================================================================


class EpManagePolicyActionsRemovePost(_EpManagePolicyActionsBase):
    """
    # Summary

    ND Manage Policy Actions — Remove Endpoint

    ## Description

    Remove (permanently delete) policies in bulk.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyActions/remove

    ## Verb

    - POST

    ## Usage

    ```python
    ep = EpManagePolicyActionsRemovePost()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    ```

    ## Request Body Example

    ```json
    {
        "policyIds": ["POLICY-121110", "POLICY-121120"]
    }
    ```
    """

    class_name: Literal["EpManagePolicyActionsRemovePost"] = Field(
        default="EpManagePolicyActionsRemovePost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyActionMutationEndpointParams = Field(
        default_factory=PolicyActionMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        base = self._action_path("remove")
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
