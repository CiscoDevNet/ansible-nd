# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Manage Config Templates endpoint models.

This module contains endpoint definitions for configuration template
operations in the ND Manage API.

Endpoints covered:
- GET /configTemplates/{templateName}/parameters - Get template parameters
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

__author__ = "L Nikhil Sri Krishna"

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
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


class ConfigTemplateEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for configTemplates endpoints.

    ## Description

    Per the ND API specification, the GET /configTemplates/{templateName}/parameters
    endpoint accepts ``clusterName`` as a query parameter.

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
# GET /configTemplates/{templateName}/parameters
# ============================================================================


class EpManageConfigTemplateParametersGet(NDEndpointBaseModel):
    """
    # Summary

    ND Manage Config Template Parameters GET Endpoint

    ## Description

    Retrieve only the parameters for a configuration template.
    Returns the ``parameters`` array without the template content.

    ## Path

    - /api/v1/manage/configTemplates/{templateName}/parameters

    ## Verb

    - GET

    ## Usage

    ```python
    ep = EpManageConfigTemplateParametersGet()
    ep.template_name = "switch_freeform"
    path = ep.path     # /api/v1/manage/configTemplates/switch_freeform/parameters
    verb = ep.verb     # GET
    ```
    """

    class_name: Literal["EpManageConfigTemplateParametersGet"] = Field(
        default="EpManageConfigTemplateParametersGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    template_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Configuration template name (e.g., switch_freeform, feature_enable)",
    )
    endpoint_params: ConfigTemplateEndpointParams = Field(
        default_factory=ConfigTemplateEndpointParams,
        description="Query parameters: clusterName",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.template_name is None:
            raise ValueError("template_name must be set before accessing path")
        base = BasePath.path("configTemplates", self.template_name, "parameters")
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
