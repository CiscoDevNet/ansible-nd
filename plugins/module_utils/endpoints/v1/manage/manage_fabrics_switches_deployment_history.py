# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage per-switch deployment-history endpoint model.

## Endpoints

- `GET /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/deploymentHistory` - Deployer history of a switch
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
    SwitchSerialNumberMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class ManageDeploymentHistoryEndpointParams(ClusterNameMixin, FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """
    # Summary

    Query parameters of the per-switch deployment-history endpoint: a Lucene `filter` (for example `entityName:port-channel120`),
    `sort` (for example `completeTimestamp:desc`), `max` and `offset` pagination, and `clusterName`. Values are percent-encoded,
    so an interface name with `/` or `.` in the filter survives intact.

    ## Raises

    None
    """

    sort: str | None = Field(default=None, min_length=1, description="Sort field and direction, e.g. `completeTimestamp:desc`")


class EpManageFabricsSwitchesDeploymentHistoryGet(FabricNameMixin, SwitchSerialNumberMixin, NDEndpointBaseModel):
    """
    # Summary

    Get the deployment history of a switch: one `deploymentRecords[]` entry per deploy, carrying the entity it targeted (`entityName`,
    `entityType`), its `status`, timestamps, and the CLI lines pushed (`configCommandResponses[].command`).

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/deploymentHistory`
    - Verb: GET

    ## Raises

    ### ValueError

    - Via `path` if `fabric_name` or `switch_sn` is not set.
    """

    class_name: Literal["EpManageFabricsSwitchesDeploymentHistoryGet"] = Field(
        default="EpManageFabricsSwitchesDeploymentHistoryGet", frozen=True, description="Class name for backward compatibility"
    )
    endpoint_params: ManageDeploymentHistoryEndpointParams = Field(
        default_factory=ManageDeploymentHistoryEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path. Each path-segment value is percent-encoded with `safe=""`; the query string is appended only when a
        parameter is set.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        - If `switch_sn` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self.switch_sn is None:
            raise ValueError(f"{type(self).__name__}.path: switch_sn must be set before accessing path.")
        base_path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "switches", quote(self.switch_sn, safe=""), "deploymentHistory")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET
