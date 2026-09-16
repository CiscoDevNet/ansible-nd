# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Links endpoint models.

## Endpoints

- `EpManageLinksListGet` - List the links of a fabric (GET /api/v1/manage/links?fabricName={fabric_name})
"""

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import ClusterNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class ManageLinksListEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """
    # Summary

    Query parameters for `GET /api/v1/manage/links`. Unlike the per-fabric interface endpoints, the fabric is a QUERY parameter here
    (`fabricName`, required by the API), not a path segment. `switch_id` narrows the listing to links touching one switch; `max` /
    `offset` page through large fabrics (the response carries `meta.counts.remaining`).

    ## Raises

    None
    """

    fabric_name: str | None = Field(default=None, min_length=1, max_length=64, description="Fabric whose links are listed (required by the API)")
    switch_id: str | None = Field(default=None, min_length=1, description="Restrict to links touching this switch serial number / ID")
    max: int | None = Field(default=None, ge=1, description="Number of records to return")
    offset: int | None = Field(default=None, ge=0, description="Number of records to skip for pagination")


class EpManageLinksListGet(NDEndpointBaseModel):
    """
    # Summary

    List the links of a fabric.

    ## Description

    Returns every link ND knows for the fabric named in `endpoint_params.fabric_name`: fabric (intra-fabric) links, inter-fabric links
    such as VRF-Lite and multisite underlay links, and discovered-only neighbor links. Links carrying an ND link policy
    (`configData.policyType`, e.g. `numbered`, `ebgpVrfLite`, `multisiteUnderlay`) are fabric-owned intent; the interface orchestrators
    use this listing to refuse overwriting their member interfaces. Links from other fabrics that terminate on this fabric's switches
    are included (lab-verified 2026-09-03: an ISN -> SITE1 VRF-Lite link appears in SITE1's listing).

    ## Path

    - `/api/v1/manage/links?fabricName={fabric_name}`
    - `/api/v1/manage/links?fabricName={fabric_name}&switchId={switch_id}&max={max}&offset={offset}`

    ## Verb

    - GET

    ## Raises

    ### ValueError

    - If `endpoint_params.fabric_name` is not set when accessing `path`.

    ## Usage

    ```python
    ep = EpManageLinksListGet()
    ep.endpoint_params.fabric_name = "SITE1"
    rest_send.path = ep.path  # /api/v1/manage/links?fabricName=SITE1
    rest_send.verb = ep.verb  # HttpVerbEnum.GET
    ```
    """

    class_name: Literal["EpManageLinksListGet"] = Field(default="EpManageLinksListGet", frozen=True, description="Class name for backward compatibility")
    endpoint_params: ManageLinksListEndpointParams = Field(default_factory=ManageLinksListEndpointParams, description="Endpoint-specific query parameters")

    @property
    def path(self) -> str:
        """
        # Summary

        Build the links listing path with its query string.

        ## Raises

        ### ValueError

        - If `endpoint_params.fabric_name` is not set.
        """
        if self.endpoint_params.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: endpoint_params.fabric_name must be set before accessing path.")
        return f"{BasePath.path('links')}?{self.endpoint_params.to_query_string()}"

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET
