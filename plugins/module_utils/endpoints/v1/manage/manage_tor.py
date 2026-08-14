# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Access/ToR Association endpoint models.

Endpoints for access or ToR switch association operations
in the ND Manage API.

Endpoints:
- EpManageTorAssociatePost - Associate access/ToR switches
  (POST /api/v1/manage/fabrics/{fabricName}/accessAssociationActions/associate)
- EpManageTorDisassociatePost - Disassociate access/ToR switches
  (POST /api/v1/manage/fabrics/{fabricName}/accessAssociationActions/disassociate)
- EpManageTorAssociationsGet - List access/ToR associations
  (GET /api/v1/manage/fabrics/{fabricName}/accessAssociations)
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import ClassVar, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class TorAssociationsGetEndpointParams(EndpointQueryParams):
    """
    Endpoint-specific query parameters for the list ToR associations endpoint.

    ## Parameters

    - aggregation_or_leaf_switch_id: Optionally restrict results to associations
      on the given aggregation/leaf switch (rendered as
      ``aggregationOrLeafSwitchId``). When ``include_candidates`` is ``False``
      this is optional -- omitting it returns every existing association in the
      fabric in a single call. It is only required when ``include_candidates``
      is ``True``.
    - include_candidates: When ``False`` (default) the API returns only the
      already-configured associations with their minimal identity fields. When
      ``True`` the API also returns candidate switches, recommendations,
      remarks and resource allocations (rendered as ``includeCandidates``), and
      ``aggregation_or_leaf_switch_id`` becomes required.
    """

    aggregation_or_leaf_switch_id: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Filter associations by aggregation/leaf switch serial number",
    )
    include_candidates: bool = Field(
        default=False,
        description="Include candidate switches and recommendations in the response",
    )


class _EpManageTorBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage Access/ToR Association endpoints.

    All ToR association endpoints require a fabric_name path parameter.
    """

    _path_suffix: ClassVar[Optional[str]] = None

    def set_identifiers(self, identifier: IdentifierKey = None):
        if isinstance(identifier, tuple) and len(identifier) >= 1:
            self.fabric_name = identifier[0]
        elif isinstance(identifier, str):
            self.fabric_name = identifier

    def _build_path(self, *segments: str) -> str:
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", self.fabric_name, *segments)


class EpManageTorAssociatePost(_EpManageTorBase):
    """
    POST /api/v1/manage/fabrics/{fabricName}/accessAssociationActions/associate

    Associate access or ToR switches with aggregation/leaf switches or VPC pairs.
    Request body is an array of accessPairWithResources objects.
    """

    class_name: Literal["EpManageTorAssociatePost"] = Field(
        default="EpManageTorAssociatePost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_path("accessAssociationActions", "associate")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageTorDisassociatePost(_EpManageTorBase):
    """
    POST /api/v1/manage/fabrics/{fabricName}/accessAssociationActions/disassociate

    Disassociate access or ToR switches from aggregation/leaf switches or VPC pairs.
    Request body is an array of aggregationAccessSwitchIds objects.
    """

    class_name: Literal["EpManageTorDisassociatePost"] = Field(
        default="EpManageTorDisassociatePost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._build_path("accessAssociationActions", "disassociate")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageTorAssociationsGet(_EpManageTorBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/accessAssociations

    List access or ToR switch associations for a fabric.
    """

    class_name: Literal["EpManageTorAssociationsGet"] = Field(
        default="EpManageTorAssociationsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: TorAssociationsGetEndpointParams = Field(
        default_factory=TorAssociationsGetEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        base = self._build_path("accessAssociations")
        # includeCandidates must be sent explicitly: the ND API returns HTTP 400
        # if the query string is entirely absent, but with includeCandidates=false
        # present it returns the whole fabric's associations (aggregationOrLeafSwitchId
        # then only optionally filters). to_query_string() always renders the bool,
        # so the query string is never empty.
        query_string = self.endpoint_params.to_query_string()
        return f"{base}?{query_string}" if query_string else base

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET
