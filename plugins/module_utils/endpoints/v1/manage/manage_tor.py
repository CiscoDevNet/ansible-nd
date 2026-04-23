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
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


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

    @property
    def path(self) -> str:
        return self._build_path("accessAssociations")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET
