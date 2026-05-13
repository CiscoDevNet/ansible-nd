# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Switch vPC Pair endpoint models.

This module contains endpoint definitions for per-switch vPC pair operations
in the ND Manage API.

## Endpoints

- `EpManageFabricSwitchVpcPairGet` - Retrieve the vPC pair config attached to a switch
  (GET /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/vpcPair)
- `EpManageFabricSwitchVpcPairPut` - Create, update, or unpair a vPC pair on a switch
  (PUT /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/vpcPair)
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, SwitchSerialNumberMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpManageFabricSwitchVpcPairBase(FabricNameMixin, SwitchSerialNumberMixin, NDEndpointBaseModel):
    """
    # Summary

    Base class for the per-switch vPC pair endpoint. The path resolves to
    `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/vpcPair`. Subclasses define the HTTP verb.

    ## Raises

    ### ValueError

    - If `fabric_name` is not set before accessing `path`.
    - If `switch_sn` is not set before accessing `path`.
    """

    @property
    def path(self) -> str:
        """
        # Summary

        Build the per-switch vPC pair endpoint path. Path-segment values are percent-encoded with `safe=""` for parity
        with the manage_interfaces endpoint family.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        - If `switch_sn` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self.switch_sn is None:
            raise ValueError(f"{type(self).__name__}.path: switch_sn must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "switches", quote(self.switch_sn, safe=""), "vpcPair")

    def set_identifiers(self, identifier: IdentifierKey = None):
        """
        # Summary

        Set `switch_sn` from `identifier`. `fabric_name` must be set separately via `_configure_endpoint` in the orchestrator.

        ## Raises

        None
        """
        self.switch_sn = identifier


class EpManageFabricSwitchVpcPairGet(_EpManageFabricSwitchVpcPairBase):
    """
    # Summary

    Retrieve the vPC pair configuration attached to a switch.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/vpcPair`
    - Verb: GET

    ## Raises

    ### ValueError

    - Via inherited `path` property if `fabric_name` or `switch_sn` is not set.
    """

    class_name: Literal["EpManageFabricSwitchVpcPairGet"] = Field(
        default="EpManageFabricSwitchVpcPairGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET


class EpManageFabricSwitchVpcPairPut(_EpManageFabricSwitchVpcPairBase):
    """
    # Summary

    Create, update, or unpair a vPC pair on a switch. The body carries `vpcAction: "pair" | "unPair"` plus pair-detail
    fields (peer, domain ID, keepalive, role priority, etc.).

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/vpcPair`
    - Verb: PUT

    ## Raises

    ### ValueError

    - Via inherited `path` property if `fabric_name` or `switch_sn` is not set.
    """

    class_name: Literal["EpManageFabricSwitchVpcPairPut"] = Field(
        default="EpManageFabricSwitchVpcPairPut", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.PUT`.

        ## Raises

        None
        """
        return HttpVerbEnum.PUT
