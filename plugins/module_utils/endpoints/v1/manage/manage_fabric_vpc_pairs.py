# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric vPC Pairs endpoint models.

This module contains the fabric-wide vPC pairs list endpoint.

## Endpoints

- `EpManageFabricVpcPairsListGet` - List all vPC pairs in a fabric
  (GET /api/v1/manage/fabrics/{fabric_name}/vpcPairs)

The fabric-wide list reflects deployed/operational pairs only; per-switch intent state
is exposed by `EpManageFabricSwitchVpcPairGet` in `manage_fabric_switch_vpc_pair.py`.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpManageFabricVpcPairsListGet(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    List all vPC pairs in a fabric. Response shape: `{"vpcPairs": [...], "meta": {"counts": {...}}}`.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/vpcPairs`
    - Verb: GET

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpManageFabricVpcPairsListGet"] = Field(
        default="EpManageFabricVpcPairsListGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the fabric-wide vPC pairs list path.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "vpcPairs")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET
