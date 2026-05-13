# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Switch Actions Deploy endpoint.

This module contains the fabric-level switch deploy endpoint used to push pending
switch-scoped intent (e.g. vPC pair configuration) to the wire.

## Endpoints

- `EpManageFabricSwitchActionsDeployPost` - Deploy switch-level configuration changes
  (POST /api/v1/manage/fabrics/{fabric_name}/switchActions/deploy)
  Body: `{"switchIds": ["serial1", "serial2", ...]}`
  Response: 207 multi-status with per-switch `status` enum.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpManageFabricSwitchActionsDeployPost(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Deploy queued switch-level configuration to the wire. Used by `nd_vpc_pair` to push pair intent created via
    `EpManageFabricSwitchVpcPairPut`. The 207 multi-status response carries per-switch results under the `switchIds`
    key (note: not `results` — that key is reserved for `interfaceActions/remove`).

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switchActions/deploy`
    - Verb: POST
    - Body: `{"switchIds": ["serial1", "serial2"]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpManageFabricSwitchActionsDeployPost"] = Field(
        default="EpManageFabricSwitchActionsDeployPost", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the fabric switch-actions deploy path.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "switchActions", "deploy")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST
