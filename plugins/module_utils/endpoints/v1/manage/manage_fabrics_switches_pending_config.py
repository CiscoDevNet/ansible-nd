# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage switch pending-configuration endpoint model.

## Endpoints

- `GET /api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/pendingConfig` - Pending configuration for a switch
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, SwitchSerialNumberMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpManageFabricsSwitchesPendingConfigGet(FabricNameMixin, SwitchSerialNumberMixin, NDEndpointBaseModel):
    """
    # Summary

    Get the pending configuration of a switch: the CLI lines ND would push on the next deploy (`pendingConfigs[]`).

    - Path: `/api/v1/manage/fabrics/{fabric_name}/switches/{switch_sn}/pendingConfig`
    - Verb: GET

    ## Raises

    ### ValueError

    - Via `path` if `fabric_name` or `switch_sn` is not set.
    """

    class_name: Literal["EpManageFabricsSwitchesPendingConfigGet"] = Field(
        default="EpManageFabricsSwitchesPendingConfigGet", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path. Each path-segment value is percent-encoded with `safe=""`.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        - If `switch_sn` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self.switch_sn is None:
            raise ValueError(f"{type(self).__name__}.path: switch_sn must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "switches", quote(self.switch_sn, safe=""), "pendingConfig")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET
