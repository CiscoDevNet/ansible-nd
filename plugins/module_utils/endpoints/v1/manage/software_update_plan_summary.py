# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Software Management software update plan summary endpoint model.

## Endpoints

- `EpFabricSoftwareUpdatePlanSummary` - Software update plan summary for a fabric
  (GET /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/summary)
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpFabricSoftwareUpdatePlanSummary(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Software update plan summary for a fabric.

    Returns the fabric-wide software update plan: every update group with its per-switch stage /
    validate / install status. Used to drive the `nd_fabric_prepare_update` pre-flight role check
    and to poll for staging completion.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/summary`
    - Verb: GET

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpFabricSoftwareUpdatePlanSummary"] = Field(
        default="EpFabricSoftwareUpdatePlanSummary", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the software update plan summary endpoint path. `fabric_name` is percent-encoded with `safe=""`.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "softwareUpdatePlan", "summary")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.GET`.

        ## Raises

        None
        """
        return HttpVerbEnum.GET
