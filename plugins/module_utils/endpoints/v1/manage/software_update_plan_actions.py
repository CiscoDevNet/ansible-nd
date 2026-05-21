# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Software Management switch-centric action endpoint models.

These endpoints back the GUI's switch-centric update-group flow. Unlike the group-centric
`updateGroups` CRUD endpoints, they are ghost-safe by construction: `attachGroup` requires at least
one switch, and `detachGroup` auto-deletes a group server-side once its last switch is removed.

## Endpoints

- `EpFabricSoftwareUpdatePlanAttachGroup` - Create an update group and assign switches to it
  (POST /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/attachGroup)
- `EpFabricSoftwareUpdatePlanDetachGroup` - Detach switches from an update group
  (POST /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/detachGroup)
- `EpFabricSoftwareUpdatePlanPropose` - Auto-assign update groups fabric-wide by algorithm
  (POST /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/propose)
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class EpFabricSoftwareUpdatePlanAttachGroup(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Create an update group and assign switches to it (switch-centric, ghost-safe).

    - Path: `/api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/attachGroup`
    - Verb: POST
    - Body: `{"attachUpdateGroups": [{"updateGroupName": "...", "switchIds": ["..."], "forceCreated": false}]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpFabricSoftwareUpdatePlanAttachGroup"] = Field(
        default="EpFabricSoftwareUpdatePlanAttachGroup", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the attachGroup action endpoint path. `fabric_name` is percent-encoded with `safe=""`.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "softwareUpdatePlan", "actions", "attachGroup")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST


class EpFabricSoftwareUpdatePlanDetachGroup(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Detach switches from an update group (switch-centric). Removing a group's last switch
    auto-deletes the group server-side.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/detachGroup`
    - Verb: POST
    - Body: `{"detachUpdateGroups": [{"updateGroupName": "...", "switchIds": ["..."]}]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpFabricSoftwareUpdatePlanDetachGroup"] = Field(
        default="EpFabricSoftwareUpdatePlanDetachGroup", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the detachGroup action endpoint path. `fabric_name` is percent-encoded with `safe=""`.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "softwareUpdatePlan", "actions", "detachGroup")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST


class EpFabricSoftwareUpdatePlanPropose(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Auto-assign update groups fabric-wide (the GUI "Auto-generate groups" action).

    ND generates the update groups itself based on the requested algorithm and applies the result
    immediately - it is not a preview.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/propose`
    - Verb: POST
    - Body: `{"algorithm": "roleBased"}`  # or "evenOdd"

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpFabricSoftwareUpdatePlanPropose"] = Field(
        default="EpFabricSoftwareUpdatePlanPropose", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the propose action endpoint path. `fabric_name` is percent-encoded with `safe=""`.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "softwareUpdatePlan", "actions", "propose")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST
