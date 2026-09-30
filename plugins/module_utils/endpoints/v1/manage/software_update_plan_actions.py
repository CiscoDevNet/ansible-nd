# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Software Management switch-centric action endpoint models.

These endpoints back the GUI's switch-centric update-group flow. Unlike the group-centric
`updateGroups` CRUD endpoints, they are ghost-safe by construction: `attachGroup` requires at least
one switch, and `detachGroup` auto-deletes a group server-side once its last switch is removed.

All three endpoints share the same shape - a POST to
`/api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/{action}` - so the path and verb
live on a common `_EpFabricSoftwareUpdatePlanActionBase`; each concrete endpoint just sets its
`_action` segment.

## Endpoints

- `EpFabricSoftwareUpdatePlanAttachGroup` - Create an update group and assign switches to it
  (POST /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/attachGroup)
- `EpFabricSoftwareUpdatePlanDetachGroup` - Detach switches from an update group
  (POST /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/detachGroup)
- `EpFabricSoftwareUpdatePlanPropose` - Auto-assign update groups fabric-wide by algorithm
  (POST /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/propose)
- `EpFabricSoftwareUpdatePlanStage` - Stage and validate images for update groups
  (POST /api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/stage)
"""

from __future__ import annotations

from typing import ClassVar, Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class _EpFabricSoftwareUpdatePlanActionBase(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Base class for the switch-centric Fabric Software Management action endpoints. Every action is a
    POST to `/api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/{_action}`; subclasses
    set the `_action` segment, the `verb`, and their own `class_name`.

    `verb` is intentionally left abstract here (rather than defined as POST on the base) so the
    endpoint metaclass keeps treating this base as abstract and does not require it to carry a
    `class_name` field - mirroring the `_EpFabricUpdateGroupBase` pattern in this package.

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    # Action path segment (e.g. "attachGroup"). Overridden per subclass. Accessed via `self._action`
    # (instance access) - the leading-underscore ClassVar trap that bites Pydantic v2 on Python 3.10
    # only fires on CLASS-level access, which this never does.
    _action: ClassVar[str] = ""

    @property
    def path(self) -> str:
        """
        # Summary

        Build the action endpoint path. `fabric_name` is percent-encoded with `safe=""`.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "softwareUpdatePlan", "actions", self._action)


class EpFabricSoftwareUpdatePlanAttachGroup(_EpFabricSoftwareUpdatePlanActionBase):
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

    _action: ClassVar[str] = "attachGroup"

    class_name: Literal["EpFabricSoftwareUpdatePlanAttachGroup"] = Field(
        default="EpFabricSoftwareUpdatePlanAttachGroup", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpFabricSoftwareUpdatePlanDetachGroup(_EpFabricSoftwareUpdatePlanActionBase):
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

    _action: ClassVar[str] = "detachGroup"

    class_name: Literal["EpFabricSoftwareUpdatePlanDetachGroup"] = Field(
        default="EpFabricSoftwareUpdatePlanDetachGroup", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpFabricSoftwareUpdatePlanPropose(_EpFabricSoftwareUpdatePlanActionBase):
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

    _action: ClassVar[str] = "propose"

    class_name: Literal["EpFabricSoftwareUpdatePlanPropose"] = Field(
        default="EpFabricSoftwareUpdatePlanPropose", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpFabricSoftwareUpdatePlanStage(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Stage and validate images for one or more update groups (the GUI "Prepare" action).

    ND copies the configured image to each switch's bootflash, runs `show install all impact`, and
    generates pre-reports. The action is asynchronous: it returns HTTP 202 with an empty body, and
    progress is observed via the `softwareUpdatePlan/summary` endpoint.

    - Path: `/api/v1/manage/fabrics/{fabric_name}/softwareUpdatePlan/actions/stage`
    - Verb: POST
    - Body: `{"updateGroupNames": ["...", "..."]}`

    ## Raises

    ### ValueError

    - Via `path` property if `fabric_name` is not set.
    """

    class_name: Literal["EpFabricSoftwareUpdatePlanStage"] = Field(
        default="EpFabricSoftwareUpdatePlanStage", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the stage action endpoint path. `fabric_name` is percent-encoded with `safe=""`.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "softwareUpdatePlan", "actions", "stage")

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST
