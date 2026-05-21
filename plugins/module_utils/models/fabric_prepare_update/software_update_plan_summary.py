# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Pydantic models for parsing the ND `softwareUpdatePlan/summary` response.

The summary endpoint returns the fabric-wide software update plan: every update group with its
per-switch stage / validate / install status. `nd_fabric_prepare_update` uses these models for the
pre-flight switch-role check and to poll for staging completion. The models are response-only -
they parse the wire shape and are never serialized back to ND.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class UpdateGroupWarningModel(NDNestedModel):
    """
    # Summary

    A single advisory warning ND attaches to an update group in the software update plan summary
    (for example, that upgrading the selected switches would impact every switch of a role).

    ## Raises

    None
    """

    message: str | None = Field(default=None, alias="message")
    switch_name: str | None = Field(default=None, alias="switchName")


class SwitchStageStatusModel(NDNestedModel):
    """
    # Summary

    Per-switch stage / validate status within an update group, as reported by the
    `softwareUpdatePlan/summary` endpoint.

    `image_staged_status` and `image_validated_status` are kept as free-form strings (not a
    `Literal`) so an unrecognized status from a newer ND release parses rather than raising during
    a poll. Known values: `none`, `inProgress`, `success`, `failed`, `skipped`.

    ## Raises

    None
    """

    switch_id: str | None = Field(default=None, alias="switchId")
    switch_name: str | None = Field(default=None, alias="switchName")
    switch_role: str | None = Field(default=None, alias="switchRole")
    switch_management_ip: str | None = Field(default=None, alias="switchManagementIP")
    switch_version: str | None = Field(default=None, alias="switchVersion")
    selected_version: str | None = Field(default=None, alias="selectedVersion")
    image_staged_status: str | None = Field(default=None, alias="imageStagedStatus")
    image_validated_status: str | None = Field(default=None, alias="imageValidatedStatus")
    switch_stage_validate_percentage: int | None = Field(default=None, alias="switchStageValidatePercentage")


class UpdateGroupStatusModel(NDNestedModel):
    """
    # Summary

    A single update group's status within the software update plan summary, including its member
    switches and any advisory warnings ND raises for the group.

    ## Raises

    None
    """

    update_group_name: str | None = Field(default=None, alias="updateGroupName")
    update_group_status: str | None = Field(default=None, alias="updateGroupStatus")
    update_type: str | None = Field(default=None, alias="updateType")
    stage_validate_percentage: int | None = Field(default=None, alias="stageValidatePercentage")
    switch_count: int | None = Field(default=None, alias="switchCount")
    warnings: list[UpdateGroupWarningModel] | None = Field(default=None, alias="warnings")
    update_group_switches: list[SwitchStageStatusModel] | None = Field(default=None, alias="updateGroupSwitches")


class SoftwareUpdatePlanSummaryModel(NDNestedModel):
    """
    # Summary

    Top-level parse of the `softwareUpdatePlan/summary` response. Only the `updateGroups` list is
    modeled; the `softwareUpdateSummary` and `tableHeaders` blocks are ignored (`extra="ignore"`).

    ## Raises

    None
    """

    update_groups: list[UpdateGroupStatusModel] | None = Field(default=None, alias="updateGroups")
