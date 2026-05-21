# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the `softwareUpdatePlan/summary` response models.

Tests:
- Parsing a full summary response (modeled on a live ND 4.2.1 capture)
- Field aliasing (camelCase wire keys -> snake_case attributes)
- Nested `UpdateGroupStatusModel`, `SwitchStageStatusModel`, `UpdateGroupWarningModel`
- Tolerance of missing optional fields and unknown wire keys
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,line-too-long,invalid-name

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_prepare_update.software_update_plan_summary import (
    SoftwareUpdatePlanSummaryModel,
    SwitchStageStatusModel,
    UpdateGroupStatusModel,
    UpdateGroupWarningModel,
)

# =============================================================================
# Test data - modeled on a live ND 4.2.1 softwareUpdatePlan/summary response
# =============================================================================

SAMPLE_SUMMARY_RESPONSE = {
    "softwareUpdateSummary": {"fabricName": "SITE1", "updatePlanStatus": "Ready To Install", "totalSwitches": 5},
    "tableHeaders": {"executions": ["parallel", "serial"]},
    "updateGroups": [
        {
            "updateGroupName": "SITE1_N9K_leaf",
            "updateGroupStatus": "none",
            "updateType": "none",
            "stageValidatePercentage": 2,
            "switchCount": 2,
            "warnings": [{"message": "Upgrading the selected switches would impact all [leaf] from the fabric [SITE1].", "switchName": "SITE1_N9K_leaf"}],
            "updateGroupSwitches": [
                {
                    "switchId": "9ASNKH8T9DJ",
                    "switchName": "S1_LE1",
                    "switchRole": "leaf",
                    "switchManagementIP": "192.168.12.151",
                    "switchVersion": "10.6(2)",
                    "selectedVersion": "10.3.8",
                    "imageStagedStatus": "none",
                    "imageValidatedStatus": "none",
                    "switchStageValidatePercentage": 0,
                },
                {
                    "switchId": "9SJKCSQND07",
                    "switchName": "S1_LE2",
                    "switchRole": "leaf",
                    "switchManagementIP": "192.168.12.155",
                    "switchVersion": "10.6(2)",
                    "selectedVersion": "10.3.8",
                    "imageStagedStatus": "inProgress",
                    "imageValidatedStatus": "none",
                    "switchStageValidatePercentage": 35,
                },
            ],
        }
    ],
}


# =============================================================================
# Test: SoftwareUpdatePlanSummaryModel
# =============================================================================


def test_fabric_prepare_update_00010() -> None:
    """
    # Summary

    Verify a full summary response parses into one update group with two member switches, and that
    the unmodeled `softwareUpdateSummary` / `tableHeaders` blocks are ignored.

    ## Classes and Methods

    - SoftwareUpdatePlanSummaryModel.from_response()
    """
    summary = SoftwareUpdatePlanSummaryModel.from_response(SAMPLE_SUMMARY_RESPONSE)

    assert isinstance(summary, SoftwareUpdatePlanSummaryModel)
    assert summary.update_groups is not None
    assert len(summary.update_groups) == 1

    group = summary.update_groups[0]
    assert isinstance(group, UpdateGroupStatusModel)
    assert group.update_group_name == "SITE1_N9K_leaf"
    assert group.update_group_status == "none"
    assert group.update_type == "none"
    assert group.stage_validate_percentage == 2
    assert group.switch_count == 2
    assert group.update_group_switches is not None
    assert len(group.update_group_switches) == 2

    assert not hasattr(summary, "software_update_summary")
    assert not hasattr(summary, "table_headers")


def test_fabric_prepare_update_00020() -> None:
    """
    # Summary

    Verify per-switch camelCase wire keys map onto the snake_case `SwitchStageStatusModel` fields.

    ## Classes and Methods

    - SwitchStageStatusModel
    """
    summary = SoftwareUpdatePlanSummaryModel.from_response(SAMPLE_SUMMARY_RESPONSE)
    switch = summary.update_groups[0].update_group_switches[0]

    assert isinstance(switch, SwitchStageStatusModel)
    assert switch.switch_id == "9ASNKH8T9DJ"
    assert switch.switch_name == "S1_LE1"
    assert switch.switch_role == "leaf"
    assert switch.switch_management_ip == "192.168.12.151"
    assert switch.switch_version == "10.6(2)"
    assert switch.selected_version == "10.3.8"
    assert switch.image_staged_status == "none"
    assert switch.image_validated_status == "none"
    assert switch.switch_stage_validate_percentage == 0

    in_progress = summary.update_groups[0].update_group_switches[1]
    assert in_progress.image_staged_status == "inProgress"
    assert in_progress.switch_stage_validate_percentage == 35


def test_fabric_prepare_update_00030() -> None:
    """
    # Summary

    Verify per-group advisory warnings parse into `UpdateGroupWarningModel` items.

    ## Classes and Methods

    - UpdateGroupWarningModel
    """
    summary = SoftwareUpdatePlanSummaryModel.from_response(SAMPLE_SUMMARY_RESPONSE)
    warnings = summary.update_groups[0].warnings

    assert warnings is not None
    assert len(warnings) == 1
    assert isinstance(warnings[0], UpdateGroupWarningModel)
    assert warnings[0].switch_name == "SITE1_N9K_leaf"
    assert warnings[0].message is not None
    assert "would impact all [leaf]" in warnings[0].message


def test_fabric_prepare_update_00040() -> None:
    """
    # Summary

    Verify an empty response yields a model with `update_groups` unset (None).

    ## Classes and Methods

    - SoftwareUpdatePlanSummaryModel.from_response()
    """
    summary = SoftwareUpdatePlanSummaryModel.from_response({})

    assert summary.update_groups is None


def test_fabric_prepare_update_00050() -> None:
    """
    # Summary

    Verify a sparse update group (only `updateGroupName`) parses with missing optional fields as
    None, and that unknown wire keys are ignored rather than raising.

    ## Classes and Methods

    - UpdateGroupStatusModel
    """
    summary = SoftwareUpdatePlanSummaryModel.from_response({"updateGroups": [{"updateGroupName": "sparse_group", "someFutureKey": "ignored"}]})

    assert summary.update_groups is not None
    group = summary.update_groups[0]
    assert group.update_group_name == "sparse_group"
    assert group.update_group_status is None
    assert group.stage_validate_percentage is None
    assert group.update_group_switches is None
    assert group.warnings is None
    assert not hasattr(group, "some_future_key")
