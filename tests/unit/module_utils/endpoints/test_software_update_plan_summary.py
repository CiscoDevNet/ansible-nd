# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for software_update_plan_summary.py

Tests the ND Manage Fabric Software Management software update plan summary endpoint, including the
optional `updateGroupName` query parameter used to scope a poll to a single update group.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.software_update_plan_summary import (
    EpFabricSoftwareUpdatePlanSummary,
    SoftwareUpdatePlanSummaryEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


def test_ep_software_update_plan_summary_00010():
    """
    # Summary

    Verify EpFabricSoftwareUpdatePlanSummary basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET
    - fabric_name defaults to None

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanSummary.__init__()
    - EpFabricSoftwareUpdatePlanSummary.verb
    - EpFabricSoftwareUpdatePlanSummary.class_name
    """
    with does_not_raise():
        instance = EpFabricSoftwareUpdatePlanSummary()
    assert instance.class_name == "EpFabricSoftwareUpdatePlanSummary"
    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None


def test_ep_software_update_plan_summary_00020():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name is not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanSummary.path
    """
    instance = EpFabricSoftwareUpdatePlanSummary()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_software_update_plan_summary_00030():
    """
    # Summary

    Verify path returns the fabric-wide summary URL with no query string when no update group is set.

    ## Test

    - fabric_name is set, update_group_name is unset
    - path returns /api/v1/manage/fabrics/SITE1/softwareUpdatePlan/summary (no `?`)

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanSummary.path
    """
    with does_not_raise():
        instance = EpFabricSoftwareUpdatePlanSummary()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/softwareUpdatePlan/summary"


def test_ep_software_update_plan_summary_00040():
    """
    # Summary

    Verify fabric_name is percent-encoded in the summary path.

    ## Test

    - fabric_name = "fab/odd"
    - path encodes the slash

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanSummary.path
    """
    instance = EpFabricSoftwareUpdatePlanSummary()
    instance.fabric_name = "fab/odd"
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/softwareUpdatePlan/summary"


def test_ep_software_update_plan_summary_00050():
    """
    # Summary

    Verify setting `update_group_name` scopes the summary path with the `updateGroupName` query
    parameter (snake_case -> camelCase conversion is automatic).

    ## Test

    - fabric_name and endpoint_params.update_group_name are set
    - path appends `?updateGroupName=<name>`

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanSummary.path
    - SoftwareUpdatePlanSummaryEndpointParams
    """
    with does_not_raise():
        instance = EpFabricSoftwareUpdatePlanSummary()
        instance.fabric_name = "SITE1"
        instance.endpoint_params.update_group_name = "SITE1_N9K_leaf"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/softwareUpdatePlan/summary?updateGroupName=SITE1_N9K_leaf"


def test_ep_software_update_plan_summary_00060():
    """
    # Summary

    Verify an empty `update_group_name` is rejected by the endpoint-params model (`min_length=1`),
    so a blank scope cannot silently render an `updateGroupName=` query string.

    ## Test

    - Constructing the params model with update_group_name="" raises ValueError

    ## Classes and Methods

    - SoftwareUpdatePlanSummaryEndpointParams
    """
    with pytest.raises(ValueError):
        SoftwareUpdatePlanSummaryEndpointParams(update_group_name="")
