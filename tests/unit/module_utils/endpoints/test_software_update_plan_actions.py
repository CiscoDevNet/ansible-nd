# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for software_update_plan_actions.py

Tests the ND Manage Fabric Software Management switch-centric action endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.software_update_plan_actions import (
    EpFabricSoftwareUpdatePlanAttachGroup,
    EpFabricSoftwareUpdatePlanDetachGroup,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test: EpFabricSoftwareUpdatePlanAttachGroup
# =============================================================================


def test_ep_software_update_plan_actions_00010():
    """
    # Summary

    Verify EpFabricSoftwareUpdatePlanAttachGroup basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST
    - fabric_name defaults to None

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanAttachGroup.__init__()
    - EpFabricSoftwareUpdatePlanAttachGroup.verb
    - EpFabricSoftwareUpdatePlanAttachGroup.class_name
    """
    with does_not_raise():
        instance = EpFabricSoftwareUpdatePlanAttachGroup()
    assert instance.class_name == "EpFabricSoftwareUpdatePlanAttachGroup"
    assert instance.verb == HttpVerbEnum.POST
    assert instance.fabric_name is None


def test_ep_software_update_plan_actions_00020():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name is not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanAttachGroup.path
    """
    instance = EpFabricSoftwareUpdatePlanAttachGroup()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_software_update_plan_actions_00030():
    """
    # Summary

    Verify path returns the correct attachGroup action URL.

    ## Test

    - fabric_name is set
    - path returns /api/v1/manage/fabrics/SITE1/softwareUpdatePlan/actions/attachGroup

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanAttachGroup.path
    """
    with does_not_raise():
        instance = EpFabricSoftwareUpdatePlanAttachGroup()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/softwareUpdatePlan/actions/attachGroup"


def test_ep_software_update_plan_actions_00040():
    """
    # Summary

    Verify fabric_name is percent-encoded in the attachGroup path.

    ## Test

    - fabric_name = "fab/odd"
    - path encodes the slash

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanAttachGroup.path
    """
    instance = EpFabricSoftwareUpdatePlanAttachGroup()
    instance.fabric_name = "fab/odd"
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/softwareUpdatePlan/actions/attachGroup"


def test_ep_software_update_plan_actions_00050():
    """
    # Summary

    Verify fabric_name="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting fabric_name to empty string raises ValueError

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanAttachGroup.__init__()
    """
    with pytest.raises(ValueError):
        EpFabricSoftwareUpdatePlanAttachGroup(fabric_name="")


# =============================================================================
# Test: EpFabricSoftwareUpdatePlanDetachGroup
# =============================================================================


def test_ep_software_update_plan_actions_00100():
    """
    # Summary

    Verify EpFabricSoftwareUpdatePlanDetachGroup basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST
    - fabric_name defaults to None

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanDetachGroup.__init__()
    - EpFabricSoftwareUpdatePlanDetachGroup.verb
    - EpFabricSoftwareUpdatePlanDetachGroup.class_name
    """
    with does_not_raise():
        instance = EpFabricSoftwareUpdatePlanDetachGroup()
    assert instance.class_name == "EpFabricSoftwareUpdatePlanDetachGroup"
    assert instance.verb == HttpVerbEnum.POST
    assert instance.fabric_name is None


def test_ep_software_update_plan_actions_00110():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name is not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanDetachGroup.path
    """
    instance = EpFabricSoftwareUpdatePlanDetachGroup()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_software_update_plan_actions_00120():
    """
    # Summary

    Verify path returns the correct detachGroup action URL.

    ## Test

    - fabric_name is set
    - path returns /api/v1/manage/fabrics/SITE1/softwareUpdatePlan/actions/detachGroup

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanDetachGroup.path
    """
    with does_not_raise():
        instance = EpFabricSoftwareUpdatePlanDetachGroup()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/softwareUpdatePlan/actions/detachGroup"


def test_ep_software_update_plan_actions_00130():
    """
    # Summary

    Verify fabric_name is percent-encoded in the detachGroup path.

    ## Test

    - fabric_name = "fab/odd"
    - path encodes the slash

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanDetachGroup.path
    """
    instance = EpFabricSoftwareUpdatePlanDetachGroup()
    instance.fabric_name = "fab/odd"
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/softwareUpdatePlan/actions/detachGroup"


def test_ep_software_update_plan_actions_00140():
    """
    # Summary

    Verify fabric_name="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting fabric_name to empty string raises ValueError

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanDetachGroup.__init__()
    """
    with pytest.raises(ValueError):
        EpFabricSoftwareUpdatePlanDetachGroup(fabric_name="")


# =============================================================================
# Test: Cross-class
# =============================================================================


def test_ep_software_update_plan_actions_00200():
    """
    # Summary

    Verify attach/detach endpoints are both POST with distinct action paths.

    ## Test

    - Both classes with the same fabric_name produce distinct paths
    - Both have verb POST

    ## Classes and Methods

    - EpFabricSoftwareUpdatePlanAttachGroup.path
    - EpFabricSoftwareUpdatePlanDetachGroup.path
    """
    with does_not_raise():
        attach = EpFabricSoftwareUpdatePlanAttachGroup(fabric_name="SITE1")
        detach = EpFabricSoftwareUpdatePlanDetachGroup(fabric_name="SITE1")

    assert attach.path == "/api/v1/manage/fabrics/SITE1/softwareUpdatePlan/actions/attachGroup"
    assert detach.path == "/api/v1/manage/fabrics/SITE1/softwareUpdatePlan/actions/detachGroup"
    assert attach.path != detach.path
    assert attach.verb == HttpVerbEnum.POST
    assert detach.verb == HttpVerbEnum.POST
