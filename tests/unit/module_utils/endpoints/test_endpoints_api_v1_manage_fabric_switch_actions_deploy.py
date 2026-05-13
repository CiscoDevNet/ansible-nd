# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric_switch_actions_deploy.py

Tests the fabric-level switch deploy endpoint.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_switch_actions_deploy import (
    EpManageFabricSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


def test_ep_manage_fabric_switch_actions_deploy_00010():
    """
    # Summary

    Verify EpManageFabricSwitchActionsDeployPost basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricSwitchActionsDeployPost.__init__()
    - EpManageFabricSwitchActionsDeployPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricSwitchActionsDeployPost()
    assert instance.class_name == "EpManageFabricSwitchActionsDeployPost"
    assert instance.verb == HttpVerbEnum.POST
    assert instance.fabric_name is None


def test_ep_manage_fabric_switch_actions_deploy_00020():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageFabricSwitchActionsDeployPost.path
    """
    instance = EpManageFabricSwitchActionsDeployPost()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_fabric_switch_actions_deploy_00030():
    """
    # Summary

    Verify path returns the fabric switch-actions deploy URL.

    ## Test

    - fabric_name set
    - path returns /api/v1/manage/fabrics/{fabric_name}/switchActions/deploy

    ## Classes and Methods

    - EpManageFabricSwitchActionsDeployPost.path
    """
    with does_not_raise():
        instance = EpManageFabricSwitchActionsDeployPost()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/switchActions/deploy"


def test_ep_manage_fabric_switch_actions_deploy_00040():
    """
    # Summary

    Verify endpoint has only FabricNameMixin (no switch_sn / interface_name).

    ## Test

    - Accessing switch_sn or interface_name returns False from hasattr

    ## Classes and Methods

    - EpManageFabricSwitchActionsDeployPost.__init__()
    """
    instance = EpManageFabricSwitchActionsDeployPost()
    assert not hasattr(instance, "switch_sn")
    assert not hasattr(instance, "interface_name")


def test_ep_manage_fabric_switch_actions_deploy_00050():
    """
    # Summary

    Verify fabric_name="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting fabric_name to empty string raises ValueError

    ## Classes and Methods

    - EpManageFabricSwitchActionsDeployPost.__init__()
    """
    with pytest.raises(ValueError):
        EpManageFabricSwitchActionsDeployPost(fabric_name="")


def test_ep_manage_fabric_switch_actions_deploy_00060():
    """
    # Summary

    Verify fabric_name with reserved characters is percent-encoded in the path.

    ## Test

    - fabric_name = "fab/odd"
    - path encodes the slash

    ## Classes and Methods

    - EpManageFabricSwitchActionsDeployPost.path
    """
    instance = EpManageFabricSwitchActionsDeployPost()
    instance.fabric_name = "fab/odd"
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/switchActions/deploy"
