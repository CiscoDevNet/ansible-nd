# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_interfaces.py

Tests the ND Manage Interfaces endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDeploy,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
    EpManageInterfacesRemove,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test: EpManageInterfacesGet
# =============================================================================


def test_ep_manage_interfaces_00010():
    """
    # Summary

    Verify EpManageInterfacesGet basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET
    - All mixin params default to None

    ## Classes and Methods

    - EpManageInterfacesGet.__init__()
    - EpManageInterfacesGet.verb
    - EpManageInterfacesGet.class_name
    """
    with does_not_raise():
        instance = EpManageInterfacesGet()
    assert instance.class_name == "EpManageInterfacesGet"
    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None
    assert instance.switch_sn is None
    assert instance.interface_name is None


def test_ep_manage_interfaces_00020():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name is not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesGet.path
    """
    instance = EpManageInterfacesGet()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_interfaces_00030():
    """
    # Summary

    Verify path raises ValueError when switch_sn is None (fabric_name set).

    ## Test

    - fabric_name is set, switch_sn is not
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesGet.path
    """
    instance = EpManageInterfacesGet()
    instance.fabric_name = "fab1"
    with pytest.raises(ValueError, match="switch_sn must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_interfaces_00040():
    """
    # Summary

    Verify path raises ValueError when interface_name is None (fabric_name + switch_sn set).

    ## Test

    - fabric_name and switch_sn are set, interface_name is not
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesGet.path
    """
    instance = EpManageInterfacesGet()
    instance.fabric_name = "fab1"
    instance.switch_sn = "SN123"
    with pytest.raises(ValueError, match="interface_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_interfaces_00050():
    """
    # Summary

    Verify path returns correct URL with all params set.

    ## Test

    - All params set
    - path returns expected URL

    ## Classes and Methods

    - EpManageInterfacesGet.path
    """
    with does_not_raise():
        instance = EpManageInterfacesGet()
        instance.fabric_name = "fab1"
        instance.switch_sn = "SN123"
        instance.interface_name = "loopback0"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/switches/SN123/interfaces/loopback0"


def test_ep_manage_interfaces_00060():
    """
    # Summary

    Verify set_identifiers sets interface_name.

    ## Test

    - set_identifiers("loopback0") sets interface_name

    ## Classes and Methods

    - EpManageInterfacesGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpManageInterfacesGet()
        instance.set_identifiers("loopback0")
    assert instance.interface_name == "loopback0"


def test_ep_manage_interfaces_00070():
    """
    # Summary

    Verify set_identifiers(None) sets interface_name to None.

    ## Test

    - set_identifiers(None) sets interface_name to None

    ## Classes and Methods

    - EpManageInterfacesGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpManageInterfacesGet()
        instance.interface_name = "loopback0"
        instance.set_identifiers(None)
    assert instance.interface_name is None


# =============================================================================
# Test: EpManageInterfacesListGet
# =============================================================================


def test_ep_manage_interfaces_00100():
    """
    # Summary

    Verify EpManageInterfacesListGet basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageInterfacesListGet.__init__()
    - EpManageInterfacesListGet.verb
    - EpManageInterfacesListGet.class_name
    """
    with does_not_raise():
        instance = EpManageInterfacesListGet()
    assert instance.class_name == "EpManageInterfacesListGet"
    assert instance.verb == HttpVerbEnum.GET


def test_ep_manage_interfaces_00110():
    """
    # Summary

    Verify path succeeds without interface_name (_require_interface_name=False).

    ## Test

    - fabric_name and switch_sn set, interface_name not set
    - path returns URL ending at /interfaces

    ## Classes and Methods

    - EpManageInterfacesListGet.path
    """
    with does_not_raise():
        instance = EpManageInterfacesListGet()
        instance.fabric_name = "fab1"
        instance.switch_sn = "SN123"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/switches/SN123/interfaces"


def test_ep_manage_interfaces_00120():
    """
    # Summary

    Verify path appends interface_name when optionally set.

    ## Test

    - All params set including optional interface_name
    - path includes interface_name segment

    ## Classes and Methods

    - EpManageInterfacesListGet.path
    """
    with does_not_raise():
        instance = EpManageInterfacesListGet()
        instance.fabric_name = "fab1"
        instance.switch_sn = "SN123"
        instance.interface_name = "loopback0"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/switches/SN123/interfaces/loopback0"


def test_ep_manage_interfaces_00130():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesListGet.path
    """
    instance = EpManageInterfacesListGet()
    instance.switch_sn = "SN123"
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


# =============================================================================
# Test: EpManageInterfacesPost
# =============================================================================


def test_ep_manage_interfaces_00200():
    """
    # Summary

    Verify EpManageInterfacesPost basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageInterfacesPost.__init__()
    - EpManageInterfacesPost.verb
    - EpManageInterfacesPost.class_name
    """
    with does_not_raise():
        instance = EpManageInterfacesPost()
    assert instance.class_name == "EpManageInterfacesPost"
    assert instance.verb == HttpVerbEnum.POST


def test_ep_manage_interfaces_00210():
    """
    # Summary

    Verify path succeeds without interface_name.

    ## Test

    - fabric_name and switch_sn set
    - path returns URL ending at /interfaces

    ## Classes and Methods

    - EpManageInterfacesPost.path
    """
    with does_not_raise():
        instance = EpManageInterfacesPost()
        instance.fabric_name = "fab1"
        instance.switch_sn = "SN123"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/switches/SN123/interfaces"


def test_ep_manage_interfaces_00220():
    """
    # Summary

    Verify path raises ValueError when switch_sn is None.

    ## Test

    - fabric_name set, switch_sn not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesPost.path
    """
    instance = EpManageInterfacesPost()
    instance.fabric_name = "fab1"
    with pytest.raises(ValueError, match="switch_sn must be set"):
        result = instance.path  # pylint: disable=unused-variable


# =============================================================================
# Test: EpManageInterfacesPut
# =============================================================================


def test_ep_manage_interfaces_00300():
    """
    # Summary

    Verify EpManageInterfacesPut basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpManageInterfacesPut.__init__()
    - EpManageInterfacesPut.verb
    - EpManageInterfacesPut.class_name
    """
    with does_not_raise():
        instance = EpManageInterfacesPut()
    assert instance.class_name == "EpManageInterfacesPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_ep_manage_interfaces_00310():
    """
    # Summary

    Verify path requires interface_name — ValueError when missing.

    ## Test

    - fabric_name and switch_sn set, interface_name not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesPut.path
    """
    instance = EpManageInterfacesPut()
    instance.fabric_name = "fab1"
    instance.switch_sn = "SN123"
    with pytest.raises(ValueError, match="interface_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_interfaces_00320():
    """
    # Summary

    Verify path correct with all params.

    ## Test

    - All params set
    - path returns expected URL

    ## Classes and Methods

    - EpManageInterfacesPut.path
    """
    with does_not_raise():
        instance = EpManageInterfacesPut()
        instance.fabric_name = "fab1"
        instance.switch_sn = "SN123"
        instance.interface_name = "loopback0"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/switches/SN123/interfaces/loopback0"


# =============================================================================
# Test: EpManageInterfacesDeploy
# =============================================================================


def test_ep_manage_interfaces_00500():
    """
    # Summary

    Verify EpManageInterfacesDeploy basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageInterfacesDeploy.__init__()
    - EpManageInterfacesDeploy.verb
    - EpManageInterfacesDeploy.class_name
    """
    with does_not_raise():
        instance = EpManageInterfacesDeploy()
    assert instance.class_name == "EpManageInterfacesDeploy"
    assert instance.verb == HttpVerbEnum.POST


def test_ep_manage_interfaces_00510():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesDeploy.path
    """
    instance = EpManageInterfacesDeploy()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_interfaces_00520():
    """
    # Summary

    Verify path returns correct deploy URL.

    ## Test

    - fabric_name set
    - path returns /api/v1/manage/fabrics/fab1/interfaceActions/deploy

    ## Classes and Methods

    - EpManageInterfacesDeploy.path
    """
    with does_not_raise():
        instance = EpManageInterfacesDeploy()
        instance.fabric_name = "fab1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/interfaceActions/deploy"


def test_ep_manage_interfaces_00530():
    """
    # Summary

    Verify Deploy does NOT have switch_sn or interface_name attributes.

    ## Test

    - EpManageInterfacesDeploy only has FabricNameMixin
    - Accessing switch_sn or interface_name raises AttributeError

    ## Classes and Methods

    - EpManageInterfacesDeploy.__init__()
    """
    instance = EpManageInterfacesDeploy()
    assert not hasattr(instance, "switch_sn")
    assert not hasattr(instance, "interface_name")


# =============================================================================
# Test: EpManageInterfacesRemove
# =============================================================================


def test_ep_manage_interfaces_00540():
    """
    # Summary

    Verify EpManageInterfacesRemove basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageInterfacesRemove.__init__()
    - EpManageInterfacesRemove.verb
    - EpManageInterfacesRemove.class_name
    """
    with does_not_raise():
        instance = EpManageInterfacesRemove()
    assert instance.class_name == "EpManageInterfacesRemove"
    assert instance.verb == HttpVerbEnum.POST


def test_ep_manage_interfaces_00550():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageInterfacesRemove.path
    """
    instance = EpManageInterfacesRemove()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_interfaces_00560():
    """
    # Summary

    Verify path returns correct remove URL.

    ## Test

    - fabric_name set
    - path returns /api/v1/manage/fabrics/fab1/interfaceActions/remove

    ## Classes and Methods

    - EpManageInterfacesRemove.path
    """
    with does_not_raise():
        instance = EpManageInterfacesRemove()
        instance.fabric_name = "fab1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/interfaceActions/remove"


def test_ep_manage_interfaces_00570():
    """
    # Summary

    Verify Remove does NOT have switch_sn or interface_name attributes.

    ## Test

    - EpManageInterfacesRemove only has FabricNameMixin
    - Accessing switch_sn or interface_name raises AttributeError

    ## Classes and Methods

    - EpManageInterfacesRemove.__init__()
    """
    instance = EpManageInterfacesRemove()
    assert not hasattr(instance, "switch_sn")
    assert not hasattr(instance, "interface_name")


# =============================================================================
# Test: Cross-class
# =============================================================================


def test_ep_manage_interfaces_00600():
    """
    # Summary

    Verify Get/Put produce same path for identical params; different verbs.

    ## Test

    - Both classes with same params produce identical path
    - Each has a distinct verb

    ## Classes and Methods

    - EpManageInterfacesGet.path
    - EpManageInterfacesPut.path
    """
    params = {"fabric_name": "fab1", "switch_sn": "SN123", "interface_name": "loopback0"}
    expected_path = "/api/v1/manage/fabrics/fab1/switches/SN123/interfaces/loopback0"

    with does_not_raise():
        get_ep = EpManageInterfacesGet(**params)
        put_ep = EpManageInterfacesPut(**params)

    assert get_ep.path == expected_path
    assert put_ep.path == expected_path

    assert get_ep.verb == HttpVerbEnum.GET
    assert put_ep.verb == HttpVerbEnum.PUT


def test_ep_manage_interfaces_00610():
    """
    # Summary

    Verify fabric_name="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting fabric_name to empty string raises ValueError

    ## Classes and Methods

    - EpManageInterfacesGet.__init__()
    """
    with pytest.raises(ValueError):
        EpManageInterfacesGet(fabric_name="")


def test_ep_manage_interfaces_00620():
    """
    # Summary

    Verify switch_sn="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting switch_sn to empty string raises ValueError

    ## Classes and Methods

    - EpManageInterfacesGet.__init__()
    """
    with pytest.raises(ValueError):
        EpManageInterfacesGet(switch_sn="")


def test_ep_manage_interfaces_00630():
    """
    # Summary

    Verify interface_name="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting interface_name to empty string raises ValueError

    ## Classes and Methods

    - EpManageInterfacesGet.__init__()
    """
    with pytest.raises(ValueError):
        EpManageInterfacesGet(interface_name="")
