# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric_switch_vpc_pair.py

Tests the per-switch vPC pair endpoint classes (GET, PUT).
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_switch_vpc_pair import (
    EpManageFabricSwitchVpcPairGet,
    EpManageFabricSwitchVpcPairPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test: EpManageFabricSwitchVpcPairGet
# =============================================================================


def test_ep_manage_fabric_switch_vpc_pair_00010():
    """
    # Summary

    Verify EpManageFabricSwitchVpcPairGet basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET
    - All mixin params default to None

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.__init__()
    - EpManageFabricSwitchVpcPairGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricSwitchVpcPairGet()
    assert instance.class_name == "EpManageFabricSwitchVpcPairGet"
    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None
    assert instance.switch_sn is None


def test_ep_manage_fabric_switch_vpc_pair_00020():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name is not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.path
    """
    instance = EpManageFabricSwitchVpcPairGet()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_fabric_switch_vpc_pair_00030():
    """
    # Summary

    Verify path raises ValueError when switch_sn is None.

    ## Test

    - fabric_name is set, switch_sn is not
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.path
    """
    instance = EpManageFabricSwitchVpcPairGet()
    instance.fabric_name = "SITE1"
    with pytest.raises(ValueError, match="switch_sn must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_fabric_switch_vpc_pair_00040():
    """
    # Summary

    Verify path returns correct URL with all params set.

    ## Test

    - fabric_name and switch_sn set
    - path ends with /vpcPair literal segment

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.path
    """
    with does_not_raise():
        instance = EpManageFabricSwitchVpcPairGet()
        instance.fabric_name = "SITE1"
        instance.switch_sn = "9ASNKH8T9DJ"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/switches/9ASNKH8T9DJ/vpcPair"


def test_ep_manage_fabric_switch_vpc_pair_00050():
    """
    # Summary

    Verify set_identifiers sets switch_sn.

    ## Test

    - set_identifiers("9ASNKH8T9DJ") sets switch_sn

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpManageFabricSwitchVpcPairGet()
        instance.set_identifiers("9ASNKH8T9DJ")
    assert instance.switch_sn == "9ASNKH8T9DJ"


def test_ep_manage_fabric_switch_vpc_pair_00060():
    """
    # Summary

    Verify set_identifiers(None) clears switch_sn.

    ## Test

    - set_identifiers(None) sets switch_sn to None

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpManageFabricSwitchVpcPairGet()
        instance.switch_sn = "9ASNKH8T9DJ"
        instance.set_identifiers(None)
    assert instance.switch_sn is None


# =============================================================================
# Test: EpManageFabricSwitchVpcPairPut
# =============================================================================


def test_ep_manage_fabric_switch_vpc_pair_00100():
    """
    # Summary

    Verify EpManageFabricSwitchVpcPairPut basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairPut.__init__()
    - EpManageFabricSwitchVpcPairPut.verb
    """
    with does_not_raise():
        instance = EpManageFabricSwitchVpcPairPut()
    assert instance.class_name == "EpManageFabricSwitchVpcPairPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_ep_manage_fabric_switch_vpc_pair_00110():
    """
    # Summary

    Verify Put produces same path as Get for identical params.

    ## Test

    - Put and Get with same identifiers produce identical URLs
    - Verbs differ

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairPut.path
    - EpManageFabricSwitchVpcPairGet.path
    """
    params = {"fabric_name": "SITE1", "switch_sn": "9ASNKH8T9DJ"}
    expected = "/api/v1/manage/fabrics/SITE1/switches/9ASNKH8T9DJ/vpcPair"

    with does_not_raise():
        get_ep = EpManageFabricSwitchVpcPairGet(**params)
        put_ep = EpManageFabricSwitchVpcPairPut(**params)

    assert get_ep.path == expected
    assert put_ep.path == expected
    assert get_ep.verb == HttpVerbEnum.GET
    assert put_ep.verb == HttpVerbEnum.PUT


def test_ep_manage_fabric_switch_vpc_pair_00120():
    """
    # Summary

    Verify Put path raises ValueError when switch_sn is None.

    ## Test

    - fabric_name set, switch_sn missing
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairPut.path
    """
    instance = EpManageFabricSwitchVpcPairPut()
    instance.fabric_name = "SITE1"
    with pytest.raises(ValueError, match="switch_sn must be set"):
        result = instance.path  # pylint: disable=unused-variable


# =============================================================================
# Test: Validation of empty identifiers
# =============================================================================


def test_ep_manage_fabric_switch_vpc_pair_00200():
    """
    # Summary

    Verify fabric_name="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting fabric_name to empty string raises ValueError

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.__init__()
    """
    with pytest.raises(ValueError):
        EpManageFabricSwitchVpcPairGet(fabric_name="")


def test_ep_manage_fabric_switch_vpc_pair_00210():
    """
    # Summary

    Verify switch_sn="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting switch_sn to empty string raises ValueError

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.__init__()
    """
    with pytest.raises(ValueError):
        EpManageFabricSwitchVpcPairGet(switch_sn="")


# =============================================================================
# Test: URL encoding of path-segment values
# =============================================================================


def test_ep_manage_fabric_switch_vpc_pair_00300():
    """
    # Summary

    Verify slashes in fabric_name are percent-encoded in the path.

    ## Test

    - fabric_name = "fab/odd"
    - path encodes the slash

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.path
    """
    instance = EpManageFabricSwitchVpcPairGet()
    instance.fabric_name = "fab/odd"
    instance.switch_sn = "9ASNKH8T9DJ"
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/switches/9ASNKH8T9DJ/vpcPair"


def test_ep_manage_fabric_switch_vpc_pair_00310():
    """
    # Summary

    Verify alphanumeric segment values are unchanged by encoding.

    ## Test

    - All alphanumeric inputs survive untouched

    ## Classes and Methods

    - EpManageFabricSwitchVpcPairGet.path
    """
    instance = EpManageFabricSwitchVpcPairGet()
    instance.fabric_name = "SITE1"
    instance.switch_sn = "9ASNKH8T9DJ"
    assert instance.path == "/api/v1/manage/fabrics/SITE1/switches/9ASNKH8T9DJ/vpcPair"
