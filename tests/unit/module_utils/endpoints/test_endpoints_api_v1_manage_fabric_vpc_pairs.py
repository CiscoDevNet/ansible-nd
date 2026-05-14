# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric_vpc_pairs.py

Tests the fabric-wide vPC pairs list endpoint.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_vpc_pairs import (
    EpManageFabricVpcPairsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


def test_ep_manage_fabric_vpc_pairs_00010():
    """
    # Summary

    Verify EpManageFabricVpcPairsListGet basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricVpcPairsListGet.__init__()
    - EpManageFabricVpcPairsListGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricVpcPairsListGet()
    assert instance.class_name == "EpManageFabricVpcPairsListGet"
    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None


def test_ep_manage_fabric_vpc_pairs_00020():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageFabricVpcPairsListGet.path
    """
    instance = EpManageFabricVpcPairsListGet()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_manage_fabric_vpc_pairs_00030():
    """
    # Summary

    Verify path returns correct URL when fabric_name is set.

    ## Test

    - fabric_name set
    - path returns /api/v1/manage/fabrics/{fabric_name}/vpcPairs

    ## Classes and Methods

    - EpManageFabricVpcPairsListGet.path
    """
    with does_not_raise():
        instance = EpManageFabricVpcPairsListGet()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/vpcPairs"


def test_ep_manage_fabric_vpc_pairs_00040():
    """
    # Summary

    Verify endpoint has only FabricNameMixin (no switch_sn / interface_name).

    ## Test

    - Accessing switch_sn or interface_name returns False from hasattr

    ## Classes and Methods

    - EpManageFabricVpcPairsListGet.__init__()
    """
    instance = EpManageFabricVpcPairsListGet()
    assert not hasattr(instance, "switch_sn")
    assert not hasattr(instance, "interface_name")


def test_ep_manage_fabric_vpc_pairs_00050():
    """
    # Summary

    Verify fabric_name="" raises ValueError (Pydantic min_length=1).

    ## Test

    - Setting fabric_name to empty string raises ValueError

    ## Classes and Methods

    - EpManageFabricVpcPairsListGet.__init__()
    """
    with pytest.raises(ValueError):
        EpManageFabricVpcPairsListGet(fabric_name="")


def test_ep_manage_fabric_vpc_pairs_00060():
    """
    # Summary

    Verify fabric_name with reserved characters is percent-encoded in the path.

    ## Test

    - fabric_name = "fab/odd"
    - path encodes the slash

    ## Classes and Methods

    - EpManageFabricVpcPairsListGet.path
    """
    instance = EpManageFabricVpcPairsListGet()
    instance.fabric_name = "fab/odd"
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/vpcPairs"
