# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_switches_pending_config.py

Tests the ND Manage switch pending-configuration endpoint class.
"""

# pylint: disable=unused-import
# pylint: disable=redefined-outer-name
# pylint: disable=protected-access
# pylint: disable=unused-argument
# pylint: disable=unused-variable
# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=too-many-lines

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_pending_config import (
    EpManageFabricsSwitchesPendingConfigGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_ep_manage_fabrics_switches_pending_config_00010():
    """
    # Summary

    Verify the path and verb of `EpManageFabricsSwitchesPendingConfigGet`.

    ## Test

    - `fabric_name` and `switch_sn` are set
    - `path` is `/api/v1/manage/fabrics/CAMPUS1/switches/CAT9KV1701/pendingConfig`
    - `verb` is GET

    ## Classes and Methods

    - EpManageFabricsSwitchesPendingConfigGet.path
    - EpManageFabricsSwitchesPendingConfigGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesPendingConfigGet()
        instance.fabric_name = "CAMPUS1"
        instance.switch_sn = "CAT9KV1701"
        result = instance.path
    assert instance.class_name == "EpManageFabricsSwitchesPendingConfigGet"
    assert result == "/api/v1/manage/fabrics/CAMPUS1/switches/CAT9KV1701/pendingConfig"
    assert instance.verb == HttpVerbEnum.GET


@pytest.mark.parametrize(
    "fabric_name, switch_sn, match",
    [
        (None, "CAT9KV1701", r"fabric_name must be set"),
        ("CAMPUS1", None, r"switch_sn must be set"),
    ],
)
def test_ep_manage_fabrics_switches_pending_config_00020(fabric_name, switch_sn, match):
    """
    # Summary

    Verify `path` raises `ValueError` until both `fabric_name` and `switch_sn` are set.

    ## Test

    - One of the two path parameters is left unset
    - Accessing `path` raises `ValueError` naming the missing parameter

    ## Classes and Methods

    - EpManageFabricsSwitchesPendingConfigGet.path
    """
    instance = EpManageFabricsSwitchesPendingConfigGet()
    if fabric_name is not None:
        instance.fabric_name = fabric_name
    if switch_sn is not None:
        instance.switch_sn = switch_sn
    with pytest.raises(ValueError, match=match):
        result = instance.path  # pylint: disable=pointless-statement
