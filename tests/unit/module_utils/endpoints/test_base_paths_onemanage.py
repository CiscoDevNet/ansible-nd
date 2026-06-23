# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for base_paths_onemanage.py.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def test_base_paths_onemanage_00010():
    """
    # Summary

    Verify API constant equals the onemanage root.
    """
    with does_not_raise():
        result = BasePath.API
    assert result == "/appcenter/cisco/ndfc/api/v1/onemanage"


def test_base_paths_onemanage_00100():
    """
    # Summary

    Verify path() with no segments returns the onemanage root.
    """
    with does_not_raise():
        result = BasePath.path()
    assert result == "/appcenter/cisco/ndfc/api/v1/onemanage"


def test_base_paths_onemanage_00110():
    """
    # Summary

    Verify path() supports the ND proxy prefix.
    """
    with does_not_raise():
        result = BasePath.path("fabrics", proxy_path="/onemanage")
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/fabrics"


def test_base_paths_onemanage_00120():
    """
    # Summary

    Verify top_down_fabrics() builds onemanage fabric resource paths.
    """
    with does_not_raise():
        result = BasePath.top_down_fabrics("MCFG_FAB", "vrfs", proxy_path="/onemanage")
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/top-down/fabrics/MCFG_FAB/vrfs"
