# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_actions_config_save.py and manage_fabrics_actions_deploy.py

Tests the ND Manage fabric configSave and deploy action endpoint classes used by
ConfigActionsMixin, including fabric_name URL-encoding (issue #292).
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpFabricConfigSavePost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_actions_config_save_00100():
    """
    # Summary

    Verify EpFabricConfigSavePost path and verb.

    ## Classes and Methods

    - EpFabricConfigSavePost.path
    - EpFabricConfigSavePost.verb
    """
    with does_not_raise():
        instance = EpFabricConfigSavePost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/actions/configSave"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_actions_config_save_00110():
    """
    # Summary

    Verify EpFabricConfigSavePost raises ValueError when fabric_name is not set.

    ## Classes and Methods

    - EpFabricConfigSavePost.path
    """
    instance = EpFabricConfigSavePost()
    with pytest.raises(ValueError, match="fabric_name is required"):
        result = instance.path  # pylint: disable=unused-variable


def test_endpoints_api_v1_manage_fabrics_actions_config_save_00120():
    """
    # Summary

    Verify fabric_name is percent-encoded in EpFabricConfigSavePost.path (issue #292).

    ## Test

    - Reserved characters (``/``, space, ``#``) in fabric_name are encoded so a
      malformed request path is not produced.

    ## Classes and Methods

    - EpFabricConfigSavePost.path
    """
    with does_not_raise():
        instance = EpFabricConfigSavePost()
        instance.fabric_name = "my/fabric name#1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my%2Ffabric%20name%231/actions/configSave"


# =============================================================================
# Test: EpFabricDeployPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_actions_deploy_00100():
    """
    # Summary

    Verify EpFabricDeployPost path and verb.

    ## Classes and Methods

    - EpFabricDeployPost.path
    - EpFabricDeployPost.verb
    """
    with does_not_raise():
        instance = EpFabricDeployPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/actions/deploy"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_actions_deploy_00110():
    """
    # Summary

    Verify EpFabricDeployPost raises ValueError when fabric_name is not set.

    ## Classes and Methods

    - EpFabricDeployPost.path
    """
    instance = EpFabricDeployPost()
    with pytest.raises(ValueError, match="fabric_name is required"):
        result = instance.path  # pylint: disable=unused-variable


def test_endpoints_api_v1_manage_fabrics_actions_deploy_00120():
    """
    # Summary

    Verify fabric_name is percent-encoded in EpFabricDeployPost.path (issue #292).

    ## Test

    - Reserved characters (``/``, space, ``#``) in fabric_name are encoded so a
      malformed request path is not produced.

    ## Classes and Methods

    - EpFabricDeployPost.path
    """
    with does_not_raise():
        instance = EpFabricDeployPost()
        instance.fabric_name = "my/fabric name#1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my%2Ffabric%20name%231/actions/deploy"
