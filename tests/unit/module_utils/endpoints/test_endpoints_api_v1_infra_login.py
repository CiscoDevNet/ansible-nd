# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for infra_login.py

Tests the ND Infra Login endpoint class
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra_login import (
    EpInfraLoginPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def test_endpoints_api_v1_infra_login_00010():
    """
    # Summary

    Verify EpInfraLoginPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpInfraLoginPost.__init__()
    - EpInfraLoginPost.class_name
    - EpInfraLoginPost.verb
    """
    with does_not_raise():
        instance = EpInfraLoginPost()
    assert instance.class_name == "EpInfraLoginPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_infra_login_00020():
    """
    # Summary

    Verify EpInfraLoginPost path

    ## Test

    - path returns /api/v1/infra/login

    ## Classes and Methods

    - EpInfraLoginPost.path
    """
    with does_not_raise():
        instance = EpInfraLoginPost()
        result = instance.path
    assert result == "/api/v1/infra/login"
