# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_credentials_switches.py

Tests the ND Manage Credentials Switches endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_credentials_switches import (
    CredentialsSwitchesEndpointParams,
    EpManageCredentialsSwitchesPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: CredentialsSwitchesEndpointParams
# =============================================================================


def test_endpoints_api_v1_manage_credentials_switches_00010():
    """
    # Summary

    Verify CredentialsSwitchesEndpointParams default values

    ## Test

    - ticket_id defaults to None

    ## Classes and Methods

    - CredentialsSwitchesEndpointParams.__init__()
    """
    with does_not_raise():
        params = CredentialsSwitchesEndpointParams()
    assert params.ticket_id is None


def test_endpoints_api_v1_manage_credentials_switches_00020():
    """
    # Summary

    Verify CredentialsSwitchesEndpointParams ticket_id can be set

    ## Test

    - ticket_id can be set to a string value

    ## Classes and Methods

    - CredentialsSwitchesEndpointParams.__init__()
    """
    with does_not_raise():
        params = CredentialsSwitchesEndpointParams(ticket_id="CHG12345")
    assert params.ticket_id == "CHG12345"


def test_endpoints_api_v1_manage_credentials_switches_00030():
    """
    # Summary

    Verify CredentialsSwitchesEndpointParams generates correct query string

    ## Test

    - to_query_string() returns ticketId=CHG12345 when ticket_id is set

    ## Classes and Methods

    - CredentialsSwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = CredentialsSwitchesEndpointParams(ticket_id="CHG12345")
        result = params.to_query_string()
    assert result == "ticketId=CHG12345"


def test_endpoints_api_v1_manage_credentials_switches_00040():
    """
    # Summary

    Verify CredentialsSwitchesEndpointParams returns empty query string when no params set

    ## Test

    - to_query_string() returns empty string when ticket_id is not set

    ## Classes and Methods

    - CredentialsSwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = CredentialsSwitchesEndpointParams()
        result = params.to_query_string()
    assert result == ""


# =============================================================================
# Test: EpManageCredentialsSwitchesPost
# =============================================================================


def test_endpoints_api_v1_manage_credentials_switches_00100():
    """
    # Summary

    Verify EpManageCredentialsSwitchesPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageCredentialsSwitchesPost.__init__()
    - EpManageCredentialsSwitchesPost.class_name
    - EpManageCredentialsSwitchesPost.verb
    """
    with does_not_raise():
        instance = EpManageCredentialsSwitchesPost()
    assert instance.class_name == "EpManageCredentialsSwitchesPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_credentials_switches_00110():
    """
    # Summary

    Verify EpManageCredentialsSwitchesPost path without query params

    ## Test

    - path returns the correct base endpoint path

    ## Classes and Methods

    - EpManageCredentialsSwitchesPost.path
    """
    with does_not_raise():
        instance = EpManageCredentialsSwitchesPost()
        result = instance.path
    assert result == "/api/v1/manage/credentials/switches"


def test_endpoints_api_v1_manage_credentials_switches_00120():
    """
    # Summary

    Verify EpManageCredentialsSwitchesPost path with ticket_id

    ## Test

    - path includes ticketId in query string when set

    ## Classes and Methods

    - EpManageCredentialsSwitchesPost.path
    """
    with does_not_raise():
        instance = EpManageCredentialsSwitchesPost()
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result == "/api/v1/manage/credentials/switches?ticketId=CHG12345"
