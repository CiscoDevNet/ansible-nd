# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ep_api_v1_infra_aaa.py

Tests the ND Infra AAA endpoint classes
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.ep_api_v1_infra_aaa import (
    EpApiV1InfraAaaLocalUsersDelete,
    EpApiV1InfraAaaLocalUsersGet,
    EpApiV1InfraAaaLocalUsersPost,
    EpApiV1InfraAaaLocalUsersPut,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: EpApiV1InfraAaaLocalUsersGet
# =============================================================================


def test_ep_api_v1_infra_aaa_00010():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet.__init__()
    - EpApiV1InfraAaaLocalUsersGet.verb
    - EpApiV1InfraAaaLocalUsersGet.class_name
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersGet()
    assert instance.class_name == "EpApiV1InfraAaaLocalUsersGet"
    assert instance.verb == HttpVerbEnum.GET


def test_ep_api_v1_infra_aaa_00020():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersGet path without login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers" when login_id is None

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet.path
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersGet()
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers"


def test_ep_api_v1_infra_aaa_00030():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersGet path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet.path
    - EpApiV1InfraAaaLocalUsersGet.login_id
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersGet()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


def test_ep_api_v1_infra_aaa_00040():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersGet login_id can be set at instantiation

    ## Test

    - login_id can be provided during instantiation

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet.__init__()
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersGet(login_id="testuser")
    assert instance.login_id == "testuser"
    assert instance.path == "/api/v1/infra/aaa/localUsers/testuser"


# =============================================================================
# Test: EpApiV1InfraAaaLocalUsersPost
# =============================================================================


def test_ep_api_v1_infra_aaa_00100():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersPost.__init__()
    - EpApiV1InfraAaaLocalUsersPost.verb
    - EpApiV1InfraAaaLocalUsersPost.class_name
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersPost()
    assert instance.class_name == "EpApiV1InfraAaaLocalUsersPost"
    assert instance.verb == HttpVerbEnum.POST


def test_ep_api_v1_infra_aaa_00110():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersPost path

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers" for POST

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersPost.path
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersPost()
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers"


def test_ep_api_v1_infra_aaa_00120():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersPost path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersPost.path
    - EpApiV1InfraAaaLocalUsersPost.login_id
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersPost()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


# =============================================================================
# Test: EpApiV1InfraAaaLocalUsersPut
# =============================================================================


def test_ep_api_v1_infra_aaa_00200():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersPut basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersPut.__init__()
    - EpApiV1InfraAaaLocalUsersPut.verb
    - EpApiV1InfraAaaLocalUsersPut.class_name
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersPut()
    assert instance.class_name == "EpApiV1InfraAaaLocalUsersPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_ep_api_v1_infra_aaa_00210():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersPut path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersPut.path
    - EpApiV1InfraAaaLocalUsersPut.login_id
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersPut()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


def test_ep_api_v1_infra_aaa_00220():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersPut with complex login_id

    ## Test

    - login_id with special characters is handled correctly

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersPut.path
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersPut(login_id="user-name_123")
    assert instance.path == "/api/v1/infra/aaa/localUsers/user-name_123"


# =============================================================================
# Test: EpApiV1InfraAaaLocalUsersDelete
# =============================================================================


def test_ep_api_v1_infra_aaa_00300():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersDelete basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is DELETE

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersDelete.__init__()
    - EpApiV1InfraAaaLocalUsersDelete.verb
    - EpApiV1InfraAaaLocalUsersDelete.class_name
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersDelete()
    assert instance.class_name == "EpApiV1InfraAaaLocalUsersDelete"
    assert instance.verb == HttpVerbEnum.DELETE


def test_ep_api_v1_infra_aaa_00310():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersDelete path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersDelete.path
    - EpApiV1InfraAaaLocalUsersDelete.login_id
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersDelete()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


def test_ep_api_v1_infra_aaa_00320():
    """
    # Summary

    Verify EpApiV1InfraAaaLocalUsersDelete without login_id

    ## Test

    - path returns base path when login_id is None

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersDelete.path
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersDelete()
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers"


# =============================================================================
# Test: All HTTP methods on same endpoint
# =============================================================================


def test_ep_api_v1_infra_aaa_00400():
    """
    # Summary

    Verify all HTTP methods work correctly on same resource

    ## Test

    - GET, POST, PUT, DELETE all return correct paths for same login_id

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet
    - EpApiV1InfraAaaLocalUsersPost
    - EpApiV1InfraAaaLocalUsersPut
    - EpApiV1InfraAaaLocalUsersDelete
    """
    login_id = "testuser"

    with does_not_raise():
        get_ep = EpApiV1InfraAaaLocalUsersGet(login_id=login_id)
        post_ep = EpApiV1InfraAaaLocalUsersPost(login_id=login_id)
        put_ep = EpApiV1InfraAaaLocalUsersPut(login_id=login_id)
        delete_ep = EpApiV1InfraAaaLocalUsersDelete(login_id=login_id)

    # All should have same path when login_id is set
    expected_path = "/api/v1/infra/aaa/localUsers/testuser"
    assert get_ep.path == expected_path
    assert post_ep.path == expected_path
    assert put_ep.path == expected_path
    assert delete_ep.path == expected_path

    # But different verbs
    assert get_ep.verb == HttpVerbEnum.GET
    assert post_ep.verb == HttpVerbEnum.POST
    assert put_ep.verb == HttpVerbEnum.PUT
    assert delete_ep.verb == HttpVerbEnum.DELETE


# =============================================================================
# Test: Pydantic validation
# =============================================================================


def test_ep_api_v1_infra_aaa_00500():
    """
    # Summary

    Verify Pydantic validation for login_id

    ## Test

    - Empty string is rejected for login_id (min_length=1)

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet.__init__()
    """
    with pytest.raises(ValueError):
        EpApiV1InfraAaaLocalUsersGet(login_id="")


def test_ep_api_v1_infra_aaa_00510():
    """
    # Summary

    Verify login_id can be None

    ## Test

    - login_id accepts None as valid value

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet.__init__()
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersGet(login_id=None)
    assert instance.login_id is None


def test_ep_api_v1_infra_aaa_00520():
    """
    # Summary

    Verify login_id can be modified after instantiation

    ## Test

    - login_id can be changed after object creation

    ## Classes and Methods

    - EpApiV1InfraAaaLocalUsersGet.login_id
    """
    with does_not_raise():
        instance = EpApiV1InfraAaaLocalUsersGet()
        assert instance.login_id is None
        instance.login_id = "newuser"
        assert instance.login_id == "newuser"
        assert instance.path == "/api/v1/infra/aaa/localUsers/newuser"
