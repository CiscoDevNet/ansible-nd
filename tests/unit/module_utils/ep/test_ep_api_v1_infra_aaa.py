# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ep_api_v1_infra_aaa.py

Tests the ND Infra AAA endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.v1.ep_infra_aaa import (
    EpInfraAaaLocalUsersDelete,
    EpInfraAaaLocalUsersGet,
    EpInfraAaaLocalUsersPost,
    EpInfraAaaLocalUsersPut,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: EpInfraAaaLocalUsersGet
# =============================================================================


def test_ep_api_v1_infra_aaa_00010():
    """
    # Summary

    Verify EpInfraAaaLocalUsersGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpInfraAaaLocalUsersGet.__init__()
    - EpInfraAaaLocalUsersGet.verb
    - EpInfraAaaLocalUsersGet.class_name
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersGet()
    assert instance.class_name == "EpInfraAaaLocalUsersGet"
    assert instance.verb == HttpVerbEnum.GET


def test_ep_api_v1_infra_aaa_00020():
    """
    # Summary

    Verify EpInfraAaaLocalUsersGet path without login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers" when login_id is None

    ## Classes and Methods

    - EpInfraAaaLocalUsersGet.path
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersGet()
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers"


def test_ep_api_v1_infra_aaa_00030():
    """
    # Summary

    Verify EpInfraAaaLocalUsersGet path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpInfraAaaLocalUsersGet.path
    - EpInfraAaaLocalUsersGet.login_id
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersGet()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


def test_ep_api_v1_infra_aaa_00040():
    """
    # Summary

    Verify EpInfraAaaLocalUsersGet login_id can be set at instantiation

    ## Test

    - login_id can be provided during instantiation

    ## Classes and Methods

    - EpInfraAaaLocalUsersGet.__init__()
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersGet(login_id="testuser")
    assert instance.login_id == "testuser"
    assert instance.path == "/api/v1/infra/aaa/localUsers/testuser"


# =============================================================================
# Test: EpInfraAaaLocalUsersPost
# =============================================================================


def test_ep_api_v1_infra_aaa_00100():
    """
    # Summary

    Verify EpInfraAaaLocalUsersPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpInfraAaaLocalUsersPost.__init__()
    - EpInfraAaaLocalUsersPost.verb
    - EpInfraAaaLocalUsersPost.class_name
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersPost()
    assert instance.class_name == "EpInfraAaaLocalUsersPost"
    assert instance.verb == HttpVerbEnum.POST


def test_ep_api_v1_infra_aaa_00110():
    """
    # Summary

    Verify EpInfraAaaLocalUsersPost path

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers" for POST

    ## Classes and Methods

    - EpInfraAaaLocalUsersPost.path
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersPost()
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers"


def test_ep_api_v1_infra_aaa_00120():
    """
    # Summary

    Verify EpInfraAaaLocalUsersPost path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpInfraAaaLocalUsersPost.path
    - EpInfraAaaLocalUsersPost.login_id
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersPost()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


# =============================================================================
# Test: EpInfraAaaLocalUsersPut
# =============================================================================


def test_ep_api_v1_infra_aaa_00200():
    """
    # Summary

    Verify EpInfraAaaLocalUsersPut basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpInfraAaaLocalUsersPut.__init__()
    - EpInfraAaaLocalUsersPut.verb
    - EpInfraAaaLocalUsersPut.class_name
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersPut()
    assert instance.class_name == "EpInfraAaaLocalUsersPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_ep_api_v1_infra_aaa_00210():
    """
    # Summary

    Verify EpInfraAaaLocalUsersPut path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpInfraAaaLocalUsersPut.path
    - EpInfraAaaLocalUsersPut.login_id
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersPut()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


def test_ep_api_v1_infra_aaa_00220():
    """
    # Summary

    Verify EpInfraAaaLocalUsersPut with complex login_id

    ## Test

    - login_id with special characters is handled correctly

    ## Classes and Methods

    - EpInfraAaaLocalUsersPut.path
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersPut(login_id="user-name_123")
    assert instance.path == "/api/v1/infra/aaa/localUsers/user-name_123"


# =============================================================================
# Test: EpInfraAaaLocalUsersDelete
# =============================================================================


def test_ep_api_v1_infra_aaa_00300():
    """
    # Summary

    Verify EpInfraAaaLocalUsersDelete basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is DELETE

    ## Classes and Methods

    - EpInfraAaaLocalUsersDelete.__init__()
    - EpInfraAaaLocalUsersDelete.verb
    - EpInfraAaaLocalUsersDelete.class_name
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersDelete()
    assert instance.class_name == "EpInfraAaaLocalUsersDelete"
    assert instance.verb == HttpVerbEnum.DELETE


def test_ep_api_v1_infra_aaa_00310():
    """
    # Summary

    Verify EpInfraAaaLocalUsersDelete path with login_id

    ## Test

    - path returns "/api/v1/infra/aaa/localUsers/admin" when login_id is set

    ## Classes and Methods

    - EpInfraAaaLocalUsersDelete.path
    - EpInfraAaaLocalUsersDelete.login_id
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersDelete()
        instance.login_id = "admin"
        result = instance.path
    assert result == "/api/v1/infra/aaa/localUsers/admin"


def test_ep_api_v1_infra_aaa_00320():
    """
    # Summary

    Verify EpInfraAaaLocalUsersDelete without login_id

    ## Test

    - path returns base path when login_id is None

    ## Classes and Methods

    - EpInfraAaaLocalUsersDelete.path
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersDelete()
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

    - EpInfraAaaLocalUsersGet
    - EpInfraAaaLocalUsersPost
    - EpInfraAaaLocalUsersPut
    - EpInfraAaaLocalUsersDelete
    """
    login_id = "testuser"

    with does_not_raise():
        get_ep = EpInfraAaaLocalUsersGet(login_id=login_id)
        post_ep = EpInfraAaaLocalUsersPost(login_id=login_id)
        put_ep = EpInfraAaaLocalUsersPut(login_id=login_id)
        delete_ep = EpInfraAaaLocalUsersDelete(login_id=login_id)

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

    - EpInfraAaaLocalUsersGet.__init__()
    """
    with pytest.raises(ValueError):
        EpInfraAaaLocalUsersGet(login_id="")


def test_ep_api_v1_infra_aaa_00510():
    """
    # Summary

    Verify login_id can be None

    ## Test

    - login_id accepts None as valid value

    ## Classes and Methods

    - EpInfraAaaLocalUsersGet.__init__()
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersGet(login_id=None)
    assert instance.login_id is None


def test_ep_api_v1_infra_aaa_00520():
    """
    # Summary

    Verify login_id can be modified after instantiation

    ## Test

    - login_id can be changed after object creation

    ## Classes and Methods

    - EpInfraAaaLocalUsersGet.login_id
    """
    with does_not_raise():
        instance = EpInfraAaaLocalUsersGet()
        assert instance.login_id is None
        instance.login_id = "newuser"
        assert instance.login_id == "newuser"
        assert instance.path == "/api/v1/infra/aaa/localUsers/newuser"
