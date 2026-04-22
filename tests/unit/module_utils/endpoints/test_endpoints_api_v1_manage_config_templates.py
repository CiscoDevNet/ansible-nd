# Copyright: (c) 2026, Cisco Systems

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_config_templates.py

Tests the ND Manage Config Templates endpoint classes.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_config_templates import (
    ConfigTemplateEndpointParams,
    EpManageConfigTemplateParametersGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: ConfigTemplateEndpointParams
# =============================================================================


def test_manage_config_templates_00010():
    """
    # Summary

    Verify ConfigTemplateEndpointParams default values

    ## Test

    - cluster_name defaults to None

    ## Classes and Methods

    - ConfigTemplateEndpointParams.__init__()
    """
    with does_not_raise():
        params = ConfigTemplateEndpointParams()
    assert params.cluster_name is None


def test_manage_config_templates_00020():
    """
    # Summary

    Verify ConfigTemplateEndpointParams generates query string

    ## Test

    - to_query_string() includes clusterName when set

    ## Classes and Methods

    - ConfigTemplateEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = ConfigTemplateEndpointParams(cluster_name="cluster1")
        result = params.to_query_string()
    assert result == "clusterName=cluster1"


def test_manage_config_templates_00030():
    """
    # Summary

    Verify ConfigTemplateEndpointParams returns empty when no params set

    ## Test

    - to_query_string() returns empty string

    ## Classes and Methods

    - ConfigTemplateEndpointParams.to_query_string()
    """
    params = ConfigTemplateEndpointParams()
    assert params.to_query_string() == ""


def test_manage_config_templates_00040():
    """
    # Summary

    Verify ConfigTemplateEndpointParams rejects extra fields

    ## Test

    - Extra fields cause validation error (extra="forbid")

    ## Classes and Methods

    - ConfigTemplateEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        ConfigTemplateEndpointParams(bogus="bad")


# =============================================================================
# Test: EpManageConfigTemplateParametersGet
# =============================================================================


def test_manage_config_templates_00100():
    """
    # Summary

    Verify EpManageConfigTemplateParametersGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageConfigTemplateParametersGet.__init__()
    - EpManageConfigTemplateParametersGet.class_name
    - EpManageConfigTemplateParametersGet.verb
    """
    with does_not_raise():
        instance = EpManageConfigTemplateParametersGet()
    assert instance.class_name == "EpManageConfigTemplateParametersGet"
    assert instance.verb == HttpVerbEnum.GET


def test_manage_config_templates_00110():
    """
    # Summary

    Verify EpManageConfigTemplateParametersGet raises ValueError when template_name is not set

    ## Test

    - Accessing path raises ValueError when template_name is None

    ## Classes and Methods

    - EpManageConfigTemplateParametersGet.path
    """
    instance = EpManageConfigTemplateParametersGet()
    with pytest.raises(ValueError):
        instance.path


def test_manage_config_templates_00120():
    """
    # Summary

    Verify EpManageConfigTemplateParametersGet path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageConfigTemplateParametersGet.path
    """
    with does_not_raise():
        instance = EpManageConfigTemplateParametersGet()
        instance.template_name = "switch_freeform"
        result = instance.path
    assert result == "/api/v1/manage/configTemplates/switch_freeform/parameters"


def test_manage_config_templates_00130():
    """
    # Summary

    Verify EpManageConfigTemplateParametersGet path with different template names

    ## Test

    - path correctly interpolates template_name

    ## Classes and Methods

    - EpManageConfigTemplateParametersGet.path
    """
    with does_not_raise():
        instance = EpManageConfigTemplateParametersGet()
        instance.template_name = "feature_enable"
        result = instance.path
    assert result == "/api/v1/manage/configTemplates/feature_enable/parameters"


def test_manage_config_templates_00140():
    """
    # Summary

    Verify EpManageConfigTemplateParametersGet path with clusterName

    ## Test

    - path includes clusterName in query string when set

    ## Classes and Methods

    - EpManageConfigTemplateParametersGet.path
    """
    with does_not_raise():
        instance = EpManageConfigTemplateParametersGet()
        instance.template_name = "switch_freeform"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == ("/api/v1/manage/configTemplates/switch_freeform/parameters?clusterName=cluster1")


def test_manage_config_templates_00150():
    """
    # Summary

    Verify EpManageConfigTemplateParametersGet template_name rejects empty string

    ## Test

    - template_name with empty string raises validation error (min_length=1)

    ## Classes and Methods

    - EpManageConfigTemplateParametersGet.__init__()
    """
    with pytest.raises(ValueError):
        EpManageConfigTemplateParametersGet(template_name="")
