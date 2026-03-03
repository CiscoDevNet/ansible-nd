# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for endpoint_mixins.py

Tests the mixin classes for endpoint models
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.enums import BooleanStringEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.endpoint_mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    ForceShowRunMixin,
    HealthCategoryMixin,
    InclAllMsdSwitchesMixin,
    LinkUuidMixin,
    LoginIdMixin,
    NetworkNameMixin,
    NodeNameMixin,
    SwitchSerialNumberMixin,
    VrfNameMixin,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: ForceShowRunMixin
# =============================================================================


def test_endpoint_mixins_00010():
    """
    # Summary

    Verify ForceShowRunMixin default value

    ## Test

    - force_show_run defaults to BooleanStringEnum.FALSE

    ## Classes and Methods

    - ForceShowRunMixin.force_show_run
    """
    with does_not_raise():
        instance = ForceShowRunMixin()
    assert instance.force_show_run == BooleanStringEnum.FALSE
    assert instance.force_show_run.value == "false"


def test_endpoint_mixins_00020():
    """
    # Summary

    Verify ForceShowRunMixin can be set

    ## Test

    - force_show_run can be set to TRUE

    ## Classes and Methods

    - ForceShowRunMixin.force_show_run
    """
    with does_not_raise():
        instance = ForceShowRunMixin(force_show_run=BooleanStringEnum.TRUE)
    assert instance.force_show_run == BooleanStringEnum.TRUE
    assert instance.force_show_run.value == "true"


# =============================================================================
# Test: InclAllMsdSwitchesMixin
# =============================================================================


def test_endpoint_mixins_00100():
    """
    # Summary

    Verify InclAllMsdSwitchesMixin default value

    ## Test

    - incl_all_msd_switches defaults to BooleanStringEnum.FALSE

    ## Classes and Methods

    - InclAllMsdSwitchesMixin.incl_all_msd_switches
    """
    with does_not_raise():
        instance = InclAllMsdSwitchesMixin()
    assert instance.incl_all_msd_switches == BooleanStringEnum.FALSE
    assert instance.incl_all_msd_switches.value == "false"


def test_endpoint_mixins_00110():
    """
    # Summary

    Verify InclAllMsdSwitchesMixin can be set

    ## Test

    - incl_all_msd_switches can be set to TRUE

    ## Classes and Methods

    - InclAllMsdSwitchesMixin.incl_all_msd_switches
    """
    with does_not_raise():
        instance = InclAllMsdSwitchesMixin(incl_all_msd_switches=BooleanStringEnum.TRUE)
    assert instance.incl_all_msd_switches == BooleanStringEnum.TRUE
    assert instance.incl_all_msd_switches.value == "true"


# =============================================================================
# Test: FabricNameMixin
# =============================================================================


def test_endpoint_mixins_00200():
    """
    # Summary

    Verify FabricNameMixin default value is None

    ## Test

    - fabric_name defaults to None

    ## Classes and Methods

    - FabricNameMixin.fabric_name
    """
    with does_not_raise():
        instance = FabricNameMixin()
    assert instance.fabric_name is None


def test_endpoint_mixins_00210():
    """
    # Summary

    Verify FabricNameMixin can be set

    ## Test

    - fabric_name can be set to a string value

    ## Classes and Methods

    - FabricNameMixin.fabric_name
    """
    with does_not_raise():
        instance = FabricNameMixin(fabric_name="MyFabric")
    assert instance.fabric_name == "MyFabric"


def test_endpoint_mixins_00220():
    """
    # Summary

    Verify FabricNameMixin validates max length

    ## Test

    - fabric_name rejects strings longer than 64 characters

    ## Classes and Methods

    - FabricNameMixin.fabric_name
    """
    long_name = "a" * 65  # 65 characters
    with pytest.raises(ValueError):
        FabricNameMixin(fabric_name=long_name)


# =============================================================================
# Test: SwitchSerialNumberMixin
# =============================================================================


def test_endpoint_mixins_00300():
    """
    # Summary

    Verify SwitchSerialNumberMixin default value is None

    ## Test

    - switch_sn defaults to None

    ## Classes and Methods

    - SwitchSerialNumberMixin.switch_sn
    """
    with does_not_raise():
        instance = SwitchSerialNumberMixin()
    assert instance.switch_sn is None


def test_endpoint_mixins_00310():
    """
    # Summary

    Verify SwitchSerialNumberMixin can be set

    ## Test

    - switch_sn can be set to a string value

    ## Classes and Methods

    - SwitchSerialNumberMixin.switch_sn
    """
    with does_not_raise():
        instance = SwitchSerialNumberMixin(switch_sn="FDO12345678")
    assert instance.switch_sn == "FDO12345678"


# =============================================================================
# Test: NetworkNameMixin
# =============================================================================


def test_endpoint_mixins_00400():
    """
    # Summary

    Verify NetworkNameMixin default value is None

    ## Test

    - network_name defaults to None

    ## Classes and Methods

    - NetworkNameMixin.network_name
    """
    with does_not_raise():
        instance = NetworkNameMixin()
    assert instance.network_name is None


def test_endpoint_mixins_00410():
    """
    # Summary

    Verify NetworkNameMixin can be set

    ## Test

    - network_name can be set to a string value

    ## Classes and Methods

    - NetworkNameMixin.network_name
    """
    with does_not_raise():
        instance = NetworkNameMixin(network_name="MyNetwork")
    assert instance.network_name == "MyNetwork"


# =============================================================================
# Test: VrfNameMixin
# =============================================================================


def test_endpoint_mixins_00500():
    """
    # Summary

    Verify VrfNameMixin default value is None

    ## Test

    - vrf_name defaults to None

    ## Classes and Methods

    - VrfNameMixin.vrf_name
    """
    with does_not_raise():
        instance = VrfNameMixin()
    assert instance.vrf_name is None


def test_endpoint_mixins_00510():
    """
    # Summary

    Verify VrfNameMixin can be set

    ## Test

    - vrf_name can be set to a string value

    ## Classes and Methods

    - VrfNameMixin.vrf_name
    """
    with does_not_raise():
        instance = VrfNameMixin(vrf_name="MyVRF")
    assert instance.vrf_name == "MyVRF"


# =============================================================================
# Test: LinkUuidMixin
# =============================================================================


def test_endpoint_mixins_00600():
    """
    # Summary

    Verify LinkUuidMixin default value is None

    ## Test

    - link_uuid defaults to None

    ## Classes and Methods

    - LinkUuidMixin.link_uuid
    """
    with does_not_raise():
        instance = LinkUuidMixin()
    assert instance.link_uuid is None


def test_endpoint_mixins_00610():
    """
    # Summary

    Verify LinkUuidMixin can be set

    ## Test

    - link_uuid can be set to a UUID string

    ## Classes and Methods

    - LinkUuidMixin.link_uuid
    """
    with does_not_raise():
        instance = LinkUuidMixin(link_uuid="123e4567-e89b-12d3-a456-426614174000")
    assert instance.link_uuid == "123e4567-e89b-12d3-a456-426614174000"


# =============================================================================
# Test: LoginIdMixin
# =============================================================================


def test_endpoint_mixins_00700():
    """
    # Summary

    Verify LoginIdMixin default value is None

    ## Test

    - login_id defaults to None

    ## Classes and Methods

    - LoginIdMixin.login_id
    """
    with does_not_raise():
        instance = LoginIdMixin()
    assert instance.login_id is None


def test_endpoint_mixins_00710():
    """
    # Summary

    Verify LoginIdMixin can be set

    ## Test

    - login_id can be set to a string value

    ## Classes and Methods

    - LoginIdMixin.login_id
    """
    with does_not_raise():
        instance = LoginIdMixin(login_id="admin")
    assert instance.login_id == "admin"


# =============================================================================
# Test: ClusterNameMixin
# =============================================================================


def test_endpoint_mixins_00800():
    """
    # Summary

    Verify ClusterNameMixin default value is None

    ## Test

    - cluster_name defaults to None

    ## Classes and Methods

    - ClusterNameMixin.cluster_name
    """
    with does_not_raise():
        instance = ClusterNameMixin()
    assert instance.cluster_name is None


def test_endpoint_mixins_00810():
    """
    # Summary

    Verify ClusterNameMixin can be set

    ## Test

    - cluster_name can be set to a string value

    ## Classes and Methods

    - ClusterNameMixin.cluster_name
    """
    with does_not_raise():
        instance = ClusterNameMixin(cluster_name="my-cluster")
    assert instance.cluster_name == "my-cluster"


# =============================================================================
# Test: HealthCategoryMixin
# =============================================================================


def test_endpoint_mixins_00900():
    """
    # Summary

    Verify HealthCategoryMixin default value is None

    ## Test

    - health_category defaults to None

    ## Classes and Methods

    - HealthCategoryMixin.health_category
    """
    with does_not_raise():
        instance = HealthCategoryMixin()
    assert instance.health_category is None


def test_endpoint_mixins_00910():
    """
    # Summary

    Verify HealthCategoryMixin can be set

    ## Test

    - health_category can be set to a string value

    ## Classes and Methods

    - HealthCategoryMixin.health_category
    """
    with does_not_raise():
        instance = HealthCategoryMixin(health_category="cpu")
    assert instance.health_category == "cpu"


# =============================================================================
# Test: NodeNameMixin
# =============================================================================


def test_endpoint_mixins_01000():
    """
    # Summary

    Verify NodeNameMixin default value is None

    ## Test

    - node_name defaults to None

    ## Classes and Methods

    - NodeNameMixin.node_name
    """
    with does_not_raise():
        instance = NodeNameMixin()
    assert instance.node_name is None


def test_endpoint_mixins_01010():
    """
    # Summary

    Verify NodeNameMixin can be set

    ## Test

    - node_name can be set to a string value

    ## Classes and Methods

    - NodeNameMixin.node_name
    """
    with does_not_raise():
        instance = NodeNameMixin(node_name="node1")
    assert instance.node_name == "node1"


# =============================================================================
# Test: Mixin composition
# =============================================================================


def test_endpoint_mixins_01100():
    """
    # Summary

    Verify mixins can be composed together

    ## Test

    - Multiple mixins can be combined in a single class

    ## Classes and Methods

    - FabricNameMixin
    - ForceShowRunMixin
    """

    # Create a composite class using multiple mixins
    class CompositeParams(FabricNameMixin, ForceShowRunMixin):
        pass

    with does_not_raise():
        instance = CompositeParams(fabric_name="MyFabric", force_show_run=BooleanStringEnum.TRUE)
    assert instance.fabric_name == "MyFabric"
    assert instance.force_show_run == BooleanStringEnum.TRUE
