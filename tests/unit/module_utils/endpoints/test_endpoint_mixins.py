# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for endpoint_mixins.py

Tests the mixin classes for endpoint models.
Only tests that verify our configuration constraints or our design
patterns (composition) are included. Simple default/getter/setter tests
are omitted as they test Pydantic itself, not our code.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
    ForceShowRunMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import BooleanStringEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: Validation constraints
# =============================================================================


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
