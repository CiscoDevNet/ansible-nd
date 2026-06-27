# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the shared storm-control percentage/pps mutual-exclusion validator (issue #351).

Exercises `StormControlMutexMixin` as applied to all five interface policy models: a config that sets both the
percentage level and the pps level for the same traffic class must be rejected, while setting only one (or putting
the percentage and pps on different classes) is accepted.
"""

# pylint: disable=line-too-long
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument

from __future__ import annotations

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import EthernetAccessPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import PortChannelAccessPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import PortChannelTrunkHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import AccessVpcHostPolicyModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_trunk_host_interface import TrunkVpcHostPolicyModel
from pydantic import ValidationError


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# Every interface policy model that carries the paired storm-control fields.
POLICY_MODELS = [
    EthernetAccessPolicyModel,
    PortChannelAccessPolicyModel,
    PortChannelTrunkHostPolicyModel,
    AccessVpcHostPolicyModel,
    TrunkVpcHostPolicyModel,
]

# (label, percentage attribute, pps attribute) per storm-control traffic class.
CLASS_FIELDS = [
    ("broadcast", "storm_control_broadcast_level", "storm_control_broadcast_level_pps"),
    ("multicast", "storm_control_multicast_level", "storm_control_multicast_level_pps"),
    ("unicast", "storm_control_unicast_level", "storm_control_unicast_level_pps"),
]

PCT = 50.0
PPS = 1000


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
@pytest.mark.parametrize("label,pct_attr,pps_attr", CLASS_FIELDS)
def test_storm_control_mutex_00100(model_cls, label, pct_attr, pps_attr) -> None:
    """
    # Summary

    Setting both the percentage and pps level for the same storm-control class is rejected.

    ## Test

    - A policy model is constructed with both `storm_control_<class>_level` and `storm_control_<class>_level_pps` set.
    - A `ValidationError` is raised naming the offending traffic class.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with pytest.raises(ValidationError, match=label):
        model_cls(**{pct_attr: PCT, pps_attr: PPS})


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
@pytest.mark.parametrize("label,pct_attr,pps_attr", CLASS_FIELDS)
def test_storm_control_mutex_00110(model_cls, label, pct_attr, pps_attr) -> None:
    """
    # Summary

    Setting only the percentage, or only the pps, for a class is accepted.

    ## Test

    - The model is constructed with just the percentage level set, then just the pps level set.
    - Neither construction raises.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with does_not_raise():
        model_cls(**{pct_attr: PCT})
    with does_not_raise():
        model_cls(**{pps_attr: PPS})


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
def test_storm_control_mutex_00120(model_cls) -> None:
    """
    # Summary

    A policy with no storm-control levels set is accepted (the validator is a no-op when nothing conflicts).

    ## Test

    - The model is constructed with no storm-control fields.
    - Construction does not raise.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with does_not_raise():
        model_cls()


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
def test_storm_control_mutex_00130(model_cls) -> None:
    """
    # Summary

    A percentage on one class and a pps on a different class do not conflict (the check is per-class).

    ## Test

    - The model is constructed with `storm_control_broadcast_level` and `storm_control_multicast_level_pps` set.
    - Construction does not raise.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with does_not_raise():
        model_cls(storm_control_broadcast_level=PCT, storm_control_multicast_level_pps=PPS)


@pytest.mark.parametrize("model_cls", POLICY_MODELS)
def test_storm_control_mutex_00140(model_cls) -> None:
    """
    # Summary

    When more than one class conflicts, the error names every offending class.

    ## Test

    - The model is constructed with both percentage and pps set for broadcast and for unicast.
    - A `ValidationError` is raised naming both `broadcast` and `unicast`.

    ## Classes and Methods

    - StormControlMutexMixin._reject_storm_control_level_and_pps()
    """
    with pytest.raises(ValidationError, match=r"broadcast, unicast"):
        model_cls(
            storm_control_broadcast_level=PCT,
            storm_control_broadcast_level_pps=PPS,
            storm_control_unicast_level=PCT,
            storm_control_unicast_level_pps=PPS,
        )
