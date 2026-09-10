# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Regression tests for atomic NetFlow policy merging."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import (
    PortChannelTrunkHostPolicyModel,
)


@pytest.mark.parametrize(
    "model_class",
    (PortChannelAccessPolicyModel, PortChannelTrunkHostPolicyModel),
)
def test_netflow_and_monitor_merge_as_one_valid_change(model_class) -> None:
    """A valid two-field proposal must not fail on the intermediate state."""
    existing = model_class(netflow=False)
    proposed = model_class(netflow=True, netflow_monitor="MONITOR-1")

    merged = existing.merge(proposed)

    assert merged is existing
    assert merged.netflow is True
    assert merged.netflow_monitor == "MONITOR-1"


@pytest.mark.parametrize(
    "model_class",
    (PortChannelAccessPolicyModel, PortChannelTrunkHostPolicyModel),
)
def test_netflow_merge_rejects_invalid_final_pair_before_mutation(model_class) -> None:
    """An invalid monitor-only change leaves the existing policy untouched."""
    existing = model_class(netflow=True, netflow_monitor="MONITOR-1")
    proposed = model_class(netflow_monitor="")

    with pytest.raises(ValueError, match="netflow_monitor must be provided when netflow is true"):
        existing.merge(proposed)

    assert existing.netflow is True
    assert existing.netflow_monitor == "MONITOR-1"
