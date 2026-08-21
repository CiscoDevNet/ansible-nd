# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``ManageTorModel`` state-aware validation.

Covers the vPC ``peer switch => resources`` rule (enforced only for write
states), the ``deleted``/``gathered`` skip, and ``resources`` flattening from
API responses.
"""

# pylint: disable=redefined-outer-name

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import (
    ManageTorModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def _cfg(**overrides):
    base = {
        "fabric_name": "fab1",
        "access_or_tor_switch_id": "T1",
        "aggregation_or_leaf_switch_id": "L1",
    }
    base.update(overrides)
    return base


def test_single_pairing_no_resources_ok_merged():
    """A single (non-peer) pairing needs no resources for merged."""
    with does_not_raise():
        ManageTorModel.from_config(_cfg(), context={"state": "merged"})


def test_vpc_leaf_peer_no_resources_ok_merged():
    """A leaf vPC pairing without resources is valid; ND defaults the VPC/PO IDs
    and returns a benign 207 ("Id [0] ... not within the range") the orchestrator
    tolerates."""
    with does_not_raise():
        ManageTorModel.from_config(_cfg(aggregation_or_leaf_peer_switch_id="L2"), context={"state": "merged"})


def test_vpc_leaf_peer_with_resources_ok_merged():
    """Supplying the required leaf resources satisfies the leaf vPC rule."""
    with does_not_raise():
        ManageTorModel.from_config(
            _cfg(
                aggregation_or_leaf_peer_switch_id="L2",
                aggregation_or_leaf_vpc_id=2,
                aggregation_or_leaf_port_channel_id=502,
                aggregation_or_leaf_peer_port_channel_id=504,
            ),
            context={"state": "merged"},
        )


def test_vpc_tor_peer_no_resources_ok_merged():
    """A ToR vPC pairing without resources is valid; ND defaults the VPC/PO IDs
    and returns a benign 207 the orchestrator tolerates."""
    with does_not_raise():
        ManageTorModel.from_config(_cfg(access_or_tor_peer_switch_id="T2"), context={"state": "merged"})


def test_deleted_skips_vpc_validation():
    """Identifier-only vPC items are accepted for deleted (no resources needed)."""
    with does_not_raise():
        ManageTorModel.from_config(_cfg(aggregation_or_leaf_peer_switch_id="L2"), context={"state": "deleted"})


def test_gathered_skips_vpc_validation():
    """gathered items are accepted without resources."""
    with does_not_raise():
        ManageTorModel.from_config(_cfg(access_or_tor_peer_switch_id="T2"), context={"state": "gathered"})


def test_flatten_resources_from_response():
    """resources sub-dict from an API response is flattened to top-level fields."""
    model = ManageTorModel.from_response(
        {
            "fabricName": "fab1",
            "accessOrTorSwitchId": "T1",
            "aggregationOrLeafSwitchId": "L1",
            "resources": {"accessOrTorPortChannelId": 501, "aggregationOrLeafPortChannelId": 502},
        }
    )
    assert model.access_or_tor_port_channel_id == 501
    assert model.aggregation_or_leaf_port_channel_id == 502
