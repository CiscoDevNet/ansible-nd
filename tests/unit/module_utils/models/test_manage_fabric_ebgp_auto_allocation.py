# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Same-Tier-AS behavior for the Multi-AS-only ASN allocation option."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)


def _config(**management) -> dict:
    return {"fabric_name": "ebgp1", "management": {"bgp_asn": "65001", **management}}


def _same_tier_response(**management) -> dict:
    return {
        "name": "ebgp1",
        "category": "fabric",
        "management": {"type": "vxlanEbgp", "bgpAsn": "65001", "bgpAsMode": "sameTierAS", **management},
    }


@pytest.mark.parametrize("auto_allocation", (False, True))
def test_same_tier_as_omits_auto_allocation_and_is_idempotent(auto_allocation: bool) -> None:
    """ND-omitted sameTierAS state matches either user value and is never sent."""
    proposed = FabricEbgpModel.from_config(
        _config(bgp_as_mode="sameTierAS", bgp_asn_auto_allocation=auto_allocation)
    )
    existing = FabricEbgpModel.from_response(_same_tier_response())

    assert proposed.management is not None
    assert existing.management is not None
    assert proposed.management.bgp_asn_auto_allocation is None
    assert existing.management.bgp_asn_auto_allocation is None
    assert "bgpAsnAutoAllocation" not in proposed.to_payload()["management"]
    assert "bgpAsnAutoAllocation" not in proposed.to_diff_dict()["management"]
    assert proposed.get_diff(existing) is True
    assert proposed.get_diff(existing, exclude_unset=True) is True


def test_multi_as_auto_allocation_default_and_explicit_value_are_preserved() -> None:
    """The sameTierAS normalization leaves Multi-AS behavior unchanged."""
    defaulted = FabricEbgpModel.from_config(_config(bgp_as_mode="multiAS"))
    disabled = FabricEbgpModel.from_config(_config(bgp_as_mode="multiAS", bgp_asn_auto_allocation=False))

    assert defaulted.management is not None
    assert defaulted.management.bgp_asn_auto_allocation is True
    assert defaulted.to_payload()["management"]["bgpAsnAutoAllocation"] is True
    assert disabled.management is not None
    assert disabled.management.bgp_asn_auto_allocation is False
    assert disabled.to_payload()["management"]["bgpAsnAutoAllocation"] is False

    option = FabricEbgpModel.get_argument_spec()["config"]["options"]["management"]["options"]["bgp_asn_auto_allocation"]
    assert option["type"] == "bool"
