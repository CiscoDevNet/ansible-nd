# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Whitespace-preservation tests for iBGP CLI and freeform fields."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
)

TEXT_FIELDS = (
    ("ibgp_peer_template", "ibgpPeerTemplate"),
    ("leaf_ibgp_peer_template", "leafIbgpPeerTemplate"),
    ("banner", "banner"),
    ("extra_config_aaa", "extraConfigAaa"),
    ("extra_config_intra_fabric_links", "extraConfigIntraFabricLinks"),
    ("extra_config_leaf", "extraConfigLeaf"),
    ("extra_config_spine", "extraConfigSpine"),
    ("extra_config_tor", "extraConfigTor"),
    ("pre_interface_config_leaf", "preInterfaceConfigLeaf"),
    ("pre_interface_config_spine", "preInterfaceConfigSpine"),
    ("pre_interface_config_tor", "preInterfaceConfigTor"),
)
AUTHORED_TEXT = "  template peer DEMO\n    send-community both\n"


def test_ibgp_cli_text_preserves_authored_whitespace_across_round_trip() -> None:
    """All CLI/freeform values survive config, response, payload, and diff paths unchanged."""
    proposed = FabricIbgpModel.from_config(
        {
            "fabric_name": "ibgp1",
            "management": {"bgp_asn": "65001", **{field: AUTHORED_TEXT for field, _ in TEXT_FIELDS}},
        }
    )
    existing = FabricIbgpModel.from_response(
        {
            "name": "ibgp1",
            "category": "fabric",
            "management": {
                "type": "vxlanIbgp",
                "bgpAsn": "65001",
                "siteId": "65001",
                **{wire_field: AUTHORED_TEXT for _, wire_field in TEXT_FIELDS},
            },
        }
    )

    assert proposed.management is not None
    assert existing.management is not None
    payload = proposed.to_payload()["management"]
    for field, wire_field in TEXT_FIELDS:
        assert getattr(proposed.management, field) == AUTHORED_TEXT
        assert getattr(existing.management, field) == AUTHORED_TEXT
        assert payload[wire_field] == AUTHORED_TEXT

    assert proposed.get_diff(existing) is True
    assert proposed.get_diff(existing, exclude_unset=True) is True

    options = FabricIbgpModel.get_argument_spec()["config"]["options"]["management"]["options"]
    assert all(options[field]["type"] == "str" for field, _ in TEXT_FIELDS)


def test_ibgp_cli_text_preserves_whitespace_on_assignment() -> None:
    """Assignment validation does not strip text values after model creation."""
    model = FabricIbgpModel.from_config({"fabric_name": "ibgp1", "management": {"bgp_asn": "65001"}})
    assert model.management is not None

    for field, _ in TEXT_FIELDS:
        setattr(model.management, field, AUTHORED_TEXT)
        assert getattr(model.management, field) == AUTHORED_TEXT
