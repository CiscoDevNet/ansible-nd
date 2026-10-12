# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the Campus iBGP VXLAN fabric model."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import (
    config_actions_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import (
    FABRIC_CONFIG_ACTIONS,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    CampusIbgpVxlanManagementModel,
    FabricCampusIbgpVxlanModel,
)


def _config(**management) -> dict:
    return {
        "fabric_name": "campus1",
        "management": {"bgp_asn": "65001", **management},
    }


def _response(**management) -> dict:
    return {
        "name": "campus1",
        "category": "fabric",
        "management": {
            "type": "vxlanCampus",
            "bgpAsn": "65001",
            "siteId": "65001",
            **management,
        },
    }


def test_manage_fabric_campus_ibgp_vxlan_00010() -> None:
    """Fixed discriminators, management name, and default site ID are derived."""
    model = FabricCampusIbgpVxlanModel.from_config(_config())

    assert model._fabric_type == FabricTypeEnum.CAMPUS_IBGP_VXLAN
    assert model.category == "fabric"
    assert model.management is not None
    assert model.management.type == FabricTypeEnum.CAMPUS_IBGP_VXLAN
    assert model.management.name == "campus1"
    assert model.management.site_id == "65001"

    payload = model.to_payload()
    assert payload["category"] == "fabric"
    assert payload["name"] == "campus1"
    assert payload["management"]["type"] == "vxlanCampus"
    assert payload["management"]["name"] == "campus1"
    assert payload["management"]["siteId"] == "65001"


@pytest.mark.parametrize(
    "bgp_asn,expected_site_id",
    (("1", "1"), ("4294967295", "4294967295"), ("65000.100", "4259840100")),
)
def test_manage_fabric_campus_ibgp_vxlan_00020(bgp_asn: str, expected_site_id: str) -> None:
    """An omitted site ID follows the iBGP ASN-to-site-ID propagation rule."""
    model = FabricCampusIbgpVxlanModel.from_config(
        {
            "fabric_name": "campus1",
            "management": {"bgp_asn": bgp_asn},
        }
    )

    assert model.management is not None
    assert model.management.site_id == expected_site_id


@pytest.mark.parametrize("site_id", ("1", "4294967295", "281474976710655", "65000.100", "65535.65535"))
def test_manage_fabric_campus_ibgp_vxlan_00030(site_id: str) -> None:
    """Explicit site IDs accepted by the 4.2.1/4.3.1 schemas are preserved."""
    model = FabricCampusIbgpVxlanModel.from_config(_config(site_id=site_id))

    assert model.management is not None
    assert model.management.site_id == site_id


@pytest.mark.parametrize("bgp_asn", ("0", "4294967296", "65536.1", "1.65536", "1.2.3", "not-an-asn"))
def test_manage_fabric_campus_ibgp_vxlan_00040(bgp_asn: str) -> None:
    """BGP ASN validation rejects values outside the shared VXLAN schema."""
    with pytest.raises(ValidationError, match="BGP ASN"):
        FabricCampusIbgpVxlanModel.from_config(
            {
                "fabric_name": "campus1",
                "management": {"bgp_asn": bgp_asn},
            }
        )


@pytest.mark.parametrize("site_id", ("0", "01", "281474976710656", "65536.1", "1.65536", "1.2.3", "not-a-site"))
def test_manage_fabric_campus_ibgp_vxlan_00050(site_id: str) -> None:
    """Site ID validation rejects malformed and out-of-range values."""
    with pytest.raises(ValidationError, match="site ID|Site ID"):
        FabricCampusIbgpVxlanModel.from_config(_config(site_id=site_id))


def test_manage_fabric_campus_ibgp_vxlan_00060() -> None:
    """Anycast MAC validation follows the dotted ND wire format and normalizes case."""
    model = FabricCampusIbgpVxlanModel.from_config(_config(anycast_gateway_mac="AABB.CCDD.EEFF"))

    assert model.management is not None
    assert model.management.anycast_gateway_mac == "aabb.ccdd.eeff"
    assert model.to_payload()["management"]["anycastGatewayMac"] == "aabb.ccdd.eeff"

    for invalid in ("aa:bb:cc:dd:ee:ff", "aabb.ccdd.eefg", "aabb.ccdd.eeff.0000"):
        with pytest.raises(ValidationError, match="MAC address"):
            FabricCampusIbgpVxlanModel.from_config(_config(anycast_gateway_mac=invalid))


def test_manage_fabric_campus_ibgp_vxlan_00070() -> None:
    """Unset or blank constrained strings are omitted from the ND payload."""
    constrained = {
        "dhcp_start_address": "",
        "dhcp_end_address": "",
        "management_gateway": "",
        "scheduled_backup_time": "",
        "ios_xe_leaf_freeform": "",
    }
    payload = FabricCampusIbgpVxlanModel.from_config(_config(**constrained)).to_payload()["management"]

    assert (
        not {
            "dhcpStartAddress",
            "dhcpEndAddress",
            "managementGateway",
            "scheduledBackupTime",
            "iosXeLeafFreeform",
            "netflowSettings",
        }
        & payload.keys()
    )
    # Free-form strings still use an empty string to express a clear.
    assert payload["banner"] == ""
    assert payload["domainName"] == ""


def test_manage_fabric_campus_ibgp_vxlan_00080() -> None:
    """Real values for optional constrained strings still reach the payload."""
    payload = FabricCampusIbgpVxlanModel.from_config(
        _config(
            dhcp_start_address="192.0.2.10",
            dhcp_end_address="192.0.2.20",
            management_gateway="192.0.2.1",
            scheduled_backup_time="23:30",
        )
    ).to_payload()["management"]

    assert payload["dhcpStartAddress"] == "192.0.2.10"
    assert payload["dhcpEndAddress"] == "192.0.2.20"
    assert payload["managementGateway"] == "192.0.2.1"
    assert payload["scheduledBackupTime"] == "23:30"


def test_manage_fabric_campus_ibgp_vxlan_00090() -> None:
    """The supported ND 4.3 field is optional and /31 remains live-rejected."""
    omitted = FabricCampusIbgpVxlanModel.from_config(_config()).to_payload()["management"]
    assert "bgpFastConvergence" not in omitted

    enabled = FabricCampusIbgpVxlanModel.from_config(_config(bgp_fast_convergence=True, management_ipv4_prefix=30)).to_payload()["management"]
    assert enabled["bgpFastConvergence"] is True
    assert enabled["managementIpv4Prefix"] == 30

    disabled = FabricCampusIbgpVxlanModel.from_config(_config(bgp_fast_convergence=False)).to_payload()["management"]
    assert disabled["bgpFastConvergence"] is False

    # ND 4.3.1 OpenAPI declares /31, but live ND 4.3.1.175 rejects it and
    # requires a shorter prefix. Keep the cross-release/live-supported bound.
    for prefix in (7, 31, 32):
        with pytest.raises(ValidationError):
            FabricCampusIbgpVxlanModel.from_config(_config(management_ipv4_prefix=prefix))


def test_manage_fabric_campus_ibgp_vxlan_00100() -> None:
    """A 4.3 controller's default false echo does not cause an exact-state diff."""
    existing = FabricCampusIbgpVxlanModel.from_response(_response(bgpFastConvergence=False))
    proposed = FabricCampusIbgpVxlanModel.from_config(_config())

    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_manage_fabric_campus_ibgp_vxlan_00110() -> None:
    """The public argspec hides fixed/internal fields and exposes Campus options."""
    spec = FabricCampusIbgpVxlanModel.get_argument_spec()
    config_options = spec["config"]["options"]
    management_options = config_options["management"]["options"]

    assert "category" not in config_options
    assert "type" not in management_options
    assert "name" not in management_options
    assert management_options["bgp_asn"] == {"type": "str"}
    assert management_options["bgp_fast_convergence"] == {"type": "bool"}
    assert management_options["management_ipv4_prefix"] == {"type": "int"}
    assert management_options["vlan_trunking_protocol_mode"] == {
        "type": "str",
        "choices": ["off", "transparent"],
    }
    assert set(spec["state"]["choices"]) == {
        "merged",
        "replaced",
        "overridden",
        "deleted",
    }
    assert spec["config_actions"] == config_actions_spec(FABRIC_CONFIG_ACTIONS)["config_actions"]


def test_manage_fabric_campus_ibgp_vxlan_00120() -> None:
    """Callers cannot override fixed discriminators or the propagated name."""
    with pytest.raises(ValidationError):
        FabricCampusIbgpVxlanModel.from_config({**_config(), "category": "fabricGroup"})

    with pytest.raises(ValidationError):
        FabricCampusIbgpVxlanModel.from_config(_config(type="vxlanIbgp"))

    model = FabricCampusIbgpVxlanModel.from_config(_config(name="caller-supplied"))
    assert model.management is not None
    assert model.management.name == "campus1"


def test_manage_fabric_campus_ibgp_vxlan_00130() -> None:
    """The Campus management model explicitly opts into blank-as-unset handling."""
    assert CampusIbgpVxlanManagementModel.empty_string_means_unset is True
