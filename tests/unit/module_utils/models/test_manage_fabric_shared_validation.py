# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Cross-family validation tests for inherited fabric attributes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    BootstrapSubnetModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
)

FABRIC_FAMILIES = (
    FabricExternalConnectivityModel,
    FabricIbgpModel,
    FabricEbgpModel,
    FabricAiIbgpVxlanModel,
    FabricAiEbgpVxlanModel,
    FabricCampusIbgpVxlanModel,
)

VXLAN_FAMILIES = (
    FabricIbgpModel,
    FabricEbgpModel,
    FabricAiIbgpVxlanModel,
    FabricAiEbgpVxlanModel,
    FabricCampusIbgpVxlanModel,
)

IBGP_FAMILIES = (FabricIbgpModel, FabricAiIbgpVxlanModel, FabricCampusIbgpVxlanModel)
UNNUMBERED_IBGP_FAMILIES = (FabricIbgpModel, FabricAiIbgpVxlanModel)

DHCP_IPV4_FIELDS = (
    ("dhcp_start_address", "dhcpStartAddress", "192.0.2.10"),
    ("dhcp_end_address", "dhcpEndAddress", "192.0.2.20"),
    ("management_gateway", "managementGateway", "192.0.2.1"),
)

UNNUMBERED_DHCP_IPV4_FIELDS = (
    ("unnumbered_dhcp_start_address", "unNumberedDhcpStartAddress", "198.51.100.10"),
    ("unnumbered_dhcp_end_address", "unNumberedDhcpEndAddress", "198.51.100.20"),
)


def _config(**management) -> dict:
    return {"fabric_name": "fabric1", "management": {"bgp_asn": "65001", **management}}


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
def test_ipv4_and_ipv6_bootstrap_subnets_are_supported_by_every_family(
    model_class,
) -> None:
    collection = [
        {
            "start_ip": "192.0.2.10",
            "end_ip": "192.0.2.20",
            "default_gateway": "192.0.2.1",
            "subnet_prefix": 24,
        },
        {
            "start_ip": "2001:db8::10",
            "end_ip": "2001:db8::20",
            "default_gateway": "2001:db8::1",
            "subnet_prefix": 64,
        },
    ]

    payload = model_class.from_config(_config(bootstrap_subnet_collection=collection)).to_payload()

    assert payload["management"]["bootstrapSubnetCollection"] == [
        {
            "startIp": "192.0.2.10",
            "endIp": "192.0.2.20",
            "defaultGateway": "192.0.2.1",
            "subnetPrefix": 24,
        },
        {
            "startIp": "2001:db8::10",
            "endIp": "2001:db8::20",
            "defaultGateway": "2001:db8::1",
            "subnetPrefix": 64,
        },
    ]


@pytest.mark.parametrize(
    "subnet",
    (
        {
            "start_ip": "not-an-ip",
            "end_ip": "192.0.2.20",
            "default_gateway": "192.0.2.1",
            "subnet_prefix": 24,
        },
        {
            "start_ip": "192.0.2.10",
            "end_ip": "2001:db8::20",
            "default_gateway": "192.0.2.1",
            "subnet_prefix": 24,
        },
        {
            "start_ip": "192.0.2.10",
            "end_ip": "192.0.2.20",
            "default_gateway": "192.0.2.1",
            "subnet_prefix": 31,
        },
        {
            "start_ip": "2001:db8::10",
            "end_ip": "2001:db8::20",
            "default_gateway": "2001:db8::1",
            "subnet_prefix": 63,
        },
        {
            "start_ip": "2001:db8::10",
            "end_ip": "2001:db8::20",
            "default_gateway": "2001:db8::1",
            "subnet_prefix": 127,
        },
    ),
)
def test_bootstrap_subnet_rejects_invalid_addresses_families_and_prefixes(
    subnet: dict,
) -> None:
    with pytest.raises(ValidationError):
        BootstrapSubnetModel.model_validate(subnet)


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize(("field", "wire_field", "value"), DHCP_IPV4_FIELDS)
def test_dhcp_address_fields_accept_ipv4_for_every_family(model_class, field: str, wire_field: str, value: str) -> None:
    payload = model_class.from_config(_config(**{field: value})).to_payload()

    assert payload["management"][wire_field] == value


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize("field", (field for field, _wire_field, _value in DHCP_IPV4_FIELDS))
def test_dhcp_address_fields_reject_ipv6_for_every_family(model_class, field: str) -> None:
    with pytest.raises(ValidationError, match="valid IPv4 address"):
        model_class.from_config(_config(**{field: "2001:db8::10"}))


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("dhcp_start_address", "not-an-ip"),
        ("dhcp_end_address", "192.0.2.999"),
        ("management_gateway", "192.0.2.1/24"),
        ("scheduled_backup_time", "99:99"),
        ("scheduled_backup_time", "9:00"),
    ),
)
def test_shared_address_and_backup_time_constraints_apply_to_every_family(model_class, field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
def test_controller_empty_optional_addresses_are_normalized_on_response(
    model_class,
) -> None:
    model = model_class.from_response(
        {
            "name": "fabric1",
            "category": "fabric",
            "management": {
                "type": model_class._fabric_type.value,
                "bgpAsn": "65001",
                "dhcpStartAddress": "",
                "dhcpEndAddress": "",
                "managementGateway": "",
            },
        }
    )

    assert model.management.dhcp_start_address is None
    assert model.management.dhcp_end_address is None
    assert model.management.management_gateway is None
    assert not {"dhcpStartAddress", "dhcpEndAddress", "managementGateway"} & model.to_payload()["management"].keys()


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
@pytest.mark.parametrize(("field", "wire_field", "value"), UNNUMBERED_DHCP_IPV4_FIELDS)
def test_unnumbered_dhcp_fields_accept_ipv4(model_class, field: str, wire_field: str, value: str) -> None:
    payload = model_class.from_config(_config(**{field: value})).to_payload()

    assert payload["management"][wire_field] == value


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
@pytest.mark.parametrize("field", (field for field, _wire_field, _value in UNNUMBERED_DHCP_IPV4_FIELDS))
def test_unnumbered_dhcp_fields_reject_ipv6(model_class, field: str) -> None:
    with pytest.raises(ValidationError, match="valid IPv4 address"):
        model_class.from_config(_config(**{field: "2001:db8::10"}))


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
def test_controller_empty_unnumbered_dhcp_addresses_are_normalized_on_response(
    model_class,
) -> None:
    model = model_class.from_response(
        {
            "name": "fabric1",
            "category": "fabric",
            "management": {
                "type": model_class._fabric_type.value,
                "bgpAsn": "65001",
                "unNumberedDhcpStartAddress": "",
                "unNumberedDhcpEndAddress": "",
            },
        }
    )

    assert model.management.unnumbered_dhcp_start_address is None
    assert model.management.unnumbered_dhcp_end_address is None
    assert not {"unNumberedDhcpStartAddress", "unNumberedDhcpEndAddress"} & model.to_payload()["management"].keys()


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
def test_inband_dhcp_servers_accept_at_most_three_ipv4_addresses(model_class) -> None:
    servers = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]

    payload = model_class.from_config(_config(inband_dhcp_servers=servers)).to_payload()

    assert payload["management"]["inbandDhcpServers"] == servers


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
@pytest.mark.parametrize(
    "servers",
    (
        ["2001:db8::1"],
        ["not-an-ip"],
        ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
    ),
)
def test_inband_dhcp_servers_reject_invalid_addresses_and_more_than_three_entries(model_class, servers: list[str]) -> None:
    with pytest.raises(ValidationError):
        model_class.from_config(_config(inband_dhcp_servers=servers))


@pytest.mark.parametrize("model_class", VXLAN_FAMILIES)
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("multicast_group_subnet", "not-a-network"),
        ("multicast_group_subnet", "239.1.1.0/31"),
        ("vrf_lite_subnet_range", "2001:db8::/64"),
        ("vrf_lite_subnet_range", "10.33.0.0"),
    ),
)
def test_shared_vxlan_cidr_constraints_apply_to_every_family(model_class, field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize("model_class", IBGP_FAMILIES)
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("ospf_area_id", "not-an-area"),
        ("seed_switch_core_interfaces", ["not an interface"]),
    ),
)
def test_shared_ibgp_ospf_and_interface_constraints_apply_to_every_family(model_class, field: str, value) -> None:
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))
