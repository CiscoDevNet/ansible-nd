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
    NetflowExporterModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
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

ANYCAST_MAC_FAMILIES = (
    (FabricIbgpModel, "vxlanIbgp"),
    (FabricEbgpModel, "vxlanEbgp"),
    (FabricAiIbgpVxlanModel, "aimlVxlanIbgp"),
    (FabricAiEbgpVxlanModel, "aimlVxlanEbgp"),
    (FabricCampusIbgpVxlanModel, "vxlanCampus"),
)

IBGP_FAMILIES = (FabricIbgpModel, FabricAiIbgpVxlanModel, FabricCampusIbgpVxlanModel)
UNNUMBERED_IBGP_FAMILIES = (FabricIbgpModel, FabricAiIbgpVxlanModel)

DHCP_IPV4_FIELDS = (
    ("dhcp_start_address", "dhcpStartAddress", "192.0.2.10"),
    ("dhcp_end_address", "dhcpEndAddress", "192.0.2.20"),
    ("management_gateway", "managementGateway", "192.0.2.1"),
)

DHCP_IPV6_FIELDS = (
    ("dhcp_start_address", "dhcpStartAddress", "2001:db8::10"),
    ("dhcp_end_address", "dhcpEndAddress", "2001:db8::20"),
    ("management_gateway", "managementGateway", "2001:db8::1"),
)

UNNUMBERED_DHCP_IPV4_FIELDS = (
    ("unnumbered_dhcp_start_address", "unNumberedDhcpStartAddress", "198.51.100.10"),
    ("unnumbered_dhcp_end_address", "unNumberedDhcpEndAddress", "198.51.100.20"),
)


def _config(**management) -> dict:
    return {"fabric_name": "fabric1", "management": {"bgp_asn": "65001", **management}}


@pytest.mark.parametrize(
    "management",
    (
        {"fabric_mtu": 575},
        {"fabric_mtu": 9217},
        {"fabric_mtu": 1501},
        {"network_vlan_range": "1-4095"},
        {"security_group_tag_id_range": "0,1-16777215"},
        {"bgp_authentication_key": "x" * 257},
        {"per_vrf_unique_loopback_ip_range": "fd00::1/64"},
        {"per_vrf_unique_loopback_ipv6_range": "192.0.2.1/24"},
    ),
)
def test_ibgp_management_template_constraints_reject_invalid_values(management) -> None:
    with pytest.raises(ValidationError):
        FabricIbgpModel.from_config(_config(**management))


@pytest.mark.parametrize(
    "management",
    (
        {"fabric_mtu": 576},
        {"fabric_mtu": 9216},
        {"network_vlan_range": "2,100-4094"},
        {"security_group_tag_id_range": "16-65535"},
        {"bgp_authentication_key": "validSecret"},
        {"per_vrf_unique_loopback_ip_range": "192.0.2.0/24"},
        {"per_vrf_unique_loopback_ipv6_range": "2001:db8::/64"},
    ),
)
def test_ibgp_management_template_constraints_accept_valid_values(management) -> None:
    FabricIbgpModel.from_config(_config(**management))


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
@pytest.mark.parametrize(("field", "value"), (
    ("dns_collection", ["not-an-ip"]),
    ("dns_vrf_collection", [""]),
    ("dns_vrf_collection", ["x" * 81]),
    ("ntp_server_collection", [""]),
    ("ntp_server_collection", ["x" * 81]),
    ("syslog_server_collection", [""]),
    ("syslog_server_collection", ["x" * 200]),
    ("syslog_severity_collection", [-1]),
    ("syslog_severity_collection", [8]),
))
def test_ibgp_scalar_collection_items_enforce_both_release_api_contracts(model_class, field, value) -> None:
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
def test_ibgp_scalar_collection_boundaries_and_argument_spec_types(model_class) -> None:
    model = model_class.from_config(_config(
        dns_collection=["192.0.2.1", "2001:db8::1"],
        dns_vrf_collection=["x", "v" * 80],
        ntp_server_collection=["n", "n" * 80],
        syslog_server_collection=["s", "s" * 199],
        syslog_severity_collection=[0, 7],
    ))
    spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]
    assert spec["syslog_severity_collection"]["elements"] == "int"
    assert spec["dns_collection"]["elements"] == "str"
    assert model.to_payload()["management"]["syslogSeverityCollection"] == [0, 7]


def test_key_management_entity_server_ip_requires_ipv4() -> None:
    FabricIbgpModel.from_config(
        _config(key_management_entity_server_ip="192.0.2.10")
    )
    with pytest.raises(ValidationError):
        FabricIbgpModel.from_config(
            _config(key_management_entity_server_ip="2001:db8::10")
        )


@pytest.mark.parametrize("value", ("-example.com", "example-.com", "example", "a" * 57 + ".domain"))
def test_ibgp_connectivity_domain_enforces_native_template_constraints(value) -> None:
    with pytest.raises(ValidationError):
        FabricIbgpModel.from_config(_config(connectivity_domain_name=value))


def test_ibgp_connectivity_domain_accepts_native_template_maximum_length() -> None:
    value = "a" * 56 + ".domain"
    assert len(value) == 63
    model = FabricIbgpModel.from_config(_config(connectivity_domain_name=value))
    assert model.to_payload()["management"]["connectivityDomainName"] == value


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
def test_ibgp_nxapi_http_default_follows_both_native_templates(model_class) -> None:
    model = model_class.from_config(_config())
    assert model.to_payload()["management"]["nxapiHttp"] is True
    assert "nxapi_http" not in model.management.model_fields_set
    explicit = model_class.from_config(_config(nxapi_http=False))
    assert explicit.to_payload()["management"]["nxapiHttp"] is False


@pytest.mark.parametrize("udp_port", (1, 65535))
def test_netflow_udp_port_accepts_template_bounds(udp_port: int) -> None:
    NetflowExporterModel.model_validate(
        {
            "exporter_name": "exporter1",
            "exporter_ip": "192.0.2.10",
            "source_interface_name": "Ethernet1/1",
            "udp_port": udp_port,
        }
    )


@pytest.mark.parametrize("udp_port", (0, 65536))
def test_netflow_udp_port_rejects_outside_template_bounds(udp_port: int) -> None:
    with pytest.raises(ValidationError):
        NetflowExporterModel.model_validate(
            {
                "exporter_name": "exporter1",
                "exporter_ip": "192.0.2.10",
                "source_interface_name": "Ethernet1/1",
                "udp_port": udp_port,
            }
        )


def test_telemetry_traffic_analytics_default_satisfies_api_required_value() -> None:
    model = FabricIbgpModel.from_config(
        {
            **_config(),
            "telemetry_settings": {"flow_collection": {}},
        }
    )

    assert (
        model.to_payload()["telemetrySettings"]["flowCollection"][
            "trafficAnalytics"
        ]
        == "disabled"
    )


def test_public_ibgp_response_secrets_are_registered_for_output_masking() -> None:
    model = FabricIbgpModel.from_response({
        "name": "fabric1", "category": "fabric",
        "management": {
            "type": "vxlanIbgp", "bgpAsn": "65001", "ntpAuthKey": "responseNtpKey",
            "ospfKeys": [{"keyId": 1, "keyString": "responseOspfKey"}],
        },
    })
    assert model.collect_replacement_secret_values() == {"responseNtpKey", "responseOspfKey"}
    config = model.to_config()["management"]
    assert config["ntp_auth_key"] != "responseNtpKey"
    assert config["ospf_keys"][0]["key_string"] != "responseOspfKey"


def test_omitted_ospf_default_does_not_change_merged_value() -> None:
    existing = FabricIbgpModel.from_config(
        _config(ospf_max_metric_startup_wait=450)
    )
    proposed = FabricIbgpModel.from_config(_config())

    existing.merge(proposed)

    assert existing.to_payload()["management"]["ospfMaxMetricStartupWait"] == 450


@pytest.mark.parametrize("address", ("192.0.2.10", "198.51.100.20"))
def test_netflow_exporter_accepts_ipv4(address: str) -> None:
    NetflowExporterModel.model_validate(
        {
            "exporterName": "collector1",
            "exporterIp": address,
            "sourceInterfaceName": "loopback0",
        }
    )


@pytest.mark.parametrize("address", ("2001:db8::10", "not-an-ip"))
def test_netflow_exporter_rejects_non_ipv4(address: str) -> None:
    with pytest.raises(ValidationError):
        NetflowExporterModel.model_validate(
            {
                "exporterName": "collector1",
                "exporterIp": address,
                "sourceInterfaceName": "loopback0",
            }
        )


@pytest.mark.parametrize(
    "management",
    (
        {"fabric_mtu": 575},
        {"fabric_mtu": 1501},
        {"anycast_loopback_id": 1024},
        {"l2_vni_range": "0-16777214"},
        {"l3_vni_range": "1-16777215"},
        {"bgp_authentication_key": "x" * 257},
    ),
)
def test_ebgp_management_template_constraints_reject_invalid_values(management) -> None:
    with pytest.raises(ValidationError):
        FabricEbgpModel.from_config(_config(**management))


@pytest.mark.parametrize(
    "management",
    (
        {"fabric_mtu": 576},
        {"anycast_loopback_id": 0},
        {"l2_vni_range": "1-16777214"},
        {"l3_vni_range": "100,200-300"},
        {"bgp_authentication_key": "validSecret"},
    ),
)
def test_ebgp_management_template_constraints_accept_valid_values(management) -> None:
    FabricEbgpModel.from_config(_config(**management))


@pytest.mark.parametrize(
    "management",
    (
        {"management_ipv6_prefix": 63},
        {"management_ipv6_prefix": 127},
        {"mpls_loopback_identifier": -1},
        {"mpls_loopback_identifier": 1024},
        {"mpls_loopback_ip_range": "2001:db8::/64"},
        {"sub_interface_dot1q_range": "1-10"},
        {"sub_interface_dot1q_range": "4094-4095"},
        {"domain_name": "-invalid.example"},
        {"connectivity_domain_name": "invalid.example-"},
    ),
)
def test_external_management_template_constraints_reject_invalid_values(
    management,
) -> None:
    with pytest.raises(ValidationError):
        FabricExternalConnectivityModel.from_config(_config(**management))


@pytest.mark.parametrize(
    "management",
    (
        {"management_ipv6_prefix": 64},
        {"management_ipv6_prefix": 126},
        {"mpls_loopback_identifier": 0},
        {"mpls_loopback_identifier": 1023},
        {"mpls_loopback_ip_range": "192.0.2.0/24"},
        {"sub_interface_dot1q_range": "2,4093"},
        {"domain_name": "edge.example.com"},
        {"connectivity_domain_name": "edge.example.com"},
    ),
)
def test_external_management_template_constraints_accept_valid_values(
    management,
) -> None:
    FabricExternalConnectivityModel.from_config(_config(**management))


@pytest.mark.parametrize(
    "model_class",
    (FabricExternalConnectivityModel, FabricEbgpModel, FabricAiEbgpVxlanModel),
)
def test_hypershield_subnet_fields_require_ipv4_cidr(model_class) -> None:
    model_class.from_config(
        _config(
            hypershield_ha_peer_link_subnet="192.0.2.0/24",
            hypershield_ha_source_subnet="198.51.100.0/24",
        )
    )
    with pytest.raises(ValidationError):
        model_class.from_config(
            _config(hypershield_ha_peer_link_subnet="2001:db8::/64")
        )


@pytest.mark.parametrize(
    "value",
    (
        "1-1",
        "1.1-2.2",
        "1-4294967295",
        "+1-+4294967295",
    ),
)
def test_ebgp_template_asn_range_accepts_native_template_values(value: str) -> None:
    FabricEbgpModel.from_config(_config(bgp_asn_range=value))


@pytest.mark.parametrize(
    "value",
    ("1", "1-", "-2", "0-2", "1-4294967296", "1-2-3"),
)
def test_ebgp_template_asn_range_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValidationError):
        FabricEbgpModel.from_config(_config(bgp_asn_range=value))


@pytest.mark.parametrize("model_class,fabric_type", ANYCAST_MAC_FAMILIES)
@pytest.mark.parametrize(
    "mac", ("2020.0000.00aa", "20:20:00:00:00:aa", "20-20-00-00-00-aa", "2020000000aa")
)
def test_anycast_mac_normalizes_across_vxlan_families(
    model_class, fabric_type: str, mac: str
) -> None:
    """Every VXLAN fabric family emits equivalent anycast MAC inputs identically."""
    model = model_class.from_config(_config(anycast_gateway_mac=mac))
    response = model_class.from_response(
        {
            "name": "fabric1",
            "category": "fabric",
            "management": {
                "type": fabric_type,
                "bgpAsn": "65001",
                "anycastGatewayMac": mac,
            },
        }
    )

    assert model.management.anycast_gateway_mac == "2020.0000.00aa"
    assert model.to_payload()["management"]["anycastGatewayMac"] == "2020.0000.00aa"
    assert response.management.anycast_gateway_mac == "2020.0000.00aa"
    assert model.get_diff(response) is True


@pytest.mark.parametrize("model_class,_fabric_type", ANYCAST_MAC_FAMILIES)
@pytest.mark.parametrize(
    "invalid",
    ("20:20:00:00:00:zz", "2020.0000.00a", "2020.0000.00aa.0000", "20:20-00:00:00:aa"),
)
def test_anycast_mac_rejects_invalid_formats(
    model_class, _fabric_type: str, invalid: str
) -> None:
    """MAC normalization rejects malformed, mixed-separator, and incomplete values."""
    with pytest.raises(ValidationError, match="MAC address"):
        model_class.from_config(_config(anycast_gateway_mac=invalid))


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

    payload = model_class.from_config(
        _config(bootstrap_subnet_collection=collection)
    ).to_payload()

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
def test_dhcp_address_fields_accept_ipv4_for_every_family(
    model_class, field: str, wire_field: str, value: str
) -> None:
    payload = model_class.from_config(_config(**{field: value})).to_payload()

    assert payload["management"][wire_field] == value


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize(("field", "wire_field", "value"), DHCP_IPV6_FIELDS)
def test_dhcp_address_fields_accept_bare_ipv6_for_every_family(
    model_class, field: str, wire_field: str, value: str
) -> None:
    model = model_class.from_config(
        _config(dhcp_protocol_version="dhcpv6", **{field: value})
    )

    assert getattr(model.management, field) == value
    assert model.to_payload()["management"][wire_field] == value


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize(("field", "wire_field", "value"), DHCP_IPV6_FIELDS)
def test_dhcp_address_fields_allow_ipv6_assignment_and_merge(
    model_class, field: str, wire_field: str, value: str
) -> None:
    existing = model_class.from_config(_config(**{field: "192.0.2.10"}))
    setattr(existing.management, field, value)
    assert existing.to_payload()["management"][wire_field] == value

    existing = model_class.from_config(_config(**{field: "192.0.2.10"}))
    proposed = model_class.from_config(
        _config(dhcp_protocol_version="dhcpv6", **{field: value}),
        context={"state": "merged"},
    )
    existing.merge(proposed)
    assert existing.to_payload()["management"][wire_field] == value


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize(
    ("field", "wire_field", "value"),
    DHCP_IPV6_FIELDS,
)
def test_dhcp_address_fields_accept_ipv6_in_controller_responses(
    model_class, field: str, wire_field: str, value: str
) -> None:
    model = model_class.from_response(
        {
            "name": "fabric1",
            "category": "fabric",
            "management": {
                "type": model_class._fabric_type.value,
                "bgpAsn": "65001",
                wire_field: value,
            },
        }
    )

    assert getattr(model.management, field) == value
    assert model.to_payload()["management"][wire_field] == value


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize(("_field", "wire_field", "_ipv4"), DHCP_IPV4_FIELDS)
@pytest.mark.parametrize("invalid", ("not-an-ip", "192.0.2.1/24", "2001:db8::1/64"))
def test_dhcp_address_fields_reject_invalid_controller_responses(
    model_class, _field: str, wire_field: str, _ipv4: str, invalid: str
) -> None:
    response = {
        "name": "fabric1",
        "category": "fabric",
        "management": {
            "type": model_class._fabric_type.value,
            "bgpAsn": "65001",
            wire_field: invalid,
        },
    }

    with pytest.raises(ValidationError, match="valid IPv4 or IPv6 address"):
        model_class.from_response(response)


@pytest.mark.parametrize("model_class", FABRIC_FAMILIES)
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("dhcp_start_address", "not-an-ip"),
        ("dhcp_end_address", "192.0.2.999"),
        ("management_gateway", "192.0.2.1/24"),
        ("dhcp_start_address", "2001:db8::zz"),
        ("dhcp_end_address", "2001:db8::20/64"),
        ("management_gateway", "2001:db8::1/64"),
        ("scheduled_backup_time", "99:99"),
        ("scheduled_backup_time", "9:00"),
    ),
)
def test_shared_address_and_backup_time_constraints_apply_to_every_family(
    model_class, field: str, value: str
) -> None:
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
    assert (
        not {"dhcpStartAddress", "dhcpEndAddress", "managementGateway"}
        & model.to_payload()["management"].keys()
    )


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
@pytest.mark.parametrize(("field", "wire_field", "value"), UNNUMBERED_DHCP_IPV4_FIELDS)
def test_unnumbered_dhcp_fields_accept_ipv4(
    model_class, field: str, wire_field: str, value: str
) -> None:
    payload = model_class.from_config(_config(**{field: value})).to_payload()

    assert payload["management"][wire_field] == value


@pytest.mark.parametrize("model_class", UNNUMBERED_IBGP_FAMILIES)
@pytest.mark.parametrize(
    "field", (field for field, _wire_field, _value in UNNUMBERED_DHCP_IPV4_FIELDS)
)
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
    assert (
        not {"unNumberedDhcpStartAddress", "unNumberedDhcpEndAddress"}
        & model.to_payload()["management"].keys()
    )


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
def test_inband_dhcp_servers_reject_invalid_addresses_and_more_than_three_entries(
    model_class, servers: list[str]
) -> None:
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
def test_shared_vxlan_cidr_constraints_apply_to_every_family(
    model_class, field: str, value: str
) -> None:
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
def test_shared_ibgp_ospf_and_interface_constraints_apply_to_every_family(
    model_class, field: str, value
) -> None:
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize("model_class", VXLAN_FAMILIES)
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize("site_id_input", (None, ""))
def test_omitted_site_id_is_derived_for_payload_but_not_marked_explicit(
    model_class, state: str, site_id_input: str | None
) -> None:
    management = {"bgp_asn": "65001"}
    if site_id_input is not None:
        management["site_id"] = site_id_input

    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": management},
        context={"state": state},
    )

    assert model.management.site_id == "65001"
    assert "site_id" not in model.management.model_fields_set
    assert model.to_payload()["management"]["siteId"] == "65001"
    assert (
        "siteId"
        not in model.model_dump(by_alias=True, exclude_unset=True)["management"]
    )


@pytest.mark.parametrize("model_class", VXLAN_FAMILIES)
def test_explicit_site_id_remains_explicit_for_merged(model_class) -> None:
    model = model_class.from_config(
        _config(site_id="12345"),
        context={"state": "merged"},
    )

    assert model.management.site_id == "12345"
    assert "site_id" in model.management.model_fields_set
    assert (
        model.model_dump(by_alias=True, exclude_unset=True)["management"]["siteId"]
        == "12345"
    )
