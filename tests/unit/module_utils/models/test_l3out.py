# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for l3out.py

Tests the L3Out Pydantic model classes.
"""

from __future__ import annotations

import copy
from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.models.l3out.l3out import (
    FabricBgpDetailsModel,
    Ipv4PeeringModel,
    Ipv6PeeringModel,
    L3OutModel,
    LinkModel,
    RoutingDetailsModel,
    StaticRouteModel,
    SwitchDetailsModel,
)
from pydantic import ValidationError  # pylint: disable=unused-import


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test data constants
# =============================================================================

SAMPLE_API_RESPONSE = {
    "name": "test-l3out",
    "fabric1Name": "DC1-Fabric",
    "fabric2Name": "External-Fabric",
    "vrf1Name": "production",
    "vrf2Name": "external",
    "configuredFabrics": "both",
    "ipVersion": "ipv4",
    "connectivityDetails": {
        "routingInterfaceType": "routed",
        "links": [
            {
                "mtu": 9216,
                "ipv4MaskLength": 30,
                "switch1Details": {
                    "switchId": "FDO12345678",
                    "interfaceName": "Ethernet1/1",
                    "ipv4Address": "10.0.0.1",
                },
                "switch2Details": {
                    "switchId": "FDO87654321",
                    "interfaceName": "Ethernet1/1",
                    "ipv4Address": "10.0.0.2",
                },
            }
        ],
    },
    "routingDetails": {
        "routingProtocol": "bgp",
        "bfd": True,
        "holdInterval": 180,
        "keepAliveInterval": 60,
        "fabric1Details": {
            "advertiseDefaultRoute": True,
            "ipv4PeeringDetails": {
                "ipv4RouteMapIn": "rm-in",
                "ipv4RouteMapOut": "rm-out",
            },
        },
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "name": "test-l3out",
    "fabric1_name": "DC1-Fabric",
    "fabric2_name": "External-Fabric",
    "vrf1_name": "production",
    "vrf2_name": "external",
    "configured_fabrics": "both",
    "ip_version": "ipv4",
    "connectivity_details": {
        "routing_interface_type": "routed",
        "links": [
            {
                "mtu": 9216,
                "ipv4_mask_length": 30,
                "switch1_details": {
                    "switch_id": "FDO12345678",
                    "interface_name": "Ethernet1/1",
                    "interface_ipv4_address": "10.0.0.1",
                },
                "switch2_details": {
                    "switch_id": "FDO87654321",
                    "interface_name": "Ethernet1/1",
                    "interface_ipv4_address": "10.0.0.2",
                },
            }
        ],
    },
    "routing_details": {
        "routing_protocol": "bgp",
        "bfd": True,
        "hold_interval": 180,
        "keep_alive_interval": 60,
        "fabric1_details": {
            "advertise_default_route": True,
            "ipv4_peering_details": {
                "ipv4_route_map_in": "rm-in",
                "ipv4_route_map_out": "rm-out",
            },
        },
    },
}


# =============================================================================
# Test: Ipv4PeeringModel
# =============================================================================


def test_l3out_00010():
    """
    # Summary

    Verify Ipv4PeeringModel field defaults.

    ## Test

    - Instantiate with no arguments
    - All fields default to None

    ## Classes and Methods

    - Ipv4PeeringModel.__init__()
    """
    with does_not_raise():
        instance = Ipv4PeeringModel()
    assert instance.ipv4_route_map_in is None
    assert instance.ipv4_route_map_out is None


def test_l3out_00020():
    """
    # Summary

    Verify Ipv4PeeringModel construction with snake_case names.

    ## Test

    - Construct with Python field names
    - All values accessible

    ## Classes and Methods

    - Ipv4PeeringModel.__init__()
    """
    with does_not_raise():
        instance = Ipv4PeeringModel(
            ipv4_route_map_in="rm-in",
            ipv4_route_map_out="rm-out",
        )
    assert instance.ipv4_route_map_in == "rm-in"
    assert instance.ipv4_route_map_out == "rm-out"


def test_l3out_00030():
    """
    # Summary

    Verify Ipv4PeeringModel construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - Ipv4PeeringModel.__init__()
    """
    with does_not_raise():
        instance = Ipv4PeeringModel(
            ipv4RouteMapIn="rm-in-alias",
            ipv4RouteMapOut="rm-out-alias",
        )
    assert instance.ipv4_route_map_in == "rm-in-alias"
    assert instance.ipv4_route_map_out == "rm-out-alias"


# =============================================================================
# Test: SwitchDetailsModel
# =============================================================================


def test_l3out_00100():
    """
    # Summary

    Verify SwitchDetailsModel requires switch_id and interface_name.

    ## Test

    - Construct with only required fields
    - Optional fields default to None

    ## Classes and Methods

    - SwitchDetailsModel.__init__()
    """
    with does_not_raise():
        instance = SwitchDetailsModel(
            switch_id="FDO12345678",
            interface_name="Ethernet1/1",
        )
    assert instance.switch_id == "FDO12345678"
    assert instance.interface_name == "Ethernet1/1"
    assert instance.interface_ipv4_address is None
    assert instance.interface_ipv6_address is None
    assert instance.interface_description is None
    assert instance.interface_admin_state is None
    assert instance.netflow is None
    assert instance.netflow_monitor is None


def test_l3out_00110():
    """
    # Summary

    Verify SwitchDetailsModel with all fields populated.

    ## Test

    - Construct with all fields
    - All values accessible

    ## Classes and Methods

    - SwitchDetailsModel.__init__()
    """
    with does_not_raise():
        instance = SwitchDetailsModel(
            switch_id="FDO12345678",
            interface_name="Ethernet1/1",
            interface_ipv4_address="10.0.0.1",
            interface_ipv6_address="2001:db8::1",
            interface_description="uplink",
            interface_admin_state=True,
            netflow=True,
            netflow_monitor="mon1",
        )
    assert instance.switch_id == "FDO12345678"
    assert instance.interface_ipv4_address == "10.0.0.1"
    assert instance.interface_ipv6_address == "2001:db8::1"
    assert instance.interface_description == "uplink"
    assert instance.interface_admin_state is True
    assert instance.netflow is True
    assert instance.netflow_monitor == "mon1"


def test_l3out_00120():
    """
    # Summary

    Verify SwitchDetailsModel fails without required switch_id.

    ## Test

    - Construct without switch_id raises ValidationError

    ## Classes and Methods

    - SwitchDetailsModel.__init__()
    """
    with pytest.raises(ValidationError):
        SwitchDetailsModel(interface_name="Ethernet1/1")


# =============================================================================
# Test: LinkModel
# =============================================================================


def test_l3out_00200():
    """
    # Summary

    Verify LinkModel defaults - all fields optional.

    ## Test

    - Instantiate with no arguments
    - All fields default to None

    ## Classes and Methods

    - LinkModel.__init__()
    """
    with does_not_raise():
        instance = LinkModel()
    assert instance.mtu is None
    assert instance.ipv4_mask_length is None
    assert instance.dot1q_id is None
    assert instance.vlan_id is None
    assert instance.switch1_details is None
    assert instance.switch2_details is None


def test_l3out_00210():
    """
    # Summary

    Verify LinkModel with routed interface details.

    ## Test

    - Construct a routed link with switch details
    - Nested SwitchDetailsModel instances accessible

    ## Classes and Methods

    - LinkModel.__init__()
    """
    with does_not_raise():
        instance = LinkModel(
            mtu=9216,
            ipv4_mask_length=30,
            switch1_details=SwitchDetailsModel(
                switch_id="FDO12345678",
                interface_name="Ethernet1/1",
                interface_ipv4_address="10.0.0.1",
            ),
        )
    assert instance.mtu == 9216
    assert instance.ipv4_mask_length == 30
    assert instance.switch1_details.switch_id == "FDO12345678"


# =============================================================================
# Test: StaticRouteModel
# =============================================================================


def test_l3out_00300():
    """
    # Summary

    Verify StaticRouteModel requires all mandatory fields.

    ## Test

    - Construct with required fields only
    - Optional fields default to None

    ## Classes and Methods

    - StaticRouteModel.__init__()
    """
    with does_not_raise():
        instance = StaticRouteModel(
            ip_version="ipv4",
            ip_prefix="0.0.0.0/0",
            next_hop="192.168.100.254",
            switch_ids=["FDO12345678"],
        )
    assert instance.ip_version == "ipv4"
    assert instance.ip_prefix == "0.0.0.0/0"
    assert instance.next_hop == "192.168.100.254"
    assert instance.switch_ids == ["FDO12345678"]
    assert instance.route_preference is None
    assert instance.tag is None


def test_l3out_00310():
    """
    # Summary

    Verify StaticRouteModel fails without required ip_prefix.

    ## Test

    - Construct without ip_prefix raises ValidationError

    ## Classes and Methods

    - StaticRouteModel.__init__()
    """
    with pytest.raises(ValidationError):
        StaticRouteModel(
            ip_version="ipv4",
            next_hop="192.168.100.254",
            switch_ids=["FDO12345678"],
        )


# =============================================================================
# Test: RoutingDetailsModel
# =============================================================================


def test_l3out_00400():
    """
    # Summary

    Verify RoutingDetailsModel with BGP protocol.

    ## Test

    - Construct with routing_protocol=bgp and BGP-specific fields
    - Static routing fields remain None

    ## Classes and Methods

    - RoutingDetailsModel.__init__()
    """
    with does_not_raise():
        instance = RoutingDetailsModel(
            routing_protocol="bgp",
            bfd=True,
            hold_interval=180,
            keep_alive_interval=60,
            fabric1_details=FabricBgpDetailsModel(
                advertise_default_route=True,
            ),
        )
    assert instance.routing_protocol == "bgp"
    assert instance.bfd is True
    assert instance.hold_interval == 180
    assert instance.fabric1_details.advertise_default_route is True
    assert instance.fabric1_static_routes is None


def test_l3out_00410():
    """
    # Summary

    Verify RoutingDetailsModel with static protocol.

    ## Test

    - Construct with routing_protocol=static and static routes
    - BGP fields remain None

    ## Classes and Methods

    - RoutingDetailsModel.__init__()
    """
    with does_not_raise():
        instance = RoutingDetailsModel(
            routing_protocol="static",
            fabric1_static_routes=[
                StaticRouteModel(
                    ip_version="ipv4",
                    ip_prefix="0.0.0.0/0",
                    next_hop="192.168.100.254",
                    switch_ids=["FDO12345678"],
                )
            ],
        )
    assert instance.routing_protocol == "static"
    assert len(instance.fabric1_static_routes) == 1
    assert instance.fabric1_static_routes[0].next_hop == "192.168.100.254"
    assert instance.fabric1_details is None


# =============================================================================
# Test: FabricBgpDetailsModel
# =============================================================================


def test_l3out_00500():
    """
    # Summary

    Verify FabricBgpDetailsModel defaults.

    ## Test

    - Instantiate with no arguments
    - All fields default to None

    ## Classes and Methods

    - FabricBgpDetailsModel.__init__()
    """
    with does_not_raise():
        instance = FabricBgpDetailsModel()
    assert instance.local_asn is None
    assert instance.ipv4_peering_details is None
    assert instance.ipv6_peering_details is None
    assert instance.advertise_host_routes is None
    assert instance.advertise_default_route is None
    assert instance.auth_key is None


def test_l3out_00510():
    """
    # Summary

    Verify FabricBgpDetailsModel with nested peering details.

    ## Test

    - Construct with ipv4 and ipv6 peering details
    - Nested models accessible

    ## Classes and Methods

    - FabricBgpDetailsModel.__init__()
    """
    with does_not_raise():
        instance = FabricBgpDetailsModel(
            advertise_default_route=True,
            ipv4_peering_details=Ipv4PeeringModel(
                ipv4_route_map_in="rm-in",
                ipv4_route_map_out="rm-out",
            ),
            ipv6_peering_details=Ipv6PeeringModel(
                ipv6_route_map_in="rm6-in",
                ipv6_route_map_out="rm6-out",
            ),
        )
    assert instance.advertise_default_route is True
    assert instance.ipv4_peering_details.ipv4_route_map_in == "rm-in"
    assert instance.ipv6_peering_details.ipv6_route_map_out == "rm6-out"


# =============================================================================
# Test: L3OutModel - Basic Construction
# =============================================================================


def test_l3out_00600():
    """
    # Summary

    Verify L3OutModel requires name field.

    ## Test

    - Construct with only name
    - All optional fields default to None

    ## Classes and Methods

    - L3OutModel.__init__()
    """
    with does_not_raise():
        instance = L3OutModel(name="test-l3out")
    assert instance.name == "test-l3out"
    assert instance.fabric1_name is None
    assert instance.fabric2_name is None
    assert instance.vrf1_name is None
    assert instance.vrf2_name is None
    assert instance.configured_fabrics is None
    assert instance.ip_version is None
    assert instance.connectivity_details is None
    assert instance.routing_details is None
    assert instance.attach is None


def test_l3out_00610():
    """
    # Summary

    Verify L3OutModel fails without name.

    ## Test

    - Construct without name raises ValidationError

    ## Classes and Methods

    - L3OutModel.__init__()
    """
    with pytest.raises(ValidationError):
        L3OutModel()


def test_l3out_00620():
    """
    # Summary

    Verify L3OutModel construction from snake_case Ansible config.

    ## Test

    - Construct from SAMPLE_ANSIBLE_CONFIG
    - All fields accessible by Python names
    - Nested models constructed correctly

    ## Classes and Methods

    - L3OutModel.__init__()
    """
    with does_not_raise():
        instance = L3OutModel(**SAMPLE_ANSIBLE_CONFIG)
    assert instance.name == "test-l3out"
    assert instance.fabric1_name == "DC1-Fabric"
    assert instance.fabric2_name == "External-Fabric"
    assert instance.vrf1_name == "production"
    assert instance.vrf2_name == "external"
    assert instance.configured_fabrics == "both"
    assert instance.ip_version == "ipv4"
    assert instance.connectivity_details.routing_interface_type == "routed"
    assert len(instance.connectivity_details.links) == 1
    assert instance.connectivity_details.links[0].mtu == 9216
    assert instance.connectivity_details.links[0].switch1_details.switch_id == "FDO12345678"
    assert instance.routing_details.routing_protocol == "bgp"
    assert instance.routing_details.bfd is True
    assert instance.routing_details.fabric1_details.advertise_default_route is True
    assert instance.routing_details.fabric1_details.ipv4_peering_details.ipv4_route_map_in == "rm-in"


def test_l3out_00630():
    """
    # Summary

    Verify L3OutModel construction from camelCase API response.

    ## Test

    - Construct from SAMPLE_API_RESPONSE using model_validate(by_alias=True)
    - All fields accessible by Python names

    ## Classes and Methods

    - L3OutModel.model_validate()
    """
    with does_not_raise():
        instance = L3OutModel.model_validate(SAMPLE_API_RESPONSE)
    assert instance.name == "test-l3out"
    assert instance.fabric1_name == "DC1-Fabric"
    assert instance.connectivity_details.routing_interface_type == "routed"
    assert instance.routing_details.hold_interval == 180


# =============================================================================
# Test: L3OutModel - Identifier
# =============================================================================


def test_l3out_00700():
    """
    # Summary

    Verify get_identifier_value returns name (single strategy).

    ## Test

    - L3OutModel with name returns name string
    - identifier_strategy is "single"

    ## Classes and Methods

    - L3OutModel.get_identifier_value()
    """
    instance = L3OutModel(name="my-l3out")
    assert instance.get_identifier_value() == "my-l3out"
    assert L3OutModel.identifier_strategy == "single"
    assert L3OutModel.identifiers == ["name"]


# =============================================================================
# Test: L3OutModel - Serialization
# =============================================================================


def test_l3out_00800():
    """
    # Summary

    Verify to_payload produces camelCase keys and excludes attach.

    ## Test

    - Construct model with attach=True
    - to_payload() output uses camelCase keys
    - attach field is excluded from payload

    ## Classes and Methods

    - L3OutModel.to_payload()
    """
    config = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config["attach"] = True
    instance = L3OutModel(**config)

    payload = instance.to_payload()
    assert "name" in payload
    assert "fabric1Name" in payload
    assert "connectivityDetails" in payload
    assert "routingDetails" in payload
    # attach must be excluded
    assert "attach" not in payload


def test_l3out_00810():
    """
    # Summary

    Verify to_config produces snake_case keys.

    ## Test

    - Construct model from API response
    - to_config() output uses snake_case keys

    ## Classes and Methods

    - L3OutModel.to_config()
    """
    instance = L3OutModel.from_response(SAMPLE_API_RESPONSE)
    config = instance.to_config()
    assert "name" in config
    assert "fabric1_name" in config
    assert "connectivity_details" in config
    assert "routing_details" in config
    # Verify nested keys are snake_case
    assert "routing_interface_type" in config["connectivity_details"]


def test_l3out_00820():
    """
    # Summary

    Verify from_response -> to_payload round-trip preserves data.

    ## Test

    - Create from API response
    - Convert to payload
    - All key API fields present with correct values

    ## Classes and Methods

    - L3OutModel.from_response()
    - L3OutModel.to_payload()
    """
    instance = L3OutModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()

    assert payload["name"] == "test-l3out"
    assert payload["fabric1Name"] == "DC1-Fabric"
    assert payload["configuredFabrics"] == "both"
    assert payload["connectivityDetails"]["routingInterfaceType"] == "routed"
    assert payload["routingDetails"]["routingProtocol"] == "bgp"
    assert payload["routingDetails"]["holdInterval"] == 180
    assert payload["routingDetails"]["fabric1Details"]["ipv4PeeringDetails"]["ipv4RouteMapIn"] == "rm-in"


def test_l3out_00830():
    """
    # Summary

    Verify from_config -> to_config round-trip preserves data.

    ## Test

    - Create from Ansible config
    - Convert back to config
    - All key fields present with correct values

    ## Classes and Methods

    - L3OutModel.from_config()
    - L3OutModel.to_config()
    """
    instance = L3OutModel.from_config(SAMPLE_ANSIBLE_CONFIG)
    config = instance.to_config()

    assert config["name"] == "test-l3out"
    assert config["fabric1_name"] == "DC1-Fabric"
    assert config["configured_fabrics"] == "both"
    assert config["connectivity_details"]["routing_interface_type"] == "routed"
    assert config["routing_details"]["routing_protocol"] == "bgp"


# =============================================================================
# Test: L3OutModel - Diff
# =============================================================================


def test_l3out_00900():
    """
    # Summary

    Verify get_diff returns False when models are identical.

    ## Test

    - Create two identical models
    - get_diff returns False (no difference)

    ## Classes and Methods

    - L3OutModel.get_diff()
    """
    instance_a = L3OutModel(**SAMPLE_ANSIBLE_CONFIG)
    instance_b = L3OutModel(**SAMPLE_ANSIBLE_CONFIG)

    # get_diff returns True when other is a subset (no diff), False when there IS a diff
    assert instance_a.get_diff(instance_b) is True


def test_l3out_00910():
    """
    # Summary

    Verify get_diff detects differences.

    ## Test

    - Create two models with different hold_interval
    - get_diff returns True (difference found)

    ## Classes and Methods

    - L3OutModel.get_diff()
    """
    config_a = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config_b = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config_b["routing_details"]["hold_interval"] = 240

    instance_a = L3OutModel(**config_a)
    instance_b = L3OutModel(**config_b)

    # instance_b is NOT a subset of instance_a because hold_interval differs
    assert instance_a.get_diff(instance_b) is False


def test_l3out_00920():
    """
    # Summary

    Verify attach is excluded from diff comparison.

    ## Test

    - Create two models identical except for attach field
    - get_diff returns True (no difference - attach excluded)

    ## Classes and Methods

    - L3OutModel.get_diff()
    - L3OutModel.exclude_from_diff
    """
    config_a = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config_a["attach"] = True
    config_b = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config_b["attach"] = False

    instance_a = L3OutModel(**config_a)
    instance_b = L3OutModel(**config_b)

    assert instance_a.get_diff(instance_b) is True


# =============================================================================
# Test: L3OutModel - Merge
# =============================================================================


def test_l3out_01000():
    """
    # Summary

    Verify merge updates explicitly set fields only.

    ## Test

    - Create base model with full config
    - Create update model with only hold_interval changed
    - Merge updates hold_interval without clearing other fields

    ## Classes and Methods

    - L3OutModel.merge()
    """
    base = L3OutModel(**SAMPLE_ANSIBLE_CONFIG)
    update = L3OutModel(
        name="test-l3out",
        routing_details=RoutingDetailsModel(
            routing_protocol="bgp",
            hold_interval=240,
        ),
    )

    base.merge(update)
    assert base.routing_details.hold_interval == 240
    # Other fields should be preserved
    assert base.fabric1_name == "DC1-Fabric"
    assert base.configured_fabrics == "both"


# =============================================================================
# Test: L3OutModel - ClassVar Configuration
# =============================================================================


def test_l3out_01100():
    """
    # Summary

    Verify ClassVar configuration for payload exclusion and diff exclusion.

    ## Test

    - payload_exclude_fields contains "attach"
    - exclude_from_diff contains "attach"

    ## Classes and Methods

    - L3OutModel class attributes
    """
    assert "attach" in L3OutModel.payload_exclude_fields
    assert "attach" in L3OutModel.exclude_from_diff


# =============================================================================
# Test: L3OutModel - get_argument_spec
# =============================================================================


def test_l3out_01200():
    """
    # Summary

    Verify get_argument_spec returns valid Ansible argument specification.

    ## Test

    - Returns dict with fabric_name, state, config keys
    - state has correct choices (merged, replaced, deleted)
    - config is list of dicts with l3out_spec options
    - Nested specs have required fields marked

    ## Classes and Methods

    - L3OutModel.get_argument_spec()
    """
    spec = L3OutModel.get_argument_spec()

    # Top-level keys
    assert "fabric_name" in spec
    assert spec["fabric_name"]["required"] is True
    assert "state" in spec
    assert spec["state"]["default"] == "merged"
    assert set(spec["state"]["choices"]) == {"merged", "replaced", "deleted"}
    assert "config" in spec
    assert spec["config"]["type"] == "list"
    assert spec["config"]["elements"] == "dict"

    # L3Out item spec
    l3out_opts = spec["config"]["options"]
    assert l3out_opts["name"]["required"] is True
    assert "attach" in l3out_opts
    assert "connectivity_details" in l3out_opts
    assert "routing_details" in l3out_opts

    # Connectivity details nested spec
    conn_opts = l3out_opts["connectivity_details"]["options"]
    assert conn_opts["routing_interface_type"]["required"] is True
    assert set(conn_opts["routing_interface_type"]["choices"]) == {"routed", "subInterface", "svi"}

    # Routing details nested spec
    routing_opts = l3out_opts["routing_details"]["options"]
    assert routing_opts["routing_protocol"]["required"] is True
    assert set(routing_opts["routing_protocol"]["choices"]) == {"static", "bgp"}

    # auth_key has no_log
    fabric_details_opts = routing_opts["fabric1_details"]["options"]
    assert fabric_details_opts["auth_key"]["no_log"] is True
