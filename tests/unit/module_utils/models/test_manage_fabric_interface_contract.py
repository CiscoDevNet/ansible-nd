"""Fabric argument-spec and gathered-state interface contract tests."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_base import (
    _build_options_from_model,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    FabricGroupVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)


class MappingShapesModel(NDNestedModel):
    """Representative generic mapping annotations used by fabric models."""

    dict_value: dict[str, Any] = Field(default_factory=dict)
    mapping_value: Mapping[str, Any] = Field(default_factory=dict)
    dict_list_value: list[dict[str, Any]] = Field(default_factory=list)
    mapping_list_value: list[Mapping[str, Any]] = Field(default_factory=list)


REGULAR_FABRIC_MODELS = (
    FabricExternalConnectivityModel,
    FabricIbgpModel,
    FabricEbgpModel,
    FabricAiIbgpVxlanModel,
    FabricAiEbgpVxlanModel,
    FabricCampusIbgpVxlanModel,
)

ALL_FABRIC_MODELS = (*REGULAR_FABRIC_MODELS, FabricGroupVxlanModel)

TELEMETRY_CHOICES = {
    ("flow_collection", "traffic_analytics"): ["compatibility", "disabled", "enabled"],
    ("flow_collection", "traffic_analytics_scope"): [
        "interFabric",
        "interFabricAndExternal",
        "intraFabric",
    ],
    ("flow_collection", "udp_categorization"): ["disabled", "enabled"],
    ("microburst", "sensitivity"): ["high", "low", "medium"],
    ("nas", "export_settings", "export_type"): ["base", "full"],
    ("nas", "export_settings", "export_format"): ["json"],
}

TELEMETRY_CONFIG = {
    "flow_collection": {
        "traffic_analytics": "compatibility",
        "traffic_analytics_scope": "interFabricAndExternal",
        "udp_categorization": "disabled",
    },
    "microburst": {
        "sensitivity": "high",
    },
    "nas": {
        "export_settings": {
            "export_type": "base",
            "export_format": "json",
        }
    },
}

MANAGEMENT_WIRE_VALUE_CASES = (
    (
        FabricIbgpModel,
        {"overlay_mode": "config-profile", "link_state_routing_protocol": "isis"},
        {"overlayMode": "configProfile", "linkStateRoutingProtocol": "is-is"},
    ),
    (
        FabricAiIbgpVxlanModel,
        {"overlay_mode": "config-profile", "link_state_routing_protocol": "isis"},
        {"overlayMode": "configProfile", "linkStateRoutingProtocol": "is-is"},
    ),
    (
        FabricEbgpModel,
        {"overlay_mode": "config-profile"},
        {"overlayMode": "configProfile"},
    ),
    (
        FabricAiEbgpVxlanModel,
        {"overlay_mode": "config-profile"},
        {"overlayMode": "configProfile"},
    ),
)

STREAMING_CONFIG = {
    "email": [
        {
            "addresses": ["fabric-ops@example.invalid"],
            "collection_settings": {"anomalies": ["critical"]},
        }
    ],
    "message_bus": [
        {
            "servers": ["broker.example.invalid:9092"],
            "authentication": {"enabled": False},
        }
    ],
    "syslog": {
        "collectionSettings": {"anomalies": ["major"]},
        "facility": "local7",
        "servers": [{"host": "192.0.2.10", "port": 514}],
    },
    "webhooks": [
        {
            "url": "https://example.invalid/fabric-events",
            "headers": {"X-Audit": "round-trip"},
        }
    ],
}


def _input_config(model_class: type) -> dict[str, Any]:
    """Return a representative replayable config for one fabric model."""
    if model_class is FabricGroupVxlanModel:
        return {
            "fabric_name": "contract_fabric_group",
            "management": {
                "route_server_collection": [
                    {
                        "route_server_ip": "192.0.2.1",
                        "route_server_asn": "65001",
                    }
                ]
            },
        }
    return {
        "fabric_name": f"contract_{model_class.__name__}",
        "management": {"bgp_asn": "65001"},
        "external_streaming_settings": deepcopy(STREAMING_CONFIG),
    }


def _validate(argument_spec: dict[str, Any], config: dict[str, Any]):
    """Validate one module config and assert the Ansible contract accepted it."""
    result = ModuleArgumentSpecValidator(argument_spec).validate({"state": "merged", "config": [deepcopy(config)]})
    assert result.error_messages == []
    assert result.unsupported_parameters == set()
    return result.validated_parameters["config"][0]


def _nested_value(value: dict[str, Any], path: tuple[str, ...]) -> Any:
    """Return a value from a nested configuration path."""
    for key in path:
        value = value[key]
    return value


def _set_nested_value(value: dict[str, Any], path: tuple[str, ...], replacement: Any) -> None:
    """Set a value at a nested configuration path."""
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


def test_build_options_preserves_generic_mapping_shapes():
    """dict, Mapping, list[dict], and list[Mapping] remain structured options."""
    options = _build_options_from_model(MappingShapesModel)

    assert options["dict_value"] == {"type": "dict"}
    assert options["mapping_value"] == {"type": "dict"}
    assert options["dict_list_value"] == {"type": "list", "elements": "dict"}
    assert options["mapping_list_value"] == {"type": "list", "elements": "dict"}


@pytest.mark.parametrize("model_class", REGULAR_FABRIC_MODELS)
def test_regular_fabric_argument_specs_preserve_external_streaming_mappings(
    model_class,
):
    """Every regular fabric exposes external streaming mappings without coercion."""
    validated = _validate(model_class.get_argument_spec(), _input_config(model_class))

    assert validated["external_streaming_settings"] == STREAMING_CONFIG


@pytest.mark.parametrize("model_class", REGULAR_FABRIC_MODELS)
def test_regular_fabric_argument_specs_expose_all_telemetry_enum_choices(model_class):
    """Every ordinary fabric exposes the shared telemetry enum constraints."""
    telemetry_options = model_class.get_argument_spec()["config"]["options"]["telemetry_settings"]["options"]

    for path, choices in TELEMETRY_CHOICES.items():
        option = telemetry_options
        for key in path:
            option = option[key] if "type" not in option else option["options"][key]
        assert option["type"] == "str"
        assert option["choices"] == choices


@pytest.mark.parametrize("model_class", REGULAR_FABRIC_MODELS)
def test_regular_fabric_telemetry_enums_round_trip_through_wire_and_gathered(
    model_class,
):
    """All shared telemetry enum choices remain replayable for every fabric."""
    config = _input_config(model_class)
    config["telemetry_settings"] = deepcopy(TELEMETRY_CONFIG)

    configured = model_class.from_config(config)
    payload = configured.to_payload()
    gathered = model_class.from_response(payload).to_gathered_config()
    replayed = _validate(model_class.get_argument_spec(), gathered)

    for path in TELEMETRY_CHOICES:
        expected = _nested_value(TELEMETRY_CONFIG, path)
        assert _nested_value(gathered["telemetry_settings"], path) == expected
        assert _nested_value(replayed["telemetry_settings"], path) == expected


@pytest.mark.parametrize("model_class", REGULAR_FABRIC_MODELS)
@pytest.mark.parametrize("path", TELEMETRY_CHOICES)
def test_regular_fabric_telemetry_enums_reject_unknown_values(model_class, path):
    """Every ordinary fabric rejects values outside each shared telemetry enum."""
    config = _input_config(model_class)
    config["telemetry_settings"] = deepcopy(TELEMETRY_CONFIG)
    _set_nested_value(config["telemetry_settings"], path, "not-a-controller-choice")

    with pytest.raises(ValueError):
        model_class.from_config(config)


@pytest.mark.parametrize(("model_class", "public_values", "wire_values"), MANAGEMENT_WIRE_VALUE_CASES)
def test_management_friendly_enum_values_translate_bidirectionally(model_class, public_values, wire_values):
    """iBGP/eBGP parents and AI children keep public values off the wire."""
    config = _input_config(model_class)
    config["management"].update(public_values)

    configured = model_class.from_config(config)
    payload = configured.to_payload()
    response_model = model_class.from_response(payload)
    management_class = type(configured.management)

    for public_key, public_value in public_values.items():
        field = management_class.model_fields[public_key]
        wire_key = field.alias or public_key
        assert configured.to_config()["management"][public_key] == public_value
        assert configured.to_diff_dict()["management"][wire_key] == public_value
        assert configured.to_gathered_config()["management"][public_key] == public_value
        assert payload["management"][wire_key] == wire_values[wire_key]
        assert response_model.to_config()["management"][public_key] == public_value
        assert set(field.json_schema_extra["wire_value_map"]) == {member.value for member in field.annotation}

    invalid = _input_config(model_class)
    invalid["management"].update({public_key: wire_values[type(configured.management).model_fields[public_key].alias] for public_key in public_values})
    with pytest.raises(ValueError):
        model_class.from_config(invalid)


@pytest.mark.parametrize("model_class", ALL_FABRIC_MODELS)
def test_fabric_gathered_config_is_a_complete_replayable_round_trip(model_class):
    """All fabric families survive Ansible, wire, response, gathered, and replay."""
    argument_spec = model_class.get_argument_spec()
    initial = _validate(argument_spec, _input_config(model_class))
    proposed = model_class.from_config(initial)
    payload = proposed.to_payload()

    response = deepcopy(payload)
    response["responseOnlyMarker"] = "must-not-be-gathered"
    response["management"]["responseOnlyNested"] = "must-not-be-gathered"
    existing = model_class.from_response(response)
    gathered = existing.to_gathered_config()
    replayed = _validate(argument_spec, gathered)

    assert "category" not in gathered
    assert "responseOnlyMarker" not in gathered
    assert "name" not in gathered["management"]
    assert "type" not in gathered["management"]
    assert "responseOnlyNested" not in gathered["management"]

    if model_class is FabricGroupVxlanModel:
        route_servers = gathered["management"]["route_server_collection"]
        assert route_servers == [{"route_server_ip": "192.0.2.1", "route_server_asn": "65001"}]
        assert replayed["management"]["route_server_collection"] == route_servers
    else:
        assert gathered["external_streaming_settings"] == STREAMING_CONFIG
        assert replayed["external_streaming_settings"] == STREAMING_CONFIG

    if model_class in (FabricEbgpModel, FabricAiEbgpVxlanModel):
        assert "evpn" not in gathered["management"]
    if model_class in (FabricAiIbgpVxlanModel, FabricAiEbgpVxlanModel):
        assert "aiml_qos" not in gathered["management"]


@pytest.mark.parametrize("model_class", REGULAR_FABRIC_MODELS)
def test_response_origin_ipv6_dhcp_addresses_round_trip_through_gathered_config(model_class):
    """A controller-returned DHCPv6 trio remains valid after Ansible config validation."""
    addresses = {
        "dhcp_start_address": ("dhcpStartAddress", "2001:db8::10"),
        "dhcp_end_address": ("dhcpEndAddress", "2001:db8::20"),
        "management_gateway": ("managementGateway", "2001:db8::1"),
    }
    response = {
        "name": "fabric1",
        "category": "fabric",
        "management": {
            "type": model_class._fabric_type.value,
            "bgpAsn": "65001",
            "dhcpProtocolVersion": "dhcpv6",
            **{wire_key: value for wire_key, value in addresses.values()},
        },
    }

    gathered = model_class.from_response(response).to_gathered_config()
    replayed_config = _validate(model_class.get_argument_spec(), gathered)
    replayed_payload = model_class.from_config(replayed_config).to_payload()

    assert gathered["management"]["dhcp_protocol_version"] == "dhcpv6"
    assert replayed_config["management"]["dhcp_protocol_version"] == "dhcpv6"
    assert replayed_payload["management"]["dhcpProtocolVersion"] == "dhcpv6"
    for public_key, (wire_key, value) in addresses.items():
        assert gathered["management"][public_key] == value
        assert replayed_config["management"][public_key] == value
        assert replayed_payload["management"][wire_key] == value
