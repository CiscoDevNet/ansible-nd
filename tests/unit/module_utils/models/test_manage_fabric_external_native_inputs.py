# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""External native input contracts, release defaults, and replay boundaries."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

CLI_FIELDS = (
    ("extra_config_aaa", "extraConfigAaa"),
    ("extra_config_fabric", "extraConfigFabric"),
    ("extra_config_nxos_bootstrap", "extraConfigNxosBootstrap"),
    ("extra_config_xe_bootstrap", "extraConfigXeBootstrap"),
)
DEFAULTS_4_3 = {
    "ai_monitoring": False,
    "allow_smart_switch_ha": False,
    "auto_smart_switch_vpc_pair_ha": False,
    "enable_remote_switch_backup": False,
    "hypershield_ha_peer_link_subnet": "10.12.0.0/22",
    "hypershield_ha_peer_link_subnet_granularity": "/30",
    "hypershield_ha_source_intf": "loopback1023",
    "hypershield_ha_source_subnet": "10.11.0.0/23",
    "hypershield_ha_vlan": 3601,
    "ios_xe_tor_bootstrap_vlan": 1,
    "software_update_in_monitored_mode": False,
    "strict_config_compliance_mode": False,
    "use_hypershield_source_loopback_for_ha": False,
}


def _config(**management):
    return {
        "fabric_name": "external_native_probe",
        "management": {"bgp_asn": "65001", **management},
    }


def _argspec(config):
    checked = ModuleArgumentSpecValidator(FabricExternalConnectivityModel.get_argument_spec()).validate({"state": "merged", "config": [deepcopy(config)]})
    assert checked.error_messages == []
    return checked.validated_parameters["config"][0]


def _preflight(model, version):
    rest = RestSend({"check_mode": False, "state": "merged"})
    rest.controller_product_version = version
    ManageExternalFabricOrchestrator(rest_send=rest).preflight([model])


@pytest.mark.parametrize(("field", "alias"), CLI_FIELDS)
@pytest.mark.parametrize("value", ("\n  interface loopback17\n    description untouched  \n\t", " \t\n"))
def test_external_cli_text_survives_input_and_gathered_replay(field, alias, value):
    """Native freeform text retains indentation and trailing whitespace through public replay."""
    model = FabricExternalConnectivityModel.from_config(_argspec(_config(**{field: value})))
    assert model.to_payload()["management"][alias] == value
    existing = FabricExternalConnectivityModel.from_response(model.to_payload())
    gathered = existing.to_gathered_config()
    assert gathered["management"][field] == value
    replay = FabricExternalConnectivityModel.from_config(_argspec(gathered))
    assert replay.to_payload()["management"][alias] == value


@pytest.mark.parametrize(
    ("field", "alias", "items"),
    (
        ("dns_collection", "dnsCollection", ["192.0.2.53", "2001:0DB8::53"]),
        ("dns_vrf_collection", "dnsVrfCollection", ["v", "V" * 80]),
    ),
)
def test_external_dns_item_boundaries_replay_without_changing_spelling(field, alias, items):
    """IP-only DNS and independent VRF item lengths survive payload and public replay."""
    model = FabricExternalConnectivityModel.from_config(_argspec(_config(**{field: items})))
    assert model.to_payload()["management"][alias] == items
    existing = FabricExternalConnectivityModel.from_response(model.to_payload())
    replay = FabricExternalConnectivityModel.from_config(_argspec(existing.to_gathered_config()))
    assert replay.to_payload()["management"][alias] == items


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("dns_collection", "dns.example.test"),
        ("dns_collection", "192.0.2.256"),
        ("dns_collection", "2001:db8::invalid"),
        ("dns_collection", "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"),
        ("dns_vrf_collection", ""),
        ("dns_vrf_collection", "v" * 81),
    ),
)
def test_external_invalid_dns_items_fail_before_payload_construction(field, value):
    """Malformed addresses and VRFs outside their item limits fail model validation."""
    with pytest.raises(ValidationError):
        FabricExternalConnectivityModel.from_config(_config(**{field: [value]}))


@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)", "4.3.1", "4.4.1"))
def test_external_release_defaults_are_absent_only_before_their_first_release(version):
    """Omitted newer defaults are filtered without changing baseline External defaults."""
    model = FabricExternalConnectivityModel.from_config(_config())
    _preflight(model, version)
    payload = model.to_payload()["management"]
    options = model.get_argument_spec()["config"]["options"]["management"]["options"]
    for field, expected in DEFAULTS_4_3.items():
        alias = type(model.management).model_fields[field].alias
        assert field not in model.management.model_fields_set
        assert "default" not in options[field]
        if version.startswith("4.2"):
            assert alias not in payload
        else:
            assert payload[alias] == expected
    assert "remoteStorageServer" not in payload
    assert payload["monitoredMode"] is True
    assert payload["nxapi"] is False
    assert payload["nxapiHttp"] is False
    assert model.to_payload()["telemetryCollectionType"] == "outOfBand"


@pytest.mark.parametrize(("field", "value"), DEFAULTS_4_3.items())
def test_external_explicit_newer_default_values_are_rejected_on_4_2(field, value):
    """Explicit default-equal values, including false, remain supplied release-gated input."""
    model = FabricExternalConnectivityModel.from_config(_config(**{field: value}))
    with pytest.raises(RuntimeError, match=rf"management\.{field}.*requires ND 4\.3\.1"):
        _preflight(model, "4.2.1")


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize(
    ("supplied", "expected"),
    (
        ("+65000", "65000"),
        ("+4294967295", "4294967295"),
        ("1.0", "1.0"),
        ("65535.65535", "65535.65535"),
    ),
)
def test_external_native_asn_spelling_normalizes_to_the_api_contract(version, supplied, expected):
    """Only decimal ASNs accept a native plus sign, with stable unsigned wire and gathered values."""
    model = FabricExternalConnectivityModel.from_config(_argspec(_config(bgp_asn=supplied)))
    _preflight(model, version)
    assert model.to_payload()["management"]["bgpAsn"] == expected
    raw = model.to_payload()
    raw["management"]["bgpAsn"] = supplied
    existing = FabricExternalConnectivityModel.from_response(raw)
    gathered = existing.to_gathered_config()
    assert gathered["management"]["bgp_asn"] == expected
    replay = FabricExternalConnectivityModel.from_config(_argspec(gathered))
    _preflight(replay, version)
    assert replay.to_payload()["management"]["bgpAsn"] == expected
    assert existing.get_diff(replay, exclude_unset=False) is True


@pytest.mark.parametrize("value", ("+0", "+4294967296", "+1.2", "+", "++65000", "65536.1"))
def test_external_invalid_native_asns_are_rejected(value):
    """Native decimal bounds and unsigned asdot constraints remain enforced."""
    with pytest.raises(ValidationError):
        FabricExternalConnectivityModel.from_config(_config(bgp_asn=value))


def test_external_empty_asn_remains_omitted_for_partial_management():
    """Blank optional ASN input retains the established partial-input unset policy."""
    model = FabricExternalConnectivityModel.from_config(_config(bgp_asn=""))
    assert model.management.bgp_asn is None
    assert "bgpAsn" not in model.to_payload()["management"]
