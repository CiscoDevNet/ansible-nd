# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""eBGP collection-item and CLI text contracts shared by the AI eBGP model."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel

FAMILIES = (FabricEbgpModel, FabricAiEbgpVxlanModel)
CLI_FIELDS = (
    ("banner", "banner"),
    ("extra_config_leaf", "extraConfigLeaf"),
    ("extra_config_spine", "extraConfigSpine"),
    ("extra_config_tor", "extraConfigTor"),
    ("extra_config_intra_fabric_links", "extraConfigIntraFabricLinks"),
    ("extra_config_aaa", "extraConfigAaa"),
    ("extra_config_nxos_bootstrap", "extraConfigNxosBootstrap"),
    ("pre_interface_config_leaf", "preInterfaceConfigLeaf"),
    ("pre_interface_config_spine", "preInterfaceConfigSpine"),
    ("pre_interface_config_tor", "preInterfaceConfigTor"),
)
COLLECTIONS = (
    ("dns_collection", "dnsCollection"),
    ("dns_vrf_collection", "dnsVrfCollection"),
    ("ntp_server_collection", "ntpServerCollection"),
    ("syslog_server_collection", "syslogServerCollection"),
    ("syslog_severity_collection", "syslogSeverityCollection"),
)


def _config(**management):
    return {"fabric_name": "ebgp_native_probe", "management": {"bgp_asn": "65001", **management}}


def _argspec(model_class, config):
    checked = ModuleArgumentSpecValidator(model_class.get_argument_spec()).validate({"state": "merged", "config": [deepcopy(config)]})
    assert checked.error_messages == []
    return checked.validated_parameters["config"][0]


@pytest.mark.parametrize("model_class", FAMILIES)
@pytest.mark.parametrize(("field", "alias"), CLI_FIELDS)
@pytest.mark.parametrize("value", ("\n  interface loopback17\n    description untouched  \n\t", " \t\n"))
def test_ebgp_cli_values_preserve_exact_whitespace_through_public_replay(model_class, field, alias, value):
    """Native CLI text must survive input, payload, response and gathered replay byte for byte."""
    proposed = model_class.from_config(_argspec(model_class, _config(**{field: value})))
    assert proposed.to_payload()["management"][alias] == value
    existing = model_class.from_response(deepcopy(proposed.to_payload()))
    gathered = existing.to_gathered_config()
    assert gathered["management"][field] == value
    replay = model_class.from_config(_argspec(model_class, gathered))
    assert replay.to_payload()["management"][alias] == value


@pytest.mark.parametrize("model_class", FAMILIES)
def test_ebgp_cli_defaults_and_non_cli_trimming_remain_unchanged(model_class):
    """CLI exceptions retain empty defaults while identifiers still use their existing trimming policy."""
    config = _config()
    config["fabric_name"] = "  ebgp_native_probe  "
    model = model_class.from_config(config)
    assert model.fabric_name == "ebgp_native_probe"
    for field, alias in CLI_FIELDS:
        assert model.to_payload()["management"][alias] == ""
        assert field not in model.management.model_fields_set


@pytest.mark.parametrize("model_class", FAMILIES)
@pytest.mark.parametrize(
    ("field", "alias", "items"),
    (
        ("dns_collection", "dnsCollection", ["192.0.2.1", "2001:0DB8::53"]),
        ("dns_vrf_collection", "dnsVrfCollection", ["v", "V" * 80]),
        ("ntp_server_collection", "ntpServerCollection", ["192.0.2.2", "2001:db8::2", "n" * 80]),
        ("syslog_server_collection", "syslogServerCollection", ["192.0.2.3", "2001:db8::3", "s" * 199]),
        ("syslog_severity_collection", "syslogSeverityCollection", [0, 7]),
    ),
)
def test_ebgp_collection_item_boundaries_survive_payload_and_gathered_replay(model_class, field, alias, items):
    """Address-only DNS, server hostname support and collection-item limits are independent contracts."""
    model = model_class.from_config(_argspec(model_class, _config(**{field: items})))
    assert model.to_payload()["management"][alias] == items
    response = model_class.from_response(model.to_payload())
    replay = model_class.from_config(_argspec(model_class, response.to_gathered_config()))
    assert replay.to_payload()["management"][alias] == items


@pytest.mark.parametrize("model_class", FAMILIES)
@pytest.mark.parametrize(
    ("field", "item"),
    (
        ("dns_collection", "resolver.example.test"),
        ("dns_collection", "not-an-address"),
        ("dns_vrf_collection", ""),
        ("dns_vrf_collection", "v" * 81),
        ("ntp_server_collection", ""),
        ("ntp_server_collection", "n" * 81),
        ("syslog_server_collection", ""),
        ("syslog_server_collection", "s" * 200),
        ("syslog_severity_collection", -1),
        ("syslog_severity_collection", 8),
    ),
)
def test_ebgp_invalid_collection_items_fail_the_current_model_contract(model_class, field, item):
    """Each primitive-list item contract rejects values outside its accepted bounds."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: [item]}))


@pytest.mark.parametrize("model_class", FAMILIES)
def test_ebgp_collection_defaults_and_unconstrained_server_vrf_inputs_stay_independent(model_class):
    """Item validation changes neither empty-list defaults nor unrelated VRF collection contracts."""
    model = model_class.from_config(_config(ntp_server_vrf_collection=["n" * 300], syslog_server_vrf_collection=["s" * 300]))
    for field, alias in COLLECTIONS:
        assert model.to_payload()["management"][alias] == []
        assert field not in model.management.model_fields_set
    assert model.management.ntp_server_vrf_collection == ["n" * 300]
    assert model.management.syslog_server_vrf_collection == ["s" * 300]


@pytest.mark.parametrize("model_class", FAMILIES)
@pytest.mark.parametrize("telemetry_collection", (False, True))
@pytest.mark.parametrize("mode", (None, "inBand", "outOfBand"))
def test_ebgp_telemetry_mode_uses_api_default_and_preserves_explicit_choices(model_class, telemetry_collection, mode):
    """The eBGP-only root default follows the API without coupling mode selection to enablement."""
    config = _config()
    config["telemetry_collection"] = telemetry_collection
    if mode is not None:
        config["telemetry_collection_type"] = mode
    model = model_class.from_config(_argspec(model_class, config))
    assert model.to_payload()["telemetryCollectionType"] == (mode or "outOfBand")
    assert model.to_payload()["telemetryCollection"] is telemetry_collection


@pytest.mark.parametrize("model_class", FAMILIES)
def test_ebgp_nxapi_http_native_default_and_explicit_values_participate_in_comparison(model_class):
    """The native default remains true while a requested false value produces an ordinary intent diff."""
    omitted = model_class.from_config(_config())
    assert omitted.to_payload()["management"]["nxapiHttp"] is True
    assert "nxapi_http" not in omitted.management.model_fields_set
    disabled = model_class.from_config(_config(nxapi_http=False))
    assert disabled.to_payload()["management"]["nxapiHttp"] is False
    assert disabled.to_diff_dict()["management"]["nxapiHttp"] is False
    assert omitted.to_diff_dict()["management"]["nxapiHttp"] is True
    assert omitted.get_diff(disabled, exclude_unset=True) is False
    assert disabled.get_diff(omitted, exclude_unset=False) is False


@pytest.mark.parametrize("model_class", FAMILIES)
@pytest.mark.parametrize("provided", (None, 1, 64))
def test_ebgp_maximum_paths_native_default_and_explicit_bounds_round_trip(model_class, provided):
    """The native default and explicit valid limits survive public input and gathered replay."""
    config = _config() if provided is None else _config(bgp_max_path=provided)
    expected = 64 if provided is None else provided
    model = model_class.from_config(_argspec(model_class, config))
    assert model.to_payload()["management"]["bgpMaxPath"] == expected
    assert ("bgp_max_path" in model.management.model_fields_set) is (provided is not None)
    response = model_class.from_response(model.to_payload())
    replay = model_class.from_config(_argspec(model_class, response.to_gathered_config()))
    assert replay.to_payload()["management"]["bgpMaxPath"] == expected


@pytest.mark.parametrize("model_class", FAMILIES)
@pytest.mark.parametrize("provided", (0, 65))
def test_ebgp_maximum_paths_outside_native_and_api_bounds_fail(model_class, provided):
    """Changing the default keeps the existing one-through-64 validation contract."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(bgp_max_path=provided))
