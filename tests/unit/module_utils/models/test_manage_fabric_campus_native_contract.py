# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Campus native constraints, release defaults, and public replay boundaries."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    CampusIbgpVxlanManagementModel,
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import NDMinimumVersion
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_campus_ibgp_vxlan import ManageCampusIbgpVxlanFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

RANGE_FIELDS = (
    ("vpc_peer_link_vlan", 2, 4094),
    ("vpc_peer_link_port_channel_id", 1, 4096),
    ("vpc_domain_id_range", 1, 1000),
    ("l2_vni_range", 1, 16777214),
    ("l3_vni_range", 1, 16777214),
    ("network_vlan_range", 2, 4094),
    ("vrf_vlan_range", 2, 4094),
    ("sub_interface_dot1q_range", 2, 4094),
)
IPV4_POOL_FIELDS = (
    "bgp_loopback_ip_range",
    "nve_loopback_ip_range",
    "anycast_rendezvous_point_ip_range",
    "intra_fabric_subnet_range",
    "per_vrf_loopback_ip_range",
)
CLI_FIELDS = (
    "banner",
    "ios_xe_banner",
    "ios_xe_leaf_freeform",
    "extra_config_xe_spine",
    "extra_config_xe_intra_fabric_links",
    "extra_config_xe_bootstrap",
    "extra_config_bootstrap_nxos_border_gateway",
    "extra_config_nxos_border_gateway",
    "extra_config_nxos_intra_fabric_links",
)
OPAQUE_FIELDS = (
    ("netflow_settings", "netflowSettings", {"netflow": True, "netflowExporterCollection": [{"exporterName": "existing", "udpPort": 2055}]}),
    ("per_vrf_loopback_auto_provision_ipv6", "perVrfLoopbackAutoProvisionIpv6", True),
    ("per_vrf_loopback_ipv6_range", "perVrfLoopbackIpv6Range", "2001:db8:5::/112"),
)


def _config(**management):
    return {"fabric_name": "campus_native_probe", "management": {"bgp_asn": "65001", **management}}


def _argspec(config):
    checked = ModuleArgumentSpecValidator(FabricCampusIbgpVxlanModel.get_argument_spec()).validate({"state": "merged", "config": [deepcopy(config)]})
    assert checked.error_messages == []
    return checked.validated_parameters["config"][0]


def _preflight(model, version, state="merged"):
    rest = RestSend({"check_mode": False, "state": state})
    rest.controller_product_version = version
    ManageCampusIbgpVxlanFabricOrchestrator(rest_send=rest).preflight([model])


def _round_trip(field, value):
    proposed = FabricCampusIbgpVxlanModel.from_config(_argspec(_config(**{field: value})))
    alias = CampusIbgpVxlanManagementModel.model_fields[field].alias or field
    assert proposed.to_payload()["management"][alias] == value
    existing = FabricCampusIbgpVxlanModel.from_response(proposed.to_payload())
    gathered = existing.to_gathered_config()
    assert gathered["management"][field] == value
    replay = FabricCampusIbgpVxlanModel.from_config(_argspec(gathered))
    assert replay.to_payload()["management"][alias] == value
    assert existing.get_diff(replay, exclude_unset=False) is True


@pytest.mark.parametrize(("field", "minimum", "maximum"), RANGE_FIELDS)
def test_integer_range_boundaries_and_comma_syntax_survive_public_replay(field, minimum, maximum):
    """All eight exact native integerRange inputs retain their string wire type."""
    metadata = CampusIbgpVxlanManagementModel.model_fields[field].json_schema_extra["nd_integer_range"]
    assert metadata == {"minimum": minimum, "maximum": maximum}
    for value in (str(minimum), str(maximum), f"{minimum}-{maximum}", f"{minimum},{minimum + 1}-{maximum}"):
        _round_trip(field, value)


@pytest.mark.parametrize(("field", "minimum", "maximum"), RANGE_FIELDS)
def test_invalid_integer_range_syntax_or_native_bounds_fail_before_payload(field, minimum, maximum):
    """Malformed lists, reverse ranges, and either outside boundary fail locally."""
    for value in (str(minimum - 1), str(maximum + 1), f"{maximum}-{minimum}", "1,,2", "1-", "1.5", "a", "+2", "2 3"):
        with pytest.raises(ValidationError):
            FabricCampusIbgpVxlanModel.from_config(_config(**{field: value}))


@pytest.mark.parametrize("field", IPV4_POOL_FIELDS)
@pytest.mark.parametrize("value", ("192.0.2.17/24", "192.0.2.1/255.255.255.0", "192.0.2.7/32"))
def test_ipv4_pool_addresses_keep_native_family_and_input_spelling(field, value):
    """CIDR validation preserves host bits, native valid netmasks, and configured defaults."""
    _round_trip(field, value)
    default = CampusIbgpVxlanManagementModel.model_fields[field].default
    assert getattr(FabricCampusIbgpVxlanModel.from_config(_config()).management, field) == default


@pytest.mark.parametrize("field", IPV4_POOL_FIELDS)
@pytest.mark.parametrize("value", ("2001:db8::/64", "192.0.2.256/24", "192.0.2.1/33", "192.0.2.1", "not-a-pool"))
def test_ipv4_pools_reject_invalid_family_and_cidr_notation(field, value):
    with pytest.raises(ValidationError):
        FabricCampusIbgpVxlanModel.from_config(_config(**{field: value}))


@pytest.mark.parametrize("field", IPV4_POOL_FIELDS)
def test_required_ipv4_pool_types_do_not_gain_nullable_model_semantics(field):
    """Direct typed management validation keeps these established required-string fields nonnullable."""
    with pytest.raises(ValidationError):
        CampusIbgpVxlanManagementModel.model_validate({field: None})


@pytest.mark.parametrize("field", CLI_FIELDS)
@pytest.mark.parametrize("value", ("\n  interface loopback17\n    description untouched  \n\t", " \t\n"))
def test_cli_and_banner_text_preserve_whitespace_through_gathered_replay(field, value):
    _round_trip(field, value)


def test_nullable_leaf_freeform_preserves_blank_omission_and_default():
    model = FabricCampusIbgpVxlanModel.from_config(_config(ios_xe_leaf_freeform=""))
    assert model.management.ios_xe_leaf_freeform is None
    assert "iosXeLeafFreeform" not in model.to_payload()["management"]


@pytest.mark.parametrize("value", ("", "example.com", "a-b.Example.COM", "a" * 63 + ".com"))
def test_domain_name_uses_native_format_with_existing_empty_clear(value):
    _round_trip("domain_name", value)


@pytest.mark.parametrize("value", ("localhost", "-example.com", "example-.com", "a" * 64 + ".com", "example.c", "example.toolong", "bad domain.com"))
def test_domain_name_rejects_native_invalid_names(value):
    with pytest.raises(ValidationError):
        FabricCampusIbgpVxlanModel.from_config(_config(domain_name=value))


@pytest.mark.parametrize("version", (None, "4.2.1", "4.2(1)", "4.3.1", "4.3.1a", "4.4.1"))
def test_native_defaults_and_later_field_filtering_use_product_release(version):
    """Native defaults remain model-owned; preflight filters the omitted newer default on older ND."""
    checked = _argspec(_config(**({"bgp_asn": None} if version is None else {})))
    model = FabricCampusIbgpVxlanModel.from_config(checked)
    options = model.get_argument_spec()["config"]["options"]["management"]["options"]
    defaults = {"fabric_mtu": 9198, "l2_host_interface_mtu": 9198, "nxapi": True, "nxapi_http": True, "bgp_fast_convergence": False}
    for field, expected in defaults.items():
        assert checked["management"][field] is None
        assert "default" not in options[field]
        assert field not in model.management.model_fields_set
        assert getattr(model.management, field) == expected
    assert NDMinimumVersion("4.3.1") in CampusIbgpVxlanManagementModel.model_fields["bgp_fast_convergence"].metadata
    _preflight(model, version)
    payload = model.to_payload()
    assert payload["telemetryCollectionType"] == "inBand"
    assert payload["management"]["fabricMtu"] == 9198
    assert payload["management"]["l2HostInterfaceMtu"] == 9198
    assert payload["management"]["nxapi"] is True
    assert payload["management"]["nxapiHttp"] is True
    if version is None or version.startswith("4.2"):
        assert "bgpFastConvergence" not in payload["management"]
        assert model.management.bgp_fast_convergence is None
    else:
        assert payload["management"]["bgpFastConvergence"] is False


@pytest.mark.parametrize("supplied", (False, True))
@pytest.mark.parametrize("version", (None, "4.2.1", "4.2(1)"))
def test_explicit_later_field_is_rejected_by_presence_including_false(supplied, version):
    model = FabricCampusIbgpVxlanModel.from_config(_argspec(_config(bgp_fast_convergence=supplied)))
    assert "bgp_fast_convergence" in model.management.model_fields_set
    with pytest.raises(RuntimeError, match=r"management\.bgp_fast_convergence.*requires ND 4\.3\.1"):
        _preflight(model, version)


@pytest.mark.parametrize(("field", "alias", "value"), OPAQUE_FIELDS)
def test_removed_management_fields_are_not_public_or_typed_but_responses_are_preserved(field, alias, value):
    """Explicitly scoped-out controls remain writable response state, not public configuration."""
    options = FabricCampusIbgpVxlanModel.get_argument_spec()["config"]["options"]["management"]["options"]
    assert field not in options
    assert field not in CampusIbgpVxlanManagementModel.model_fields
    for spelling in (field, alias):
        config = _config(**{spelling: deepcopy(value)})
        checked = ModuleArgumentSpecValidator(FabricCampusIbgpVxlanModel.get_argument_spec()).validate({"state": "merged", "config": [config]})
        assert checked.unsupported_parameters
        with pytest.raises(ValidationError, match="not managed as public fabric parameters"):
            FabricCampusIbgpVxlanModel.from_config(config)
    raw = FabricCampusIbgpVxlanModel.from_config(_config()).to_payload()
    raw["management"][alias] = deepcopy(value)
    snapshot = deepcopy(raw)
    existing = FabricCampusIbgpVxlanModel.from_response(raw)
    assert raw == snapshot
    assert existing.to_payload()["management"][alias] == value
    for config in (existing.to_config(), existing.to_gathered_config()):
        assert field not in config["management"]
        assert alias not in config["management"]
    replay = FabricCampusIbgpVxlanModel.from_config(_argspec(existing.to_gathered_config()))
    assert alias not in replay.to_payload()["management"]
    replacement = replay.prepare_for_replacement(existing)
    assert replacement.to_payload()["management"][alias] == value
    assert existing.get_diff(replacement, exclude_unset=False) is True


@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)", "4.3.1", "4.3.1a", "4.4.1"))
@pytest.mark.parametrize(("supplied", "expected"), (("1", "1"), ("65535", "65535"), ("+65001", "65001")))
def test_baseline_decimal_asn_boundaries_replay_on_both_releases(version, supplied, expected):
    """Baseline ASNs and canonicalized native plus spelling remain public and replayable."""
    model = FabricCampusIbgpVxlanModel.from_config(_argspec(_config(bgp_asn=supplied)))
    _preflight(model, version)
    assert model.to_payload()["management"]["bgpAsn"] == expected
    assert model.to_payload()["management"]["siteId"] == expected
    existing = FabricCampusIbgpVxlanModel.from_response(model.to_payload())
    gathered = existing.to_gathered_config()
    assert gathered["management"]["bgp_asn"] == expected
    replay = FabricCampusIbgpVxlanModel.from_config(_argspec(gathered))
    _preflight(replay, version)
    assert existing.get_diff(replay, exclude_unset=False) is True


@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)"))
@pytest.mark.parametrize("value", ("65536", "70000", "4294967295", "1.1", "65535.65535"))
def test_expanded_asn_values_fail_release_preflight_on_4_2(version, value):
    """The field exists in both releases; its older-release value contract is narrower."""
    model = FabricCampusIbgpVxlanModel.from_config(_config(bgp_asn=value))
    with pytest.raises(RuntimeError, match=r"management\.bgp_asn.*ND release-specific format"):
        _preflight(model, version)


@pytest.mark.parametrize("version", ("4.3.1", "4.3.1a", "4.4.1"))
@pytest.mark.parametrize(("supplied", "expected"), (("65536", "65536"), ("+4294967295", "4294967295"), ("1.1", "1.1"), ("65535.65535", "65535.65535")))
def test_expanded_asn_values_pass_and_replay_from_4_3(version, supplied, expected):
    model = FabricCampusIbgpVxlanModel.from_config(_argspec(_config(bgp_asn=supplied)))
    _preflight(model, version)
    assert model.to_payload()["management"]["bgpAsn"] == expected
    existing = FabricCampusIbgpVxlanModel.from_response(model.to_payload())
    replay = FabricCampusIbgpVxlanModel.from_config(_argspec(existing.to_gathered_config()))
    _preflight(replay, version)
    assert existing.get_diff(replay, exclude_unset=False) is True


@pytest.mark.parametrize("version", (None, "unknown", "4.3.1.175"))
def test_explicit_asn_requires_product_version_when_its_value_contract_varies(version):
    model = FabricCampusIbgpVxlanModel.from_config(_config())
    with pytest.raises(RuntimeError, match=r"management\.bgp_asn.*product version is required"):
        _preflight(model, version)


@pytest.mark.parametrize("value", ("+0", "+4294967296", "+1.1", "+", "++65001", "65536.1"))
def test_invalid_native_asn_plus_spelling_and_bounds_fail_model_validation(value):
    with pytest.raises(ValidationError):
        FabricCampusIbgpVxlanModel.from_config(_config(bgp_asn=value))


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("value", (1501, 9215))
def test_mtu_contract_does_not_invent_an_even_number_rule(version, value):
    """Both native controllers persisted odd MTUs; descriptions must not imply an absent validator."""
    model = FabricCampusIbgpVxlanModel.from_config(_argspec(_config(fabric_mtu=value, l2_host_interface_mtu=value)))
    _preflight(model, version)
    assert model.to_payload()["management"]["fabricMtu"] == value
    assert model.to_payload()["management"]["l2HostInterfaceMtu"] == value


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("value", (1500, 9216))
def test_both_mtu_boundaries_replay_on_each_supported_release(version, value):
    model = FabricCampusIbgpVxlanModel.from_config(_argspec(_config(fabric_mtu=value, l2_host_interface_mtu=value)))
    _preflight(model, version)
    existing = FabricCampusIbgpVxlanModel.from_response(model.to_payload())
    replay = FabricCampusIbgpVxlanModel.from_config(_argspec(existing.to_gathered_config()))
    _preflight(replay, version)
    assert replay.to_payload()["management"]["fabricMtu"] == value
    assert replay.to_payload()["management"]["l2HostInterfaceMtu"] == value
    assert existing.get_diff(replay, exclude_unset=False) is True


@pytest.mark.parametrize("field", ("fabric_mtu", "l2_host_interface_mtu"))
@pytest.mark.parametrize("value", (576, 1498, 1499, 9217))
def test_mtu_bounds_fail_before_transport(field, value):
    """Both actual controllers rejected fabric MTUs below1500 with host MTU held valid."""
    with pytest.raises(ValidationError):
        FabricCampusIbgpVxlanModel.from_config(_config(**{field: value}))


@pytest.mark.parametrize("value", ("239.0.0.0/16", "239.0.0.0/30", "239.0.0.17/24", "239.0.0.17/255.255.255.0"))
def test_campus_multicast_native_prefix_boundaries_preserve_spelling_and_replay(value):
    _round_trip("multicast_group_subnet", value)


@pytest.mark.parametrize("value", ("239.0.0.0/8", "239.0.0.0/15", "239.0.0.0/31", "239.0.0.0/32", "2001:db8::/64", "239.0.0.0", "not-a-network"))
def test_campus_multicast_rejects_wrong_family_notation_and_outside_native_prefix(value):
    with pytest.raises(ValidationError):
        FabricCampusIbgpVxlanModel.from_config(_config(multicast_group_subnet=value))


@pytest.mark.parametrize("mode", (None, "inBand", "outOfBand"))
def test_campus_keeps_established_inband_default_and_explicit_mode_input(mode):
    """Compatibility default follows observed Campus behavior; explicit API choices remain input."""
    config = _config()
    if mode is not None:
        config["telemetry_collection_type"] = mode
    checked = _argspec(config)
    model = FabricCampusIbgpVxlanModel.from_config(checked)
    assert "default" not in model.get_argument_spec()["config"]["options"]["telemetry_collection_type"]
    assert model.to_payload()["telemetryCollectionType"] == (mode or "inBand")
    existing = FabricCampusIbgpVxlanModel.from_response(model.to_payload())
    replay = FabricCampusIbgpVxlanModel.from_config(_argspec(existing.to_gathered_config()))
    assert existing.get_diff(replay, exclude_unset=False) is True


def test_omitted_controller_telemetry_mode_uses_existing_campus_inband_compatibility_default():
    """Disabled telemetry responses omit their mode; fallback must not force replacement."""
    model = FabricCampusIbgpVxlanModel.from_config(_config())
    raw = model.to_payload()
    raw.pop("telemetryCollectionType")
    existing = FabricCampusIbgpVxlanModel.from_response(raw)
    assert existing.telemetry_collection_type == "inBand"
    assert "telemetry_collection_type" not in existing.model_fields_set
    assert existing.get_diff(model, exclude_unset=False) is True
