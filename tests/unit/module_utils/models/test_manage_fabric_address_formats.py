# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""iBGP native address-format contracts across input, payload, and gathered replay."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    AimlVxlanIbgpManagementModel,
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
    VxlanIbgpManagementModel,
)

FAMILIES = (
    pytest.param(FabricIbgpModel, VxlanIbgpManagementModel, id="ibgp"),
    pytest.param(FabricAiIbgpVxlanModel, AimlVxlanIbgpManagementModel, id="ai-ibgp"),
)

# Defaults are deliberately captured independently of model metadata: adding
# validation must not change the existing payload or omission contract.
IPV4_POOLS = (
    ("bgp_loopback_ip_range", "bgpLoopbackIpRange", "10.2.0.0/22", "192.0.2.7/24"),
    ("nve_loopback_ip_range", "nveLoopbackIpRange", "10.3.0.0/22", "192.0.2.7/24"),
    ("anycast_rendezvous_point_ip_range", "anycastRendezvousPointIpRange", "10.254.254.0/24", "192.0.2.7/24"),
    ("intra_fabric_subnet_range", "intraFabricSubnetRange", "10.4.0.0/16", "192.0.2.7/24"),
    ("per_vrf_loopback_ip_range", "perVrfLoopbackIpRange", "10.5.0.0/22", "192.0.2.7/24"),
    ("mpls_loopback_ip_range", "mplsLoopbackIpRange", "10.101.0.0/25", "192.0.2.7/24"),
)
IPV6_POOLS = (
    ("bgp_loopback_ipv6_range", "bgpLoopbackIpv6Range", "fd00::a02:0/119", "2001:0DB8:0000::7/120"),
    ("nve_loopback_ipv6_range", "nveLoopbackIpv6Range", "fd00::a03:0/118", "2001:0DB8:0000::7/120"),
    ("ipv6_anycast_rendezvous_point_ip_range", "ipv6AnycastRendezvousPointIpRange", "fd00::254:254:0/118", "2001:0DB8:0000::7/120"),
    ("ipv6_subnet_range", "ipv6SubnetRange", "fd00::a04:0/112", "2001:0DB8:0000::7/120"),
    ("per_vrf_loopback_ipv6_range", "perVrfLoopbackIpv6Range", "fd00::a05:0/112", "2001:0DB8:0000::7/120"),
    ("ipv6_multicast_group_subnet", "ipv6MulticastGroupSubnet", "ff1e::/121", "FF1E:0000::7/120"),
)
BARE_ADDRESSES = (
    ("l3vni_multicast_group", "l3vniMulticastGroup", "239.1.1.0", "192.0.2.7"),
    ("l3_vni_ipv6_multicast_group", "l3VniIpv6MulticastGroup", "ff1e::", "2001:0DB8::7"),
)
ADDRESS_FIELDS = (*IPV4_POOLS, *IPV6_POOLS, *BARE_ADDRESSES)


def _config(**management) -> dict:
    return {"fabric_name": "format_probe", "management": {"bgp_asn": "65001", **management}}


def _validate_argspec(model_class, config: dict) -> dict:
    result = ModuleArgumentSpecValidator(model_class.get_argument_spec()).validate({"state": "merged", "config": [deepcopy(config)]})
    assert result.error_messages == []
    assert result.unsupported_parameters == set()
    return result.validated_parameters["config"][0]


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize(("field", "alias", "default", "value"), ADDRESS_FIELDS)
def test_address_values_keep_host_bits_case_and_whitespace_behavior_through_gathered_replay(model_class, management_class, field, alias, default, value):
    """All 14 fields preserve existing trimming and exact address spelling on replay."""
    config = _validate_argspec(model_class, _config(**{field: f"  {value}\t"}))
    proposed = model_class.from_config(config)
    assert getattr(proposed.management, field) == value
    assert field in proposed.management.model_fields_set
    payload = proposed.to_payload()
    assert payload["management"][alias] == value

    existing = model_class.from_response(deepcopy(payload))
    assert getattr(existing.management, field) == value
    gathered = existing.to_gathered_config()
    assert gathered["management"][field] == value
    replayed = model_class.from_config(_validate_argspec(model_class, gathered))
    assert replayed.to_payload()["management"][alias] == value
    assert existing.get_diff(replayed, exclude_unset=False) is True


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
def test_address_validation_keeps_defaults_nonnullable_strings_and_ansible_omission(model_class, management_class):
    """Typed validation retains all 14 defaults without adding argspec defaults."""
    model = model_class.from_config(_validate_argspec(model_class, _config()))
    payload = model.to_payload()["management"]
    schema = management_class.model_json_schema(by_alias=False)["properties"]
    spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]

    for field, alias, default, _ in ADDRESS_FIELDS:
        assert payload[alias] == default
        assert field not in model.management.model_fields_set
        assert management_class.model_fields[field].annotation is str
        assert schema[field]["type"] == "string"
        assert schema[field]["default"] == default
        assert spec[field] == {"type": "str"}
        # Pydantic does not validate omitted defaults automatically. Supplying
        # each original default exercises its new annotation explicitly.
        assert getattr(management_class.model_validate({field: default}), field) == default
        for invalid in (None, "", " \t", 123):
            with pytest.raises(ValidationError):
                management_class.model_validate({field: invalid})
            response = model.to_payload()
            response["management"][alias] = invalid
            with pytest.raises(ValidationError):
                model_class.from_response(response)
            if invalid is not None:
                with pytest.raises(ValidationError):
                    model_class.from_config(_config(**{field: invalid}))
        # Ansible represents unspecified options as None; from_config strips
        # them before validation, preserving the established default behavior.
        omitted = model_class.from_config(_config(**{field: None}))
        assert omitted.to_payload()["management"][alias] == default
        assert field not in omitted.management.model_fields_set


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("field", [entry[0] for entry in IPV4_POOLS])
@pytest.mark.parametrize("value", ("not-an-ip/24", "999.0.0.1/24", "2001:db8::1/64", "192.0.2.1/33", "192.0.2.1/-1", "192.0.2.1"))
def test_ipv4_pool_fields_reject_invalid_addresses_wrong_family_and_missing_or_invalid_prefix(model_class, management_class, field, value):
    """Every IPv4 pool requires a valid IPv4 address with an explicit prefix."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("field", [entry[0] for entry in IPV6_POOLS])
@pytest.mark.parametrize("value", ("not-an-ip/120", "2001:db8:::1/120", "192.0.2.1/24", "2001:db8::1/129", "2001:db8::1/-1"))
def test_ipv6_pool_fields_reject_invalid_addresses_wrong_family_and_invalid_prefix(model_class, management_class, field, value):
    """Every IPv6 pool checks address family and the IPv6 prefix limits."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("field", [entry[0] for entry in IPV6_POOLS] + ["per_vrf_unique_loopback_ipv6_range"])
def test_ipv6_pool_fields_preserve_existing_bare_address_as_implicit_128(model_class, management_class, field):
    """The approved IPv6 shorthand stays valid and retains its original spelling."""
    value = "2001:0DB8:0000::7"
    model = model_class.from_config(_config(**{field: value}))
    assert getattr(model.management, field) == value
    alias = management_class.model_fields[field].alias
    assert model.to_payload()["management"][alias] == value


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("prefix", (0, 64, 111))
def test_ipv6_multicast_pool_enforces_native_lower_prefix_limit(model_class, management_class, prefix):
    """Native IPv6 multicast pools require prefixes of at least 112 bits."""
    with pytest.raises(ValidationError, match="between 112 and 128"):
        model_class.from_config(_config(ipv6_multicast_group_subnet=f"ff1e::7/{prefix}"))


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("prefix", (112, 128))
def test_ipv6_multicast_pool_accepts_native_prefix_boundaries_without_new_membership_rule(model_class, management_class, prefix):
    """Only the declared format/prefix contract is imposed, preserving host bits."""
    value = f"2001:0DB8::7/{prefix}"
    assert model_class.from_config(_config(ipv6_multicast_group_subnet=value)).to_payload()["management"]["ipv6MulticastGroupSubnet"] == value


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("l3vni_multicast_group", "not-an-ip"),
        ("l3vni_multicast_group", "2001:db8::1"),
        ("l3vni_multicast_group", "239.1.1.1/32"),
        ("l3_vni_ipv6_multicast_group", "not-an-ip"),
        ("l3_vni_ipv6_multicast_group", "192.0.2.1"),
        ("l3_vni_ipv6_multicast_group", "ff1e::1/128"),
    ),
)
def test_mdt_address_fields_reject_wrong_family_malformed_addresses_and_prefixes(model_class, management_class, field, value):
    """MDT inputs are bare addresses rather than host CIDRs or arbitrary text."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("telemetry_collection", (False, True))
@pytest.mark.parametrize("explicit_type", (None, "inBand", "outOfBand"))
def test_ibgp_telemetry_collection_type_uses_api_default_and_respects_explicit_input(model_class, management_class, telemetry_collection, explicit_type):
    """Both iBGP models default to outOfBand independently of telemetry enablement."""
    config = {**_config(), "telemetry_collection": telemetry_collection}
    if explicit_type is not None:
        config["telemetry_collection_type"] = explicit_type
    model = model_class.from_config(_validate_argspec(model_class, config))
    expected = explicit_type or "outOfBand"
    assert model.to_payload()["telemetryCollectionType"] == expected
    assert model.to_payload()["telemetryCollection"] is telemetry_collection
    assert ("telemetry_collection_type" in model.model_fields_set) is (explicit_type is not None)
    existing = model_class.from_response(model.to_payload())
    replay = model_class.from_config(_validate_argspec(model_class, existing.to_gathered_config()))
    assert replay.to_payload()["telemetryCollectionType"] == expected


@pytest.mark.parametrize(("model_class", "expected"), ((FabricEbgpModel, "outOfBand"), (FabricExternalConnectivityModel, "inBand")))
def test_telemetry_default_changes_keep_each_fabric_familys_policy(model_class, expected):
    """Each family's explicit default policy remains independent of the shared base."""
    assert model_class.model_fields["telemetry_collection_type"].default == expected
