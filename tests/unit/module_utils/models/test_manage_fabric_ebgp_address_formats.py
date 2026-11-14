# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""eBGP native address controls across Ansible input, API payload and gathered replay."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    AimlVxlanEbgpManagementModel,
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
    VxlanEbgpManagementModel,
)

FAMILIES = (
    pytest.param(FabricEbgpModel, VxlanEbgpManagementModel, id="ebgp"),
    pytest.param(FabricAiEbgpVxlanModel, AimlVxlanEbgpManagementModel, id="ai-ebgp"),
)
IPV4_POOLS = (
    ("bgp_loopback_ip_range", "bgpLoopbackIpRange", "10.2.0.0/22", "192.0.2.7/24"),
    ("nve_loopback_ip_range", "nveLoopbackIpRange", "10.3.0.0/22", "192.0.2.7/24"),
    ("anycast_rendezvous_point_ip_range", "anycastRendezvousPointIpRange", "10.254.254.0/24", "192.0.2.7/24"),
    ("intra_fabric_subnet_range", "intraFabricSubnetRange", "10.4.0.0/16", "192.0.2.7/24"),
    ("per_vrf_loopback_ip_range", "perVrfLoopbackIpRange", "10.5.0.0/22", "192.0.2.7/24"),
)
IPV6_POOLS = (
    ("bgp_loopback_ipv6_range", "bgpLoopbackIpv6Range", "fd00::a02:0/119", "2001:0DB8:0000::7/120"),
    ("nve_loopback_ipv6_range", "nveLoopbackIpv6Range", "fd00::a03:0/118", "2001:0DB8:0000::7/120"),
    ("ipv6_anycast_rendezvous_point_ip_range", "ipv6AnycastRendezvousPointIpRange", "fd00::254:254:0/118", "2001:0DB8:0000::7/120"),
    ("per_vrf_loopback_ipv6_range", "perVrfLoopbackIpv6Range", "fd00::a05:0/112", "2001:0DB8:0000::7/120"),
    ("ipv6_multicast_group_subnet", "ipv6MulticastGroupSubnet", "ff1e::/121", "FF1E:0000::7/120"),
)
BARE_ADDRESSES = (
    ("l3vni_multicast_group", "l3vniMulticastGroup", "239.1.1.0", "192.0.2.7"),
    ("l3_vni_ipv6_multicast_group", "l3VniIpv6MulticastGroup", "ff1e::", "2001:0DB8::7"),
)
ADDRESS_FIELDS = (*IPV4_POOLS, *IPV6_POOLS, *BARE_ADDRESSES)


def _config(**management):
    return {"fabric_name": "ebgp_format_probe", "management": {"bgp_asn": "65001", **management}}


def _validate_argspec(model_class, config):
    validation = ModuleArgumentSpecValidator(model_class.get_argument_spec()).validate({"state": "merged", "config": [deepcopy(config)]})
    assert validation.error_messages == []
    assert validation.unsupported_parameters == set()
    return validation.validated_parameters["config"][0]


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize(("field", "alias", "default", "value"), ADDRESS_FIELDS)
def test_ebgp_address_values_preserve_spelling_and_host_bits_through_gathered_replay(model_class, management_class, field, alias, default, value):
    """Native format checks preserve valid values through every public input/output surface."""
    config = _validate_argspec(model_class, _config(**{field: f"  {value}\t"}))
    proposed = model_class.from_config(config)
    assert getattr(proposed.management, field) == value
    assert proposed.to_payload()["management"][alias] == value
    existing = model_class.from_response(deepcopy(proposed.to_payload()))
    gathered = existing.to_gathered_config()
    assert gathered["management"][field] == value
    replayed = model_class.from_config(_validate_argspec(model_class, gathered))
    assert replayed.to_payload()["management"][alias] == value


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
def test_ebgp_address_checks_preserve_all_defaults_nonnullable_types_and_omission(model_class, management_class):
    """Adding format validation does not alter the twelve existing strings or their defaults."""
    model = model_class.from_config(_validate_argspec(model_class, _config()))
    payload = model.to_payload()["management"]
    spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]
    schema = management_class.model_json_schema(by_alias=False)["properties"]
    for field, alias, default, _ in ADDRESS_FIELDS:
        assert payload[alias] == default
        assert field not in model.management.model_fields_set
        assert management_class.model_fields[field].annotation is str
        assert schema[field]["type"] == "string"
        assert schema[field]["default"] == default
        assert spec[field] == {"type": "str"}
        assert getattr(management_class.model_validate({field: default}), field) == default
        for invalid in (None, "", " \t", 123):
            with pytest.raises(ValidationError):
                management_class.model_validate({field: invalid})
            response = model.to_payload()
            response["management"][alias] = invalid
            with pytest.raises(ValidationError):
                model_class.from_response(response)
        omitted = model_class.from_config(_config(**{field: None}))
        assert omitted.to_payload()["management"][alias] == default
        assert field not in omitted.management.model_fields_set


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize(("field", "alias", "default", "value"), ADDRESS_FIELDS)
@pytest.mark.parametrize("construction", ("from_config", "from_response"))
def test_ebgp_every_native_address_field_rejects_malformed_text(model_class, management_class, field, alias, default, value, construction):
    """Each previously unconstrained field rejects a non-address on input and controller parsing."""
    if construction == "from_config":
        with pytest.raises(ValidationError):
            model_class.from_config(_config(**{field: "not-an-address"}))
    else:
        response = model_class.from_config(_config()).to_payload()
        response["management"][alias] = "not-an-address"
        with pytest.raises(ValidationError):
            model_class.from_response(response)


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("field", [entry[0] for entry in IPV4_POOLS])
@pytest.mark.parametrize("value", ("2001:db8::1/64", "192.0.2.1/33", "192.0.2.1/-1", "192.0.2.1"))
def test_ebgp_ipv4_pools_require_ipv4_and_an_explicit_valid_prefix(model_class, management_class, field, value):
    """Every IPv4 pool checks its family and IPv4 prefix bounds."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("field", [entry[0] for entry in IPV6_POOLS])
@pytest.mark.parametrize("value", ("192.0.2.1/24", "2001:db8::1/129", "2001:db8::1/-1"))
def test_ebgp_ipv6_pools_check_family_and_prefix_limits(model_class, management_class, field, value):
    """Every IPv6 pool rejects IPv4 values and out-of-range prefixes."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("field", [entry[0] for entry in IPV6_POOLS])
def test_ebgp_ipv6_pools_keep_bare_address_shorthand(model_class, management_class, field):
    """Existing implicit-/128 IPv6 notation retains its spelling and remains accepted."""
    value = "2001:0DB8:0000::7"
    model = model_class.from_config(_config(**{field: value}))
    alias = management_class.model_fields[field].alias
    assert model.to_payload()["management"][alias] == value


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize("prefix", (0, 111, 112, 128))
def test_ebgp_ipv6_multicast_prefix_boundaries_preserve_unicast_values(model_class, management_class, prefix):
    """The native 112-128 prefix rule adds no multicast-membership requirement."""
    value = f"2001:0DB8::7/{prefix}"
    if prefix < 112:
        with pytest.raises(ValidationError, match="between 112 and 128"):
            model_class.from_config(_config(ipv6_multicast_group_subnet=value))
    else:
        assert model_class.from_config(_config(ipv6_multicast_group_subnet=value)).to_payload()["management"]["ipv6MulticastGroupSubnet"] == value


@pytest.mark.parametrize(("model_class", "management_class"), FAMILIES)
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("l3vni_multicast_group", "2001:db8::1"),
        ("l3vni_multicast_group", "239.1.1.1/32"),
        ("l3_vni_ipv6_multicast_group", "192.0.2.1"),
        ("l3_vni_ipv6_multicast_group", "ff1e::1/128"),
    ),
)
def test_ebgp_mdt_address_fields_require_bare_addresses_of_the_right_family(model_class, management_class, field, value):
    """Bare MDT address controls reject the wrong family and CIDR suffixes."""
    with pytest.raises(ValidationError):
        model_class.from_config(_config(**{field: value}))
