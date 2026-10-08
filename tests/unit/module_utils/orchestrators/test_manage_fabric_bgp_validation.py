# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Cross-family tests for fabric BGP and release-aware site-ID preflight."""

from __future__ import annotations

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    parse_controller_version,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_campus_ibgp_vxlan import (
    ManageCampusIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import (
    ManageEbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

FABRIC_FAMILIES = (
    (FabricExternalConnectivityModel, ManageExternalFabricOrchestrator),
    (FabricIbgpModel, ManageIbgpFabricOrchestrator),
    (FabricEbgpModel, ManageEbgpFabricOrchestrator),
    (FabricAiIbgpVxlanModel, ManageAiIbgpVxlanFabricOrchestrator),
    (FabricAiEbgpVxlanModel, ManageAiEbgpVxlanFabricOrchestrator),
    (FabricCampusIbgpVxlanModel, ManageCampusIbgpVxlanFabricOrchestrator),
)

SITE_ID_FAMILIES = tuple(family for family in FABRIC_FAMILIES if family[0] is not FabricExternalConnectivityModel)

DHCP_IPV6_FIELDS = (
    ("dhcp_start_address", "2001:db8::10"),
    ("dhcp_end_address", "2001:db8::20"),
    ("management_gateway", "2001:db8::1"),
)


def _orchestrator(orchestrator_class, state: str, version: str | None = None):
    rest_send = RestSend({"check_mode": False, "state": state})
    rest_send.controller_version = version
    return orchestrator_class(rest_send=rest_send)


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_partial_merged_proposal_may_omit_bgp_asn(model_class, orchestrator_class) -> None:
    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": {"performance_monitoring": True}},
        context={"state": "merged"},
    )

    assert model.management is not None
    assert model.management.bgp_asn is None
    orchestrator = _orchestrator(orchestrator_class, "merged")
    orchestrator.preflight_create([])
    orchestrator.preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_create_requires_bgp_asn(model_class, orchestrator_class) -> None:
    model = model_class.from_config({"fabric_name": "fabric1", "management": {}}, context={"state": "merged"})

    with pytest.raises(RuntimeError, match=r"management\.bgp_asn is required when creating.*fabric1"):
        _orchestrator(orchestrator_class, "merged").preflight_create([model])


@pytest.mark.parametrize("state", ("replaced", "overridden"))
@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_exact_states_require_bgp_asn(model_class, orchestrator_class, state: str) -> None:
    model = model_class.from_config({"fabric_name": "fabric1", "management": {}}, context={"state": state})

    with pytest.raises(RuntimeError, match=rf"management\.bgp_asn is required when state is '{state}'"):
        _orchestrator(orchestrator_class, state).preflight([model])


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("4.2.1.10", (4, 2, 1)),
        ("4.3.1.175", (4, 3, 1)),
        (None, None),
        ("invalid", None),
    ),
)
def test_parse_controller_version(value, expected) -> None:
    assert parse_controller_version(value) == expected


@pytest.mark.parametrize(("model_class", "orchestrator_class"), SITE_ID_FAMILIES)
def test_extended_site_id_is_release_aware(model_class, orchestrator_class) -> None:
    model = model_class.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "site_id": "4294967296"},
        }
    )

    with pytest.raises(RuntimeError, match="require ND 4.3.1 or later"):
        _orchestrator(orchestrator_class, "merged", "4.2.1.10").preflight([model])

    with pytest.raises(RuntimeError, match="controller version is 'unknown'"):
        _orchestrator(orchestrator_class, "merged", None).preflight([model])

    _orchestrator(orchestrator_class, "merged", "4.3.1.175").preflight([model])


@pytest.mark.parametrize("value", (True, False))
@pytest.mark.parametrize("version", (None, "4.2.1.10"))
def test_campus_bgp_fast_convergence_rejects_supplied_value_before_4_3_1(value: bool, version: str | None) -> None:
    model = FabricCampusIbgpVxlanModel.from_config({"fabric_name": "fabric1", "management": {"bgp_asn": "65001", "bgp_fast_convergence": value}})

    with pytest.raises(RuntimeError, match="bgp_fast_convergence requires ND 4.3.1 or later"):
        _orchestrator(ManageCampusIbgpVxlanFabricOrchestrator, "merged", version).preflight([model])


def test_campus_bgp_fast_convergence_is_allowed_when_omitted_or_supported() -> None:
    omitted = FabricCampusIbgpVxlanModel.from_config({"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}})
    supplied = FabricCampusIbgpVxlanModel.from_config({"fabric_name": "fabric1", "management": {"bgp_asn": "65001", "bgp_fast_convergence": False}})

    _orchestrator(ManageCampusIbgpVxlanFabricOrchestrator, "merged", "4.2.1.10").preflight([omitted])
    _orchestrator(ManageCampusIbgpVxlanFabricOrchestrator, "merged", "4.3.1.175").preflight([supplied])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize(("field", "value"), DHCP_IPV6_FIELDS)
@pytest.mark.parametrize("version", (None, "4.2.1.10", "4.3.0.1"))
def test_explicit_ipv6_dhcp_and_gateway_fields_fail_closed_before_4_3_1(model_class, orchestrator_class, field, value, version) -> None:
    management = {"bgp_asn": "65001", field: value}
    if field != "management_gateway":
        management["dhcp_protocol_version"] = "dhcpv6"
    model = model_class.from_config({"fabric_name": "fabric1", "management": management})

    with pytest.raises(RuntimeError, match="require ND 4.3.1 or later"):
        _orchestrator(orchestrator_class, "merged", version).preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize(("field", "value"), DHCP_IPV6_FIELDS)
@pytest.mark.parametrize("version", ("4.3.1.175", "4.4.0"))
def test_explicit_ipv6_dhcp_and_gateway_fields_pass_release_preflight_on_4_3_1_plus(model_class, orchestrator_class, field, value, version) -> None:
    management = {"bgp_asn": "65001", field: value}
    if field != "management_gateway":
        management["dhcp_protocol_version"] = "dhcpv6"
    model = model_class.from_config({"fabric_name": "fabric1", "management": management})

    # This is a local schema/release check, not evidence that a particular
    # controller installation accepts DHCPv6 writes.
    _orchestrator(orchestrator_class, "merged", version).preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize("field", ("dhcp_start_address", "dhcp_end_address"))
@pytest.mark.parametrize("protocol", (None, "dhcpv4"))
def test_ipv6_dhcp_scope_requires_explicit_dhcpv6_protocol(model_class, orchestrator_class, field, protocol) -> None:
    management = {"bgp_asn": "65001", field: "2001:db8::10"}
    if protocol is not None:
        management["dhcp_protocol_version"] = protocol
    model = model_class.from_config({"fabric_name": "fabric1", "management": management})

    with pytest.raises(RuntimeError, match="dhcp_protocol_version.*dhcpv6"):
        _orchestrator(orchestrator_class, "merged", "4.3.1.175").preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_ipv6_gateway_requires_dhcpv6_only_with_local_dhcp(model_class, orchestrator_class) -> None:
    config = {
        "fabric_name": "fabric1",
        "management": {
            "bgp_asn": "65001",
            "management_gateway": "2001:db8::1",
            "day0_bootstrap": True,
            "local_dhcp_server": True,
        },
    }
    with pytest.raises(RuntimeError, match="dhcp_protocol_version.*dhcpv6"):
        _orchestrator(orchestrator_class, "merged", "4.3.1.175").preflight([model_class.from_config(config)])

    config["management"]["local_dhcp_server"] = False
    _orchestrator(orchestrator_class, "merged", "4.3.1.175").preflight([model_class.from_config(config)])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_exact_state_ipv6_dhcp_scope_requires_explicit_dhcpv6_protocol(model_class, orchestrator_class, state) -> None:
    config = {"fabric_name": "fabric1", "management": {"bgp_asn": "65001", "dhcp_start_address": "2001:db8::10"}}
    without_protocol = model_class.from_config(config, context={"state": state})

    with pytest.raises(RuntimeError, match="dhcp_protocol_version.*dhcpv6"):
        _orchestrator(orchestrator_class, state, "4.3.1.175").preflight([without_protocol])

    config["management"]["dhcp_protocol_version"] = "dhcpv6"
    with_protocol = model_class.from_config(config, context={"state": state})
    _orchestrator(orchestrator_class, state, "4.3.1.175").preflight([with_protocol])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize("version", (None, "4.2.1.10"))
def test_ipv4_dhcp_fields_do_not_trigger_ipv6_release_preflight(model_class, orchestrator_class, version) -> None:
    model = model_class.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "dhcp_protocol_version": "dhcpv4",
                "dhcp_start_address": "192.0.2.10",
                "dhcp_end_address": "192.0.2.20",
                "management_gateway": "192.0.2.1",
            },
        }
    )

    _orchestrator(orchestrator_class, "merged", version).preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_response_origin_ipv6_config_replay_passes_4_3_preflight_and_fails_4_2(model_class, orchestrator_class) -> None:
    response = {
        "name": "fabric1",
        "category": "fabric",
        "management": {
            "type": model_class._fabric_type.value,
            "bgpAsn": "65001",
            "dhcpProtocolVersion": "dhcpv6",
            "dhcpStartAddress": "2001:db8::10",
            "dhcpEndAddress": "2001:db8::20",
            "managementGateway": "2001:db8::1",
        },
    }
    gathered = model_class.from_response(response).to_gathered_config()
    result = ModuleArgumentSpecValidator(model_class.get_argument_spec()).validate({"state": "merged", "config": [gathered]})
    assert result.error_messages == []
    replayed = model_class.from_config(result.validated_parameters["config"][0])

    _orchestrator(orchestrator_class, "merged", "4.3.1.175").preflight([replayed])
    with pytest.raises(RuntimeError, match="require ND 4.3.1 or later"):
        _orchestrator(orchestrator_class, "merged", "4.2.1.10").preflight([replayed])
