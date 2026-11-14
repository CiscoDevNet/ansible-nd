# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Cross-family tests for fabric BGP and release-aware site-ID preflight."""

from __future__ import annotations

from typing import get_args

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
from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import (
    NDMinimumVersion,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    parse_controller_product_version,
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

SITE_ID_FAMILIES = tuple(
    family
    for family in FABRIC_FAMILIES
    if family[0] is not FabricExternalConnectivityModel
)
BASELINE_IPV6_FAMILIES = (
    (FabricIbgpModel, ManageIbgpFabricOrchestrator),
    (FabricAiIbgpVxlanModel, ManageAiIbgpVxlanFabricOrchestrator),
    (FabricEbgpModel, ManageEbgpFabricOrchestrator),
    (FabricAiEbgpVxlanModel, ManageAiEbgpVxlanFabricOrchestrator),
    (FabricExternalConnectivityModel, ManageExternalFabricOrchestrator),
)
DHCP_VERSION_GATED_FAMILIES = tuple(family for family in FABRIC_FAMILIES if family not in BASELINE_IPV6_FAMILIES)

DHCP_IPV6_FIELDS = (
    ("dhcp_start_address", "2001:db8::10"),
    ("dhcp_end_address", "2001:db8::20"),
    ("management_gateway", "2001:db8::1"),
)

IBGP_RELEASE_GATE_PRESENCE_CASES = (("allow_smart_switch_ha", False), ("isis_keys", []))

# Exact readable defaults from the ND 4.3.1 Easy_Fabric parameter metadata.
IBGP_TEMPLATE_DEFAULTS_4_3 = {
    "ai_load_sharing_opcode": False,
    "ai_load_sharing_packet_sequence_number": False,
    "ai_load_sharing_queuepair": False,
    "allow_smart_switch_ha": False,
    "auto_smart_switch_vpc_pair_ha": False,
    "bfd_min_rx_interval": 50,
    "bfd_multiplier": 3,
    "bfd_tx_interval": 50,
    "dlb_all_interfaces": True,
    "hypershield_ha_peer_link_subnet": "10.12.0.0/22",
    "hypershield_ha_peer_link_subnet_granularity": "/30",
    "hypershield_ha_source_intf": "loopback1023",
    "hypershield_ha_source_subnet": "10.11.0.0/23",
    "hypershield_ha_vlan": 3601,
    "use_hypershield_source_loopback_for_ha": False,
    "isis_auth_use_key_entries": False,
    "isis_border_level12": False,
    "ntp_auth_algorithm": "aes128cmac",
    "ntp_auth_enable": False,
    "ospf_auth_use_keychain": False,
    "ospf_auto_cost_ref_bw": 40,
    "ospf_log_adj_changes": False,
    "ospf_max_metric_startup_wait": 600,
    "pim_auth_use_keychain": False,
    "system_qos_classification": True,
}
IBGP_RELEASE_INPUT_CASES = {
    **IBGP_TEMPLATE_DEFAULTS_4_3,
    "isis_keys": [],
    "ntp_auth_key": "auditKey",
    "ntp_auth_key_id": 1,
    "ntp_auth_key_type": "7",
    "ospf_auth_keychain_name": "auditOspf",
    "ospf_keys": [],
    "pim_auth_keychain_name": "auditPim",
    "pim_keys": [],
}


def _orchestrator(orchestrator_class, state: str, version: str | None = None):
    rest_send = RestSend({"check_mode": False, "state": state})
    rest_send.controller_product_version = version
    return orchestrator_class(rest_send=rest_send)


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_partial_merged_proposal_may_omit_bgp_asn(
    model_class, orchestrator_class
) -> None:
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
    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": {}}, context={"state": "merged"}
    )

    with pytest.raises(
        RuntimeError, match=r"management\.bgp_asn is required when creating.*fabric1"
    ):
        _orchestrator(orchestrator_class, "merged").preflight_create([model])


@pytest.mark.parametrize("state", ("replaced", "overridden"))
@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_exact_states_require_bgp_asn(
    model_class, orchestrator_class, state: str
) -> None:
    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": {}}, context={"state": state}
    )

    with pytest.raises(
        RuntimeError, match=rf"management\.bgp_asn is required when state is '{state}'"
    ):
        _orchestrator(orchestrator_class, state).preflight([model])


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("4.2.1", (4, 2, 1, 0)),
        ("4.2(1)", (4, 2, 1, 0)),
        ("4.3.1", (4, 3, 1, 0)),
        ("4.3(1)", (4, 3, 1, 0)),
        ("4.3.1a", (4, 3, 1, 1)),
        ("4.3(1a)", (4, 3, 1, 1)),
        ("4.3.1b", (4, 3, 1, 2)),
        ("4.3.1aa", (4, 3, 1, 27)),
        ("4.3.1.175", None),
        (None, None),
        ("invalid", None),
    ),
)
def test_parse_controller_product_version(value, expected) -> None:
    assert parse_controller_product_version(value) == expected


@pytest.mark.parametrize("version", (None, "4.2.1", "4.2(1)"))
def test_all_new_ibgp_defaults_are_omitted_before_their_minimum_release(version) -> None:
    model = FabricIbgpModel.from_config(
        {"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}}
    )
    management = model.management
    assert management is not None
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", version).preflight([model])
    payload = model.to_payload()["management"]
    for field in IBGP_RELEASE_INPUT_CASES:
        assert field not in management.model_fields_set
        assert type(management).model_fields[field].alias not in payload


@pytest.mark.parametrize("version", ("4.3.1", "4.3.1a", "4.4.1"))
def test_new_ibgp_defaults_match_the_supported_native_template(version) -> None:
    model = FabricIbgpModel.from_config(
        {"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}}
    )
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", version).preflight([model])
    payload = model.to_payload()["management"]
    options = FabricIbgpModel.get_argument_spec()["config"]["options"]["management"]["options"]
    for field, expected in IBGP_TEMPLATE_DEFAULTS_4_3.items():
        assert model.management is not None
        alias = type(model.management).model_fields[field].alias
        assert payload[alias] == expected
        assert field not in model.management.model_fields_set
        assert "default" not in options[field]


@pytest.mark.parametrize(("field", "value"), IBGP_RELEASE_INPUT_CASES.items())
def test_every_new_ibgp_field_rejects_explicit_input_on_nd_4_2(field, value) -> None:
    validated = ModuleArgumentSpecValidator(FabricIbgpModel.get_argument_spec()).validate(
        {"state": "merged", "config": [
            {"fabric_name": "fabric1", "management": {"bgp_asn": "65001", field: value}}
        ]}
    )
    assert validated.error_messages == []
    model = FabricIbgpModel.from_config(validated.validated_parameters["config"][0])
    with pytest.raises(RuntimeError, match=rf"{field} \(requires ND 4\.3\.1 or later\)"):
        _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.2(1)").preflight([model])
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.3.1").preflight([model])


@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)", "4.3.1"))
def test_connectivity_domain_name_is_supported_on_both_releases(version) -> None:
    model = FabricIbgpModel.from_config(
        {"fabric_name": "fabric1", "management": {"bgp_asn": "65001", "connectivity_domain_name": "example.com"}}
    )
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", version).preflight([model])
    assert model.to_payload()["management"]["connectivityDomainName"] == "example.com"


@pytest.mark.parametrize("field", ("isis_keys", "ospf_keys", "pim_keys"))
def test_ibgp_keychain_material_defaults_and_release_gate(field) -> None:
    model = FabricIbgpModel.from_config({
        "fabric_name": "fabric1",
        "management": {"bgp_asn": "65001", field: [{"key_id": 1, "key_string": "auditKey"}]},
    })
    with pytest.raises(RuntimeError, match=rf"{field} \(requires ND 4\.3\.1 or later\)"):
        _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.2(1)").preflight([model])
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.3.1").preflight([model])
    alias = type(model.management).model_fields[field].alias
    entry = model.to_payload()["management"][alias][0]
    assert entry["keyString"] == "auditKey"
    assert entry["keyType"] == "7"
    assert entry["acceptLifetimeLocal"] is False
    assert entry["sendLifetimeLocal"] is False
    assert model.to_config()["management"][field][0]["key_string"] != "auditKey"


@pytest.mark.parametrize(("field", "maximum"), (("ntp_auth_key", 128), ("isis_keys", 255), ("ospf_keys", 255), ("pim_keys", 255)))
def test_ibgp_secret_constraints_reject_invalid_plaintext_without_type_error(field, maximum) -> None:
    for value in ("bad key", "x" * (maximum + 1)):
        supplied = value if field == "ntp_auth_key" else [{"key_id": 1, "key_string": value}]
        with pytest.raises(ValueError):
            FabricIbgpModel.from_config({
                "fabric_name": "fabric1",
                "management": {"bgp_asn": "65001", field: supplied},
            })


@pytest.mark.parametrize(
    ("older", "newer"),
    (("4.3.1", "4.3.1a"), ("4.3.1a", "4.3.1b")),
)
def test_parse_controller_product_version_orders_lettered_bug_fixes(
    older, newer
) -> None:
    assert parse_controller_product_version(older) < parse_controller_product_version(
        newer
    )


@pytest.mark.parametrize(
    ("model_class", "orchestrator_class"),
    (
        (FabricIbgpModel, ManageIbgpFabricOrchestrator),
        (FabricAiIbgpVxlanModel, ManageAiIbgpVxlanFabricOrchestrator),
    ),
)
def test_ibgp_release_gate_rejects_explicit_false_and_empty_values_at_boundary(
    model_class, orchestrator_class
) -> None:
    for field, value in IBGP_RELEASE_GATE_PRESENCE_CASES:
        management_class = next(
            item
            for item in get_args(model_class.model_fields["management"].annotation)
            if isinstance(item, type) and hasattr(item, "model_fields")
        )
        field_info = management_class.model_fields[field]
        assert NDMinimumVersion("4.3.1") in field_info.metadata
        assert "NDMinimumVersion" not in str(management_class.model_json_schema())
        model = model_class.from_config(
            {"fabric_name": "fabric1", "management": {"bgp_asn": "65001", field: value}}
        )
        assert model.management is not None
        assert field in model.management.model_fields_set
        with pytest.raises(
            RuntimeError, match=rf"{field} \(requires ND 4\.3\.1 or later\)"
        ):
            _orchestrator(orchestrator_class, "merged", "4.2.1").preflight([model])
        _orchestrator(orchestrator_class, "merged", "4.3.1").preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES[:-1])
def test_metadata_release_gate_covers_each_non_campus_fabric_family(
    model_class, orchestrator_class
) -> None:
    model = model_class.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "allow_smart_switch_ha": False},
        }
    )
    with pytest.raises(
        RuntimeError, match=r"allow_smart_switch_ha \(requires ND 4\.3\.1 or later\)"
    ):
        _orchestrator(orchestrator_class, "merged", "4.2.1").preflight([model])
    _orchestrator(orchestrator_class, "merged", "4.3.1").preflight([model])


def test_ibgp_field_minimum_can_be_a_lettered_bug_fix_release(monkeypatch) -> None:
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "allow_smart_switch_ha": False},
        }
    )
    assert model.management is not None
    field_info = type(model.management).model_fields["allow_smart_switch_ha"]
    monkeypatch.setattr(field_info, "metadata", [NDMinimumVersion("4.3.1a")])
    with pytest.raises(RuntimeError, match=r"requires ND 4\.3\.1a or later"):
        _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.3.1").preflight(
            [model]
        )
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.3.1a").preflight([model])


@pytest.mark.parametrize(
    "record_template", ("netflowIpv4Record", "netflowLayer2Record")
)
def test_netflow_record_template_enum_is_enforced_through_nd_4_2(
    record_template,
) -> None:
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "netflow_settings": {
                    "netflow": True,
                    "netflow_record_collection": [
                        {"record_name": "record1", "record_template": record_template}
                    ],
                },
            },
        }
    )
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.2.1").preflight([model])


def test_netflow_record_template_rejects_non_enum_value_on_nd_4_2() -> None:
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "netflow_settings": {
                    "netflow": True,
                    "netflow_record_collection": [
                        {"record_name": "record1", "record_template": "customRecord"}
                    ],
                },
            },
        }
    )
    with pytest.raises(RuntimeError, match="record_template must be one of"):
        _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.2.1").preflight(
            [model]
        )


@pytest.mark.parametrize("version", ("4.3.1", "4.3.1a"))
def test_netflow_record_template_is_string_for_nd_4_3_and_later(version) -> None:
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "netflow_settings": {
                    "netflow": True,
                    "netflow_record_collection": [
                        {"record_name": "record1", "record_template": "customRecord"}
                    ],
                },
            },
        }
    )
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", version).preflight([model])


@pytest.mark.parametrize("version", ("4.3.1", "4.3.1a"))
def test_ibgp_secret_pattern_is_enforced_from_nd_4_3(version) -> None:
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "bgp_authentication_key": "secret with spaces",
            },
        }
    )
    with pytest.raises(RuntimeError, match="bgp_authentication_key does not match"):
        _orchestrator(ManageIbgpFabricOrchestrator, "merged", version).preflight(
            [model]
        )


def test_ibgp_secret_pattern_is_not_applied_before_nd_4_3() -> None:
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "bgp_authentication_key": "secret with spaces",
            },
        }
    )
    _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.2.1").preflight([model])


@pytest.mark.parametrize("value", (4, 86401))
def test_ospf_max_metric_startup_wait_enforces_live_template_bounds(value: int) -> None:
    with pytest.raises(ValueError):
        FabricIbgpModel.from_config(
            {
                "fabric_name": "fabric1",
                "management": {
                    "bgp_asn": "65001",
                    "ospf_max_metric_startup_wait": value,
                },
            }
        )


def test_ospf_max_metric_startup_wait_default_is_release_aware() -> None:
    proposed = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001"},
        }
    )
    assert proposed.management is not None
    assert proposed.management.ospf_max_metric_startup_wait == 600
    assert "ospf_max_metric_startup_wait" not in proposed.management.model_fields_set

    _orchestrator(ManageIbgpFabricOrchestrator, "replaced", "4.2.1").preflight(
        [proposed]
    )
    assert proposed.management.ospf_max_metric_startup_wait is None
    assert "ospf_max_metric_startup_wait" not in proposed.management.model_fields_set
    assert "ospfMaxMetricStartupWait" not in proposed.to_payload().get("management", {})

    newer_release = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric2",
            "management": {"bgp_asn": "65002"},
        }
    )
    _orchestrator(ManageIbgpFabricOrchestrator, "replaced", "4.3.1").preflight(
        [newer_release]
    )
    assert newer_release.to_payload()["management"]["ospfMaxMetricStartupWait"] == 600


def test_explicit_ospf_max_metric_startup_wait_is_rejected_before_nd_4_3() -> None:
    proposed = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "ospf_max_metric_startup_wait": 600,
            },
        }
    )

    with pytest.raises(RuntimeError, match="ospf_max_metric_startup_wait.*requires ND 4.3.1"):
        _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.2.1").preflight(
            [proposed]
        )


@pytest.mark.parametrize(("model_class", "orchestrator_class"), SITE_ID_FAMILIES)
def test_extended_site_id_is_release_aware(model_class, orchestrator_class) -> None:
    model = model_class.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "site_id": "4294967296"},
        }
    )

    with pytest.raises(RuntimeError, match="require ND 4.3.1 or later"):
        _orchestrator(orchestrator_class, "merged", "4.2.1").preflight([model])

    with pytest.raises(RuntimeError, match="controller product version is 'unknown'"):
        _orchestrator(orchestrator_class, "merged", None).preflight([model])

    _orchestrator(orchestrator_class, "merged", "4.3.1").preflight([model])
    _orchestrator(orchestrator_class, "merged", "4.3.1a").preflight([model])


@pytest.mark.parametrize("value", (True, False))
@pytest.mark.parametrize("version", (None, "4.2.1"))
def test_campus_bgp_fast_convergence_rejects_supplied_value_before_4_3_1(
    value: bool, version: str | None
) -> None:
    model = FabricCampusIbgpVxlanModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "bgp_fast_convergence": value},
        }
    )

    with pytest.raises(
        RuntimeError, match=r"bgp_fast_convergence \(requires ND 4.3.1 or later\)"
    ):
        _orchestrator(
            ManageCampusIbgpVxlanFabricOrchestrator, "merged", version
        ).preflight([model])


def test_campus_bgp_fast_convergence_is_allowed_when_omitted_or_supported() -> None:
    omitted = FabricCampusIbgpVxlanModel.from_config(
        {"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}}
    )
    supplied = FabricCampusIbgpVxlanModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "bgp_fast_convergence": False},
        }
    )

    _orchestrator(ManageCampusIbgpVxlanFabricOrchestrator, "merged", "4.2.1").preflight(
        [omitted]
    )
    _orchestrator(
        ManageCampusIbgpVxlanFabricOrchestrator, "merged", "4.3.1a"
    ).preflight([supplied])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), DHCP_VERSION_GATED_FAMILIES)
@pytest.mark.parametrize(("field", "value"), DHCP_IPV6_FIELDS)
@pytest.mark.parametrize("version", (None, "4.2.1", "4.3.0"))
def test_explicit_ipv6_dhcp_and_gateway_fields_fail_closed_before_4_3_1(
    model_class, orchestrator_class, field, value, version
) -> None:
    management = {"bgp_asn": "65001", field: value}
    if field != "management_gateway":
        management["dhcp_protocol_version"] = "dhcpv6"
    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": management}
    )

    with pytest.raises(RuntimeError, match="require ND 4.3.1 or later"):
        _orchestrator(orchestrator_class, "merged", version).preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), BASELINE_IPV6_FAMILIES)
@pytest.mark.parametrize(("field", "value"), DHCP_IPV6_FIELDS)
@pytest.mark.parametrize("version", (None, "4.2.1", "4.2(1)"))
def test_ipv6_management_addresses_follow_baseline_native_template(model_class, orchestrator_class, field, value, version) -> None:
    management = {"bgp_asn": "65001", field: value, "dhcp_protocol_version": "dhcpv6"}
    model = model_class.from_config({"fabric_name": "fabric1", "management": management})
    _orchestrator(orchestrator_class, "merged", version).preflight([model])
    alias = type(model.management).model_fields[field].alias
    assert model.to_payload()["management"][alias] == value


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize(("field", "value"), DHCP_IPV6_FIELDS)
@pytest.mark.parametrize("version", ("4.3.1", "4.3.1a", "4.4.0"))
def test_explicit_ipv6_dhcp_and_gateway_fields_pass_release_preflight_on_4_3_1_plus(
    model_class, orchestrator_class, field, value, version
) -> None:
    management = {"bgp_asn": "65001", field: value}
    if field != "management_gateway":
        management["dhcp_protocol_version"] = "dhcpv6"
    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": management}
    )

    # This is a local schema/release check, not evidence that a particular
    # controller installation accepts DHCPv6 writes.
    _orchestrator(orchestrator_class, "merged", version).preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize("field", ("dhcp_start_address", "dhcp_end_address"))
@pytest.mark.parametrize("protocol", (None, "dhcpv4"))
def test_ipv6_dhcp_scope_requires_explicit_dhcpv6_protocol(
    model_class, orchestrator_class, field, protocol
) -> None:
    management = {"bgp_asn": "65001", field: "2001:db8::10"}
    if protocol is not None:
        management["dhcp_protocol_version"] = protocol
    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": management}
    )

    with pytest.raises(RuntimeError, match="dhcp_protocol_version.*dhcpv6"):
        _orchestrator(orchestrator_class, "merged", "4.3.1a").preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_ipv6_gateway_requires_dhcpv6_only_with_local_dhcp(
    model_class, orchestrator_class
) -> None:
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
        _orchestrator(orchestrator_class, "merged", "4.3.1a").preflight(
            [model_class.from_config(config)]
        )

    config["management"]["local_dhcp_server"] = False
    _orchestrator(orchestrator_class, "merged", "4.3.1a").preflight(
        [model_class.from_config(config)]
    )


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_exact_state_ipv6_dhcp_scope_requires_explicit_dhcpv6_protocol(
    model_class, orchestrator_class, state
) -> None:
    config = {
        "fabric_name": "fabric1",
        "management": {"bgp_asn": "65001", "dhcp_start_address": "2001:db8::10"},
    }
    without_protocol = model_class.from_config(config, context={"state": state})

    with pytest.raises(RuntimeError, match="dhcp_protocol_version.*dhcpv6"):
        _orchestrator(orchestrator_class, state, "4.3.1a").preflight([without_protocol])

    config["management"]["dhcp_protocol_version"] = "dhcpv6"
    with_protocol = model_class.from_config(config, context={"state": state})
    _orchestrator(orchestrator_class, state, "4.3.1a").preflight([with_protocol])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
@pytest.mark.parametrize("version", (None, "4.2.1"))
def test_ipv4_dhcp_fields_do_not_trigger_ipv6_release_preflight(
    model_class, orchestrator_class, version
) -> None:
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
def test_response_origin_ipv6_config_replay_obeys_each_family_release_policy(
    model_class, orchestrator_class
) -> None:
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
    assert "ospf_max_metric_startup_wait" not in gathered["management"]
    result = ModuleArgumentSpecValidator(model_class.get_argument_spec()).validate(
        {"state": "merged", "config": [gathered]}
    )
    assert result.error_messages == []
    replayed = model_class.from_config(result.validated_parameters["config"][0])

    _orchestrator(orchestrator_class, "merged", "4.3.1a").preflight([replayed])
    if (model_class, orchestrator_class) in BASELINE_IPV6_FAMILIES:
        _orchestrator(orchestrator_class, "merged", "4.2.1").preflight([replayed])
    else:
        with pytest.raises(RuntimeError, match="require ND 4.3.1 or later"):
            _orchestrator(orchestrator_class, "merged", "4.2.1").preflight([replayed])
