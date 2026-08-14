# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for Interface Groups playbook-facing models."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupConfigModel,
    InterfaceGroupGatheredFilterModel,
    InterfaceGroupModuleConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.data_models import (
    InterfaceGroupsCreateRequestModel,
    InterfaceGroupsCreateResponseModel,
    InterfaceGroupsDeleteResponseModel,
    InterfaceGroupsListResponseModel,
    InterfaceGroupsRemoveRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.enums import (
    InterfaceGroupConfigActionType,
    InterfaceGroupState,
    InterfaceGroupType,
)
from pydantic import ValidationError


def test_manage_interface_groups_model_00010() -> None:
    """
    # Summary

    Verify enum choices match the Interface Groups API and issue #368 contracts.

    ## Test

    - Assert all six group types, five resource states, and two action scopes.

    ## Classes and Methods

    - InterfaceGroupType.choices()
    - InterfaceGroupState.choices()
    - InterfaceGroupConfigActionType.choices()
    """
    assert InterfaceGroupType.choices() == [
        "any",
        "ethernetCustom",
        "ethernetWithPolicy",
        "ethernetWithoutPolicy",
        "portChannel",
        "vpc",
    ]
    assert InterfaceGroupState.choices() == [
        "merged",
        "replaced",
        "overridden",
        "deleted",
        "gathered",
    ]
    assert InterfaceGroupConfigActionType.choices() == ["resource", "switch"]


def test_manage_interface_groups_model_00015() -> None:
    """Validate gathered filters separately from write-resource input."""
    gathered = InterfaceGroupModuleConfigModel.model_validate(
        {
            "fabric_name": " fabric-1 ",
            "state": "gathered",
            "config": [
                {
                    "networks": ["network-b", "network-a", "network-a"],
                    "switch_interfaces": [
                        {
                            "switch_id": " SN1 ",
                            "interface_names": ["eth1/2", "Ethernet1/1"],
                        }
                    ],
                }
            ],
        }
    )

    assert gathered.fabric_name == "fabric-1"
    assert isinstance(gathered.config[0], InterfaceGroupGatheredFilterModel)
    assert gathered.config[0].to_filter_config() == {
        "networks": ["network-a", "network-b"],
        "switch_interfaces": [
            {
                "switch_id": "SN1",
                "interface_names": ["Ethernet1/1", "Ethernet1/2"],
            }
        ],
    }

    gather_all = InterfaceGroupModuleConfigModel.model_validate({"fabric_name": "fabric-1", "state": "gathered"})
    assert gather_all.config == []

    with pytest.raises(ValidationError, match="interfaceGroupName"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fabric-1",
                "state": "merged",
                "config": [{"type": "portChannel"}],
            }
        )


def test_manage_interface_groups_model_00017() -> None:
    """Preserve explicit empty association filters and reject write-only keys."""
    filter_item = InterfaceGroupGatheredFilterModel.model_validate({"networks": [], "switch_interfaces": []})
    assert filter_item.to_filter_config() == {
        "networks": [],
        "switch_interfaces": [],
    }

    switch_only = InterfaceGroupGatheredFilterModel.model_validate({"switch_interfaces": [{"switch_id": "SN1"}]})
    assert switch_only.to_filter_config() == {"switch_interfaces": [{"switch_id": "SN1"}]}

    with pytest.raises(ValidationError, match="deploy"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fabric-1",
                "state": "gathered",
                "config": [{"deploy": False}],
            }
        )

    with pytest.raises(ValidationError, match="type=ethernetCustom"):
        InterfaceGroupGatheredFilterModel.model_validate(
            {
                "type": "portChannel",
                "template_name": "custom-template",
            }
        )


def test_manage_interface_groups_model_00020() -> None:
    """
    # Summary

    Verify member, network, and switch associations are normalized for stable diffs.

    ## Test

    - Merge repeated switch entries.
    - Canonicalize port-channel prefixes.
    - De-duplicate and sort networks and members.

    ## Classes and Methods

    - InterfaceGroupConfigModel.from_config()
    - InterfaceGroupConfigModel.to_payload()
    """
    model = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": " group-one ",
            "type": "portChannel",
            "networks": ["net-b", "net-a", "net-b"],
            "switch_interfaces": [
                {"switch_id": " SN2 ", "interface_names": ["po20", "PORT-CHANNEL10"]},
                {"switch_id": "SN2", "interface_names": ["port_channel10"]},
                {"switch_id": "SN1", "interface_names": ["Port-channel2"]},
            ],
        }
    )

    assert model.interface_group_name == "group-one"
    assert model.networks == ["net-a", "net-b"]
    assert [item.switch_id for item in model.switch_interfaces or []] == ["SN1", "SN2"]
    assert (model.switch_interfaces or [])[1].interface_names == [
        "Port-channel10",
        "Port-channel20",
    ]
    assert model.to_payload() == {
        "interfaceGroupName": "group-one",
        "type": "portChannel",
        "networkNames": ["net-a", "net-b"],
        "switchInterfaces": [
            {"switchId": "SN1", "interfaceNames": ["Port-channel2"]},
            {"switchId": "SN2", "interfaceNames": ["Port-channel10", "Port-channel20"]},
        ],
    }


def test_manage_interface_groups_model_00030() -> None:
    """
    # Summary

    Verify API responses using interfaceGroupAssociation are flattened into the playbook shape.

    ## Test

    - Parse the supported nested response shape.
    - Exclude controller-generated counts and policy ID from gathered config and write payloads.

    ## Classes and Methods

    - InterfaceGroupConfigModel.from_response()
    - InterfaceGroupConfigModel.to_config()
    - InterfaceGroupConfigModel.to_payload()
    """
    model = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "eth-group",
            "type": "ethernet",
            "description": "Server-facing Ethernet group",
            "interfaceGroupAssociation": {
                "networkNames": ["net2", "net1"],
                "switchInterfaces": [{"switchId": "SN1", "interfaceNames": ["eth1/2", "Ethernet1/1"]}],
            },
            "policyDetails": {
                "policyId": "POLICY-SHARED-1",
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": {"adminState": True},
            },
            "interfaceCount": 2,
            "networkCount": 2,
        }
    )

    assert model.networks == ["net1", "net2"]
    assert (model.switch_interfaces or [])[0].interface_names == [
        "Ethernet1/1",
        "Ethernet1/2",
    ]
    gathered_config = model.to_config()
    assert gathered_config["description"] == "Server-facing Ethernet group"
    assert gathered_config["networks"] == ["net1", "net2"]
    assert "network_names" not in gathered_config
    assert "interface_count" not in gathered_config
    assert "network_count" not in gathered_config
    assert "policy_id" not in gathered_config
    assert "interfaceCount" not in model.to_payload()
    assert "networkCount" not in model.to_payload()
    assert "policyId" not in model.to_payload()


def test_manage_interface_groups_model_00035() -> None:
    """
    # Summary

    Normalize the generic Ethernet shape returned by a live ND controller.

    ## Test

    - Derive ethernetWithPolicy from type=ethernet and policyDetails.
    - Flatten the nested policy identifier and attributes.
    - Preserve the direct Manage 1.1.411 Ethernet attribute names and types.
    - Keep type=ethernet invalid for playbook input.

    ## Classes and Methods

    - InterfaceGroupConfigModel.from_response()
    - InterfaceGroupConfigModel.from_config()
    """
    model = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "testing-groups",
            "type": "ethernet",
            "policyDetails": {
                "policyId": "POLICY-SHARED-3215880",
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": {
                    "adminState": True,
                    "allowedVlans": "none",
                    "autoNegotiate": True,
                    "duplexMode": "auto",
                    "orphanPort": False,
                    "portTypeEdge": False,
                    "portTypeEdgeTrunk": True,
                },
            },
        }
    )

    assert model.type == "ethernetWithPolicy"
    assert model.policy_id == "POLICY-SHARED-3215880"
    assert model.ethernet_attributes.to_payload() == {
        "adminState": True,
        "allowedVlans": "none",
        "autoNegotiate": True,
        "duplexMode": "auto",
        "orphanPort": False,
        "portTypeEdge": False,
        "portTypeEdgeTrunk": True,
    }

    policyless = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "no-policy",
            "type": "ethernet",
            "policyDetails": {"policyType": "none"},
        }
    )
    assert policyless.type == "ethernetWithoutPolicy"

    with pytest.raises(ValidationError, match=r"policyDetails\.policyType"):
        InterfaceGroupConfigModel.from_response({"interfaceGroupName": "missing-policy-details", "type": "ethernet"})

    with pytest.raises(ValidationError, match=r"policyDetails\.policyType"):
        InterfaceGroupConfigModel.from_response(
            {
                "interfaceGroupName": "unknown-policy-type",
                "type": "ethernet",
                "policyDetails": {"policyType": "futurePolicyType"},
            }
        )

    with pytest.raises(ValidationError):
        InterfaceGroupConfigModel.from_config({"interface_group_name": "invalid-input", "type": "ethernet"})


@pytest.mark.parametrize(
    ("group_type", "input_name", "expected_name"),
    [
        ("any", "e1/1", "Ethernet1/1"),
        ("ethernetCustom", "ETH1/2", "Ethernet1/2"),
        ("ethernetWithPolicy", "ethernet1/3", "Ethernet1/3"),
        ("ethernetWithoutPolicy", "et1/4", "Ethernet1/4"),
        ("portChannel", "po10", "Port-channel10"),
        ("vpc", "Vpc20", "vPC20"),
    ],
)
def test_manage_interface_groups_model_00040(group_type: str, input_name: str, expected_name: str) -> None:
    """
    # Summary

    Verify each Interface Group type accepts and canonicalizes its supported member kind.

    ## Test

    - Parse one member for each of the six group types.

    ## Classes and Methods

    - InterfaceGroupConfigModel.from_config()
    """
    config: dict = {
        "interface_group_name": "group1",
        "type": group_type,
        "switch_interfaces": [{"switch_id": "SN1", "interface_names": [input_name]}],
    }
    if group_type == "ethernetCustom":
        config["template_name"] = "int_shared_custom_trunk_host"

    model = InterfaceGroupConfigModel.from_config(config)

    assert (model.switch_interfaces or [])[0].interface_names == [expected_name]


@pytest.mark.parametrize(
    ("group_type", "invalid_member"),
    [
        ("ethernetWithPolicy", "Port-channel10"),
        ("portChannel", "Ethernet1/1"),
        ("vpc", "Port-channel20"),
        ("any", "Loopback0"),
    ],
)
def test_manage_interface_groups_model_00050(group_type: str, invalid_member: str) -> None:
    """
    # Summary

    Verify type-specific membership prevents invalid switch configuration from reaching ND.

    ## Test

    - Supply a member kind that is incompatible with the group discriminator.

    ## Classes and Methods

    - InterfaceGroupConfigModel.from_config()
    """
    with pytest.raises(ValidationError, match="is not valid for interface group type"):
        InterfaceGroupConfigModel.from_config(
            {
                "interface_group_name": "group1",
                "type": group_type,
                "switch_interfaces": [{"switch_id": "SN1", "interface_names": [invalid_member]}],
            }
        )


def test_manage_interface_groups_model_00060() -> None:
    """
    # Summary

    Verify type-specific custom-template and ethernet-policy fields are gated correctly.

    ## Test

    - Reject custom-template fields on port-channel groups.
    - Reject non-empty ethernet attributes for an ethernetWithoutPolicy group.

    ## Classes and Methods

    - InterfaceGroupConfigModel.from_config()
    """
    with pytest.raises(ValidationError, match="valid only for type=ethernetCustom"):
        InterfaceGroupConfigModel.from_config(
            {
                "interface_group_name": "group1",
                "type": "portChannel",
                "template_name": "template1",
            }
        )
    with pytest.raises(ValidationError, match="must be empty"):
        InterfaceGroupConfigModel.from_config(
            {
                "interface_group_name": "group1",
                "type": "ethernetWithoutPolicy",
                "ethernet_attributes": {"admin_state": True},
            }
        )


def test_manage_interface_groups_model_00070() -> None:
    """
    # Summary

    Verify shared Ethernet attributes are validated before an API call.

    ## Test

    - Serialize valid snake-case input to the API aliases.
    - Reject unknown fields, an invalid native VLAN, and an invalid enum.

    ## Classes and Methods

    - InterfaceGroupConfigModel.from_config()
    - InterfaceGroupConfigModel.to_payload()
    """
    model = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group1",
            "type": "ethernetWithPolicy",
            "ethernet_attributes": {
                "admin_state": True,
                "auto_negotiate": False,
                "native_vlan": 200,
                "speed": "25Gb",
                "orphan_port": False,
            },
        }
    )
    assert model.to_payload()["ethernetAttributes"] == {
        "adminState": True,
        "autoNegotiate": False,
        "nativeVlan": 200,
        "orphanPort": False,
        "speed": "25Gb",
    }

    for attributes in (
        {"unknown_attribute": True},
        {"native_vlan": 4095},
        {"bpdu_guard": "enabled"},
    ):
        with pytest.raises(ValidationError):
            InterfaceGroupConfigModel.from_config(
                {
                    "interface_group_name": "group1",
                    "type": "ethernetWithPolicy",
                    "ethernet_attributes": attributes,
                }
            )


def test_manage_interface_groups_model_00072() -> None:
    """Round-trip every shared Ethernet property defined by Manage 1.1.411."""
    module_attributes = {
        "admin_state": False,
        "allowed_vlans": "1, 10-20, 4094",
        "auto_negotiate": False,
        "bpdu_guard": "disable",
        "cdp": False,
        "description": "Server-facing Ethernet interface",
        "duplex_mode": "full",
        "extra_config": "logging event port link-status",
        "mtu": "default",
        "native_vlan": 200,
        "netflow": True,
        "netflow_monitor": "MONITOR-L2",
        "netflow_sampler": "SAMPLER-1",
        "orphan_port": True,
        "port_type_edge": True,
        "port_type_edge_trunk": False,
        "speed": "100Gb",
    }
    wire_attributes = {
        "adminState": False,
        "allowedVlans": "1,10-20,4094",
        "autoNegotiate": False,
        "bpduGuard": "disable",
        "cdp": False,
        "description": "Server-facing Ethernet interface",
        "duplexMode": "full",
        "extraConfig": "logging event port link-status",
        "mtu": "default",
        "nativeVlan": 200,
        "netflow": True,
        "netflowMonitor": "MONITOR-L2",
        "netflowSampler": "SAMPLER-1",
        "orphanPort": True,
        "portTypeEdge": True,
        "portTypeEdgeTrunk": False,
        "speed": "100Gb",
    }
    model = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "ethernet-all-fields",
            "type": "ethernetWithPolicy",
            "description": "All 1.1.411 attributes",
            "ethernet_attributes": module_attributes,
        }
    )

    wire = InterfaceGroupsCreateRequestModel(interface_groups=[model]).to_payload()["interfaceGroups"][0]
    assert wire == {
        "interfaceGroupName": "ethernet-all-fields",
        "type": "ethernet",
        "description": "All 1.1.411 attributes",
        "networkNames": [],
        "switchInterfaces": [],
        "policyDetails": {
            "policyType": "sharedTrunkHost",
            "ethernetAttributes": wire_attributes,
        },
    }

    response = InterfaceGroupConfigModel.from_response(wire)
    assert response.type == "ethernetWithPolicy"
    assert response.description == "All 1.1.411 attributes"
    assert response.to_config()["ethernet_attributes"] == {
        **module_attributes,
        "allowed_vlans": "1,10-20,4094",
    }


def test_manage_interface_groups_model_00074() -> None:
    """Emit only the defaults explicitly documented by Manage 1.1.411."""
    model = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "ethernet-defaults",
            "type": "ethernetWithPolicy",
        }
    )

    attributes = InterfaceGroupsCreateRequestModel(interface_groups=[model]).to_payload()["interfaceGroups"][0]["policyDetails"]["ethernetAttributes"]
    assert attributes == {
        "adminState": True,
        "allowedVlans": "none",
        "autoNegotiate": True,
        "bpduGuard": "default",
        "cdp": True,
        "duplexMode": "auto",
        "mtu": "jumbo",
        "netflow": False,
        "orphanPort": False,
        "portTypeEdge": False,
        "portTypeEdgeTrunk": True,
        "speed": "auto",
    }
    assert not {
        "adminStatus",
        "autoNegotiation",
        "fex",
        "portDuplexMode",
        "portTypeFast",
        "ptp",
        "ptpTimestampTagging",
        "trunkAllowedVlans",
        "vPCOrphanPort",
    }.intersection(attributes)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, "1"),
        ("none", "none"),
        ("all", "all"),
        ("1, 20-30, 4094", "1,20-30,4094"),
        ("001-010", "1-10"),
    ],
)
def test_manage_interface_groups_model_00076(value, expected: str) -> None:
    """Normalize valid allowed-VLAN values, including integer controller echoes."""
    response = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "allowed-vlans",
            "type": "ethernet",
            "policyDetails": {
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": {"allowedVlans": value},
            },
        }
    )
    assert response.ethernet_attributes.allowed_vlans == expected


@pytest.mark.parametrize(
    "value",
    [True, "", 0, 4095, "200-100", "1,,2", "1-2-3", "one", "1;2"],
)
def test_manage_interface_groups_model_00077(value) -> None:
    """Reject malformed or out-of-range allowed-VLAN expressions."""
    with pytest.raises(ValidationError, match="allowed_vlans"):
        InterfaceGroupConfigModel.from_config(
            {
                "interface_group_name": "invalid-vlans",
                "type": "ethernetWithPolicy",
                "ethernet_attributes": {"allowed_vlans": value},
            }
        )


@pytest.mark.parametrize(
    "removed_field",
    [
        "admin_status",
        "auto_negotiation",
        "fex",
        "port_duplex_mode",
        "port_type_fast",
        "ptp",
        "ptp_timestamp_tagging",
        "trunk_allowed_vlans",
        "vpc_orphan_port",
    ],
)
def test_manage_interface_groups_model_00078(removed_field: str) -> None:
    """Reject 1.1.332 Ethernet names that are not part of the target contract."""
    with pytest.raises(ValidationError, match=removed_field):
        InterfaceGroupConfigModel.from_config(
            {
                "interface_group_name": "old-schema-field",
                "type": "ethernetWithPolicy",
                "ethernet_attributes": {removed_field: True},
            }
        )


def test_manage_interface_groups_model_00079() -> None:
    """Enforce the Manage 1.1.411 nested Ethernet description bounds."""
    for description in ("", "x" * 255, "interface description ☃"):
        with pytest.raises(ValidationError):
            InterfaceGroupConfigModel.from_config(
                {
                    "interface_group_name": "invalid-description",
                    "type": "ethernetWithPolicy",
                    "ethernet_attributes": {"description": description},
                }
            )


def test_manage_interface_groups_model_00080() -> None:
    """Treat a controller-echoed blank Ethernet description as unset."""
    response = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "controller-default-description",
            "type": "ethernet",
            "policyDetails": {
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": {
                    "description": "",
                    "extraConfig": "",
                    "netflowMonitor": "",
                    "netflowSampler": "",
                },
            },
        }
    )

    assert response.ethernet_attributes.description is None
    assert response.ethernet_attributes.extra_config == ""
    assert response.ethernet_attributes.netflow_monitor == ""
    assert response.ethernet_attributes.netflow_sampler == ""
    assert "description" not in response.to_config()["ethernet_attributes"]


def test_manage_interface_groups_model_00100() -> None:
    """
    # Summary

    Verify the module argspec composes the shared config_actions fragment.

    ## Test

    - Include deploy and type, but not save.
    - Restrict deployment scopes to resource and switch for Interface Groups.
    - Do not inject a config-item deploy default that would erase explicitness.

    ## Classes and Methods

    - InterfaceGroupModuleConfigModel.get_argument_spec()
    """
    spec = InterfaceGroupModuleConfigModel.get_argument_spec()
    action_options = spec["config_actions"]["options"]
    config_options = spec["config"]["options"]

    assert set(action_options) == {"deploy", "type"}
    assert action_options["deploy"] == {"type": "bool", "default": True}
    assert action_options["type"] == {
        "type": "str",
        "default": "switch",
        "choices": ["resource", "switch"],
    }
    assert config_options["deploy"] == {"type": "bool"}
    assert config_options["networks"] == {"type": "list", "elements": "str"}
    assert "network_names" not in config_options
    assert config_options["description"] == {"type": "str"}
    assert "ticket_id" not in spec
    assert "cluster_name" not in spec

    with pytest.raises(ValidationError, match="resource|switch"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fab1",
                "config_actions": {"type": "global"},
                "config": [{"interface_group_name": "group1", "type": "portChannel"}],
            }
        )


def test_manage_interface_groups_model_00110() -> None:
    """
    # Summary

    Verify every state requires config and authoritative states require type.

    ## Test

    - Reject an empty merged request.
    - Accept a merged update shape without type.
    - Reject a replaced entry without type.
    - Reject deleted without config.

    ## Classes and Methods

    - InterfaceGroupModuleConfigModel.model_validate()
    """
    with pytest.raises(ValidationError, match="config is required when state=merged"):
        InterfaceGroupModuleConfigModel.model_validate({"fabric_name": "fab1"})
    merged_update = InterfaceGroupModuleConfigModel.model_validate({"fabric_name": "fab1", "config": [{"interface_group_name": "group1"}]})
    assert merged_update.config[0].type is None

    with pytest.raises(ValidationError, match="type is required"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fab1",
                "state": "replaced",
                "config": [{"interface_group_name": "group1"}],
            }
        )

    with pytest.raises(ValidationError, match="config is required when state=deleted"):
        InterfaceGroupModuleConfigModel.model_validate({"fabric_name": "fab1", "state": "deleted"})


def test_manage_interface_groups_model_00120() -> None:
    """
    # Summary

    Verify per-resource deploy flags are rejected outside resource scope.

    ## Test

    - Use the default switch scope with an explicit config-item deploy key.

    ## Classes and Methods

    - InterfaceGroupModuleConfigModel.model_validate()
    """
    with pytest.raises(ValidationError, match=r"config\[\]\.deploy is valid only"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fab1",
                "config": [
                    {
                        "interface_group_name": "group1",
                        "type": "portChannel",
                        "deploy": False,
                    }
                ],
            }
        )

    model = InterfaceGroupModuleConfigModel.model_validate(
        {
            "fabric_name": "fab1",
            "config": [
                {
                    "interface_group_name": "group1",
                    "type": "portChannel",
                    "deploy": None,
                }
            ],
        }
    )
    assert "deploy" not in model.config[0].model_fields_set


def test_manage_interface_groups_model_00130() -> None:
    """
    # Summary

    Verify resource-scope deploy defaults and overrides follow issue #368.

    ## Test

    - Omitted config-item deploy defaults effectively to true.
    - Explicit false disables only that resource.
    - Top-level config_actions.deploy=false disables all resources.

    ## Classes and Methods

    - InterfaceGroupModuleConfigModel.resource_deploy_enabled()
    """
    model = InterfaceGroupModuleConfigModel.model_validate(
        {
            "fabric_name": "fab1",
            "config_actions": {"type": "resource"},
            "config": [
                {"interface_group_name": "group1", "type": "portChannel"},
                {
                    "interface_group_name": "group2",
                    "type": "portChannel",
                    "deploy": False,
                },
            ],
        }
    )

    assert model.resource_deploy_enabled(model.config[0]) is True
    assert model.resource_deploy_enabled(model.config[1]) is False

    disabled = InterfaceGroupModuleConfigModel.model_validate(
        {
            "fabric_name": "fab1",
            "config_actions": {"type": "resource", "deploy": False},
            "config": [{"interface_group_name": "group1", "type": "portChannel"}],
        }
    )
    assert disabled.resource_deploy_enabled(disabled.config[0]) is False


def test_manage_interface_groups_model_00140() -> None:
    """
    # Summary

    Verify duplicate group keys and cross-group member conflicts fail before writes.

    ## Test

    - Reject the same group name twice.
    - Reject one normalized switch interface assigned to two requested groups.

    ## Classes and Methods

    - InterfaceGroupModuleConfigModel.model_validate()
    """
    with pytest.raises(ValidationError, match="duplicate interface_group_name"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fab1",
                "config": [
                    {"interface_group_name": "group1", "type": "any"},
                    {"interface_group_name": "group1", "type": "any"},
                ],
            }
        )

    with pytest.raises(ValidationError, match="is present in both"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fab1",
                "config": [
                    {
                        "interface_group_name": "group1",
                        "type": "ethernetWithPolicy",
                        "switch_interfaces": [{"switch_id": "SN1", "interface_names": ["eth1/1"]}],
                    },
                    {
                        "interface_group_name": "group2",
                        "type": "ethernetWithoutPolicy",
                        "switch_interfaces": [{"switch_id": "SN1", "interface_names": ["Ethernet1/1"]}],
                    },
                ],
            }
        )


def test_manage_interface_groups_model_00150() -> None:
    """
    # Summary

    Verify merged performs additive reconciliation at every Interface Group nesting level.

    ## Test

    - Preserve existing networks, switches, interfaces, and dictionary keys.
    - Add new networks, switches, interfaces, and dictionary keys.
    - Treat already-present values and explicit empty collections as no-ops.

    ## Classes and Methods

    - InterfaceGroupConfigModel.get_diff()
    - InterfaceGroupConfigModel.merge()
    """
    existing = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "group1",
            "type": "ethernet",
            "networkNames": ["net-a"],
            "switchInterfaces": [
                {"switchId": "SN1", "interfaceNames": ["Ethernet1/1"]},
                {"switchId": "SN2", "interfaceNames": ["Ethernet1/2"]},
            ],
            "policyDetails": {
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": {
                    "adminState": True,
                    "cdp": False,
                },
            },
        }
    )
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group1",
            "networks": ["net-b"],
            "switch_interfaces": [
                {"switch_id": "SN1", "interface_names": ["Ethernet1/3"]},
                {"switch_id": "SN3", "interface_names": ["Ethernet1/4"]},
            ],
            "ethernet_attributes": {
                "netflow": True,
            },
        }
    )

    assert existing.get_diff(proposed, exclude_unset=True) is False
    merged = existing.merge(proposed)
    assert merged.networks == ["net-a", "net-b"]
    assert [(item.switch_id, item.interface_names) for item in merged.switch_interfaces or []] == [
        ("SN1", ["Ethernet1/1", "Ethernet1/3"]),
        ("SN2", ["Ethernet1/2"]),
        ("SN3", ["Ethernet1/4"]),
    ]
    assert merged.ethernet_attributes.to_payload() == {
        "adminState": True,
        "cdp": False,
        "netflow": True,
    }

    already_present = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group1",
            "networks": ["net-a"],
            "switch_interfaces": [{"switch_id": "SN1", "interface_names": ["Ethernet1/1"]}],
        }
    )
    empty_collections = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group1",
            "networks": [],
            "switch_interfaces": [],
            "ethernet_attributes": {},
        }
    )
    assert merged.get_diff(already_present, exclude_unset=True) is True
    assert merged.get_diff(empty_collections, exclude_unset=True) is True


def test_manage_interface_groups_model_00155() -> None:
    """
    # Summary

    Verify authoritative states still have a removal path.

    ## Test

    - Confirm the proposed model retains exactly the supplied network and member lists.
    - Confirm normal non-merged comparison detects the shorter lists as a change.

    ## Classes and Methods

    - InterfaceGroupConfigModel.get_diff()
    """
    existing = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "group1",
            "type": "portChannel",
            "networkNames": ["net-a", "net-b"],
            "switchInterfaces": [
                {
                    "switchId": "SN1",
                    "interfaceNames": ["Port-channel10", "Port-channel20"],
                }
            ],
        }
    )
    proposed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "group1",
            "type": "portChannel",
            "networks": ["net-a"],
            "switch_interfaces": [{"switch_id": "SN1", "interface_names": ["Port-channel10"]}],
        }
    )

    assert existing.get_diff(proposed, exclude_unset=False) is False
    assert proposed.networks == ["net-a"]
    assert (proposed.switch_interfaces or [])[0].interface_names == ["Port-channel10"]


def test_manage_interface_groups_model_00157() -> None:
    """Accept and serialize the top-level Interface Group description."""
    module_config = InterfaceGroupModuleConfigModel.model_validate(
        {
            "fabric_name": "fabric1",
            "state": "merged",
            "config": [
                {
                    "interface_group_name": "group1",
                    "type": "portChannel",
                    "description": "Server-facing port channels",
                }
            ],
        }
    )

    assert module_config.config[0].description == "Server-facing port channels"
    assert module_config.config[0].to_payload()["description"] == "Server-facing port channels"


def test_manage_interface_groups_model_00160() -> None:
    """
    # Summary

    Verify ethernetCustom write requests require a template name.

    ## Test

    - Reject a replaced ethernetCustom entry without template_name.

    ## Classes and Methods

    - InterfaceGroupModuleConfigModel.model_validate()
    """
    with pytest.raises(ValidationError, match="template_name is required"):
        InterfaceGroupModuleConfigModel.model_validate(
            {
                "fabric_name": "fab1",
                "state": "replaced",
                "config": [{"interface_group_name": "custom1", "type": "ethernetCustom"}],
            }
        )


def test_manage_interface_groups_model_00200() -> None:
    """
    # Summary

    Verify bulk create and remove request wrappers match the supported request shapes.

    ## Test

    - Wrap create entries under interfaceGroups and omit module-only deploy.
    - Normalize bulk-remove names under interfaceGroupNames.

    ## Classes and Methods

    - InterfaceGroupsCreateRequestModel.to_payload()
    - InterfaceGroupsRemoveRequestModel.to_payload()
    """
    create = InterfaceGroupsCreateRequestModel(
        interface_groups=[
            InterfaceGroupConfigModel(
                interface_group_name="group1",
                type="portChannel",
                deploy=False,
            )
        ]
    )
    remove = InterfaceGroupsRemoveRequestModel(interface_group_names=["group2", "group1", "group2"])

    assert create.to_payload() == {
        "interfaceGroups": [
            {
                "interfaceGroupName": "group1",
                "type": "portChannel",
                "networkNames": [],
                "switchInterfaces": [],
            }
        ]
    }
    assert remove.to_payload() == {"interfaceGroupNames": ["group1", "group2"]}


def test_manage_interface_groups_model_00205() -> None:
    """Translate a shared-policy group to the live generic Ethernet write shape."""
    create = InterfaceGroupsCreateRequestModel(
        interface_groups=[
            InterfaceGroupConfigModel.from_config(
                {
                    "interface_group_name": "ethernet-policy",
                    "type": "ethernetWithPolicy",
                    "ethernet_attributes": {
                        "admin_state": False,
                        "auto_negotiate": False,
                        "allowed_vlans": "100-200",
                    },
                }
            )
        ]
    )

    group = create.to_payload()["interfaceGroups"][0]
    assert group["type"] == "ethernet"
    assert group["networkNames"] == []
    assert group["switchInterfaces"] == []
    assert "ethernetAttributes" not in group
    assert group["policyDetails"]["policyType"] == "sharedTrunkHost"
    assert group["policyDetails"]["ethernetAttributes"]["adminState"] is False
    assert group["policyDetails"]["ethernetAttributes"]["autoNegotiate"] is False
    assert group["policyDetails"]["ethernetAttributes"]["allowedVlans"] == "100-200"
    assert group["policyDetails"]["ethernetAttributes"]["portTypeEdge"] is False


def test_manage_interface_groups_model_00207() -> None:
    """
    # Summary

    Translate a policy-less Ethernet group to the live generic Ethernet shape.

    ## Test

    - Write the group as generic Ethernet with policy type none.
    - Do not emit Ethernet attributes for the policy-less group.

    ## Classes and Methods

    - InterfaceGroupsCreateRequestModel.to_payload()
    """
    create = InterfaceGroupsCreateRequestModel(
        interface_groups=[
            InterfaceGroupConfigModel.from_config(
                {
                    "interface_group_name": "ethernet-no-policy",
                    "type": "ethernetWithoutPolicy",
                }
            )
        ]
    )

    group = create.to_payload()["interfaceGroups"][0]
    assert group["type"] == "ethernet"
    assert group["policyDetails"] == {"policyType": "none"}
    assert "ethernetAttributes" not in group


def test_manage_interface_groups_model_00208() -> None:
    """Translate custom Ethernet groups to and from the live generic Ethernet shape."""
    create = InterfaceGroupsCreateRequestModel(
        interface_groups=[
            InterfaceGroupConfigModel.from_config(
                {
                    "interface_group_name": "ethernet-custom",
                    "type": "ethernetCustom",
                    "template_name": "int_shared_custom_trunk_host",
                    "template_config": {
                        "adminStatus": True,
                        "extraConfig": "logging event port link-status",
                    },
                }
            )
        ]
    )

    group = create.to_payload()["interfaceGroups"][0]
    assert group["type"] == "ethernet"
    assert group["policyDetails"] == {
        "policyType": "userDefinedSharedTrunk",
        "templateName": "int_shared_custom_trunk_host",
        "templateConfig": {
            "adminStatus": True,
            "extraConfig": "logging event port link-status",
        },
    }
    assert "templateName" not in group
    assert "templateConfig" not in group

    response = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "ethernet-custom",
            "type": "ethernet",
            "policyDetails": {
                "policyType": "userDefinedSharedTrunk",
                "templateName": "int_shared_custom_trunk_host",
                "templateConfig": {
                    "adminStatus": True,
                    "extraConfig": "logging event port link-status",
                },
            },
        }
    )
    assert response.type == "ethernetCustom"
    assert response.template_name == "int_shared_custom_trunk_host"
    assert response.template_config == {
        "adminStatus": True,
        "extraConfig": "logging event port link-status",
    }


@pytest.mark.parametrize(
    ("group_type", "input_name", "wire_name"),
    [
        ("any", "eth1/1", "Ethernet1/1"),
        ("portChannel", "po10", "Port-channel10"),
        ("vpc", "vpc200", "vPC200"),
    ],
)
def test_manage_interface_groups_model_002085(group_type: str, input_name: str, wire_name: str) -> None:
    """Keep non-Ethernet discriminators unchanged through write/read translation."""
    model = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": f"{group_type}-group",
            "type": group_type,
            "switch_interfaces": [{"switch_id": "PRIMARY-SERIAL", "interface_names": [input_name]}],
        }
    )

    wire = InterfaceGroupsCreateRequestModel(interface_groups=[model]).to_payload()["interfaceGroups"][0]
    assert wire == {
        "interfaceGroupName": f"{group_type}-group",
        "type": group_type,
        "networkNames": [],
        "switchInterfaces": [
            {
                "switchId": "PRIMARY-SERIAL",
                "interfaceNames": [wire_name],
            }
        ],
    }

    response = InterfaceGroupConfigModel.from_response(wire)
    assert response.type == group_type
    assert response.switch_interfaces[0].switch_id == "PRIMARY-SERIAL"
    assert response.switch_interfaces[0].interface_names == [wire_name]


def test_manage_interface_groups_model_00209() -> None:
    """Preserve explicit null values within native custom-template inputs."""
    model = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "ethernet-custom-null",
            "type": "ethernetCustom",
            "template_name": "dupe_shared_trunk_host",
            "template_config": {
                "ALLOWED_VLANS": "none",
                "NATIVE_VLAN": None,
            },
        }
    )

    assert model.template_config == {
        "ALLOWED_VLANS": "none",
        "NATIVE_VLAN": None,
    }
    group = InterfaceGroupsCreateRequestModel(interface_groups=[model]).to_payload()["interfaceGroups"][0]
    assert group["policyDetails"]["templateConfig"] == {
        "ALLOWED_VLANS": "none",
        "NATIVE_VLAN": None,
    }


def test_manage_interface_groups_model_002095() -> None:
    """Treat typed custom-template input as equal to its controller echo."""
    existing = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": "ethernet-custom-live",
            "type": "ethernet",
            "policyDetails": {
                "policyType": "userDefinedSharedTrunk",
                "templateName": "dupe_shared_trunk_host",
                "templateConfig": {
                    "ADMIN_STATE": "true",
                    "CDP_ENABLE": "true",
                    "NATIVE_VLAN": "1",
                    "POLICY_ID": "POLICY-SHARED-1",
                    "PRIORITY": 500,
                },
            },
        }
    )
    unchanged = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "ethernet-custom-live",
            "type": "ethernetCustom",
            "template_name": "dupe_shared_trunk_host",
            "template_config": {
                "ADMIN_STATE": True,
                "CDP_ENABLE": True,
                "NATIVE_VLAN": None,
            },
        }
    )
    changed = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "ethernet-custom-live",
            "template_config": {"CDP_ENABLE": False},
        }
    )

    assert existing.template_config == {
        "ADMIN_STATE": "true",
        "CDP_ENABLE": "true",
        "NATIVE_VLAN": "1",
    }
    assert existing.get_diff(unchanged, exclude_unset=True) is True
    assert existing.get_diff(unchanged, exclude_unset=False) is True
    assert existing.get_diff(changed, exclude_unset=True) is False


def test_manage_interface_groups_model_00210() -> None:
    """
    # Summary

    Verify HTTP 207 response models inspect each result instead of treating 207 as success.

    ## Test

    - Parse mixed success and failed create/delete results.
    - Return only unsuccessful or missing-status entries from failures.

    ## Classes and Methods

    - InterfaceGroupsCreateResponseModel.failures
    - InterfaceGroupsDeleteResponseModel.failures
    """
    create = InterfaceGroupsCreateResponseModel.from_response(
        {
            "interfaceGroups": [
                {"type": "portChannel", "status": "success", "message": "created"},
                {"type": "ethernet", "status": "success", "message": "created"},
                {"type": "vpc", "status": "failed", "message": "member conflict"},
            ]
        }
    )
    delete = InterfaceGroupsDeleteResponseModel.from_response(
        {
            "interfaceGroups": [
                {
                    "interfaceGroupName": "group1",
                    "status": "success",
                    "message": "deleted",
                },
                {
                    "interfaceGroupName": "group2",
                    "status": "failed",
                    "message": "not empty",
                },
            ]
        }
    )

    assert [item.message for item in create.failures] == ["member conflict"]
    assert [item.type for item in create.interface_groups] == [
        "portChannel",
        "ethernet",
        "vpc",
    ]
    assert [item.interface_group_name for item in delete.failures] == ["group2"]


def test_manage_interface_groups_model_00220() -> None:
    """
    # Summary

    Verify list responses accept the Manage 1.1.411 response wrapper.

    ## Test

    - Parse all entries under interfaceGroupDetails.

    ## Classes and Methods

    - InterfaceGroupsListResponseModel.from_response()
    """
    documented = InterfaceGroupsListResponseModel.from_response(
        {
            "interfaceGroupDetails": [
                {"interfaceGroupName": "group1", "type": "portChannel"},
                {
                    "interfaceGroupName": "group2",
                    "type": "ethernet",
                    "policyDetails": {"policyType": "none"},
                },
            ],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        }
    )

    assert [item.interface_group_name for item in documented.interface_group_details] == ["group1", "group2"]
    assert documented.interface_group_details[1].type == "ethernetWithoutPolicy"
