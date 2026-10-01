# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for security and segmentation Pydantic models."""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import (
    SecurityAssociationModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.contracts import (
    SecurityContractModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import (
    SecurityGroupModel,
    SecurityGroupSelectorModel,
    SecurityGroupVmDataModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.protocol_definitions import (
    ProtocolDefinitionMatchCriteriaModel,
    SecurityProtocolDefinitionModel,
)
from pydantic import ValidationError


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


def test_security_models_00020():
    """Verify protocol port ranges reject service names and invalid ranges."""
    with pytest.raises(ValidationError, match="numeric port"):
        ProtocolDefinitionMatchCriteriaModel(match_name="ssh", dst_port_range="ssh")
    with pytest.raises(ValidationError, match="less than or equal"):
        ProtocolDefinitionMatchCriteriaModel(match_name="bad", dst_port_range="200-100")
    with does_not_raise():
        model = ProtocolDefinitionMatchCriteriaModel(match_name="web", dst_port_range="80-443", dscp=10)
    assert model.dst_port_range == "80-443"


def test_security_models_00030():
    """Verify DSCP range is enforced."""
    with pytest.raises(ValidationError):
        ProtocolDefinitionMatchCriteriaModel(match_name="bad", dscp=64)


def test_security_models_00040():
    """Verify protocol payload uses OpenAPI aliases and excludes read-only fields."""
    model = SecurityProtocolDefinitionModel(
        name="web_tcp",
        tenant_name="common",
        match_type="any",
        match_items=[
            {
                "match_name": "web",
                "type": "IPv4",
                "protocol_options": "TCP",
                "dst_port_range": "443",
            }
        ],
        match_summary="read-only",
        security_contract_count=2,
    )
    payload = model.to_payload()

    assert payload["name"] == "common~web_tcp"
    assert payload["tenantName"] == "common"
    assert payload["matchType"] == "any"
    assert payload["matchItems"][0]["matchName"] == "web"
    assert "matchSummary" not in payload
    assert "securityContractCount" not in payload


def test_security_models_00050():
    """Verify security group selector type-specific requiredness."""
    with pytest.raises(ValidationError, match="requires"):
        SecurityGroupSelectorModel(type="networkPort", network_name="net1", switch_id="FDO123")
    with does_not_raise():
        selector = SecurityGroupSelectorModel(
            type="networkPort",
            network_name="net1",
            switch_id="FDO123",
            interface_name="Ethernet1/10",
        )
    assert selector.interface_name == "Ethernet1/10"


def test_security_models_00060():
    """Verify connected endpoint selector normalizes plain IP to a host prefix."""
    selector = SecurityGroupSelectorModel(type="connectedEndpoint", vrf_name="vrf1", ip="10.1.1.1")
    assert selector.ip == "10.1.1.1/32"


def test_security_models_00065():
    """Verify network selector read-only fields do not force repeat diffs."""
    existing = SecurityGroupModel.from_response(
        {
            "name": "app_web",
            "id": 101,
            "attach": True,
            "vrfNames": ["AnsibleVRF"],
            "selectors": [
                {
                    "type": "network",
                    "networkName": "AnsibleNet1",
                    "vrfName": "AnsibleVRF",
                    "displayNetworkName": "AnsibleNet1",
                    "vlanId": "2303",
                }
            ],
        }
    )
    proposed = SecurityGroupModel.from_config(
        {
            "name": "app_web",
            "id": 101,
            "attach": True,
            "vrf_names": ["AnsibleVRF"],
            "selectors": [
                {
                    "type": "network",
                    "network_name": "AnsibleNet1",
                }
            ],
        }
    )

    assert existing.get_diff(proposed) is True
    assert "vrfName" not in existing.to_payload()["selectors"][0]


def test_security_models_00066():
    """Verify connected endpoint selectors keep vrfName in write payloads."""
    group = SecurityGroupModel(
        name="app_endpoint",
        id=102,
        vrf_names=["AnsibleVRF"],
        selectors=[
            SecurityGroupSelectorModel(
                type="connectedEndpoint",
                vrf_name="AnsibleVRF",
                ip="10.1.1.1",
            )
        ],
    )

    selector_payload = group.to_payload()["selectors"][0]

    assert selector_payload["vrfName"] == "AnsibleVRF"
    assert selector_payload["ip"] == "10.1.1.1/32"


def test_security_models_00070():
    """Verify security group names reject unsupported product characters."""
    with pytest.raises(ValidationError, match="cannot contain"):
        SecurityGroupModel(name="bad{name")


def test_security_models_00080():
    """Verify security group required create fields are enforced by the model helper."""
    model = SecurityGroupModel(name="app_web")
    with pytest.raises(ValueError, match="missing required"):
        model.validate_required_payload_fields()


def test_security_models_00085():
    """Verify security group read models accept controller-returned id zero."""
    with does_not_raise():
        model = SecurityGroupModel.from_response({"name": "default", "id": 0, "vrfNames": ["default"]})
    assert model.id == 0


def test_security_models_00090():
    """Verify security association rejects inter-VRF input when both VRFs are supplied."""
    with pytest.raises(ValidationError, match="must match"):
        SecurityAssociationModel(
            name="web_to_app",
            contract_name="allow_web",
            src_security_group_name="web",
            src_vrf_name="vrf1",
            dst_security_group_name="app",
            dst_vrf_name="vrf2",
        )


def test_security_models_00100():
    """Verify argspec exposes gathered state, optional config, and shared action defaults."""
    argspec = SecurityGroupModel.get_argument_spec()

    assert argspec["state"]["choices"] == [
        "merged",
        "replaced",
        "overridden",
        "deleted",
        "gathered",
    ]
    assert argspec["config"]["required"] is False
    assert "config_actions" in argspec
    assert argspec["config_actions"]["options"]["save"]["default"] is False
    assert argspec["config_actions"]["options"]["deploy"]["default"] is False
    assert argspec["config_actions"]["options"]["type"]["default"] == "switch"


def test_security_models_00110():
    """Verify ND 4.2 and 4.3 TCP flag grammar."""
    for tcp_flag in ("est", "ack", "fin", "rst", "syn"):
        model = ProtocolDefinitionMatchCriteriaModel.model_validate(
            {"match_name": "tcp", "tcp_flags": tcp_flag},
            context={"mode": "config", "controller_version": "4.2.1.10"},
        )
        assert model.tcp_flags == tcp_flag

    with pytest.raises(ValidationError, match="require ND 4.3"):
        ProtocolDefinitionMatchCriteriaModel.model_validate(
            {"match_name": "tcp", "tcp_flags": "ack;syn"},
            context={"mode": "config", "controller_version": "4.2.1.10"},
        )

    combined = ProtocolDefinitionMatchCriteriaModel.model_validate(
        {"match_name": "tcp", "tcp_flags": "ack;syn"},
        context={"mode": "config", "controller_version": "4.3.1.10"},
    )
    assert combined.tcp_flags == "ack;syn"

    top_level = SecurityProtocolDefinitionModel.from_config(
        {
            "name": "tcp_combined",
            "match_items": [{"match_name": "tcp", "tcp_flags": "ack;syn"}],
        },
        context={"controller_version": "4.3.1.10"},
    )
    assert top_level.match_items[0].tcp_flags == "ack;syn"


@pytest.mark.parametrize("tcp_flags", ["est;syn", "ack;ack", "ack;bogus", "ack;"])
def test_security_models_00120(tcp_flags):
    """Verify combined TCP flags enforce exclusivity, uniqueness, and vocabulary."""
    with pytest.raises(ValidationError):
        ProtocolDefinitionMatchCriteriaModel.model_validate(
            {"match_name": "tcp", "tcp_flags": tcp_flags},
            context={"mode": "config", "controller_version": "4.3.1.10"},
        )


def test_security_models_00130():
    """Verify 4.3 combined TCP flags remain readable without version context."""
    model = ProtocolDefinitionMatchCriteriaModel.model_validate(
        {"matchName": "tcp", "tcpFlags": "ack;fin"},
        by_alias=True,
        context={"mode": "response"},
    )
    assert model.tcp_flags == "ack;fin"


def test_security_models_00140():
    """Verify security descriptions follow the shared and release-specific schemas."""
    unicode_description = "Aplicación 東京"
    model = SecurityGroupModel.from_config(
        {"name": "app_web", "description": unicode_description},
        context={"controller_version": "4.3.1.10"},
    )
    assert model.description == unicode_description
    assert SecurityGroupModel(name="app_web", description="").description == ""
    assert SecurityGroupModel(name="app_web", description="x" * 128).description == "x" * 128

    with pytest.raises(ValidationError):
        SecurityGroupModel(name="app_web", description="x" * 129)
    for invalid_description in (
        "line one\nline two",
        "\nline one",
        "line one\n",
        "line one\rline two",
    ):
        with pytest.raises(ValidationError, match="must not contain"):
            SecurityGroupModel.from_config(
                {"name": "app_web", "description": invalid_description},
                context={"controller_version": "4.3.1.10"},
            )

    legacy = SecurityGroupModel.from_config(
        {"name": "app_web", "description": "line one\nline two"},
        context={"controller_version": "4.2.1.10"},
    )
    assert legacy.description == "line one\nline two"


def test_security_models_00150():
    """Verify response parsing remains tolerant of release-specific description syntax."""
    response = SecurityGroupModel.from_response(
        {
            "name": "app_web",
            "id": 16,
            "vrfNames": ["vrf1"],
            "description": "line one\nline two",
        }
    )
    assert response.description == "line one\nline two"


def test_security_models_00160():
    """Verify release-specific qualified-name limits and tenant characters."""
    tenant_42 = "tenant"
    tenant_43 = "tenant.with.dot"
    with does_not_raise():
        SecurityProtocolDefinitionModel.from_config(
            {"name": "p" * 20},
            context={"controller_version": "4.2.1.10", "state": "merged"},
        )
        SecurityProtocolDefinitionModel.from_config(
            {"name": "p" * (102 - len(tenant_43) - 1), "tenant_name": tenant_43},
            context={"controller_version": "4.3.1.10"},
        )
        SecurityContractModel.from_config(
            {"name": "c" * (102 - len(tenant_43) - 1), "tenant_name": tenant_43},
            context={"controller_version": "4.3.1.10"},
        )
        SecurityGroupModel.from_config(
            {"name": "g" * (125 - len(tenant_43) - 1), "tenant_name": tenant_43},
            context={"controller_version": "4.3.1.10"},
        )
        SecurityAssociationModel.from_config(
            {"name": "a" * 128},
            context={"controller_version": "4.3.1.10"},
        )

    with pytest.raises(ValidationError, match="at most 20"):
        SecurityProtocolDefinitionModel.from_config(
            {"name": "p" * 21},
            context={"controller_version": "4.2.1.10", "state": "merged"},
        )
    with pytest.raises(ValidationError, match="at most 92"):
        SecurityProtocolDefinitionModel.from_config(
            {"name": "p" * (92 - len(tenant_42)), "tenant_name": tenant_42},
            context={"controller_version": "4.2.1.10"},
        )
    with pytest.raises(ValidationError, match="at most 63"):
        SecurityGroupModel.from_config(
            {"name": "g" * 64},
            context={"controller_version": "4.2.1.10"},
        )
    with pytest.raises(ValidationError, match="tenant_name"):
        SecurityGroupModel.from_config(
            {"name": "app_web", "tenant_name": "tenant.with.dot"},
            context={"controller_version": "4.2.1.10"},
        )


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_security_models_00165(state):
    """Verify the live ND 4.2 protocol-name limit applies only to writes."""
    with pytest.raises(ValidationError, match="at most 20"):
        SecurityProtocolDefinitionModel.from_config(
            {"name": "p" * 21},
            context={"controller_version": "4.2.1.10", "state": state},
        )

    assert (
        SecurityProtocolDefinitionModel.from_config(
            {"name": "p" * 63},
            context={"controller_version": "4.3.1.10", "state": state},
        ).name
        == "p" * 63
    )
    assert (
        SecurityProtocolDefinitionModel.from_config(
            {"name": "p" * 63, "tenant_name": "tenant"},
            context={"controller_version": "4.2.1.10", "state": state},
        ).name
        == "p" * 63
    )


def test_security_models_00166():
    """Verify long legacy protocol names remain readable and removable."""
    long_name = "p" * 63
    assert SecurityProtocolDefinitionModel.from_response({"name": long_name}).name == long_name
    for state in ("deleted", "gathered"):
        assert (
            SecurityProtocolDefinitionModel.from_config(
                {"name": long_name},
                context={"controller_version": "4.2.1.10", "state": state},
            ).name
            == long_name
        )
    assert SecurityProtocolDefinitionModel.from_config({"name": long_name}).name == long_name


def test_security_models_00170():
    """Verify common name, display-name, match-name, VRF, and network constraints."""
    with pytest.raises(ValidationError, match="cannot contain"):
        SecurityGroupModel(name="group with spaces")
    with pytest.raises(ValidationError, match="display_name"):
        SecurityGroupModel(name="app_web", display_name="display name")
    with pytest.raises(ValidationError):
        SecurityGroupModel(name="app_web", display_name="d" * 65)
    with pytest.raises(ValidationError):
        SecurityGroupSelectorModel(type="network", network_name="n" * 129)
    with pytest.raises(ValidationError):
        SecurityGroupSelectorModel(type="connectedEndpoint", vrf_name="v" * 95, ip="10.1.1.1")
    with pytest.raises(ValidationError, match="at most 94"):
        SecurityGroupModel(name="app_web", vrf_names=["v" * 95])

    with does_not_raise():
        ProtocolDefinitionMatchCriteriaModel.model_validate(
            {"match_name": "entry~one"},
            context={"controller_version": "4.2.1.10"},
        )
        ProtocolDefinitionMatchCriteriaModel.model_validate(
            {"match_name": "entry:one"},
            context={"controller_version": "4.3.1.10"},
        )
    with pytest.raises(ValidationError):
        ProtocolDefinitionMatchCriteriaModel.model_validate(
            {"match_name": "entry:one"},
            context={"controller_version": "4.2.1.10"},
        )
    with pytest.raises(ValidationError):
        ProtocolDefinitionMatchCriteriaModel.model_validate(
            {"match_name": "entry~one"},
            context={"controller_version": "4.3.1.10"},
        )


def test_security_models_00180():
    """Verify typed vCenter VM selector data and OpenAPI aliases."""
    selector = SecurityGroupSelectorModel.from_config(
        {
            "type": "vm",
            "vm_data": [
                {
                    "vm_data_type": "vCenter",
                    "v_center": "192.0.2.10",
                    "vm_uuid": "10111111-11e1-1111-1211-111feeaaa5aa",
                    "nic_mac": "00:A0:11:11:11:11",
                }
            ],
        }
    )

    assert isinstance(selector.vm_data[0], SecurityGroupVmDataModel)
    assert selector.to_payload() == {
        "type": "vm",
        "vmData": [
            {
                "vmDataType": "vCenter",
                "vCenter": "192.0.2.10",
                "vmUuid": "10111111-11e1-1111-1211-111feeaaa5aa",
                "nicMac": "00:A0:11:11:11:11",
            }
        ],
    }


def test_security_models_00190():
    """Verify VM selector read-only controller fields are excluded from writes and diffs."""
    group = SecurityGroupModel.from_response(
        {
            "name": "vm_group",
            "id": 100,
            "vrfNames": ["vrf1"],
            "selectors": [
                {
                    "type": "vm",
                    "vmData": [
                        {
                            "vmDataType": "vCenter",
                            "vCenter": "192.0.2.10",
                            "vmUuid": "10111111-11e1-1111-1211-111feeaaa5aa",
                            "nicMac": "00:A0:11:11:11:11",
                            "nicName": "Network adapter 1",
                            "vmName": "app-vm",
                            "esxiHost": "192.0.2.20",
                            "vrfName": "vrf1",
                            "networkName": "net1",
                            "switchName": "leaf1",
                            "switchInterfaceName": "Ethernet1/1",
                            "vlanId": "100",
                            "ipCollection": ["10.1.1.10"],
                        }
                    ],
                }
            ],
        }
    )

    expected_vm_data = {
        "vmDataType": "vCenter",
        "vCenter": "192.0.2.10",
        "vmUuid": "10111111-11e1-1111-1211-111feeaaa5aa",
        "nicMac": "00:A0:11:11:11:11",
    }
    assert group.to_payload()["selectors"][0]["vmData"] == [expected_vm_data]
    assert group.to_diff_dict()["selectors"][0]["vmData"] == [expected_vm_data]


@pytest.mark.parametrize("missing_key", ["vCenter", "vmUuid", "nicMac"])
def test_security_models_00200(missing_key):
    """Verify every required vCenter VM selector field is enforced."""
    vm_data = {
        "vmDataType": "vCenter",
        "vCenter": "192.0.2.10",
        "vmUuid": "10111111-11e1-1111-1211-111feeaaa5aa",
        "nicMac": "00:A0:11:11:11:11",
    }
    vm_data.pop(missing_key)
    with pytest.raises(ValidationError):
        SecurityGroupSelectorModel.model_validate({"type": "vm", "vmData": [vm_data]}, by_alias=True)


def test_security_models_00210():
    """Verify VM data discriminator and typed argspec are constrained to vCenter."""
    with pytest.raises(ValidationError):
        SecurityGroupVmDataModel.model_validate(
            {
                "vmDataType": "openstack",
                "vCenter": "192.0.2.10",
                "vmUuid": "uuid",
                "nicMac": "00:A0:11:11:11:11",
            },
            by_alias=True,
        )

    vm_options = SecurityGroupModel.get_argument_spec()["config"]["options"]["selectors"]["options"]["vm_data"]["options"]
    assert vm_options["vm_data_type"]["choices"] == ["vCenter"]
    assert vm_options["v_center"]["required"] is True
    assert vm_options["vm_uuid"]["required"] is True
    assert vm_options["nic_mac"]["required"] is True


def test_security_models_00220():
    """Verify group ID bounds, reserved input IDs, and controller-owned response IDs."""
    for group_id in (0, 15):
        with pytest.raises(ValidationError, match="reserved"):
            SecurityGroupModel.from_config({"name": "reserved", "id": group_id, "vrf_names": ["vrf1"]})
        response = SecurityGroupModel.from_response({"name": "reserved", "id": group_id, "vrfNames": ["vrf1"]})
        assert response.id == group_id

    assert SecurityGroupModel.from_config({"name": "user_group", "id": 16, "vrf_names": ["vrf1"]}).id == 16
    assert SecurityGroupModel.from_config({"name": "user_group", "id": 65535, "vrf_names": ["vrf1"]}).id == 65535
    with pytest.raises(ValidationError):
        SecurityGroupModel(name="user_group", id=-1)
    with pytest.raises(ValidationError):
        SecurityGroupModel(name="user_group", id=65536)


def test_security_models_00225():
    """Verify controller-owned groups are protected and omitted from replayable gathered output."""
    from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
        NDConfigCollection,
    )

    response = [
        {
            "name": "Any",
            "id": 0,
            "type": "default",
            "attach": True,
            "vrfNames": ["default"],
        },
        {
            "name": "SG_DEFAULT~GPO_UNAWARE",
            "id": 15,
            "type": "default",
            "attach": True,
            "vrfNames": ["default"],
        },
        {
            "name": "user_group",
            "id": 101,
            "type": "user",
            "attach": True,
            "vrfNames": ["vrf1"],
        },
    ]
    collection = NDConfigCollection.from_api_response(response_data=response, model_class=SecurityGroupModel)

    assert [item.is_controller_owned for item in collection] == [True, True, False]
    assert [item["name"] for item in collection.to_gathered_config()] == ["user_group"]


def test_security_models_00226():
    """Verify the live default-group empty VRF sentinel is read-only while user groups remain strict."""
    default_group = SecurityGroupModel.from_response(
        {
            "name": "Any",
            "id": 0,
            "type": "defaultgroup",
            "attach": True,
            "vrfNames": [""],
        }
    )

    assert default_group.vrf_names is None
    assert default_group.is_controller_owned is True
    assert default_group.exclude_from_gathered is True
    with pytest.raises(ValidationError, match="vrf_names entries must not be empty"):
        SecurityGroupModel.from_response({"name": "user_group", "id": 101, "type": "user", "vrfNames": [""]})


def test_security_models_00227():
    """Verify override and explicit delete preserve controller-owned groups."""
    from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
        NDStateMachineError,
    )
    from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
        NDConfigCollection,
    )
    from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
        NDStateMachine,
    )

    existing = NDConfigCollection.from_api_response(
        response_data=[
            {
                "name": "Any",
                "id": 0,
                "type": "default",
                "attach": True,
                "vrfNames": ["default"],
            },
            {
                "name": "SG_DEFAULT~GPO_UNAWARE",
                "id": 15,
                "type": "default",
                "attach": True,
                "vrfNames": ["default"],
            },
        ],
        model_class=SecurityGroupModel,
    )
    state_machine = object.__new__(NDStateMachine)
    state_machine.before = existing
    state_machine.existing = existing.copy()
    state_machine.proposed = NDConfigCollection(model_class=SecurityGroupModel)

    state_machine._manage_override_deletions()

    assert [item.id for item in state_machine.existing] == [0, 15]

    state_machine.proposed = NDConfigCollection.from_ansible_config(
        data=[{"name": "Any"}],
        model_class=SecurityGroupModel,
        context={"state": "deleted", "controller_version": "4.3.1"},
    )
    with pytest.raises(NDStateMachineError, match="Controller-owned security group.*cannot delete"):
        state_machine._manage_delete_state()


def test_security_models_00230():
    """Verify the group required-field hook supports ND 4.3 create-time ID allocation."""
    model = SecurityGroupModel(name="auto_id_group", vrf_names=["vrf1"])
    with pytest.raises(ValueError, match="id"):
        model.validate_required_payload_fields()
    with does_not_raise():
        model.validate_required_payload_fields(require_id=False)

    missing_vrf = SecurityGroupModel(name="auto_id_group")
    with pytest.raises(ValueError, match="vrf_names"):
        missing_vrf.validate_required_payload_fields(require_id=False)


def test_security_models_00240():
    """Verify static defaults normalize while scope-dependent direction stays material."""
    existing_protocol = SecurityProtocolDefinitionModel.from_response(
        {
            "name": "Web_TCP",
            "matchType": "any",
            "matchItems": [{"matchName": "web", "onlyFragments": False, "stateful": False}],
        }
    )
    proposed_protocol = SecurityProtocolDefinitionModel.from_config({"name": "web_tcp", "match_items": [{"match_name": "web"}]})
    assert existing_protocol.get_diff(proposed_protocol) is True

    existing_contract = SecurityContractModel.from_response(
        {
            "name": "Allow_Web",
            "direction": "bidirectional",
            "rules": [
                {
                    "ruleDirection": "bidirectional",
                    "action": "permit",
                    "protocolDefinitionName": "Web_TCP",
                }
            ],
        }
    )
    proposed_contract = SecurityContractModel.from_config(
        {
            "name": "allow_web",
            "rules": [
                {
                    "rule_direction": "bidirectional",
                    "action": "permit",
                    "protocol_definition_name": "web_tcp",
                }
            ],
        }
    )
    assert existing_contract.get_diff(proposed_contract) is False

    existing_group = SecurityGroupModel.from_response({"name": "app_web", "id": 101, "attach": True, "vrfNames": ["vrf1"]})
    proposed_group = SecurityGroupModel.from_config({"name": "app_web", "id": 101, "vrf_names": ["vrf1"]})
    assert existing_group.get_diff(proposed_group) is True

    existing_association = SecurityAssociationModel.from_response(
        {
            "name": "web_to_app",
            "contractName": "Allow_Web",
            "srcSecurityGroupName": "web",
            "dstSecurityGroupName": "app",
            "attach": True,
        }
    )
    proposed_association = SecurityAssociationModel.from_config(
        {
            "name": "web_to_app",
            "contract_name": "allow_web",
            "src_security_group_name": "web",
            "dst_security_group_name": "app",
        }
    )
    assert existing_association.get_diff(proposed_association) is True


def test_security_models_00250():
    """Verify case-insensitive model keys are hash-safe and retain wire spelling."""
    existing_protocol = SecurityProtocolDefinitionModel(name="TenantA~Web_TCP")
    proposed_protocol = SecurityProtocolDefinitionModel(name="tenanta~web_tcp")
    existing_contract = SecurityContractModel(name="Allow_Web")
    proposed_contract = SecurityContractModel(name="allow_web")

    existing_protocol_id = existing_protocol.get_identifier_value()
    proposed_protocol_id = proposed_protocol.get_identifier_value()
    assert existing_protocol_id == proposed_protocol_id
    assert hash(existing_protocol_id) == hash(proposed_protocol_id)
    assert {existing_protocol_id: "existing"}[proposed_protocol_id] == "existing"
    assert existing_protocol_id != "TenantA~Web_TCP"
    assert "TenantA~Web_TCP" != existing_protocol_id
    assert existing_protocol_id != "tenanta~web_tcp"
    assert {existing_protocol_id: "existing"}.get("TenantA~Web_TCP") is None
    assert {existing_protocol_id: "existing"}.get("tenanta~web_tcp") is None
    assert {"TenantA~Web_TCP": "plain"}.get(existing_protocol_id) is None
    assert str(existing_protocol_id) == "TenantA~Web_TCP"
    assert existing_protocol.to_payload()["name"] == "TenantA~Web_TCP"
    assert existing_contract.get_identifier_value() == proposed_contract.get_identifier_value()
    assert str(existing_contract.get_identifier_value()) == "Allow_Web"


def test_security_models_00260():
    """Verify tenant-qualified names normalize safely for config and responses."""
    response = SecurityContractModel.from_response({"name": "TenantA~Allow_Web"})
    configured = SecurityContractModel.from_config({"name": "Allow_Web", "tenant_name": "TenantA"})

    assert response.name == "Allow_Web"
    assert response.tenant_name == "TenantA"
    assert response.api_name == "TenantA~Allow_Web"
    assert response.to_payload()["name"] == "TenantA~Allow_Web"
    assert response.get_identifier_value() == configured.get_identifier_value()

    with pytest.raises(ValidationError, match="must match tenant_name"):
        SecurityContractModel.from_config({"name": "TenantB~Allow_Web", "tenant_name": "TenantA"})
    with pytest.raises(ValidationError, match="tenantName~resourceName"):
        SecurityGroupModel.from_config({"name": "TenantA~nested~group"})


def test_security_models_00265():
    """Verify tenant qualifiers follow each resource family's case contract."""
    existing_protocol = SecurityProtocolDefinitionModel.from_response({"name": "TenantA~Web_TCP", "matchType": "any"})
    proposed_protocol = SecurityProtocolDefinitionModel.from_config({"name": "tenanta~web_tcp"})
    existing_contract = SecurityContractModel.from_response({"name": "TenantA~Allow_Web", "direction": "bidirectional"})
    proposed_contract = SecurityContractModel.from_config({"name": "tenanta~allow_web", "direction": "bidirectional"})

    assert existing_protocol.get_diff(proposed_protocol) is True
    assert existing_contract.get_diff(proposed_contract) is True
    assert existing_protocol.to_diff_dict()["tenantName"] == "tenanta"
    assert existing_contract.to_diff_dict()["tenantName"] == "tenanta"

    explicitly_qualified = SecurityContractModel.from_config({"name": "TenantA~Allow_Web", "tenant_name": "tenanta"})
    assert explicitly_qualified.api_name == "TenantA~Allow_Web"
    assert explicitly_qualified.to_payload()["name"] == "TenantA~Allow_Web"
    assert explicitly_qualified.to_payload()["tenantName"] == "TenantA"

    with pytest.raises(ValidationError, match="must match tenant_name"):
        SecurityGroupModel.from_config({"name": "TenantA~Web", "tenant_name": "tenanta"})
    with pytest.raises(ValidationError, match="must match tenant_name"):
        SecurityAssociationModel.from_config({"name": "TenantA~Web", "tenant_name": "tenanta"})


def test_security_models_00270():
    """Verify contract parsing tolerates every schema direction/scope combination."""
    combinations = (
        {"name": "default_custom", "direction": "custom"},
        {"name": "default_bidir", "direction": "bidirectional"},
        {"name": "default_unidir", "direction": "unidirectional"},
        {"name": "TenantA~tenant_custom", "direction": "custom"},
        {"name": "TenantA~tenant_bidir", "direction": "bidirectional"},
        {"name": "TenantA~tenant_unidir", "direction": "unidirectional"},
    )

    for item in combinations:
        response = SecurityContractModel.from_response(item)
        replay = SecurityContractModel.from_config(response.to_config())
        assert replay.api_name == response.api_name
        assert replay.direction == response.direction


def test_security_models_00280():
    """Verify OpenAPI uniqueItems constraints reject duplicate list members."""
    with pytest.raises(ValidationError, match="match_items entries must be unique"):
        SecurityProtocolDefinitionModel(
            name="duplicate_matches",
            match_items=[{"match_name": "web"}, {"match_name": "web"}],
        )
    with pytest.raises(ValidationError, match="rules entries must be unique"):
        SecurityContractModel(
            name="duplicate_rules",
            rules=[
                {
                    "rule_direction": "bidirectional",
                    "action": "permit",
                    "protocol_definition_name": "Web_TCP",
                },
                {
                    "rule_direction": "bidirectional",
                    "action": "permit",
                    "protocol_definition_name": "web_tcp",
                },
            ],
        )
    with pytest.raises(ValidationError, match="vrf_names entries must be unique"):
        SecurityGroupModel(name="duplicate_vrfs", vrf_names=["vrf1", "vrf1"])
    with pytest.raises(ValidationError, match="selectors entries must be unique"):
        SecurityGroupModel(
            name="duplicate_selectors",
            selectors=[
                {"type": "network", "network_name": "net1"},
                {"type": "network", "network_name": "net1"},
            ],
        )
    vm_data = {
        "v_center": "192.0.2.10",
        "vm_uuid": "10111111-11e1-1111-1211-111feeaaa5aa",
        "nic_mac": "00:A0:11:11:11:11",
    }
    with pytest.raises(ValidationError, match="vm_data entries must be unique"):
        SecurityGroupSelectorModel(type="vm", vm_data=[vm_data, vm_data])
