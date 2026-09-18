# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for security and segmentation Pydantic models."""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import SecurityAssociationModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import ConfigActionsModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import SecurityGroupModel, SecurityGroupSelectorModel
from ansible_collections.cisco.nd.plugins.module_utils.models.security.protocol_definitions import (
    ProtocolDefinitionMatchCriteriaModel,
    SecurityProtocolDefinitionModel,
)
from pydantic import ValidationError


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


def test_security_models_00010():
    """Verify config_actions deploy requires save."""
    with pytest.raises(ValidationError, match="deploy=true requires"):
        ConfigActionsModel(save=False, deploy=True)
    with does_not_raise():
        model = ConfigActionsModel(save=True, deploy=True, type="global")
    assert model.type == "global"


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
        match_items=[{"match_name": "web", "type": "IPv4", "protocol_options": "TCP", "dst_port_range": "443"}],
        match_summary="read-only",
        security_contract_count=2,
    )
    payload = model.to_payload()

    assert payload["name"] == "web_tcp"
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
            "displayName": "app_web",
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
    """Verify argspec uses the initial four-state contract and config_actions."""
    argspec = SecurityGroupModel.get_argument_spec()

    assert argspec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
    assert "gathered" not in argspec["state"]["choices"]
    assert "config_actions" in argspec
    assert argspec["config"]["required"] is True
