# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the nd_manage_links Pydantic models.

Covers the discriminated-union template resolution, secret-field masking in
output/diff, policy-type-change rejection, and the argument spec contract.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import (
    LinkConfigDataModel,
    NDLinkModel,
)
from pydantic import ValidationError


def _link(policy_type, template_inputs):
    """Build a minimal valid NDLinkModel for the given policy."""
    return NDLinkModel(
        srcFabricName="fab1",
        dstFabricName="fab1",
        srcSwitchName="leaf-1",
        dstSwitchName="spine-1",
        srcInterfaceName="Ethernet1/1",
        dstInterfaceName="Ethernet1/1",
        configData={"policyType": policy_type, "templateInputs": template_inputs},
    )


# ---------------------------------------------------------------------------
# Discriminated union
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy_type,expected_cls",
    [
        ("numbered", "NumberedTemplateInputs"),
        ("unnumbered", "UnnumberedTemplateInputs"),
        ("ipv6LinkLocal", "Ipv6LinkLocalTemplateInputs"),
        ("ebgpVrfLite", "EbgpVrfLiteTemplateInputs"),
        ("layer2Dci", "Layer2DciTemplateInputs"),
        ("layer3DciVrfLite", "Layer3DciVrfLiteTemplateInputs"),
        ("multisiteOverlay", "MultisiteOverlayTemplateInputs"),
        ("multisiteUnderlay", "MultisiteUnderlayTemplateInputs"),
        ("mplsOverlay", "MplsOverlayTemplateInputs"),
        ("mplsUnderlay", "MplsUnderlayTemplateInputs"),
        ("preprovision", "PreprovisionTemplateInputs"),
        ("userDefined", "UserDefinedTemplateInputs"),
        ("vpcPeerKeepalive", "VpcPeerKeepaliveTemplateInputs"),
    ],
)
def test_policy_type_resolves_to_template_class(policy_type, expected_cls):
    """Each policy_type selects the matching template_inputs subclass."""
    link = _link(policy_type, {})
    assert type(link.config_data.template_inputs).__name__ == expected_cls


def test_wrong_field_for_policy_is_rejected():
    """A field that does not belong to the policy is rejected (extra=forbid)."""
    with pytest.raises(ValidationError):
        _link("numbered", {"ebgpMultihop": 5})  # ebgpMultihop belongs to multisiteOverlay


def test_user_defined_allows_extra_fields():
    """userDefined is an open shape and accepts unknown keys."""
    link = _link("userDefined", {"someVendorField": "x", "allowedVlans": "10,20"})
    assert type(link.config_data.template_inputs).__name__ == "UserDefinedTemplateInputs"


def test_policy_marker_injection_does_not_mutate_input():
    """The internal policy_type_marker is not written back into the caller's dict
    (which is module.params), so it never leaks into the invocation echo."""
    config_item = {
        "src_fabric_name": "f1",
        "dst_fabric_name": "f2",
        "src_switch_name": "a",
        "dst_switch_name": "b",
        "src_interface_name": "Ethernet1/30",
        "dst_interface_name": "Ethernet1/30",
        "config_data": {"policy_type": "numbered", "template_inputs": {"src_ip": "10.0.0.1"}},
    }
    NDLinkModel.from_config(config_item)
    assert "policy_type_marker" not in config_item["config_data"]["template_inputs"]


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "policy_type,template_inputs,secret_alias,secret_pyname",
    [
        ("ebgpVrfLite", {"defaultVrfEbgpNeighborPassword": "S1"}, "defaultVrfEbgpNeighborPassword", "default_vrf_ebgp_neighbor_password"),
        ("ebgpVrfLite", {"macsecPrimaryKeyString": "S2"}, "macsecPrimaryKeyString", "macsec_primary_key_string"),
        ("layer2Dci", {"macsecFallbackKeyString": "S3"}, "macsecFallbackKeyString", "macsec_fallback_key_string"),
        ("multisiteUnderlay", {"ebgpPassword": "S4"}, "ebgpPassword", "ebgp_password"),
    ],
)
def test_secret_in_payload_masked_in_config_absent_from_diff(policy_type, template_inputs, secret_alias, secret_pyname):
    """Secrets reach the controller payload, are masked in output, and excluded from diff."""
    link = _link(policy_type, template_inputs)
    payload_ti = link.to_payload()["configData"]["templateInputs"]
    config_ti = link.to_config()["config_data"]["template_inputs"]
    diff_ti = link.to_diff_dict()["configData"]["templateInputs"]
    assert payload_ti.get(secret_alias) == list(template_inputs.values())[0]
    assert config_ti[secret_pyname] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    assert secret_alias not in diff_ti


def test_non_secret_fields_survive_in_config():
    """Non-secret template fields stay visible; secrets are masked, not dropped."""
    link = _link("ebgpVrfLite", {"linkMtu": 9216, "defaultVrfEbgpNeighborPassword": "secret"})
    config_ti = link.to_config()["config_data"]["template_inputs"]
    assert config_ti.get("link_mtu") == 9216
    assert config_ti["default_vrf_ebgp_neighbor_password"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


def test_collect_secret_values_finds_free_form_template_input_secrets():
    """collect_secret_values surfaces free-form template_inputs secrets for no_log."""
    config_item = {
        "src_interface_name": "Ethernet1/30",
        "config_data": {
            "policy_type": "ebgpVrfLite",
            "template_inputs": {"ebgp_password": "S3cret!", "link_mtu": 9216},
        },
    }
    assert NDLinkModel.collect_secret_values(config_item) == {"S3cret!"}


def test_collect_secret_values_empty_when_no_secrets():
    """No secrets (e.g. gathered/empty config) yields an empty set, no error."""
    assert NDLinkModel.collect_secret_values({}) == set()
    assert NDLinkModel.collect_secret_values({"config_data": {"template_inputs": {"link_mtu": 9216}}}) == set()


# ---------------------------------------------------------------------------
# Policy-type-change rejection
# ---------------------------------------------------------------------------


def test_merge_rejects_policy_type_change():
    """Merging configs with a different policy_type is rejected."""
    existing = LinkConfigDataModel(policyType="numbered", templateInputs={})
    proposed = LinkConfigDataModel(policyType="unnumbered", templateInputs={})
    with pytest.raises(Exception):
        existing.merge(proposed)


def test_merge_allows_same_policy_type():
    """Merging configs with the same policy_type is allowed."""
    existing = LinkConfigDataModel(policyType="numbered", templateInputs={"srcIp": "1.1.1.1"})
    proposed = LinkConfigDataModel(policyType="numbered", templateInputs={"dstIp": "1.1.1.2"})
    merged = existing.merge(proposed)
    assert merged.policy_type == "numbered"


# ---------------------------------------------------------------------------
# Argument spec contract
# ---------------------------------------------------------------------------


def test_argument_spec_state_choices_include_gathered():
    spec = NDLinkModel.get_argument_spec()
    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted", "gathered"]


def test_argument_spec_config_not_required():
    """config is optional so state=gathered needs no config."""
    spec = NDLinkModel.get_argument_spec()
    assert spec["config"].get("required", False) is False


def test_argument_spec_template_inputs_not_blanket_no_log():
    """template_inputs is not blanket no_log; secret masking is done at the model
    layer so non-secret fields stay visible in output."""
    spec = NDLinkModel.get_argument_spec()
    template_inputs = spec["config"]["options"]["config_data"]["options"]["template_inputs"]
    assert template_inputs.get("no_log") is not True
