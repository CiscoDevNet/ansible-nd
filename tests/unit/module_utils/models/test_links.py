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


def _user_defined_config(template_name=None):
    config = {
        "src_fabric_name": "f1",
        "dst_fabric_name": "f1",
        "src_switch_name": "a",
        "dst_switch_name": "b",
        "src_interface_name": "Ethernet1/1",
        "dst_interface_name": "Ethernet1/1",
        "config_data": {"policy_type": "userDefined", "template_inputs": {"custom_setting": "x"}},
    }
    if template_name is not None:
        config["config_data"]["template_name"] = template_name
    return config


def test_user_defined_requires_template_name_on_write():
    """On a write state, userDefined without template_name is rejected locally
    (ND schema requires it) rather than failing later at the controller."""
    with pytest.raises(ValidationError):
        NDLinkModel.from_config(_user_defined_config(), context={"state": "merged"})


def test_user_defined_accepts_template_name_on_write():
    """userDefined with template_name validates on a write state."""
    link = NDLinkModel.from_config(_user_defined_config(template_name="custom_tmpl"), context={"state": "merged"})
    assert link.config_data.template_name == "custom_tmpl"


def test_user_defined_missing_template_name_tolerated_on_read():
    """A controller read (no state context) is not blocked if template_name is absent,
    so query_all never aborts on an odd userDefined response."""
    link = NDLinkModel.from_config(_user_defined_config())
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


def test_caller_supplied_marker_cannot_override_policy_type():
    """policy_type is the sole schema authority; a caller-injected marker is ignored,
    so an invalid field for the real policy is still rejected."""
    config_item = {
        "src_fabric_name": "f1",
        "dst_fabric_name": "f2",
        "src_switch_name": "a",
        "dst_switch_name": "b",
        "src_interface_name": "Ethernet1/30",
        "dst_interface_name": "Ethernet1/30",
        "config_data": {
            "policy_type": "numbered",
            "template_inputs": {"policy_type_marker": "userDefined", "unexpected": "value"},
        },
    }
    with pytest.raises(ValidationError):
        NDLinkModel.from_config(config_item)


@pytest.mark.parametrize("template_inputs_key", ["template_inputs", "templateInputs"])
def test_empty_template_inputs_consistent_across_spellings(template_inputs_key):
    """An explicit empty template_inputs resolves the same under either spelling
    (the snake_case empty dict used to fall through and fail to inject the marker)."""
    link = NDLinkModel.from_config(
        {
            "src_fabric_name": "f1",
            "dst_fabric_name": "f2",
            "src_switch_name": "a",
            "dst_switch_name": "b",
            "src_interface_name": "Ethernet1/30",
            "dst_interface_name": "Ethernet1/30",
            "config_data": {"policy_type": "numbered", template_inputs_key: {}},
        }
    )
    assert type(link.config_data.template_inputs).__name__ == "NumberedTemplateInputs"


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


def test_gathered_omits_controller_typed_empties_rejected_on_write():
    """Controller sentinels remain inspectable in normal output but are omitted
    from gathered configuration so the gathered item validates when reapplied."""
    existing = NDLinkModel.from_response(
        _link("layer2Dci", {"trunkAllowedVlans": "100,200", "nativeVlan": 1}).to_payload()
    )

    normal_inputs = existing.to_config()["config_data"]["template_inputs"]
    gathered = existing.to_gathered_config()
    gathered_inputs = gathered["config_data"]["template_inputs"]

    assert normal_inputs["bpdu_guard"] == ""
    assert normal_inputs["mtu_type"] == ""
    assert "bpdu_guard" not in gathered_inputs
    assert "mtu_type" not in gathered_inputs
    round_tripped = NDLinkModel.from_config(gathered, context={"state": "merged"})
    assert existing.get_diff(round_tripped, exclude_unset=True) is True


def test_minimal_numbered_payload_sends_documented_defaults():
    """A minimal numbered create sends ND's documented defaults for defaulted fields
    (mtu 9216, admin_state true, fec auto, speed auto) instead of schema-violating
    typed empties, while keeping every other known field present (ND's template
    references each key, so a missing key fails template execution)."""
    link = _link("numbered", {"srcIp": "10.99.30.1", "dstIp": "10.99.30.2"})
    ti = link.to_payload()["configData"]["templateInputs"]
    # documented defaults, not typed empties
    assert ti["mtu"] == 9216
    assert ti["interfaceAdminState"] is True
    assert ti["fec"] == "auto"
    assert ti["speed"] == "auto"
    assert ti["macsec"] is False
    # user-supplied values preserved
    assert ti["srcIp"] == "10.99.30.1"
    assert ti["dstIp"] == "10.99.30.2"
    # no-default fields stay present as typed empties so ND's template has the keys
    assert ti["srcIpv6"] == ""
    assert ti["srcInterfaceDescription"] == ""


def test_replaced_is_idempotent_after_controller_echoes_payload_defaults():
    """A replaced declaration is sparse, but its PUT carries all link-template
    defaults. When ND echoes that effective payload, the next run must compare as
    equal instead of repeatedly updating because defaulted fields were omitted by
    the user."""
    proposed = _link(
        "numbered",
        {
            "srcIp": "10.99.30.1",
            "dstIp": "10.99.30.2",
            "mtu": 9216,
            "interfaceAdminState": True,
        },
    )
    existing = NDLinkModel.from_response(proposed.to_payload())

    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_replaced_still_detects_nondefault_field_removal():
    """Default normalization must not hide a real replaced-state reset. A
    non-empty interface description present on ND and omitted by the proposed
    declaration still requires one update."""
    configured = _link(
        "numbered",
        {
            "srcIp": "10.99.30.1",
            "dstIp": "10.99.30.2",
            "mtu": 9216,
            "interfaceAdminState": True,
            "srcInterfaceDescription": "remove me",
        },
    )
    existing = NDLinkModel.from_response(configured.to_payload())
    proposed = _link(
        "numbered",
        {
            "srcIp": "10.99.30.1",
            "dstIp": "10.99.30.2",
            "mtu": 9216,
            "interfaceAdminState": True,
        },
    )

    assert existing.get_diff(proposed, exclude_unset=False) is False


def test_unset_secret_sent_empty_but_excluded_from_diff():
    """An unset secret is sent as an empty key (ND's template requires the key to be
    present) but is excluded from serialized diff output. Documented defaults still
    flow for the other fields."""
    link = _link("multisiteUnderlay", {"srcEbgpAsn": "1", "dstEbgpAsn": "2"})
    payload_ti = link.to_payload()["configData"]["templateInputs"]
    diff_ti = link.to_diff_dict()["configData"]["templateInputs"]
    assert payload_ti["ebgpPassword"] == ""
    assert "ebgpPassword" not in diff_ti
    assert payload_ti["ebgpMaximumPaths"] == 64
    assert payload_ti["enableEbgpPassword"] is True


def test_explicit_secret_is_update_intent_without_leaking_into_diff():
    """A write-only secret cannot be compared with controller state. Supplying one
    therefore schedules an update, while serialized diff output still omits it."""
    existing = _link("multisiteUnderlay", {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002"})
    proposed = _link(
        "multisiteUnderlay",
        {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002", "ebgpPassword": "RotateMe!"},
    )

    assert existing.get_diff(proposed, exclude_unset=True) is False
    assert "ebgpPassword" not in proposed.to_diff_dict()["configData"]["templateInputs"]


def test_omitted_secret_remains_idempotent():
    """Omitting write-only secrets does not force an update."""
    existing = _link("multisiteUnderlay", {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002"})
    proposed = _link("multisiteUnderlay", {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002"})

    assert existing.get_diff(proposed, exclude_unset=True) is True


@pytest.mark.parametrize(
    "policy_type,base_inputs,secret_alias",
    [
        (
            "ebgpVrfLite",
            {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002", "srcIpAddressMask": "10.99.30.1/30", "dstIpAddress": "10.99.30.2"},
            "defaultVrfEbgpNeighborPassword",
        ),
        ("ebgpVrfLite", {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002"}, "macsecPrimaryKeyString"),
        ("ebgpVrfLite", {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002"}, "macsecFallbackKeyString"),
        ("layer2Dci", {"trunkAllowedVlans": "100,200", "nativeVlan": 1}, "macsecPrimaryKeyString"),
        ("layer2Dci", {"trunkAllowedVlans": "100,200", "nativeVlan": 1}, "macsecFallbackKeyString"),
        ("layer3DciVrfLite", {"srcIpAddressMask": "10.99.30.1/30", "dstIpAddressMask": "10.99.30.2/30"}, "macsecPrimaryKeyString"),
        ("layer3DciVrfLite", {"srcIpAddressMask": "10.99.30.1/30", "dstIpAddressMask": "10.99.30.2/30"}, "macsecFallbackKeyString"),
        (
            "multisiteOverlay",
            {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002", "srcIpAddress": "10.99.30.1", "dstIpAddress": "10.99.30.2"},
            "ebgpPassword",
        ),
        (
            "multisiteOverlay",
            {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002", "srcIpAddress": "10.99.30.1", "dstIpAddress": "10.99.30.2"},
            "macsecPrimaryKeyString",
        ),
        (
            "multisiteOverlay",
            {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002", "srcIpAddress": "10.99.30.1", "dstIpAddress": "10.99.30.2"},
            "macsecFallbackKeyString",
        ),
        ("multisiteUnderlay", {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002"}, "ebgpPassword"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_secret_lifecycle_for_every_secret_bearing_link_template(policy_type, base_inputs, secret_alias):
    """For every supported secret field: controller echoes are idempotent,
    explicit user values are update intent and report changed, output is masked,
    and a fresh controller read returns to idempotent."""
    response = _link(policy_type, base_inputs).to_payload()
    before = NDLinkModel.from_response(response)
    identical_response = NDLinkModel.from_response(response)
    omitted_secret = _link(policy_type, base_inputs)

    assert before._has_explicit_secret_template_input() is False
    assert before.get_diff(identical_response, exclude_unset=False) is True
    assert before.get_diff(omitted_secret, exclude_unset=True) is True

    explicit_secret = _link(policy_type, {**base_inputs, secret_alias: "RotateMe!"})
    assert before.get_diff(explicit_secret, exclude_unset=True) is False

    after = identical_response.merge(explicit_secret)
    assert after._has_explicit_secret_template_input() is True
    assert before.get_diff(after, exclude_unset=False) is False

    template_model = type(after.config_data.template_inputs)
    secret_python_name = next(
        field_name for field_name, field_info in template_model.model_fields.items() if (field_info.alias or field_name) == secret_alias
    )
    assert after.to_config()["config_data"]["template_inputs"][secret_python_name] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    assert secret_alias not in after.to_diff_dict()["configData"]["templateInputs"]

    next_read = NDLinkModel.from_response(response)
    assert next_read.get_diff(NDLinkModel.from_response(response), exclude_unset=False) is True

    gathered = next_read.to_gathered_config()
    gathered_inputs = gathered["config_data"]["template_inputs"]
    for secret_field in template_model.secret_field_keys(by_alias=False):
        assert secret_field not in gathered_inputs
    round_tripped = NDLinkModel.from_config(gathered, context={"state": "merged"})
    assert next_read.get_diff(round_tripped, exclude_unset=True) is True


@pytest.mark.parametrize(
    "secret_key",
    [
        "default_vrf_ebgp_neighbor_password",
        "defaultVrfEbgpNeighborPassword",
        "macsec_primary_key_string",
        "macsecPrimaryKeyString",
        "macsec_fallback_key_string",
        "macsecFallbackKeyString",
        "ebgp_password",
        "ebgpPassword",
    ],
)
def test_collect_secret_values_finds_free_form_template_input_secrets(secret_key):
    """Both documented names and API aliases are registered with Ansible's
    global value scrubber before free-form template input validation."""
    config_item = {
        "src_interface_name": "Ethernet1/30",
        "config_data": {
            "policy_type": "ebgpVrfLite",
            "template_inputs": {secret_key: "S3cret!", "link_mtu": 9216},
        },
    }
    assert NDLinkModel.collect_secret_values(config_item) == {"S3cret!"}


def test_collect_secret_values_empty_when_no_secrets():
    """No secrets (e.g. gathered/empty config) yields an empty set, no error."""
    assert NDLinkModel.collect_secret_values({}) == set()
    assert NDLinkModel.collect_secret_values({"config_data": {"template_inputs": {"link_mtu": 9216}}}) == set()


# ---------------------------------------------------------------------------
# Unsupported policy tolerance (read fallback)
# ---------------------------------------------------------------------------


def _response_link(policy_type, template_inputs, link_id="LINK-UUID-1", iface="Ethernet1/1"):
    return {
        "srcClusterName": "c1",
        "dstClusterName": "c1",
        "srcFabricName": "f1",
        "dstFabricName": "f1",
        "srcSwitchName": "a",
        "dstSwitchName": "b",
        "srcInterfaceName": iface,
        "dstInterfaceName": iface,
        "linkId": link_id,
        "configData": {"policyType": policy_type, "templateInputs": template_inputs},
    }


def test_iosxe_numbered_is_supported():
    """iosXeNumbered is first-class (Campus requirement), not a fallback."""
    link = NDLinkModel.from_response(_response_link("iosXeNumbered", {"srcIp": "1.1.1.1", "dstIp": "1.1.1.2", "mtu": 9198}))
    assert type(link.config_data.template_inputs).__name__ == "IosXeNumberedTemplateInputs"
    assert link.is_unsupported_policy is False


def test_unsupported_policy_read_does_not_raise_and_is_flagged():
    """A valid but unmodeled controller policy is preserved as an opaque record."""
    link = NDLinkModel.from_response(_response_link("ipfmNumbered", {"srcIp": "9.9.9.9", "interfaceVrf": "default", "mtu": 1500}))
    assert link.is_unsupported_policy is True
    assert link.config_data.policy_type == "ipfmNumbered"
    raw = link.config_data.template_inputs.model_dump(by_alias=True)
    assert raw.get("srcIp") == "9.9.9.9"
    assert raw.get("interfaceVrf") == "default"


def test_supported_policy_with_unknown_field_stays_mutable_on_read():
    """A supported policy carrying an extra response field must resolve to its real
    policy model (mutable), NOT fall back to the opaque unsupported record. The
    unknown key is dropped on read so extra=forbid does not misclassify the link
    (mikewiebe finding: a valid preprovision link returning mtu/speed became immutable)."""
    link = NDLinkModel.from_response(_response_link("numbered", {"srcIp": "1.1.1.1", "someBrandNewField": "x"}))
    assert link.is_unsupported_policy is False
    assert link.config_data.policy_type == "numbered"
    assert type(link.config_data.template_inputs).__name__ == "NumberedTemplateInputs"
    # the unknown key is dropped, the known one is kept
    dumped = link.config_data.template_inputs.model_dump(by_alias=True)
    assert dumped.get("srcIp") == "1.1.1.1"
    assert "someBrandNewField" not in dumped


def test_unsupported_policy_rejected_on_write():
    """User input for an unmodeled policy type is strictly rejected (not tolerated)."""
    with pytest.raises(ValidationError):
        NDLinkModel.from_config(
            {
                "src_fabric_name": "f1",
                "dst_fabric_name": "f1",
                "src_switch_name": "a",
                "dst_switch_name": "b",
                "src_interface_name": "Ethernet1/1",
                "dst_interface_name": "Ethernet1/1",
                "config_data": {"policy_type": "ipfmNumbered", "template_inputs": {"srcIp": "9.9.9.9"}},
            },
            context={"state": "merged"},
        )


def test_describe_unsupported_policy_message():
    link = NDLinkModel.from_response(_response_link("routedFabric", {"srcEbgpAsn": "1"}, link_id="LINK-UUID-77"))
    msg = link.describe_unsupported_policy()
    assert "LINK-UUID-77" in msg and "routedFabric" in msg


def test_collection_read_tolerates_unsupported_alongside_supported():
    """A full-fabric read with one unsupported link still parses every link and
    flags only the unsupported one (no abort)."""
    from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection

    response = [
        _response_link("numbered", {"srcIp": "1.1.1.1", "dstIp": "1.1.1.2"}, link_id="L1", iface="Ethernet1/1"),
        _response_link("ipfmNumbered", {"srcIp": "9.9.9.9"}, link_id="L2", iface="Ethernet1/2"),
    ]
    coll = NDConfigCollection.from_api_response(response_data=response, model_class=NDLinkModel)
    items = list(coll)
    assert len(items) == 2
    unsupported = [i for i in items if i.is_unsupported_policy]
    assert [i.link_id for i in unsupported] == ["L2"]


def test_collection_preserves_duplicate_endpoint_records_for_gathered():
    """Distinct controller records sharing endpoint identity remain visible instead
    of aborting collection construction before gathered can return them."""
    from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection

    response = [
        _response_link("numbered", {"srcIp": "1.1.1.1", "dstIp": "1.1.1.2"}, link_id="L1"),
        _response_link("numbered", {"srcIp": "1.1.1.1", "dstIp": "1.1.1.2"}, link_id="L2"),
    ]
    collection = NDConfigCollection.from_api_response(response_data=response, model_class=NDLinkModel)

    assert len(collection) == 2
    assert [item.link_id for item in collection] == ["L1", "L2"]


def test_override_preserves_unsupported_controller_link():
    """An authoritative override never implicitly deletes an opaque policy."""
    from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
    from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine

    existing = NDConfigCollection.from_api_response(
        response_data=[_response_link("ipfmNumbered", {"srcIp": "9.9.9.9"}, link_id="L-opaque")],
        model_class=NDLinkModel,
    )
    state_machine = object.__new__(NDStateMachine)
    state_machine.before = existing
    state_machine.existing = existing.copy()
    state_machine.proposed = NDConfigCollection(model_class=NDLinkModel)

    state_machine._manage_override_deletions()

    assert [item.link_id for item in state_machine.existing] == ["L-opaque"]


def test_explicit_delete_rejects_unsupported_controller_link():
    """An explicit delete of an opaque policy fails before any mutation."""
    from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
    from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
    from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine

    existing = NDConfigCollection.from_api_response(
        response_data=[_response_link("ipfmNumbered", {"srcIp": "9.9.9.9"}, link_id="L-opaque")],
        model_class=NDLinkModel,
    )
    proposed = NDConfigCollection.from_ansible_config(
        data=[
            {
                "src_cluster_name": "c1",
                "dst_cluster_name": "c1",
                "src_fabric_name": "f1",
                "dst_fabric_name": "f1",
                "src_switch_name": "a",
                "dst_switch_name": "b",
                "src_interface_name": "Ethernet1/1",
                "dst_interface_name": "Ethernet1/1",
            }
        ],
        model_class=NDLinkModel,
        context={"state": "deleted"},
    )
    state_machine = object.__new__(NDStateMachine)
    state_machine.existing = existing.copy()
    state_machine.proposed = proposed

    with pytest.raises(NDStateMachineError, match="cannot delete"):
        state_machine._manage_delete_state()


# ---------------------------------------------------------------------------
# Orientation independence (intra-fabric physical links)
# ---------------------------------------------------------------------------


def _phys_link(src_sw, src_if, dst_sw, dst_if, template_inputs=None, src_fabric="f1", dst_fabric="f1"):
    return NDLinkModel.from_response(
        {
            "srcClusterName": "c1",
            "dstClusterName": "c1",
            "srcFabricName": src_fabric,
            "dstFabricName": dst_fabric,
            "srcSwitchName": src_sw,
            "dstSwitchName": dst_sw,
            "srcInterfaceName": src_if,
            "dstInterfaceName": dst_if,
            "configData": {"policyType": "numbered", "templateInputs": template_inputs or {}},
        }
    )


def test_intra_fabric_identity_is_orientation_independent():
    """The same physical intra-fabric cable has one identity in either orientation."""
    fwd = _phys_link("LEAF1", "Ethernet1/49", "SPINE1", "Ethernet1/1")
    rev = _phys_link("SPINE1", "Ethernet1/1", "LEAF1", "Ethernet1/49")
    assert fwd.get_identifier_value() == rev.get_identifier_value()


def test_reversed_intra_fabric_link_compares_equal():
    """A reversed link with correspondingly swapped directional values -- including
    the asymmetric DHCP relay / BFD echo per-interface toggles -- shows no diff, so
    merged stays idempotent instead of trying to recreate/update it."""
    fwd = _phys_link(
        "LEAF1",
        "Ethernet1/49",
        "SPINE1",
        "Ethernet1/1",
        {
            "srcIp": "10.0.0.1",
            "dstIp": "10.0.0.2",
            "dhcpRelayOnSrcInterface": True,
            "dhcpRelayOnDstInterface": False,
            "bfdEchoOnSrcInterface": True,
            "bfdEchoOnDstInterface": False,
        },
    )
    rev = _phys_link(
        "SPINE1",
        "Ethernet1/1",
        "LEAF1",
        "Ethernet1/49",
        {
            "srcIp": "10.0.0.2",
            "dstIp": "10.0.0.1",
            "dhcpRelayOnSrcInterface": False,
            "dhcpRelayOnDstInterface": True,
            "bfdEchoOnSrcInterface": False,
            "bfdEchoOnDstInterface": True,
        },
    )
    assert fwd.to_diff_dict() == rev.to_diff_dict()


def test_reversed_link_with_unswapped_toggle_still_diffs():
    """The other failure mode: a reversed link whose directional toggle was NOT
    correspondingly swapped is a genuine asymmetric change and must still diff, so
    canonicalization never masks a real per-interface difference."""
    fwd = _phys_link(
        "LEAF1",
        "Ethernet1/49",
        "SPINE1",
        "Ethernet1/1",
        {"srcIp": "10.0.0.1", "dstIp": "10.0.0.2", "dhcpRelayOnSrcInterface": True, "dhcpRelayOnDstInterface": False},
    )
    # Endpoints reversed and IPs swapped, but the DHCP toggle left on the src end:
    # after canonicalization this leaves dhcp_relay on the wrong interface.
    rev = _phys_link(
        "SPINE1",
        "Ethernet1/1",
        "LEAF1",
        "Ethernet1/49",
        {"srcIp": "10.0.0.2", "dstIp": "10.0.0.1", "dhcpRelayOnSrcInterface": True, "dhcpRelayOnDstInterface": False},
    )
    assert fwd.to_diff_dict() != rev.to_diff_dict()


def test_payload_keeps_user_orientation():
    """Canonicalization is comparison-only; the payload keeps the user's orientation."""
    rev = _phys_link("SPINE1", "Ethernet1/1", "LEAF1", "Ethernet1/49", {"srcIp": "10.0.0.2", "dstIp": "10.0.0.1"})
    payload = rev.to_payload()
    assert payload["srcSwitchName"] == "SPINE1"
    assert payload["configData"]["templateInputs"]["srcIp"] == "10.0.0.2"


def test_inter_fabric_identity_is_orientation_independent():
    """A physical inter-fabric cable (distinct fabrics) has one identity in either
    orientation, so a reversed declaration is matched, not duplicated/missed/recreated."""
    a = _phys_link("X", "Ethernet1/1", "Y", "Ethernet1/1", src_fabric="f1", dst_fabric="f2")
    b = _phys_link("Y", "Ethernet1/1", "X", "Ethernet1/1", src_fabric="f2", dst_fabric="f1")
    assert a.get_identifier_value() == b.get_identifier_value()


def _ebgp_vrf_lite_link(src_sw, src_fabric, dst_sw, dst_fabric, template_inputs):
    return NDLinkModel.from_response(
        {
            "srcClusterName": "c1",
            "dstClusterName": "c1",
            "srcFabricName": src_fabric,
            "dstFabricName": dst_fabric,
            "srcSwitchName": src_sw,
            "dstSwitchName": dst_sw,
            "srcInterfaceName": "Ethernet1/1",
            "dstInterfaceName": "Ethernet1/1",
            "configData": {"policyType": "ebgpVrfLite", "templateInputs": template_inputs},
        }
    )


def test_reversed_inter_fabric_link_compares_equal():
    """A reversed inter-fabric cable compares by physical endpoint, including the
    asymmetric masked-source/plain-destination IPv4 representation."""
    fwd = _ebgp_vrf_lite_link(
        "X",
        "f1",
        "Y",
        "f2",
        {
            "srcEbgpAsn": "100",
            "dstEbgpAsn": "200",
            "srcIpAddressMask": "10.0.0.1/30",
            "dstIpAddress": "10.0.0.2",
            "srcInterfaceDescription": "to-Y",
            "dstInterfaceDescription": "to-X",
        },
    )
    rev = _ebgp_vrf_lite_link(
        "Y",
        "f2",
        "X",
        "f1",
        {
            "srcEbgpAsn": "200",
            "dstEbgpAsn": "100",
            "srcIpAddressMask": "10.0.0.2/30",
            "dstIpAddress": "10.0.0.1",
            "srcInterfaceDescription": "to-X",
            "dstInterfaceDescription": "to-Y",
        },
    )
    assert fwd.get_identifier_value() == rev.get_identifier_value()
    assert fwd.to_diff_dict() == rev.to_diff_dict()


def test_directional_pairs_are_policy_specific():
    """The directional swap set is derived per policy from the model's own fields:
    ebgpVrfLite pairs the symmetric srcEbgpAsn/dstEbgpAsn; numbered pairs srcIp/dstIp
    and the dhcp/bfd per-interface toggles. Asymmetric address fields use their own
    prefix-preserving canonicalization path rather than the plain value-swap set."""
    ebgp = _ebgp_vrf_lite_link("X", "f1", "Y", "f2", {"srcEbgpAsn": "100", "dstEbgpAsn": "200"})
    pairs = set(ebgp._template_directional_pairs())
    assert ("srcEbgpAsn", "dstEbgpAsn") in pairs
    assert ("srcIpAddressMask", "dstIpAddress") not in pairs
    assert ("srcIpAddressMask", "dstIpAddress") in set(ebgp._template_asymmetric_address_pairs())
    numbered = _phys_link("X", "Ethernet1/1", "Y", "Ethernet1/1", {"srcIp": "1.1.1.1", "dstIp": "1.1.1.2"})
    npairs = set(numbered._template_directional_pairs())
    assert ("srcIp", "dstIp") in npairs
    assert ("dhcpRelayOnSrcInterface", "dhcpRelayOnDstInterface") in npairs


# ---------------------------------------------------------------------------
# Realized preprovision -> numbered lifecycle
# ---------------------------------------------------------------------------


def _proposed_preprovision(template_inputs=None):
    if template_inputs is None:
        template_inputs = {"src_interface_description": "planned"}
    return NDLinkModel.from_config(
        {
            "src_fabric_name": "f1",
            "dst_fabric_name": "f1",
            "src_switch_name": "LEAF1",
            "dst_switch_name": "SPINE1",
            "src_interface_name": "Ethernet1/1",
            "dst_interface_name": "Ethernet1/1",
            "config_data": {"policy_type": "preprovision", "template_inputs": template_inputs},
        },
        context={"state": "merged"},
    )


def test_realized_preprovision_numbered_is_treated_as_unchanged():
    """Persistent intent: an ND-realized numbered link whose user-managed fields
    already match the preprovision declaration is no diff, so the module is
    idempotent and preserves ND-assigned addresses/numbered-only fields."""
    existing = _phys_link(
        "LEAF1",
        "Ethernet1/1",
        "SPINE1",
        "Ethernet1/1",
        {"srcIp": "10.4.0.1", "dstIp": "10.4.0.2", "srcInterfaceDescription": "planned"},
    )
    assert existing.get_diff(_proposed_preprovision()) is True


def test_realized_preprovision_user_field_change_is_a_diff():
    """Persistent intent: after realization, a change to a user-managed field
    (interface description) in the preprovision declaration is a real diff, so the
    module updates it instead of silently ignoring the edit."""
    existing = _phys_link(
        "LEAF1",
        "Ethernet1/1",
        "SPINE1",
        "Ethernet1/1",
        {"srcIp": "10.4.0.1", "dstIp": "10.4.0.2", "srcInterfaceDescription": "planned"},
    )
    assert existing.get_diff(_proposed_preprovision()) is True
    # Change the declared description -> now a diff.
    changed = NDLinkModel.from_config(
        {
            "src_fabric_name": "f1",
            "dst_fabric_name": "f1",
            "src_switch_name": "LEAF1",
            "dst_switch_name": "SPINE1",
            "src_interface_name": "Ethernet1/1",
            "dst_interface_name": "Ethernet1/1",
            "config_data": {"policy_type": "preprovision", "template_inputs": {"src_interface_description": "updated"}},
        },
        context={"state": "merged"},
    )
    assert existing.get_diff(changed) is False  # False == has a diff


def test_realized_preprovision_merge_stays_numbered_and_applies_user_field():
    """Persistent intent: merging the changed preprovision declaration onto the
    realized link keeps it numbered (a valid PUT, not a rejected policy change),
    preserves ND-assigned addresses, and applies the new interface description."""
    existing = _phys_link(
        "LEAF1",
        "Ethernet1/1",
        "SPINE1",
        "Ethernet1/1",
        {"srcIp": "10.4.0.1", "dstIp": "10.4.0.2", "srcInterfaceDescription": "planned"},
    )
    changed = NDLinkModel.from_config(
        {
            "src_fabric_name": "f1",
            "dst_fabric_name": "f1",
            "src_switch_name": "LEAF1",
            "dst_switch_name": "SPINE1",
            "src_interface_name": "Ethernet1/1",
            "dst_interface_name": "Ethernet1/1",
            "config_data": {"policy_type": "preprovision", "template_inputs": {"src_interface_description": "updated"}},
        },
        context={"state": "merged"},
    )
    merged = existing.merge(changed)
    assert merged.config_data.policy_type == "numbered"  # stays numbered (no policy change)
    assert merged.config_data.template_inputs.src_interface_description == "updated"  # user field applied
    assert merged.config_data.template_inputs.src_ip == "10.4.0.1"  # ND-assigned address preserved


@pytest.mark.parametrize(
    "field,alias,existing_value,changed_value",
    [
        ("mtu", "mtu", 9216, 9000),
        ("speed", "speed", "auto", "100Gb"),
    ],
)
def test_realized_preprovision_persists_mtu_and_speed(field, alias, existing_value, changed_value):
    """mtu and speed remain declarative intent after ND realizes a preprovision
    link as numbered: unchanged values are idempotent and edits survive the merge."""
    existing = _phys_link(
        "LEAF1",
        "Ethernet1/1",
        "SPINE1",
        "Ethernet1/1",
        {"srcIp": "10.4.0.1", "dstIp": "10.4.0.2", alias: existing_value},
    )

    assert existing.get_diff(_proposed_preprovision({field: existing_value})) is True

    changed = _proposed_preprovision({field: changed_value})
    assert existing.get_diff(changed) is False
    merged = existing.merge(changed)
    assert merged.config_data.policy_type == "numbered"
    assert getattr(merged.config_data.template_inputs, field) == changed_value
    assert merged.config_data.template_inputs.src_ip == "10.4.0.1"


def test_non_realized_policy_difference_still_diffs():
    """A genuine policy difference (numbered vs unnumbered) is still a change."""
    existing = _phys_link("LEAF1", "Ethernet1/1", "SPINE1", "Ethernet1/1", {"srcIp": "10.4.0.1", "dstIp": "10.4.0.2"})
    proposed_unnumbered = NDLinkModel.from_config(
        {
            "src_fabric_name": "f1",
            "dst_fabric_name": "f1",
            "src_switch_name": "LEAF1",
            "dst_switch_name": "SPINE1",
            "src_interface_name": "Ethernet1/1",
            "dst_interface_name": "Ethernet1/1",
            "config_data": {"policy_type": "unnumbered", "template_inputs": {}},
        },
        context={"state": "merged"},
    )
    assert existing.get_diff(proposed_unnumbered) is False


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


def test_argument_spec_omits_read_only_link_type():
    """link_type is a read-only response field (ND schema: readOnly, absent from
    linkPost) so it is not a settable option."""
    spec = NDLinkModel.get_argument_spec()
    assert "link_type" not in spec["config"]["options"]


def test_argument_spec_requires_identity_fields():
    """Fabric and interface names on both ends are required within each config item
    (mandatory identity), while top-level config stays optional so gathered runs."""
    spec = NDLinkModel.get_argument_spec()
    options = spec["config"]["options"]
    for name in ("src_fabric_name", "dst_fabric_name", "src_interface_name", "dst_interface_name"):
        assert options[name].get("required") is True, name
    assert spec["config"].get("required") is not True  # top-level config optional (gathered)


# ---------------------------------------------------------------------------
# Write-contract enforcement (OpenAPI): strict on write, tolerant on read
# ---------------------------------------------------------------------------


def _write_config(policy_type, template_inputs, state="merged"):
    return NDLinkModel.from_config(
        {
            "src_fabric_name": "f1",
            "dst_fabric_name": "f1",
            "src_switch_name": "a",
            "dst_switch_name": "b",
            "src_interface_name": "Ethernet1/1",
            "dst_interface_name": "Ethernet1/1",
            "config_data": {"policy_type": policy_type, "template_inputs": template_inputs},
        },
        context={"state": state},
    )


def test_out_of_range_mtu_rejected_on_write():
    """mtu below the OpenAPI minimum fails at the Ansible boundary, before check mode
    proposes a change or any request is sent (mikewiebe: mtu 0 reached ND and blocked delete)."""
    with pytest.raises(ValidationError):
        _write_config("numbered", {"mtu": 0})


def test_invalid_speed_enum_rejected_on_write():
    """An invalid speed enum fails on write instead of only at the controller."""
    with pytest.raises(ValidationError):
        _write_config("numbered", {"speed": "invalid-speed"})


def test_description_over_max_length_rejected_on_write():
    """Interface description longer than 254 chars fails on write."""
    with pytest.raises(ValidationError):
        _write_config("numbered", {"srcInterfaceDescription": "x" * 255})


def test_required_asn_missing_rejected_on_write():
    """ebgpVrfLite requires srcEbgpAsn/dstEbgpAsn (no default), so omitting them fails on write."""
    with pytest.raises(ValidationError):
        _write_config("ebgpVrfLite", {})


def test_required_asn_present_ok_on_write():
    """ebgpVrfLite with the required ASNs validates on write."""
    link = _write_config("ebgpVrfLite", {"srcEbgpAsn": "65001", "dstEbgpAsn": "65002"})
    assert link.config_data.template_inputs.src_ebgp_asn == "65001"


def test_required_field_with_default_not_forced_on_write():
    """mtu is required by the spec but carries a documented default, so the module
    supplies it and the user is not forced to provide it (no false rejection)."""
    link = _write_config("numbered", {"speed": "auto"})
    assert link.config_data.policy_type == "numbered"


def test_out_of_range_and_bad_enum_tolerated_on_read():
    """Controller reads stay tolerant: an already-invalid ND record (mtu 0, unknown
    speed) is still gathered so it can be inspected and repaired/deleted."""
    link = NDLinkModel.from_response(_response_link("numbered", {"mtu": 0, "speed": "weird"}))
    assert link.is_unsupported_policy is False
    assert link.config_data.template_inputs.mtu == 0
    assert link.config_data.template_inputs.speed == "weird"


def test_multisite_overlay_accepts_macsec_fields_on_write():
    """multisiteOverlay now models the macsec/qkd fields (previously missing), so a
    write that sets them validates instead of being rejected as unknown."""
    link = _write_config(
        "multisiteOverlay",
        {
            "srcEbgpAsn": "65001",
            "dstEbgpAsn": "65002",
            "srcIpAddress": "10.0.0.1",
            "dstIpAddress": "10.0.0.2",
            "macsec": True,
            "macsecPrimaryKeyString": "s3cret",
        },
    )
    assert type(link.config_data.template_inputs).__name__ == "MultisiteOverlayTemplateInputs"
    assert link.config_data.template_inputs.macsec is True


def test_layer2dci_ttag_field_removed():
    """inheritTtagFabricSetting is not in the OpenAPI layer2DciConfig schema, so it is
    no longer a layer2Dci field and is rejected as unknown on write."""
    with pytest.raises(ValidationError):
        _write_config("layer2Dci", {"inheritTtagFabricSetting": True})


def test_link_type_still_read_from_response():
    """link_type remains a model field populated on read (e.g. gathered/before/after)."""
    link = NDLinkModel.from_response(
        {
            "srcFabricName": "f1",
            "dstFabricName": "f1",
            "srcSwitchName": "a",
            "dstSwitchName": "b",
            "srcInterfaceName": "Ethernet1/1",
            "dstInterfaceName": "Ethernet1/1",
            "linkType": "lan_planned_link",
            "configData": {"policyType": "numbered", "templateInputs": {}},
        }
    )
    assert link.link_type == "lan_planned_link"
    # ...but it is never sent back to the controller.
    assert "linkType" not in link.to_payload()
