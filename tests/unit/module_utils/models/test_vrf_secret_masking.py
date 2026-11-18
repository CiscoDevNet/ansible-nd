# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""VRF secret tagging: BGP password, recursive discovery, CLI/template containers."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
    VrfAttachmentConfigModel,
    VrfChildConfigModel,
    VrfConfigModel,
    VrfParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import (
    VrfDataModel,
    VxlanFabricInstance,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    vrf_parent_argument_spec,
    vrf_standalone_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.utils import NO_LOG_PLACEHOLDER

CANARY = "c0de359a"
ECHO = "aabbccdd"
CHANGED = "11223344"
MASK = NO_LOG_PLACEHOLDER


def _existing(password=ECHO):
    return VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "vxlanIbgp",
            "fabricData": {"bgpPassword": password, "bgpPasswordKeyType": "type7"},
        }
    )


def _proposed(password=None):
    fabric = {"bgpPasswordKeyType": "type7"}
    if password is not None:
        fabric["bgpPassword"] = password
    return VrfDataModel.from_config(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "vxlanIbgp",
            "fabricData": fabric,
        }
    )


def test_vrf_bgp_password_fields_are_tagged_and_encrypt_is_not():
    for model_cls in (VrfConfigModel, VrfChildConfigModel, VrfParentConfigModel, VxlanFabricInstance):
        assert "bgp_password" in model_cls.secret_field_keys(by_alias=False)
        assert "bgpPassword" in model_cls.secret_field_keys(by_alias=True)
        assert "bgp_passwd_encrypt" not in model_cls.secret_field_keys(by_alias=False)
        assert "bgp_password_key_type" not in model_cls.secret_field_keys(by_alias=False)


def test_vrf_argument_spec_marks_bgp_password_no_log():
    assert vrf_standalone_argument_spec()["bgp_password"]["no_log"] is True
    assert vrf_parent_argument_spec()["child_fabric_config"]["options"]["bgp_password"]["no_log"] is True


def test_playbook_config_masks_display_and_keeps_request_values():
    model = VrfConfigModel.from_config(
        {"vrf_name": "BLUE", "bgp_password": CANARY, "bgp_passwd_encrypt": "type7"},
        context={"state": "merged"},
    )
    assert model.to_config()["bgp_password"] == MASK
    assert model.to_internal_config()["bgp_password"] == CANARY
    assert model.to_payload()["bgpPassword"] == CANARY


def test_parent_child_secret_discovery_is_recursive():
    raw = {
        "vrf_name": "BLUE",
        "child_fabric_config": [{"fabric_name": "AK-VXLAN", "bgp_password": CANARY, "bgp_passwd_encrypt": "type7"}],
    }
    assert VrfParentConfigModel.collect_secret_values(raw) == {CANARY}
    parent = VrfParentConfigModel.from_config(raw, context={"state": "merged"})
    display = parent.to_config()
    assert display["child_fabric_config"][0]["bgp_password"] == MASK
    internal = parent.to_internal_config()
    assert internal["child_fabric_config"][0]["bgp_password"] == CANARY


def test_vrf_data_model_discovers_playbook_and_fabric_data_passwords():
    assert VrfDataModel.collect_secret_values({"vrf_name": "BLUE", "bgp_password": CANARY}) == {CANARY}
    assert VrfDataModel.collect_secret_values({"fabricData": {"bgpPassword": ECHO}}) == {ECHO}
    assert VrfDataModel.collect_secret_values({"child_fabric_config": [{"fabric_name": "AK-VXLAN", "bgp_password": CANARY}]}) == {CANARY}


def test_get_echoed_password_is_registered_and_omitted_from_gathered():
    existing = _existing(password=ECHO)
    assert existing.collect_model_secret_values() == {ECHO}
    gathered = existing.to_gathered_config()
    assert "bgp_password" not in gathered
    assert gathered["bgp_passwd_encrypt"] == "type7"
    display = existing.to_config()
    fabric = display["fabric_data"]
    assert MASK in (fabric.get("bgp_password"), fabric.get("bgpPassword"))
    assert existing.to_payload()["fabricData"]["bgpPassword"] == ECHO
    assert "bgpPassword" not in existing.to_diff_dict().get("fabricData", {})


def test_get_echoed_non_string_password_is_still_registered():
    existing = _existing(password=11223344)
    assert existing.collect_model_secret_values() == {"11223344"}
    assert "bgp_password" not in existing.to_gathered_config()


def test_same_password_is_idempotent_and_new_password_is_a_change():
    existing = _existing()
    assert existing.get_diff(_proposed(ECHO), exclude_unset=True)
    assert not existing.get_diff(_proposed(CHANGED), exclude_unset=True)
    assert existing.get_diff(_proposed(None), exclude_unset=True)
    omitted = VrfDataModel.from_config({"fabricName": "AK-VXLAN", "vrfName": "BLUE", "vrfType": "vxlanIbgp"})
    assert existing.get_diff(omitted, exclude_unset=True)


CLI_CANARY = "interface loopback10\n description POC-CLI-CANARY-359"
TEMPLATE_CANARY = "POC-TMPL-CANARY-359"


def test_vrf_cli_and_template_containers_are_tagged_not_as_secrets():
    assert "freeform_config" in VrfAttachmentConfigModel.sensitive_container_keys(by_alias=False)
    assert "freeform_config" not in VrfAttachmentConfigModel.secret_field_keys(by_alias=False)
    for model_cls in (VrfConfigModel, VrfParentConfigModel, VrfDataModel):
        assert "vrf_template_config" in model_cls.sensitive_container_keys(by_alias=False)
        assert "vrf_template_config" not in model_cls.secret_field_keys(by_alias=False)
    assert "freeform_config" in VrfConfigModel.sensitive_container_keys(by_alias=False)


def test_vrf_argument_spec_marks_cli_and_template_no_log():
    assert vrf_standalone_argument_spec()["attach"]["options"]["freeform_config"]["no_log"] is True
    assert vrf_standalone_argument_spec()["vrf_template_config"]["no_log"] is True
    assert vrf_parent_argument_spec()["attach"]["options"]["freeform_config"]["no_log"] is True


def test_freeform_config_is_hidden_in_display_kept_for_request_and_diff():
    raw = {
        "vrf_name": "BLUE",
        "attach": [{"ip_address": "192.0.2.10", "freeform_config": CLI_CANARY}],
    }
    assert VrfConfigModel.collect_secret_values(raw) == {CLI_CANARY}
    assert VrfDataModel.collect_secret_values(raw) == {CLI_CANARY}
    model = VrfConfigModel.from_config(raw, context={"state": "merged"})
    display = model.to_config()
    assert display["attach"][0]["freeform_config"] == MASK
    assert CLI_CANARY not in str(display)
    assert model.to_internal_config()["attach"][0]["freeform_config"] == CLI_CANARY
    assert model.to_diff_dict()["attach"][0]["freeform_config"] == CLI_CANARY
    gathered = model.to_gathered_config()
    assert "freeform_config" not in gathered["attach"][0]
    same = VrfConfigModel.from_config(raw, context={"state": "merged"})
    changed = VrfConfigModel.from_config(
        {"vrf_name": "BLUE", "attach": [{"ip_address": "192.0.2.10", "freeform_config": "hostname changed"}]},
        context={"state": "merged"},
    )
    assert model.get_diff(same, exclude_unset=True)
    assert not model.get_diff(changed, exclude_unset=True)


def test_vrf_template_config_is_hidden_in_display_kept_for_request_and_diff():
    raw = {
        "vrf_name": "BLUE",
        "vrf_template_name": "CustomTemplate1",
        "vrf_template_config": {"secret_param": TEMPLATE_CANARY},
    }
    assert VrfConfigModel.collect_secret_values(raw) == {TEMPLATE_CANARY}
    model = VrfConfigModel.from_config(raw, context={"state": "merged"})
    assert model.to_config()["vrf_template_config"] == MASK
    assert TEMPLATE_CANARY not in str(model.to_config())
    assert model.to_internal_config()["vrf_template_config"] == {"secret_param": TEMPLATE_CANARY}
    assert model.to_payload()["vrfTemplateConfig"] == {"secret_param": TEMPLATE_CANARY}
    assert model.to_diff_dict()["vrfTemplateConfig"] == {"secret_param": TEMPLATE_CANARY}
    assert "vrf_template_config" not in model.to_gathered_config()

    data = VrfDataModel.from_config(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "userDefined",
            "vrfTemplateName": "CustomTemplate1",
            "vrfTemplateConfig": {"secret_param": TEMPLATE_CANARY},
        }
    )
    assert data.collect_model_secret_values() == {TEMPLATE_CANARY}
    assert data.to_config()["vrf_template_config"] == MASK
    assert data.to_payload()["vrfTemplateConfig"]["secret_param"] == TEMPLATE_CANARY
    assert "vrf_template_config" not in data.to_gathered_config()
    same = VrfDataModel.from_config(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "userDefined",
            "vrfTemplateName": "CustomTemplate1",
            "vrfTemplateConfig": {"secret_param": TEMPLATE_CANARY},
        }
    )
    changed = VrfDataModel.from_config(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "userDefined",
            "vrfTemplateName": "CustomTemplate1",
            "vrfTemplateConfig": {"secret_param": "other"},
        }
    )
    assert data.get_diff(same, exclude_unset=True)
    assert not data.get_diff(changed, exclude_unset=True)
