from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import SecretStr, ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    FabricGroupVxlanModel,
    VxlanFabricGroupManagementModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_vxlan import ManageFabricGroupVxlanOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.test_nd_state_machine_fabric_replacement import (
    _module,
    _replacement_spy,
    _rest_send,
)

MASK = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
RANGES = (
    ("l2_vni_range", 1, 16777214),
    ("l3_vni_range", 1, 16777214),
    ("downstream_l2_vni_range", 1, 16777214),
    ("downstream_l3_vni_range", 1, 16777214),
    ("security_group_tag_id_range", 16, 65535),
)


def _argspec_model(management):
    params = {"config": [{"fabric_name": "MSD1", "management": deepcopy(management)}], "state": "merged"}
    result = ModuleArgumentSpecValidator(FabricGroupVxlanModel.get_argument_spec()).validate(params)
    assert result.error_messages == []
    assert not result.unsupported_parameters
    return FabricGroupVxlanModel.from_config(result.validated_parameters["config"][0])


@pytest.mark.parametrize("field,minimum,maximum", RANGES)
@pytest.mark.parametrize("shape", ("minimum", "maximum", "span", "comma_list"))
def test_group_native_range_boundaries_and_gathered_replay(field, minimum, maximum, shape):
    """All native integer-range forms survive public input, payload and gathered replay."""
    values = {
        "minimum": str(minimum),
        "maximum": str(maximum),
        "span": f"{minimum}-{maximum}",
        "comma_list": f"{minimum},{minimum + 1}-{minimum + 2},{maximum}",
    }
    value = values[shape]
    model = _argspec_model({field: value})
    wire = VxlanFabricGroupManagementModel.model_fields[field].alias
    assert model.to_payload()["management"][wire] == value
    response = FabricGroupVxlanModel.from_response(model.to_payload())
    gathered = response.to_gathered_config()
    replay = _argspec_model(gathered["management"])
    assert replay.to_payload()["management"][wire] == value


@pytest.mark.parametrize("field,minimum,maximum", RANGES)
@pytest.mark.parametrize("shape", ("below", "above", "reversed", "malformed", "trailing_comma", "empty", "not_numeric", "interior_space"))
def test_group_rejects_out_of_range_or_malformed_native_integer_ranges(field, minimum, maximum, shape):
    """A valid public string option cannot bypass native numeric bounds or range syntax."""
    values = {
        "below": str(minimum - 1),
        "above": str(maximum + 1),
        "reversed": f"{minimum + 1}-{minimum}",
        "malformed": f"{minimum}--{maximum}",
        "trailing_comma": f"{minimum},",
        "empty": "",
        "not_numeric": "not-a-range",
        "interior_space": f"{minimum}, {maximum}",
    }
    with pytest.raises(ValidationError, match=field):
        _argspec_model({field: values[shape]})


@pytest.mark.parametrize("address", ("192.0.2.1", "2001:db8::1"))
@pytest.mark.parametrize("asn,expected", (("+65001", "65001"), ("+4294967295", "4294967295"), ("65535.65535", "65535.65535")))
def test_group_route_server_native_asn_shorthand_uses_unsigned_api_wire(address, asn, expected):
    """Native plus shorthand is normalized before requests and replay on either release."""
    model = _argspec_model({"route_server_collection": [{"route_server_ip": address, "route_server_asn": asn}]})
    servers = model.to_payload()["management"]["routeServerCollection"]
    assert servers == [{"routeServerIp": address, "routeServerAsn": expected}]
    response = FabricGroupVxlanModel.from_response(model.to_payload())
    assert response.to_gathered_config()["management"]["route_server_collection"][0]["route_server_asn"] == expected


@pytest.mark.parametrize("asn", ("0", "+0", "4294967296", "+4294967296", "+1.2", "65536.0", "1.65536", "65001\ninvalid"))
def test_group_rejects_invalid_route_server_asn(asn):
    with pytest.raises(ValidationError):
        _argspec_model({"route_server_collection": [{"route_server_ip": "192.0.2.1", "route_server_asn": asn}]})


@pytest.mark.parametrize("key_type", ("3des", "type6", "type7"))
@pytest.mark.parametrize("length", (1, 160, 161, 164))
def test_group_bgp_plaintext_input_boundaries_remain_typed_secret_and_masked(key_type, length):
    key = "a" * length
    model = _argspec_model({"multisite_inter_connect_bgp_auth_key_type": key_type, "multisite_inter_connect_bgp_key": key})
    assert isinstance(model.management.multisite_inter_connect_bgp_key, SecretStr)
    assert model.to_payload()["management"]["multisiteInterConnectBgpKey"] == key
    assert model.to_config()["management"]["multisite_inter_connect_bgp_key"] == MASK
    assert "multisite_inter_connect_bgp_key" not in model.to_gathered_config()["management"]
    assert model.to_diff_dict()["management"]["multisiteInterConnectBgpKey"] == MASK


@pytest.mark.parametrize("value", ("a" * 165, "a" * 257))
def test_group_bgp_plaintext_input_limits_do_not_disclose_the_key(value):
    with pytest.raises(ValidationError) as error:
        _argspec_model({"multisite_inter_connect_bgp_key": value})
    assert value not in str(error.value)


@pytest.mark.parametrize("length,accepted", ((164, True), (165, False)))
def test_group_already_wrapped_bgp_key_uses_the_native_input_limit(length, accepted):
    """Input length validation applies equally to plain strings and existing SecretStr values."""
    key = "a" * length
    config = {"fabric_name": "MSD1", "management": {"multisite_inter_connect_bgp_key": SecretStr(key)}}
    if accepted:
        model = FabricGroupVxlanModel.from_config(config)
        assert isinstance(model.management.multisite_inter_connect_bgp_key, SecretStr)
        assert model.to_payload()["management"]["multisiteInterConnectBgpKey"] == key
        assert model.to_config()["management"]["multisite_inter_connect_bgp_key"] == MASK
    else:
        with pytest.raises(ValidationError) as error:
            FabricGroupVxlanModel.from_config(config)
        assert key not in str(error.value)


@pytest.mark.parametrize("algorithm,length", (("AES_128_CMAC", 66), ("AES_256_CMAC", 130)))
def test_group_cloudsec_plaintext_algorithm_validation_and_masking(algorithm, length):
    key = "ab" * (length // 2)
    model = _argspec_model({"cloud_sec_algorithm": algorithm, "cloud_sec_key": key})
    assert model.to_payload()["management"]["cloudSecKey"] == key
    assert model.to_config()["management"]["cloud_sec_key"] == MASK
    with pytest.raises(ValidationError, match="exactly"):
        _argspec_model({"cloud_sec_algorithm": algorithm, "cloud_sec_key": key[:-1]})


@pytest.mark.parametrize("algorithm,hex_characters", (("AES_128_CMAC", 65), ("AES_256_CMAC", 129)))
def test_group_rejects_typed_cloudsec_keys_with_a_final_newline(algorithm, hex_characters):
    """An existing SecretStr must not use regex end-of-line behavior to satisfy the exact length."""
    key = "a" * hex_characters + "\n"
    with pytest.raises(ValidationError, match="hexadecimal") as error:
        FabricGroupVxlanModel.from_config({"fabric_name": "MSD1", "management": {"cloud_sec_algorithm": algorithm, "cloud_sec_key": SecretStr(key)}})
    assert key not in str(error.value)


@pytest.mark.parametrize("cloud_key", ("opaque-controller-material", "a" * 130))
def test_group_response_secrets_are_not_reinterpreted_as_plaintext_on_unrelated_merge(cloud_key):
    """Opaque/ciphertext response keys remain typed, masked and payload-preserved through merge."""
    bgp_key = "controller-ciphertext-" + "a" * 200
    response = FabricGroupVxlanModel.from_response(
        {"name": "MSD1", "category": "fabricGroup", "management": {"type": "vxlan", "cloudSecKey": cloud_key, "multisiteInterConnectBgpKey": bgp_key}}
    )
    assert response.collect_replacement_secret_values() == {cloud_key, bgp_key}
    assert response.to_config()["management"]["cloud_sec_key"] == MASK
    assert response.to_config()["management"]["multisite_inter_connect_bgp_key"] == MASK
    response.merge(_argspec_model({"multisite_delay_restore": 301}))
    assert response.to_payload()["management"]["cloudSecKey"] == cloud_key
    assert response.to_payload()["management"]["multisiteInterConnectBgpKey"] == bgp_key
    assert response.management.multisite_delay_restore == 301


@pytest.mark.parametrize("masked", ("********", MASK))
def test_group_known_response_masks_never_become_literal_put_secrets(masked):
    """Known masks mean unavailable response material, not a new encrypted credential."""
    model = FabricGroupVxlanModel.from_response(
        {"name": "MSD1", "category": "fabricGroup", "management": {"type": "vxlan", "cloudSecKey": masked, "multisiteInterConnectBgpKey": masked}}
    )
    assert model.management.cloud_sec_key is None
    assert model.management.multisite_inter_connect_bgp_key is None
    assert model.collect_replacement_secret_values() == set()
    model.merge(_argspec_model({"multisite_delay_restore": 301}))
    payload = model.to_payload()["management"]
    assert "cloudSecKey" not in payload
    assert "multisiteInterConnectBgpKey" not in payload


def test_group_gathered_secrets_are_omitted_to_make_the_remaining_configuration_replayable():
    response = FabricGroupVxlanModel.from_response(
        {
            "name": "MSD1",
            "category": "fabricGroup",
            "management": {"type": "vxlan", "cloudSecKey": "controller-opaque", "multisiteInterConnectBgpKey": "ciphertext"},
        }
    )
    assert response.to_config()["management"]["cloud_sec_key"] == MASK
    gathered = response.to_gathered_config()
    assert "cloud_sec_key" not in gathered["management"]
    assert "multisite_inter_connect_bgp_key" not in gathered["management"]
    replay = _argspec_model(gathered["management"])
    assert replay.management.cloud_sec_key is None
    assert replay.management.multisite_inter_connect_bgp_key is None


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_group_real_state_update_scrubs_existing_controller_keys_and_keeps_omission_policy(state):
    """Actual preparation registers public controller secrets; merged preserves and exact states omit them."""
    cloud_key = "controller-cloudsec-ciphertext"
    bgp_key = "controller-bgp-ciphertext"
    response = {
        "name": "fabric1",
        "category": "fabricGroup",
        "management": {"type": "vxlan", "cloudSecKey": cloud_key, "multisiteInterConnectBgpKey": bgp_key},
    }
    spy = _replacement_spy(ManageFabricGroupVxlanOrchestrator, response)(rest_send=_rest_send())
    module = _module(state)
    module.params["config"] = [{"fabric_name": "fabric1", "management": {"multisite_delay_restore": 301}}]
    instance = NDStateMachine(module=module, model_orchestrator=spy)
    instance.manage_state()
    assert instance.output.format()["changed"] is True
    assert {cloud_key, bgp_key}.issubset(module.no_log_values)
    assert len(spy._updated) == 1
    payload = spy._updated[0].to_payload()["management"]
    if state == "merged":
        assert payload["cloudSecKey"] == cloud_key
        assert payload["multisiteInterConnectBgpKey"] == bgp_key
    else:
        assert "cloudSecKey" not in payload
        assert "multisiteInterConnectBgpKey" not in payload
    output = str(instance.output.format())
    assert cloud_key not in output
    assert bgp_key not in output


def test_group_secret_only_changes_keep_the_existing_no_write_policy():
    response = FabricGroupVxlanModel.from_response(
        {
            "name": "MSD1",
            "category": "fabricGroup",
            "management": {"type": "vxlan", "cloudSecKey": "controller-opaque", "multisiteInterConnectBgpKey": "old-key"},
        }
    )
    proposed = _argspec_model({"cloud_sec_key": "ab" * 33, "multisite_inter_connect_bgp_key": "new-key"})
    assert response.get_diff(proposed) is True


@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)"))
def test_group_baseline_bgp_key_contract_accepts_internal_whitespace(version):
    """The newer schema constraint must not retroactively reject baseline string input."""
    model = _argspec_model({"multisite_inter_connect_bgp_key": "baseline synthetic key"})
    rest = RestSend({"check_mode": False, "state": "merged"})
    rest.controller_product_version = version
    ManageFabricGroupVxlanOrchestrator(rest_send=rest).preflight([model])


@pytest.mark.parametrize("version", ("4.3.1", "4.4.1", None))
def test_group_newer_bgp_key_constraint_fails_before_transport_without_secret_text(version):
    """Explicit newer-release constraints use the reusable product-version preflight."""
    key = "sensitive synthetic key"
    model = _argspec_model({"multisite_inter_connect_bgp_key": key})
    rest = RestSend({"check_mode": False, "state": "merged"})
    rest.controller_product_version = version
    with pytest.raises(RuntimeError, match="multisite_inter_connect_bgp_key") as error:
        ManageFabricGroupVxlanOrchestrator(rest_send=rest).preflight([model])
    assert key not in str(error.value)


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1", "4.4.1"))
def test_group_valid_bgp_key_contract_is_accepted_across_releases(version):
    model = _argspec_model({"multisite_inter_connect_bgp_key": "a" * 164})
    rest = RestSend({"check_mode": False, "state": "merged"})
    rest.controller_product_version = version
    ManageFabricGroupVxlanOrchestrator(rest_send=rest).preflight([model])
