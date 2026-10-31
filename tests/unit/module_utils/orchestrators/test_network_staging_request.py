"""The staging receipt binds raw NaC requests to native Ansible defaults."""

from copy import deepcopy

from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import network_parent_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_staging_request import network_staging_request_digest


def _config():
    return [
        {
            "network_name": "BLUE",
            "network_id": "50001",
            "vrf_name": "TENANT",
            "attach": [{"ip_address": "192.0.2.1", "interfaces": [{"mode": "trunk", "interface_range": "port-channel10"}]}],
            "child_fabric_config": [{"fabric_name": "child", "dhcp_servers": [{"server_address": "192.0.2.10"}]}],
        }
    ]


def _expanded(config):
    spec = {"config": {"type": "list", "elements": "dict", "options": network_parent_argument_spec(), "default": []}}
    result = ArgumentSpecValidator(spec).validate({"config": config})
    assert not result.error_messages
    return result.validated_parameters["config"]


def _digest(config, **kwargs):
    return network_staging_request_digest(kwargs.get("fabric", "fab1"), kwargs.get("state", "replaced"), config, kwargs.get("actions"))


def test_raw_and_native_expanded_nested_defaults_have_identical_digest():
    raw = _config()
    expanded = _expanded(raw)
    assert expanded[0]["mtu"] == expanded[0]["mtu_l3intf"] == 9216
    assert expanded[0]["deploy"] is True
    assert expanded[0]["attach"][0]["deploy"] is True
    assert expanded[0]["attach"][0]["interfaces"][0]["native_vlan"] is False
    assert expanded[0]["child_fabric_config"][0]["dhcp_servers"][0]["server_vrf"] is None
    assert _digest(raw) == _digest(expanded)
    assert len(_digest(raw)) == 64


def test_known_none_values_match_omitted_fields_and_native_defaults():
    raw = _config()
    raw[0].update(mtu=None, vlan_id=None, deploy=None)
    raw[0]["attach"][0]["interfaces"][0]["native_vlan"] = None
    assert _digest(raw) == _digest(_config()) == _digest(_expanded(_config()))


@pytest.mark.parametrize(
    "path,value",
    [
        (("network_name",), "GREEN"),
        (("mtu",), 1500),
        (("deploy",), False),
        (("attach", 0, "deploy"), False),
        (("attach", 0, "interfaces", 0, "native_vlan"), True),
        (("attach", 0, "interfaces", 0, "interface_range"), "port-channel11"),
        (("child_fabric_config", 0, "fabric_name"), "another-child"),
    ],
)
def test_meaningful_nested_intent_changes_alter_digest(path, value):
    config = _config()
    target = config[0]
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    assert _digest(config) != _digest(_config())


def test_request_scope_and_list_order_are_bound():
    config = _config()
    assert _digest(config, fabric="fab2") != _digest(config)
    assert _digest(config, state="merged") != _digest(config)
    other = deepcopy(config[0])
    other["network_name"] = "GREEN"
    assert _digest(config + [other]) != _digest([other] + config)


def test_explicit_false_zero_and_native_scalar_conversions_are_preserved():
    config = _config()
    config[0].update(deploy="false", mtu="0", display_name=0)
    config[0]["attach"][0].update(deploy=0, vlan_id="0")
    config[0]["attach"][0]["interfaces"][0]["native_vlan"] = "no"
    expanded = _expanded(config)
    assert expanded[0]["deploy"] is False
    assert expanded[0]["mtu"] == 0
    assert expanded[0]["display_name"] == "0"
    assert expanded[0]["attach"][0]["deploy"] is False
    assert _digest(config) == _digest(expanded)
    assert _digest(config) != _digest(_config())


def test_unknown_fields_and_untyped_dict_content_remain_bound():
    config = _config()
    original = _digest(config)
    config[0]["future_option"] = {"flag": False, "value": None}
    assert _digest(config) != original
    config[0]["future_option"]["flag"] = True
    changed = _digest(config)
    config[0]["future_option"]["flag"] = False
    assert _digest(config) != changed
    config[0]["network_template_config"] = {"CUSTOM": None}
    assert _digest(config) != _digest([{**config[0], "network_template_config": {}}])


def test_absent_actions_are_equivalent_but_explicit_actions_remain_bound():
    config = _config()
    assert _digest(config) == _digest(config, actions={})
    assert _digest(config, actions={"deploy": False}) != _digest(config)
    assert _digest(config, actions={"future": None}) != _digest(config)


def test_mapping_order_is_irrelevant_and_inputs_are_not_mutated():
    config = _config()
    actions = {"deploy": False, "metadata": {"b": 2, "a": 1}}
    before = deepcopy((config, actions))
    digest = _digest(config, actions=actions)
    reversed_config = [dict(reversed(list(config[0].items())))]
    assert digest == _digest(reversed_config, actions={"metadata": {"a": 1, "b": 2}, "deploy": False})
    assert (config, actions) == before


def test_empty_config_none_and_list_have_same_digest():
    assert _digest(None) == _digest([])
