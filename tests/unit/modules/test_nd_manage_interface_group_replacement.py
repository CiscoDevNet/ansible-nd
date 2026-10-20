# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Exercise Ethernet replacement policy semantics through the module entry point."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules import nd_manage_interface_group

_GROUP_NAME = "ethernet-policy-group"
_ORIGINAL_MEMBERS = [{"switch_id": "SN1", "interface_names": ["Ethernet1/10"]}]
_EXPANDED_MEMBERS = [{"switch_id": "SN1", "interface_names": ["Ethernet1/10", "Ethernet1/11"]}]
_NONDEFAULT_ATTRIBUTES = {
    "admin_state": False,
    "allowed_vlans": "10-20",
    "auto_negotiate": False,
    "bpdu_guard": "enable",
    "cdp": False,
    "duplex_mode": "full",
    "mtu": "default",
    "netflow": True,
    "orphan_port": True,
    "port_type_edge": True,
    "port_type_edge_trunk": False,
    "speed": "1Gb",
}
_OPTIONAL_ATTRIBUTES = {
    "extra_config": "description existing-policy",
    "native_vlan": 100,
    "netflow_monitor": "existing-monitor",
    "netflow_sampler": "existing-sampler",
}


class _ModuleExited(BaseException):
    """Capture ``exit_json`` without being treated as a module failure."""


@pytest.fixture
def replacement_runner(monkeypatch):
    """Mock only controller reads/writes while preserving module reconciliation."""

    def make_runner(attributes=None, *, omit_empty_echoes=False, sparse_default_echoes=False, native_default_echo=False):
        model = InterfaceGroupConfigModel.from_config(
            {
                "interface_group_name": _GROUP_NAME,
                "type": "ethernetWithPolicy",
                "networks": ["network-a"],
                "switch_interfaces": deepcopy(_ORIGINAL_MEMBERS),
                "ethernet_attributes": attributes or {},
            }
        )
        controller = InterfaceGroupValidators.to_wire_group(model.to_payload(), include_empty_associations=True)
        put_payloads = []

        def query_all(orchestrator, model_instance=None, **kwargs):
            del model_instance, kwargs
            response = deepcopy(controller)
            echoed_attributes = response["policyDetails"]["ethernetAttributes"]
            if native_default_echo:
                echoed_attributes.setdefault("nativeVlan", 1)
            if sparse_default_echoes:
                for key, default in InterfaceGroupValidators.ethernet_with_policy_defaults().items():
                    if echoed_attributes.get(key) == default:
                        echoed_attributes.pop(key)
            if omit_empty_echoes:
                for key in ("extraConfig", "netflowMonitor", "netflowSampler"):
                    if echoed_attributes.get(key) == "":
                        echoed_attributes.pop(key)
            observed = InterfaceGroupConfigModel.from_response(response)
            orchestrator._existing_groups = {_GROUP_NAME: deepcopy(observed)}
            return [response]

        def put_group(orchestrator, proposed):
            nonlocal controller
            payload = orchestrator._payload_for_update(proposed)
            put_payloads.append(deepcopy(payload))
            controller = deepcopy(payload)
            return {}

        orchestrator_class = nd_manage_interface_group.ManageInterfaceGroupOrchestrator
        monkeypatch.setattr(orchestrator_class, "query_all", query_all)
        monkeypatch.setattr(orchestrator_class, "_put_group", put_group)
        monkeypatch.setattr(nd_manage_interface_group, "require_pydantic", lambda module: None)
        monkeypatch.setattr(nd_manage_interface_group, "setup_logging", lambda module: None)

        def run(state, update, *, check_mode=False):
            params = {
                "fabric_name": "fabric-1",
                "state": state,
                "config_actions": {"type": "resource", "deploy": False},
                "config": [
                    {
                        "interface_group_name": _GROUP_NAME,
                        "type": "ethernetWithPolicy",
                        **deepcopy(update),
                    }
                ],
                "output_level": "normal",
            }

            def exit_json(**output):
                raise _ModuleExited(output)

            def fail_json(**output):
                raise AssertionError(f"Unexpected module failure: {output}")

            module = SimpleNamespace(
                params=params,
                check_mode=check_mode,
                no_log_values=set(),
                _verbosity=0,
                warn=lambda message: None,
                exit_json=exit_json,
                fail_json=fail_json,
            )
            monkeypatch.setattr(nd_manage_interface_group, "AnsibleModule", lambda **kwargs: module)
            with pytest.raises(_ModuleExited) as exited:
                nd_manage_interface_group.main()
            return exited.value.args[0]

        return SimpleNamespace(run=run, put_payloads=put_payloads)

    return make_runner


def _assert_check_apply_replay(runner, state, update, expected_attributes, *, controller_omits_empty=False):
    """Require matching prediction, transmitted policy, and idempotent replay."""
    checked = runner.run(state, update, check_mode=True)
    assert checked["changed"] is True
    assert checked["after"][0]["ethernet_attributes"] == expected_attributes
    assert runner.put_payloads == []

    applied = runner.run(state, update)
    assert applied["changed"] is True
    assert applied["after"] == checked["after"]
    assert len(runner.put_payloads) == 1
    expected_model = InterfaceGroupConfigModel.from_config(applied["after"][0])
    expected_wire_attributes = expected_model.to_payload()["ethernetAttributes"]
    assert runner.put_payloads[0]["policyDetails"]["ethernetAttributes"] == expected_wire_attributes

    replayed = runner.run(state, update)
    assert replayed["changed"] is False
    expected_replay = deepcopy(applied["after"])
    if controller_omits_empty:
        for key in ("extra_config", "netflow_monitor", "netflow_sampler"):
            expected_replay[0]["ethernet_attributes"].pop(key, None)
    assert replayed["after"] == expected_replay
    assert len(runner.put_payloads) == 1


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("add_member", [False, True], ids=["policy-only", "membership-change"])
@pytest.mark.parametrize("attribute", list(_NONDEFAULT_ATTRIBUTES))
def test_authoritative_omitted_attribute_resets_before_comparison(replacement_runner, state, add_member, attribute):
    """Every omitted default must reset independently of a membership change."""
    runner = replacement_runner({attribute: _NONDEFAULT_ATTRIBUTES[attribute]})
    supplied_attribute = "cdp" if attribute == "admin_state" else "admin_state"
    update = {"ethernet_attributes": {supplied_attribute: True}}
    if add_member:
        update["switch_interfaces"] = deepcopy(_EXPANDED_MEMBERS)
    expected = InterfaceGroupConfigModel.from_config({"interface_group_name": _GROUP_NAME, "type": "ethernetWithPolicy"}).ethernet_attributes.to_config()

    _assert_check_apply_replay(runner, state, update, expected)
    payload = runner.put_payloads[0]
    assert payload["networkNames"] == ["network-a"]
    assert payload["switchInterfaces"] == [{"switchId": "SN1", "interfaceNames": ["Ethernet1/10", "Ethernet1/11"] if add_member else ["Ethernet1/10"]}]


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("existing_cdp", [False, True], ids=["reset-nondefault", "already-default"])
def test_authoritative_sparse_controller_default_echoes_do_not_create_false_diffs(replacement_runner, state, existing_cdp):
    """Defaulted values omitted by a GET must reconcile like their full echoes."""
    runner = replacement_runner({"cdp": existing_cdp}, sparse_default_echoes=True)
    update = {"ethernet_attributes": {"admin_state": True}}

    checked = runner.run(state, update, check_mode=True)
    assert checked["changed"] is (not existing_cdp)
    assert runner.put_payloads == []
    if not existing_cdp:
        assert checked["after"][0]["ethernet_attributes"]["cdp"] is True
    applied = runner.run(state, update)
    assert applied["changed"] is (not existing_cdp)
    if not existing_cdp:
        assert applied["after"][0]["ethernet_attributes"]["cdp"] is True
        assert runner.put_payloads[0]["policyDetails"]["ethernetAttributes"]["cdp"] is True
    replayed = runner.run(state, update)
    assert replayed["changed"] is False
    assert len(runner.put_payloads) == int(not existing_cdp)


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("add_member", [False, True], ids=["policy-only", "membership-change"])
@pytest.mark.parametrize("attribute", list(_OPTIONAL_ATTRIBUTES))
def test_authoritative_omitted_optional_attribute_is_removed(replacement_runner, state, add_member, attribute):
    """An omitted optional value must not survive merely because defaults match."""
    runner = replacement_runner({attribute: _OPTIONAL_ATTRIBUTES[attribute]})
    update = {"ethernet_attributes": {"admin_state": True}}
    if add_member:
        update["switch_interfaces"] = deepcopy(_EXPANDED_MEMBERS)
    expected = InterfaceGroupConfigModel.from_config({"interface_group_name": _GROUP_NAME, "type": "ethernetWithPolicy"}).ethernet_attributes.to_config()

    _assert_check_apply_replay(runner, state, update, expected)
    assert attribute not in runner.run(state, update)["after"][0]["ethernet_attributes"]
    assert len(runner.put_payloads) == 1


@pytest.mark.parametrize("supply_policy", [False, True], ids=["omitted-block", "sparse-block"])
@pytest.mark.parametrize("add_member", [False, True], ids=["policy-only", "membership-change"])
def test_merged_sparse_policy_keeps_every_existing_nondefault(replacement_runner, supply_policy, add_member):
    """Replacement normalization must not leak into additive merged updates."""
    initial = {**_NONDEFAULT_ATTRIBUTES, **_OPTIONAL_ATTRIBUTES, "admin_state": True}
    runner = replacement_runner(initial)
    update = {"ethernet_attributes": {"admin_state": True}} if supply_policy else {}
    if add_member:
        update["switch_interfaces"] = deepcopy(_EXPANDED_MEMBERS)

    checked = runner.run("merged", update, check_mode=True)
    applied = runner.run("merged", update)
    replayed = runner.run("merged", update)

    assert checked["changed"] is add_member
    assert applied["changed"] is add_member
    assert replayed["changed"] is False
    for output in (checked, applied, replayed):
        assert output["after"][0]["ethernet_attributes"] == initial
        assert output["after"][0]["networks"] == ["network-a"]
    assert len(runner.put_payloads) == int(add_member)
    if add_member:
        assert runner.put_payloads[0]["policyDetails"]["ethernetAttributes"]["cdp"] is False


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("add_member", [False, True], ids=["policy-only", "membership-change"])
def test_authoritative_omitted_whole_policy_retains_default_reset_contract(replacement_runner, state, add_member):
    """An omitted block already becomes defaults for an authoritative request."""
    runner = replacement_runner({"cdp": False})
    update = {"switch_interfaces": deepcopy(_EXPANDED_MEMBERS)} if add_member else {}
    expected = InterfaceGroupConfigModel.from_config({"interface_group_name": _GROUP_NAME, "type": "ethernetWithPolicy"}).ethernet_attributes.to_config()

    _assert_check_apply_replay(runner, state, update, expected)


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("association", ["networks", "switch_interfaces", "both"])
def test_authoritative_explicit_empty_associations_still_clear(replacement_runner, state, association):
    """Hydrating policy defaults preserves the omitted-versus-empty list boundary."""
    runner = replacement_runner({"cdp": False})
    update = {"ethernet_attributes": {"admin_state": True}}
    if association in {"networks", "both"}:
        update["networks"] = []
    if association in {"switch_interfaces", "both"}:
        update["switch_interfaces"] = []
    expected = InterfaceGroupConfigModel.from_config({"interface_group_name": _GROUP_NAME, "type": "ethernetWithPolicy"}).ethernet_attributes.to_config()

    _assert_check_apply_replay(runner, state, update, expected)
    payload = runner.put_payloads[0]
    assert payload["networkNames"] == ([] if association in {"networks", "both"} else ["network-a"])
    assert payload["switchInterfaces"] == ([] if association in {"switch_interfaces", "both"} else [{"switchId": "SN1", "interfaceNames": ["Ethernet1/10"]}])


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("echo_empty_values", [False, True], ids=["omitted-echo", "empty-echo"])
def test_authoritative_defaults_keep_controller_empty_echo_idempotence(replacement_runner, state, echo_empty_values):
    """Optional empty-string echoes and absence remain semantically equivalent."""
    empty_attributes = {"extra_config": "", "netflow_monitor": "", "netflow_sampler": ""}
    runner = replacement_runner(empty_attributes if echo_empty_values else {})
    update = {"ethernet_attributes": {"admin_state": True}}

    for check_mode in (True, False):
        output = runner.run(state, update, check_mode=check_mode)
        assert output["changed"] is False
    assert runner.put_payloads == []


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_explicit_empty_strings_clear_nonempty_optional_values_and_replay(replacement_runner, state):
    """Only missing-versus-empty controller echoes normalize away, not removals."""
    runner = replacement_runner(_OPTIONAL_ATTRIBUTES, omit_empty_echoes=True)
    update = {"ethernet_attributes": {"admin_state": True, "extra_config": "", "netflow_monitor": "", "netflow_sampler": ""}}
    expected = InterfaceGroupConfigModel.from_config({"interface_group_name": _GROUP_NAME, "type": "ethernetWithPolicy"}).ethernet_attributes.to_config()
    expected.update(extra_config="", netflow_monitor="", netflow_sampler="")

    _assert_check_apply_replay(runner, state, update, expected, controller_omits_empty=True)


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("add_member", [False, True], ids=["policy-only", "membership-change"])
@pytest.mark.parametrize("existing_native_vlan", [None, 1, 100], ids=["omitted-default", "explicit-default", "nondefault-reset"])
def test_authoritative_native_vlan_default_echo_is_idempotent(replacement_runner, state, add_member, existing_native_vlan):
    """An omitted native VLAN reconciles with the controller's VLAN 1 echo."""
    attributes = {"native_vlan": existing_native_vlan} if existing_native_vlan is not None else {}
    runner = replacement_runner(attributes, native_default_echo=True)
    update = {"ethernet_attributes": {"admin_state": True}}
    if add_member:
        update["switch_interfaces"] = deepcopy(_EXPANDED_MEMBERS)
    expected_change = add_member or existing_native_vlan == 100

    checked = runner.run(state, update, check_mode=True)
    assert checked["changed"] is expected_change
    assert runner.put_payloads == []
    if expected_change:
        assert "native_vlan" not in checked["after"][0]["ethernet_attributes"]
    else:
        assert checked["after"][0]["ethernet_attributes"]["native_vlan"] == 1
    applied = runner.run(state, update)
    assert applied["changed"] is expected_change
    assert applied["after"] == checked["after"]
    assert len(runner.put_payloads) == int(expected_change)
    if expected_change:
        assert "nativeVlan" not in runner.put_payloads[0]["policyDetails"]["ethernetAttributes"]

    replayed = runner.run(state, update)
    assert replayed["changed"] is False
    assert replayed["after"][0]["ethernet_attributes"]["native_vlan"] == 1
    assert len(runner.put_payloads) == int(expected_change)


@pytest.mark.parametrize(
    ("native_vlan", "cdp", "expected_matches"),
    [(1, True, True), (100, True, False), (1, False, False)],
    ids=["controller-native-default", "wrong-native-vlan", "wrong-cdp"],
)
def test_readback_native_default_echo_matches_only_semantically_correct_policy(native_vlan, cdp, expected_matches):
    """Shared-policy readback must accept VLAN 1 but reject real policy drift."""
    expected = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": _GROUP_NAME,
            "type": "ethernetWithPolicy",
            "networks": ["network-a"],
            "switch_interfaces": deepcopy(_ORIGINAL_MEMBERS),
        }
    )
    actual = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": _GROUP_NAME,
            "type": "ethernet",
            "networkNames": ["network-a"],
            "switchInterfaces": [{"switchId": "SN1", "interfaceNames": ["Ethernet1/10"]}],
            "interfaceCount": 1,
            "networkCount": 1,
            "policyDetails": {
                "policyType": "sharedTrunkHost",
                "policyId": "policy-1",
                "ethernetAttributes": {
                    **InterfaceGroupValidators.ethernet_with_policy_defaults(),
                    "nativeVlan": native_vlan,
                    "cdp": cdp,
                    "extraConfig": "",
                    "netflowMonitor": "",
                    "netflowSampler": "",
                },
            },
        }
    )
    orchestrator = nd_manage_interface_group.ManageInterfaceGroupOrchestrator(
        rest_send=RestSend({"fabric_name": "fabric-1", "state": "replaced", "config_actions": {"type": "resource", "deploy": False}}),
        results=Results(),
    )

    assert orchestrator._matches_expected_model(actual, expected) is expected_matches


@pytest.mark.parametrize("current_native_vlan", [None, 1, 100], ids=["current-omitted", "current-default", "current-nondefault"])
@pytest.mark.parametrize("desired_native_vlan", [None, 1, 100], ids=["desired-omitted", "desired-default", "desired-nondefault"])
def test_native_vlan_comparison_is_symmetric_and_does_not_rewrite_intent(current_native_vlan, desired_native_vlan):
    """Only VLAN 1 and omission are equivalent; explicit wire intent survives."""
    current_attributes = InterfaceGroupValidators.ethernet_with_policy_defaults()
    if current_native_vlan is not None:
        current_attributes["nativeVlan"] = current_native_vlan
    current = InterfaceGroupConfigModel.from_response(
        {
            "interfaceGroupName": _GROUP_NAME,
            "type": "ethernet",
            "policyDetails": {"policyType": "sharedTrunkHost", "ethernetAttributes": current_attributes},
        }
    )
    desired_attributes = {"adminState": True}
    if desired_native_vlan is not None:
        desired_attributes["nativeVlan"] = desired_native_vlan
    proposed = InterfaceGroupConfigModel.from_config(
        {"interfaceGroupName": _GROUP_NAME, "type": "ethernetWithPolicy", "ethernetAttributes": desired_attributes}
    )
    current_before = current.model_dump()
    proposed_before = proposed.model_dump()
    proposed_supplied_fields = set(proposed.ethernet_attributes.model_fields_set)

    prepared = proposed.prepare_for_replacement(current)
    expected_matches = (current_native_vlan or 1) == (desired_native_vlan or 1)

    assert current.get_diff(prepared, exclude_unset=False) is expected_matches
    assert prepared.get_diff(current, exclude_unset=False) is expected_matches
    assert current.model_dump() == current_before
    assert proposed.model_dump() == proposed_before
    assert proposed.ethernet_attributes.model_fields_set == proposed_supplied_fields
    wire_attributes = prepared.to_payload()["ethernetAttributes"]
    if desired_native_vlan is None:
        assert "nativeVlan" not in wire_attributes
    else:
        assert wire_attributes["nativeVlan"] == desired_native_vlan
