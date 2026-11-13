# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Authoritative Network port omissions are staged before exact reattachment."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import NetworkAttachmentConfigModel, NetworkInterfaceConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager as Attachments


def _attachment(name="BLUE", ports=("Port-channel61",)):
    return {"networkName": name, "switchId": "S1", "vlanId": 191, "attach": True, "interfaces": [{"mode": "trunk", "interfaceRange": port} for port in ports]}


def _record_attachment_phases(state, current, desired):
    names = sorted({key[0] for key in desired})
    args = {"state": state, "config": [{"network_name": name, "deploy": False} for name in names]}
    calls = []

    def reject_query(*_args, **_kwargs):
        raise AssertionError("Attachment planning must reuse the supplied observation")

    class Recorder(Attachments):
        def post_network_attachments(self, _args, _strategy, payloads, deploy_targets, operation_type):
            calls.append((operation_type, deepcopy(payloads), deepcopy(deploy_targets)))
            return {"changed": True, "payloads": payloads, "deploy_targets": deploy_targets}

        def deploy_network_attachments(self, *_args, **_kwargs):
            raise AssertionError("Attachment preparation must not deploy")

    manager = Recorder(SimpleNamespace(_new_network_orchestrator=reject_query))
    strategy = SimpleNamespace()
    pre = manager.apply_phase(args, strategy, "pre", desired, names, current, [])
    remaining = Attachments.attachment_map_after_detach(current, pre.get("payloads", []))
    manager.apply_phase(args, strategy, "post", pre.get("desired", desired), names, remaining, [])
    return calls, remaining


@pytest.mark.parametrize("state", ["staged", "replaced", "overridden"])
def test_authoritative_port_move_resets_exact_network_switch_and_preserves_shared_network(state):
    current = {("BLUE", "S1"): _attachment(), ("SHARED", "S1"): _attachment("SHARED")}
    desired = {("BLUE", "S1"): _attachment(ports=("Ethernet1/46",)), ("SHARED", "S1"): _attachment("SHARED")}
    payloads = Attachments.planned_detach_payloads(state, [{"network_name": "BLUE"}, {"network_name": "SHARED"}], current, desired)
    assert payloads == [{"networkName": "BLUE", "switchId": "S1", "vlanId": 191, "attach": False}]
    remaining = Attachments.attachment_map_after_detach(current, payloads)
    assert Attachments.planned_attach_payloads(remaining, desired) == [desired[("BLUE", "S1")]]


def test_merged_never_removes_omitted_ports():
    current = {("BLUE", "S1"): _attachment()}
    desired = {("BLUE", "S1"): _attachment(ports=("Ethernet1/46",))}
    assert Attachments.planned_detach_payloads("merged", [], current, desired) == []


def test_absent_interfaces_does_not_authorize_port_removal():
    current = {("BLUE", "S1"): _attachment()}
    desired = {("BLUE", "S1"): {"networkName": "BLUE", "switchId": "S1", "attach": True}}
    assert Attachments.planned_detach_payloads("staged", [], current, desired) == []


def test_explicit_empty_interfaces_removes_ports_but_reattaches_network_to_switch():
    current = {("BLUE", "S1"): _attachment()}
    desired = {("BLUE", "S1"): _attachment(ports=())}
    payloads = Attachments.planned_detach_payloads("staged", [], current, desired)
    assert payloads == [{"networkName": "BLUE", "switchId": "S1", "vlanId": 191, "attach": False}]
    assert Attachments.planned_attach_payloads(Attachments.attachment_map_after_detach(current, payloads), desired) == [desired[("BLUE", "S1")]]
    model = NetworkAttachmentConfigModel(ip_address="192.0.2.1", interfaces=[])
    assert model.to_config()["interfaces"] == []
    assert Attachments._attachment_interfaces({"interfaces": []}) == []
    assert Attachments._attachment_interfaces({}) is None


def test_synthesized_passive_vpc_peer_empty_interfaces_is_not_destructive_authority():
    current = {("BLUE", "S1"): _attachment()}
    desired = {("BLUE", "S1"): _attachment(ports=())}
    assert Attachments.planned_detach_payloads("staged", [], current, desired, explicit_interface_keys=set()) == []


@pytest.mark.parametrize(
    "before,after,removed",
    [
        (("Ethernet1/1-4",), ("Eth1/1", "Ethernet1/2", "Ethernet1/3", "Eth1/4"), False),
        (("Ethernet1/1-4",), ("Eth1/1-3",), True),
        (("Po61",), ("port-channel61",), False),
        (("Ethernet1/1",), ("Ethernet1/1-4",), False),
    ],
)
def test_omission_compares_bounded_canonical_range_members(before, after, removed):
    assert Attachments._has_removed_ports(_attachment(ports=before), _attachment(ports=after)) is removed


def test_ambiguous_removal_range_fails_before_any_payload_is_sent():
    current = {("BLUE", "S1"): _attachment(ports=("Unknown1-4",))}
    desired = {("BLUE", "S1"): _attachment(ports=("Ethernet1/46",))}
    with pytest.raises(ValueError, match="Cannot prove Network port omission"):
        Attachments.planned_detach_payloads("staged", [], current, desired)


@pytest.mark.parametrize("state", ["replaced", "staged"])
@pytest.mark.parametrize(
    "change",
    [
        {"mode": "access"},
        {"nativeVlan": True},
        {"mapping": {"mappingType": "single", "customerVlan": 101}},
    ],
)
def test_same_unresolved_group_target_updates_options_without_detachment(state, change):
    attachment = _attachment(ports=("group-members",))
    attachment["interfaces"][0].update(interfaceGroupName="GROUP", nativeVlan=False)
    current = {("BLUE", "S1"): attachment}
    desired = deepcopy(current)
    desired[("BLUE", "S1")]["interfaces"][0].update(change)
    before = deepcopy((current, desired))

    assert Attachments.planned_detach_payloads(state, [{"network_name": "BLUE"}], current, desired) == []
    assert Attachments.planned_attach_payloads(current, desired) == [desired[("BLUE", "S1")]]
    assert (current, desired) == before


@pytest.mark.parametrize("state", ["replaced", "staged", "overridden"])
@pytest.mark.parametrize(
    "interfaces",
    [
        [],
        [{"interfaceRange": "group-members", "interfaceGroupName": "OTHER", "mode": "trunk"}],
        [{"interfaceRange": "other-group-members", "interfaceGroupName": "GROUP", "mode": "trunk"}],
        [{"interfaceRange": "Ethernet1/46", "mode": "trunk"}],
    ],
)
def test_changed_or_removed_group_target_stages_bounded_detach_and_exact_reattach(state, interfaces):
    attachment = _attachment(ports=("group-members",))
    attachment["interfaces"][0]["interfaceGroupName"] = "GROUP"
    current = {("BLUE", "S1"): attachment, ("SHARED", "S1"): _attachment("SHARED")}
    desired = deepcopy(current)
    desired[("BLUE", "S1")]["interfaces"] = interfaces
    before = deepcopy((current, desired))
    calls, remaining = _record_attachment_phases(state, current, desired)

    assert calls == [
        (OperationType.DELETE, [{"networkName": "BLUE", "switchId": "S1", "vlanId": 191, "attach": False}], {"BLUE": {"S1"}}),
        (OperationType.CREATE, [desired[("BLUE", "S1")]], {}),
    ]
    assert remaining[("SHARED", "S1")] == current[("SHARED", "S1")]
    assert (current, desired) == before


def test_merged_explicit_group_change_updates_without_detach_or_inventing_a_union():
    attachment = _attachment(ports=("group-members",))
    attachment["interfaces"][0]["interfaceGroupName"] = "GROUP"
    current = {("BLUE", "S1"): attachment}
    desired = deepcopy(current)
    desired[("BLUE", "S1")]["interfaces"] = [{"interfaceRange": "other-group-members", "interfaceGroupName": "OTHER", "mode": "trunk"}]
    before = deepcopy((current, desired))

    assert Attachments.planned_detach_payloads("merged", [{"network_name": "BLUE"}], current, desired) == []
    assert Attachments.planned_attach_payloads(current, desired, preserve_omitted_fields=True) == [desired[("BLUE", "S1")]]
    assert (current, desired) == before


@pytest.mark.parametrize("state", ["replaced", "staged", "overridden"])
def test_added_group_preserves_existing_group_target_without_detachment(state):
    attachment = _attachment(ports=("group-members",))
    attachment["interfaces"][0]["interfaceGroupName"] = "GROUP"
    current = {("BLUE", "S1"): attachment}
    desired = deepcopy(current)
    desired[("BLUE", "S1")]["interfaces"].append({"interfaceRange": "other-group-members", "interfaceGroupName": "OTHER", "mode": "trunk"})
    before = deepcopy((current, desired))

    assert Attachments.planned_detach_payloads(state, [{"network_name": "BLUE"}], current, desired) == []
    assert Attachments.planned_attach_payloads(current, desired) == [desired[("BLUE", "S1")]]
    assert (current, desired) == before


@pytest.mark.parametrize("state", ["replaced", "staged", "overridden"])
def test_group_removal_does_not_authorize_malformed_physical_replacement(state):
    attachment = _attachment(ports=("group-members",))
    attachment["interfaces"][0]["interfaceGroupName"] = "GROUP"
    current = {("BLUE", "S1"): attachment}
    desired = {("BLUE", "S1"): _attachment(ports=("Unknown1-4",))}
    before = deepcopy((current, desired))

    with pytest.raises(ValueError, match="Cannot prove Network port omission"):
        Attachments.planned_detach_payloads(state, [{"network_name": "BLUE"}], current, desired)
    assert (current, desired) == before


@pytest.mark.parametrize("state", ["replaced", "staged", "overridden"])
@pytest.mark.parametrize(
    "old_selector,new_selector",
    [
        ("GigabitEthernet1/0/1", "GigabitEthernet1/0/3"),
        ("GigabitEthernet1/0/1/3", "GigabitEthernet1/0/1/4"),
        ("TenGigabitEthernet1/0/1-4", "TenGigabitEthernet1/0/2-4"),
    ],
)
def test_known_ios_xe_target_change_stages_exact_attachment_replacement(state, old_selector, new_selector):
    model = NetworkInterfaceConfigModel(mode="trunk", interface_range=new_selector)
    assert model.to_config()["interface_range"] == new_selector
    current = {("BLUE", "S1"): _attachment(ports=(old_selector,)), ("SHARED", "S1"): _attachment("SHARED")}
    desired = deepcopy(current)
    desired[("BLUE", "S1")]["interfaces"] = [{"mode": "trunk", "interfaceRange": new_selector}]
    before = deepcopy((current, desired))

    calls, remaining = _record_attachment_phases(state, current, desired)

    assert calls == [
        (OperationType.DELETE, [{"networkName": "BLUE", "switchId": "S1", "vlanId": 191, "attach": False}], {"BLUE": {"S1"}}),
        (OperationType.CREATE, [desired[("BLUE", "S1")]], {}),
    ]
    assert remaining[("SHARED", "S1")] == current[("SHARED", "S1")]
    assert (current, desired) == before


@pytest.mark.parametrize(
    "canonical,abbreviated",
    [
        ("GigabitEthernet1/0/1", "gi1/0/1"),
        ("GigabitEthernet1/0/1/3", "GI1/0/1/3"),
        ("TenGigabitEthernet1/0/1-4", "te1/0/1-4"),
        ("TenGigabitEthernet1/0/1", "TE1/0/1"),
    ],
)
def test_known_ios_xe_abbreviations_do_not_create_attachment_churn(canonical, abbreviated):
    current = _attachment(ports=(canonical,))
    desired = _attachment(ports=(abbreviated,))
    assert not Attachments._attachment_changed(current, desired)
    assert not Attachments._has_removed_ports(current, desired)


@pytest.mark.parametrize("state", ["replaced", "staged", "overridden"])
@pytest.mark.parametrize(
    "old_selector,new_selector,change",
    [
        ("gi1/0/1", "GigabitEthernet1/0/1", {"nativeVlan": True}),
        ("te1/0/1-4", "TenGigabitEthernet1/0/1-4", {"mode": "access"}),
    ],
)
def test_same_canonical_ios_xe_target_option_update_avoids_predetach(state, old_selector, new_selector, change):
    current = {("BLUE", "S1"): _attachment(ports=(old_selector,))}
    desired = {("BLUE", "S1"): _attachment(ports=(new_selector,))}
    desired[("BLUE", "S1")]["interfaces"][0].update(change)
    before = deepcopy((current, desired))

    calls, remaining = _record_attachment_phases(state, current, desired)

    assert calls == [(OperationType.CREATE, [desired[("BLUE", "S1")]], {})]
    assert remaining == current
    assert (current, desired) == before


@pytest.mark.parametrize("selector", ["Ethernet1/4-1", "Unknown1-4", "t1/0/1", "TenGigabitEthernet1/0/4-1"])
def test_ios_xe_support_does_not_admit_descending_unknown_or_ambiguous_selectors(selector):
    current = {("BLUE", "S1"): _attachment(ports=(selector,))}
    desired = {("BLUE", "S1"): _attachment(ports=("Ethernet1/46",))}
    before = deepcopy((current, desired))
    with pytest.raises(ValueError):
        Attachments.planned_detach_payloads("staged", [{"network_name": "BLUE"}], current, desired)
    assert (current, desired) == before


def test_real_attachment_phases_stage_detach_then_reattach_without_deployment():
    args = {"state": "staged", "config": [{"network_name": "BLUE", "deploy": False}]}
    current = {("BLUE", "S1"): _attachment()}
    desired = {("BLUE", "S1"): _attachment(ports=("Ethernet1/46",))}
    calls = []

    class Recorder(Attachments):
        def post_network_attachments(self, _args, _strategy, payloads, deploy_targets, operation_type):
            calls.append(payloads)
            return {"changed": True, "payloads": payloads, "deploy_targets": deploy_targets}

    manager = Recorder(SimpleNamespace())
    strategy = SimpleNamespace()
    pre = manager.apply_phase(args, strategy, "pre", desired, ["BLUE"], current, [])
    manager.apply_phase(args, strategy, "post", pre["desired"], ["BLUE"], Attachments.attachment_map_after_detach(current, pre["payloads"]), [])
    assert calls == [[{"networkName": "BLUE", "switchId": "S1", "vlanId": 191, "attach": False}], [desired[("BLUE", "S1")]]]
