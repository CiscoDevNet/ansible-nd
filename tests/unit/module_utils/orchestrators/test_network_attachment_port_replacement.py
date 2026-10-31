# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Authoritative Network port omissions are staged before exact reattachment."""

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import NetworkAttachmentConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager as Attachments


def _attachment(name="BLUE", ports=("Port-channel61",)):
    return {"networkName": name, "switchId": "S1", "vlanId": 191, "attach": True, "interfaces": [{"mode": "trunk", "interfaceRange": port} for port in ports]}


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
