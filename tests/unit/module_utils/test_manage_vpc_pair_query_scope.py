# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Scoped vPC writes keep complete membership while enriching affected pairs."""

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import query
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import VpcPairResourceError

from .vpc_query_scope_fakes import VpcController, config_for, make_machine, make_module, pair, patch_controller


def _read(module):
    return query.custom_vpc_query_all(SimpleNamespace(module=module))


def _key(value):
    return frozenset((value.get("switchId", value.get("switch_id")), value.get("peerSwitchId", value.get("peer_switch_id"))))


@pytest.mark.parametrize("state", ["merged", "replaced"])
@pytest.mark.parametrize("count", [1, 3, 10])
def test_explicit_pair_detail_get_count_is_independent_of_fabric_size(monkeypatch, state, count):
    pairs = [pair(number, virtual=bool(number % 2)) for number in range(count)]
    controller = VpcController(pairs, page_size=2)
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(pairs[0])], state=state)

    result = _read(module)

    assert [_key(value) for value in result] == [_key(pairs[0])]
    assert {_key(value) for value in module.params["_have"]} == {_key(value) for value in pairs}
    assert controller.detail_serials == [pairs[0]["switchId"]]
    assert controller.overview_serials == []
    assert controller.writes == []


@pytest.mark.parametrize("state", ["merged", "replaced"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("physical", [False, True], ids=["preprovisioned", "physical"])
def test_unrelated_unreadable_pair_cannot_block_requested_noop(monkeypatch, state, check_mode, physical):
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs, page_size=1, physical=physical)
    controller.failures.add(pairs[2]["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(pairs[0], mode=False)], state=state, check_mode=check_mode, verify=True)

    machine = make_machine(module)
    machine.manage_state(state, module.params["config"])
    machine.add_logs_and_outputs()

    assert machine.result["changed"] is False
    assert len(machine.result["before"]) == len(machine.result["after"]) == 1
    assert len(module.params["_have"]) == 3
    assert controller.detail_serials == [pairs[0]["switchId"]]
    assert controller.writes == []


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_required_unreadable_pair_fails_before_any_mutation(monkeypatch, state, check_mode):
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs)
    controller.failures.add(pairs[0]["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(pairs[0], mode=True)], state=state, check_mode=check_mode)

    with pytest.raises(NDStateMachineError) as caught:
        make_machine(module)

    message = str(caught.value)
    assert "scope-fabric" in message
    assert pairs[0]["switchId"] in message
    assert pairs[0]["peerSwitchId"] in message
    assert "controller diagnostics" not in message
    assert controller.writes == []


@pytest.mark.parametrize("state", ["merged", "replaced"])
@pytest.mark.parametrize("use_ips", [False, True])
def test_full_membership_prevents_repairing_member_from_unenriched_later_page(monkeypatch, state, use_ips):
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs, page_size=1, extra_switches=("UNPAIRED-EXTRA",))
    controller.failures.add(pairs[2]["switchId"])
    patch_controller(monkeypatch, controller)
    # Request the second member of a pair whose full details are unrelated to
    # this proposed identity. The intended identity itself must remain visible.
    desired = {"switch_id": "UNPAIRED-EXTRA", "peer_switch_id": pairs[2]["peerSwitchId"]}
    if use_ips:
        desired = {"switch_id": "198.51.100.1", "peer_switch_id": "192.0.2.6"}
    module = make_module([desired], state=state)
    machine = make_machine(module)

    with pytest.raises(VpcPairResourceError, match="Switch conflicts detected"):
        machine.manage_state(state, module.params["config"])

    assert len(module.params["_have"]) == 3
    assert pairs[2]["switchId"] not in controller.detail_serials
    assert controller.writes == []


@pytest.mark.parametrize("use_ips", [False, True])
def test_reverse_order_and_ip_normalization_keep_existing_virtual_pair(monkeypatch, use_ips):
    pairs = [pair(number, virtual=True) for number in range(3)]
    controller = VpcController(pairs, page_size=1)
    patch_controller(monkeypatch, controller)
    desired = config_for(pairs[2], reverse=True)
    if use_ips:
        desired = {"switch_id": "192.0.2.6", "peer_switch_id": "192.0.2.5"}
    module = make_module([desired])
    machine = make_machine(module)

    machine.manage_state("merged", module.params["config"])
    machine.add_logs_and_outputs()

    assert machine.result["changed"] is False
    assert machine.result["after"][0]["use_virtual_peer_link"] is True
    assert controller.detail_serials == [pairs[2]["switchId"]]
    assert controller.writes == []


@pytest.mark.parametrize("check_mode", [False, True])
def test_merged_update_keeps_affected_custom_details_and_refresh_scope(monkeypatch, check_mode):
    details = {"type": "custom", "templateName": "retained-vpc-template", "templateConfig": {"peer1Port": "Ethernet1/11", "peer2Port": "Ethernet1/12"}}
    pairs = [pair(0, virtual=True, details=details), pair(1)]
    controller = VpcController(pairs)
    controller.failures.add(pairs[1]["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(pairs[0], mode=False)], check_mode=check_mode, verify=True)
    machine = make_machine(module)

    machine.manage_state("merged", module.params["config"])
    machine.add_logs_and_outputs()

    assert machine.result["changed"] is True
    assert len(machine.result["before"]) == len(machine.result["after"]) == 1
    assert machine.proposed_config["vpcPairDetails"] == details
    assert machine.proposed_config["useVirtualPeerLink"] is False
    assert controller.detail_serials == [pairs[0]["switchId"]] * (1 if check_mode else 2)
    if check_mode:
        assert controller.writes == []
    else:
        assert len(controller.writes) == 1
        assert controller.writes[0][2]["vpcPairDetails"] == details


def test_post_write_required_detail_failure_reports_accepted_change(monkeypatch):
    pairs = [pair(0, virtual=True), pair(1)]
    controller = VpcController(pairs)
    controller.fail_after_write.add(pairs[0]["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(pairs[0], mode=False)], verify=True)
    machine = make_machine(module)
    machine.manage_state("merged", module.params["config"])

    with pytest.raises(VpcPairResourceError, match="Failed to refresh final after-state") as caught:
        machine.add_logs_and_outputs()

    assert caught.value.details["changed"] is True
    assert len(controller.writes) == 1
    assert next(value for value in controller.pairs if _key(value) == _key(pairs[0]))["useVirtualPeerLink"] is False
    assert machine.logs[0]["status"] == "updated"


def test_empty_overridden_keeps_every_removal_candidate(monkeypatch):
    pairs = [pair(number, virtual=bool(number % 2)) for number in range(3)]
    controller = VpcController(pairs, page_size=1)
    patch_controller(monkeypatch, controller)
    module = make_module([], state="overridden")
    machine = make_machine(module)

    machine.manage_state("overridden", [])
    machine.add_logs_and_outputs()

    assert controller.detail_serials == [value["switchId"] for value in pairs]
    assert {_key(call[2]) for call in controller.writes} == {_key(value) for value in pairs}
    assert all(call[2]["vpcAction"] == "unPair" for call in controller.writes)
    assert controller.pairs == []
    assert len(machine.result["deleted"]) == 3


@pytest.mark.parametrize("filtered", [False, True])
def test_gathered_retains_full_and_filtered_detail_scope(monkeypatch, filtered):
    pairs = [pair(number, virtual=True) for number in range(3)]
    controller = VpcController(pairs, page_size=1)
    patch_controller(monkeypatch, controller)
    module = make_module(state="gathered")
    if filtered:
        module.params["_gather_filter_config"] = [config_for(pairs[2], reverse=True)]

    result = _read(module)

    expected = pairs[-1:] if filtered else pairs
    assert [_key(value) for value in result] == [_key(value) for value in expected]
    assert all(value["useVirtualPeerLink"] is True for value in result)
    assert controller.detail_serials == [value["switchId"] for value in expected]
    assert controller.writes == []


@pytest.mark.parametrize("list_available", [False, True])
def test_targeted_delete_keeps_staged_recovery_without_full_detail_reads(monkeypatch, list_available):
    pairs = [pair(0), pair(1)]
    controller = VpcController(pairs[1:])
    controller.list_failure = not list_available
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(pairs[0])], state="deleted")

    result = _read(module)

    assert [_key(value) for value in result] == [_key(pairs[0])]
    assert controller.detail_serials == []
    assert controller.overview_serials == []
    assert controller.writes == []


@pytest.mark.parametrize("state", ["merged", "replaced"])
@pytest.mark.parametrize("save,deploy", [(False, False), (True, False), (True, True)])
def test_empty_write_config_preserves_full_query_and_save_deploy_scope(monkeypatch, state, save, deploy):
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs)
    controller.pending_switches.add(pairs[2]["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([], state=state, save=save, deploy=deploy)

    result = _read(module)

    assert {_key(value) for value in result} == {_key(value) for value in pairs}
    assert controller.detail_serials == [value["switchId"] for value in pairs]
    assert controller.overview_serials == ([value["switchId"] for value in pairs] if save or deploy else [])
    assert {_key(value) for value in module.params["_not_in_sync_pairs"]} == ({_key(pairs[2])} if save or deploy else set())
    assert controller.writes == []


@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_scoped_write_does_not_narrow_fabric_save_deploy_sync_checks(monkeypatch, state):
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs)
    controller.pending_switches.add(pairs[2]["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(pairs[0])], state=state, save=True)

    result = _read(module)

    assert [_key(value) for value in result] == [_key(pairs[0])]
    assert controller.detail_serials == [pairs[0]["switchId"]]
    assert controller.overview_serials == [value["switchId"] for value in pairs]
    assert {_key(value) for value in module.params["_not_in_sync_pairs"]} == {_key(pairs[2])}
    assert controller.writes == []


def test_merged_write_does_not_assume_list_mode_alone_is_complete_configuration(monkeypatch):
    observed = pair(0, virtual=True)
    controller = VpcController([observed], list_mode=True)
    controller.failures.add(observed["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(observed, mode=False)])

    with pytest.raises(VpcPairResourceError) as caught:
        _read(module)

    assert "vpcPairDetails" in str(caught.value)
    assert "scope-fabric" in str(caught.value)
    assert controller.writes == []


@pytest.mark.parametrize("state,config_present", [("merged", False), ("replaced", True), ("overridden", True)])
def test_nonmerging_and_empty_write_keep_known_mode_fallback(monkeypatch, state, config_present):
    observed = pair(0, virtual=True)
    controller = VpcController([observed], list_mode=True)
    controller.failures.add(observed["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(observed)] if config_present else [], state=state)

    result = _read(module)

    assert result[0]["useVirtualPeerLink"] is True
    assert _key(result[0]) == _key(observed)
    assert controller.writes == []


@pytest.mark.parametrize("details", [None, {"type": "custom", "templateName": "existing", "templateConfig": {"peer": "preserved"}}])
def test_explicit_complete_list_fallback_preserves_custom_or_null_details(monkeypatch, details):
    observed = pair(0, virtual=True)
    observed["vpcPairDetails"] = details
    controller = VpcController([observed], list_mode=True, list_details=True)
    controller.failures.add(observed["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([config_for(observed)])

    result = _read(module)

    assert result[0]["useVirtualPeerLink"] is True
    assert "vpcPairDetails" in result[0]
    assert result[0]["vpcPairDetails"] == details
    assert controller.writes == []


def test_gathered_keeps_legacy_mode_only_fallback_for_unavailable_details(monkeypatch):
    observed = pair(0, virtual=True)
    controller = VpcController([observed], list_mode=True)
    controller.failures.add(observed["switchId"])
    patch_controller(monkeypatch, controller)

    result = _read(make_module(state="gathered"))

    assert result[0]["useVirtualPeerLink"] is True
    assert _key(result[0]) == _key(observed)
    assert controller.writes == []


@pytest.mark.parametrize("empty_config", [False, True])
def test_overridden_cannot_skip_unreadable_omitted_removal_candidate(monkeypatch, empty_config):
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs)
    controller.failures.add(pairs[2]["switchId"])
    patch_controller(monkeypatch, controller)
    module = make_module([] if empty_config else [config_for(pairs[0])], state="overridden")

    with pytest.raises(VpcPairResourceError):
        _read(module)

    assert controller.detail_serials == [value["switchId"] for value in pairs]
    assert controller.writes == []


def test_deleted_does_not_reconstruct_pair_whose_member_has_a_new_peer(monkeypatch):
    observed = pair(0)
    controller = VpcController([observed])
    patch_controller(monkeypatch, controller)
    module = make_module([{"switch_id": observed["peerSwitchId"], "peer_switch_id": "OLD-PEER"}], state="deleted")

    assert _read(module) == []
    assert controller.detail_serials == []
    assert controller.writes == []
    module.warn.assert_called()


@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_new_disjoint_pair_can_be_created_while_other_details_are_unreadable(monkeypatch, state):
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs, extra_switches=("NEW-PAIR-A", "NEW-PAIR-B"))
    controller.failures.update(value["switchId"] for value in pairs)
    patch_controller(monkeypatch, controller)
    desired = {"switch_id": "NEW-PAIR-A", "peer_switch_id": "NEW-PAIR-B", "use_virtual_peer_link": False}
    module = make_module([desired], state=state, verify=True)
    machine = make_machine(module)

    machine.manage_state(state, module.params["config"])
    machine.add_logs_and_outputs()

    assert machine.result["changed"] is True
    assert machine.result["before"] == []
    assert len(machine.result["after"]) == 1
    assert len(controller.writes) == 1
    assert controller.writes[0][2]["switchId"] == "NEW-PAIR-A"
    assert not set(controller.detail_serials) & {value["switchId"] for value in pairs}


@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_incomplete_low_level_selector_conservatively_keeps_full_scope(monkeypatch, state):
    # Public module validation rejects incomplete write pairs. A direct query
    # caller still must never narrow an uncertain selector to an empty fabric.
    pairs = [pair(number) for number in range(3)]
    controller = VpcController(pairs)
    patch_controller(monkeypatch, controller)
    module = make_module([{"switch_id": pairs[0]["switchId"]}], state=state)

    result = _read(module)

    assert {_key(value) for value in result} == {_key(value) for value in pairs}
    assert controller.detail_serials == [value["switchId"] for value in pairs]
    assert controller.writes == []
