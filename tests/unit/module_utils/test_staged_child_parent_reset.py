# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""An accepted child delete must not block its parent's staged default reset."""

from copy import deepcopy
from dataclasses import replace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import InterfaceWorkflowExecutor
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceOrchestrator
from ansible_collections.cisco.nd.tests.unit.module_utils.test_interface_workflow_planner import _planner, _wire_interface

SWITCH = "SERIAL1"
PARENT = "Ethernet1/1"
CHILD = PARENT + ".10"


def _tombstone():
    return {
        "switchId": SWITCH,
        "interfaceName": CHILD,
        "interfaceType": "ethernet",
        "configData": {
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": "userDefined",
                    "templateName": "interface_delete",
                    "templateConfig": {"ReadOnlyOnEdit": True},
                },
            }
        },
    }


def _preview():
    return {
        "configurationDiffs": [
            {
                "switchId": SWITCH,
                "interfaceName": CHILD,
                "status": "success",
                "combinedConfigs": [
                    {"configType": "running", "config": f"interface {CHILD}\n  encapsulation dot1q 10\n", "lines": 2},
                    {"configType": "pending", "config": f"no interface {CHILD}\nconfigure terminal\n", "lines": 2},
                    {"configType": "expected", "config": "", "lines": 0},
                ],
            }
        ]
    }


def _advance_snapshot(snapshot):
    """Publish a new simulated inventory observation to orchestrator caches."""
    snapshot._revisions_by_switch[SWITCH] = snapshot.switch_revision(SWITCH) + 1


def _setup(monkeypatch, *, already_staged=False):
    previews, calls = [_preview()], []

    def preview(_self, payload):
        calls.append(deepcopy(payload))
        return deepcopy(previews[0])

    monkeypatch.setattr(NDBaseInterfaceOrchestrator, "_preview_interfaces", preview)
    parent = _wire_interface(PARENT, "ethernet", "routedHost", mode="routed", ip="198.51.100.1", prefix=30)
    parent["switchId"] = SWITCH
    child = _tombstone() if already_staged else _wire_interface(CHILD, "subInterface", "subinterface", mode="managed", vlanId=10)
    child["switchId"] = SWITCH
    planner, _recorder = _planner(switches={"192.0.2.1": SWITCH}, responses=[{"interfaces": [parent, child]}])
    plan = planner.plan([{"type": "subinterface_managed", "state": "deleted", "config": [{"switch_ip": "192.0.2.1", "interface_name": CHILD}]}])
    executor = InterfaceWorkflowExecutor(snapshot=planner.snapshot, deploy=False)
    executor._build_items(plan)
    if not already_staged:
        resource = plan.resources[0]
        executor._item(resource, "delete", next(iter(resource.operations.deletes))).status = "succeeded"
    planner.snapshot._interfaces_by_switch[SWITCH][CHILD.casefold()] = _tombstone()
    ethernet = EthernetTrunkHostInterfaceOrchestrator(
        rest_send=plan.resources[0].orchestrator.rest_send,
        interface_state_snapshot=planner.snapshot,
    )
    return planner, plan, executor, ethernet, previews, calls


def test_fresh_accepted_child_delete_uses_one_preview_for_repeated_parent_checks(monkeypatch):
    _planner_, plan, executor, ethernet, _previews, calls = _setup(monkeypatch)
    checker = executor._staged_child_delete_resolver(plan)
    with ethernet.staged_child_deletion_context(checker):
        assert not ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
        assert not ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
    assert len(calls) == 1
    assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)


def test_retry_uses_exact_planning_proof_without_new_delete_or_preview(monkeypatch):
    _planner_, plan, executor, ethernet, _previews, calls = _setup(monkeypatch, already_staged=True)
    assert plan.logical_staged_deletions
    assert not executor._items
    assert len(calls) == 1
    with ethernet.staged_child_deletion_context(executor._staged_child_delete_resolver(plan)):
        assert not ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
    assert len(calls) == 1


@pytest.mark.parametrize("status", ["failed", "not_attempted"])
def test_unaccepted_child_delete_cannot_authorize_a_parent_reset(monkeypatch, status):
    _planner_, plan, executor, ethernet, _previews, calls = _setup(monkeypatch)
    executor._items[0].status = status
    with ethernet.staged_child_deletion_context(executor._staged_child_delete_resolver(plan)):
        assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
    assert calls == []


@pytest.mark.parametrize("bad_preview", ["wrong_pending", "extra_pending", "wrong_target", "nonempty_expected"])
def test_child_tombstone_requires_exact_scoped_removal_preview(monkeypatch, bad_preview):
    _planner_, plan, executor, ethernet, previews, calls = _setup(monkeypatch)
    row = previews[0]["configurationDiffs"][0]
    if bad_preview == "wrong_pending":
        row["combinedConfigs"][1]["config"] = "no interface Ethernet1/1.11\n"
    elif bad_preview == "extra_pending":
        row["combinedConfigs"][1]["config"] += "interface Ethernet1/2\nshutdown\n"
    elif bad_preview == "wrong_target":
        row["switchId"] = "OTHER"
    else:
        row["combinedConfigs"][2].update(config="interface Ethernet1/1.10\n", lines=1)
    with ethernet.staged_child_deletion_context(executor._staged_child_delete_resolver(plan)):
        assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
    assert len(calls) == 1


def test_bool_only_tombstone_acceptance_does_not_replace_strict_logical_proof(monkeypatch):
    planner, plan, executor, ethernet, _previews, _calls = _setup(monkeypatch)
    # Legacy replay classification accepts this shape, but strict publication
    # refuses its unknown policy field. That cannot authorize a parent reset.
    row = planner.snapshot._interfaces_by_switch[SWITCH][CHILD.casefold()]
    row["configData"]["networkOS"]["policy"]["unexpectedField"] = True
    with ethernet.staged_child_deletion_context(executor._staged_child_delete_resolver(plan)):
        assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)


def test_changed_observation_revalidates_and_live_recreation_blocks(monkeypatch):
    planner, plan, executor, ethernet, _previews, calls = _setup(monkeypatch)
    checker = executor._staged_child_delete_resolver(plan)
    with ethernet.staged_child_deletion_context(checker):
        assert not ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
        row = planner.snapshot._interfaces_by_switch[SWITCH][CHILD.casefold()]
        row["operData"] = {"operationalStatus": "down"}
        _advance_snapshot(planner.snapshot)
        assert not ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
        assert len(calls) == 2
        row["interfaceType"] = "subInterface"
        row["configData"]["networkOS"]["policy"] = {"policyType": "subinterface", "vlanId": 10}
        _advance_snapshot(planner.snapshot)
        assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)


@pytest.mark.parametrize("mismatch", ["switch", "name", "extra_live_sibling"])
def test_proof_never_hides_wrong_identity_or_additional_children(monkeypatch, mismatch):
    planner, plan, executor, ethernet, _previews, _calls = _setup(monkeypatch)
    rows = planner.snapshot._interfaces_by_switch[SWITCH]
    if mismatch == "switch":
        rows[CHILD.casefold()]["switchId"] = "OTHER"
    elif mismatch == "name":
        rows[CHILD.casefold()]["interfaceName"] = "Ethernet1/1.11"
    else:
        rows["ethernet1/1.11"] = dict(_wire_interface("Ethernet1/1.11", "subInterface", "subinterface"), switchId=SWITCH)
    with ethernet.staged_child_deletion_context(executor._staged_child_delete_resolver(plan)):
        assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)


def test_workflow_scope_covers_auxiliary_ethernet_sources_and_expires_on_error(monkeypatch):
    _planner_, plan, executor, ethernet, _previews, calls = _setup(monkeypatch)
    plan = replace(plan, auxiliary_orchestrators=(ethernet,))

    def fail_after_validating(_plan):
        assert not ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
        raise RuntimeError("simulated reset failure")

    monkeypatch.setattr(executor, "_flush_ethernet_remove_queues", fail_after_validating)
    with pytest.raises(RuntimeError, match="simulated reset failure"):
        executor._flush_ethernet_removes(plan)
    assert len(calls) == 1
    assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)


@pytest.mark.parametrize("workflow_authorized", [False, True])
def test_routed_residue_correction_stages_only_under_proven_child_delete(monkeypatch, workflow_authorized):
    planner, plan, executor, ethernet, _previews, calls = _setup(monkeypatch)
    defaults = InterfaceDefaultConfig.to_reset_payload(PARENT, SWITCH)
    current = deepcopy(defaults)
    current["configData"]["networkOS"]["policy"].update(ip="198.51.100.1", prefix="30", routingTag="400")
    planner.snapshot._interfaces_by_switch[SWITCH][PARENT.casefold()] = current
    monkeypatch.setattr(planner.snapshot, "refresh", lambda _ids: _advance_snapshot(planner.snapshot))
    monkeypatch.setattr(ethernet, "_check_port_channel_delete_restriction", lambda *_a, **_k: None)
    monkeypatch.setattr(ethernet, "_check_fabric_ownership", lambda *_a, **_k: None)
    monkeypatch.setattr(ethernet, "_fabric_link_endpoints", set)
    monkeypatch.setattr(ethernet, "_retain_reset_auto_negotiation", lambda *_a, **_k: False)
    writes = []

    def put(**kwargs):
        assert kwargs["verb"] == HttpVerbEnum.PUT
        assert kwargs["data"] == defaults
        writes.append(kwargs)
        planner.snapshot._interfaces_by_switch[SWITCH][PARENT.casefold()] = deepcopy(defaults)
        return {"status": "success"}

    monkeypatch.setattr(ethernet, "_request", put)
    if not workflow_authorized:
        with pytest.raises(RuntimeError, match="child subinterfaces"):
            ethernet._correct_normalized_routed_residue([(PARENT, SWITCH)])
        assert writes == []
        assert calls == []
        return
    with ethernet.staged_child_deletion_context(executor._staged_child_delete_resolver(plan)):
        result = ethernet._correct_normalized_routed_residue([(PARENT, SWITCH)])
    assert result == [{"status": "success"}]
    assert len(writes) == len(calls) == 1
    assert CHILD.casefold() in planner.snapshot._interfaces_by_switch[SWITCH]
    assert ethernet._has_blocking_child_subinterfaces(PARENT, SWITCH)
