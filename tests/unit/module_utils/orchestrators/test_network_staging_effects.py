# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""A global native effect witness must cover writes, not just NaC candidates."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_staging_effects import NetworkStagingEffects, network_staging_request_digest
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import network_parent_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy


def _observer(*, check_mode=False):
    strategy = SimpleNamespace(fabric_name="fab1", is_parent=False, is_child=False, is_multicluster=False, is_multisite=False)
    return NetworkStagingEffects({"state": "staged", "config": [{"network_name": "EDIT"}]}, strategy, check_mode)


def _row(name, serial, **kwargs):
    return {"networkName": name, "switchId": serial, "attach": True, "status": "inSync", "ipAddress": "192.0.2." + serial[1:], **kwargs}


def _snapshot(observer, rows, names=("EDIT", "UNCHANGED")):
    definitions = [{"networkName": name, "networkType": "vxlanIbgp"} for name in names]
    observer.observe_page(
        "definitions", {"networks": definitions, "metadata": {"counts": {"total": len(definitions), "remaining": 0}}}, definitions, 0, 500, False
    )
    observer.observe_page("attachments", {"attachments": rows, "metadata": {"counts": {"total": len(rows), "remaining": 0}}}, rows, 0, 500, False, list(names))


def _sm(changed=(), before=("EDIT", "UNCHANGED")):
    return SimpleNamespace(before=[SimpleNamespace(network_name=name) for name in before], sent=[SimpleNamespace(network_name=name) for name in changed])


def test_real_pydantic_orchestrator_accepts_declared_observer_via_real_coordinator():
    params = {"fabric_name": "fab1", "state": "staged", "config": []}
    module = SimpleNamespace(params=params, check_mode=False)
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    coordinator = NetworkWorkflowCoordinator(module, strategy=strategy)
    observer = NetworkStagingEffects(params, strategy, False)
    coordinator._network_staging_effects = observer
    # Use the real Pydantic orchestrator and NDStateMachine. Only its existing
    # controller read is replaced; this regression test performs no ND I/O.
    with patch.object(NDNetworkOrchestrator, "query_all", return_value=[]):
        sm, config, state = coordinator._new_state_machine(params, strategy)
    try:
        assert isinstance(sm.model_orchestrator, NDNetworkOrchestrator)
        assert sm.model_orchestrator.staging_effects is observer
        assert "staging_effects" not in sm.model_orchestrator.model_dump()
        sm.model_orchestrator.staging_effects = None
        assert sm.model_orchestrator.staging_effects is None
    finally:
        coordinator._restore_state_machine_params(config, state)


def test_real_coordinator_binds_original_ansible_request_before_model_aliases_and_crud_rewrites():
    config = [
        {
            "network_name": "EDIT",
            "network_id": 29991,
            "vlan_id": 191,
            "vrf_name": "BLUE",
            "gw_ip_subnet": "192.0.2.1/24",
            "deploy": False,
            "attach": [
                {
                    "ip_address": "192.0.2.10",
                    "vlan_id": 191,
                    "attachment_options": {"svi_enabled": True},
                    "interfaces": [{"mode": "trunk", "interface_range": "Ethernet1/1"}],
                }
            ],
        }
    ]
    expected = network_staging_request_digest("fab1", "staged", config)
    spec = {"config": {"type": "list", "elements": "dict", "options": network_parent_argument_spec()}}
    validation = ArgumentSpecValidator(spec).validate({"config": config})
    assert not validation.error_messages
    params = {"fabric_name": "fab1", "state": "staged", "config": validation.validated_parameters["config"]}
    module = SimpleNamespace(params=params, check_mode=True)
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    coordinator = NetworkWorkflowCoordinator(module, strategy=strategy)
    assert coordinator._network_staging_request_sha256 == expected
    parsed = coordinator._parse_config(params["config"], strategy.config_model_cls, "staged")
    assert network_staging_request_digest("fab1", "staged", parsed) != expected
    with (
        patch.object(NDNetworkOrchestrator, "query_all", return_value=[]),
        patch.object(NetworkAttachmentManager, "resolve_switch_ids", return_value={"192.0.2.10": "S1"}),
    ):
        result = coordinator.run()
    assert result["network_staging_effects"]["request_sha256"] == expected
    assert result["network_staging_effects"]["observed"] is False


def test_native_svi_options_and_explicit_multicast_group_are_bounded_to_attached_switch():
    observer = _observer()
    current = [_row("EDIT", "S1", instanceValues={"sviEnabled": True, "dpuSecure": False})]
    _snapshot(observer, current)
    observer.record_payloads([{"networkName": "EDIT", "switchId": "S1", "attach": True, "instanceValues": {"svi_enabled": True}}])
    sm = _sm(changed=("EDIT",))
    sm.sent = [{"network_name": "EDIT", "l2_data": {"fabricData": {"multicastGroup": "239.1.1.0"}}}]
    result = observer.finish({"changed": True}, sm, current, {}, [])
    assert result["complete"] is True
    assert result["unknown_effects"] == []


def test_definition_update_scopes_old_new_attachments_without_unchanged_networks():
    observer = _observer()
    current = [_row("EDIT", "S1"), _row("UNCHANGED", "S3")]
    _snapshot(observer, current)
    desired = {("EDIT", "S2"): _row("EDIT", "S2")}
    observer.remember_switch(desired[("EDIT", "S2")])
    result = observer.finish({"changed": True}, _sm(changed=("EDIT",)), current, desired, [])
    assert result["complete"] is result["observed"] is True
    assert result["affected_switches"] == [{"switch_id": "S1", "management_ip": "192.0.2.1"}, {"switch_id": "S2", "management_ip": "192.0.2.2"}]
    assert result["observed_scope"] == "all_staged_attachments"
    assert result["deployment_attempts"] == 0


def test_external_omitted_network_detach_and_vpc_peer_are_in_global_scope():
    observer = _observer()
    current = [_row("EDIT", "S1"), _row("UNCHANGED", "S3", peerSwitchId="S4"), _row("UNCHANGED", "S4", peerSwitchId="S3")]
    _snapshot(observer, current)
    observer.record_payloads([{"networkName": "UNCHANGED", "switchId": "S3", "attach": False}])
    result = observer.finish({"changed": True}, _sm(), current, {}, [])
    assert result["complete"] is True
    assert [row["switch_id"] for row in result["affected_switches"]] == ["S3", "S4"]


def test_known_noop_has_positive_empty_scope_even_with_many_unchanged_attachments():
    observer = _observer()
    current = [_row("UNCHANGED", f"S{number}") for number in range(1, 201)]
    _snapshot(observer, current)
    result = observer.finish({"changed": False}, _sm(), current, {}, [])
    assert result["complete"] is result["observed"] is True
    assert result["affected_switches"] == result["unknown_effects"] == []


def test_existing_pending_attachment_is_scoped_even_without_a_new_native_write():
    observer = _observer()
    current = [_row("UNCHANGED", "S1", status="pending"), _row("UNCHANGED", "S2")]
    _snapshot(observer, current)
    result = observer.finish({"changed": False}, _sm(), current, {}, [])
    assert result["complete"] is True
    assert result["affected_switches"] == [{"switch_id": "S1", "management_ip": "192.0.2.1"}]


def test_unknown_attachment_status_does_not_prove_an_empty_effect_scope():
    observer = _observer()
    current = [_row("UNCHANGED", "S1", status="newUnknownStatus")]
    _snapshot(observer, current)
    result = observer.finish({"changed": False}, _sm(), current, {}, [])
    assert result["complete"] is False
    assert "attachment_deployment_state_unproven" in result["unknown_effects"]


@pytest.mark.parametrize("mode", ["check", "failed"])
def test_failed_or_check_mode_never_claims_observed_or_complete(mode):
    observer = _observer(check_mode=mode == "check")
    _snapshot(observer, [])
    result = observer.finish({"failed": mode == "failed"}, _sm(), [], {}, [])
    assert result["observed"] is result["complete"] is False


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"network_template_name": "custom"}, "custom_network_template"),
        ({"network_template_config": {"CUSTOM": "1"}}, "custom_network_template_config"),
        ({"l3_data": {"fabricData": {"trmEnable": True}}}, "dynamic_network_effects"),
        ({"l3_data": {"dhcpServerCollection": [{"address": "192.0.2.1"}]}}, "dynamic_network_effects"),
        ({"network_type": "userDefined"}, "unsupported_network_type"),
    ],
)
def test_custom_or_dynamic_definition_effects_fall_back(change, reason):
    observer = _observer()
    current = [_row("EDIT", "S1")]
    _snapshot(observer, current)
    sm = _sm(changed=("EDIT",))
    sm.sent[0].__dict__.update(change)
    # Real native models expose their model_fields; plain fake nested data is
    # supplied as a mapping so the same recursive observer examines it.
    sm.sent = [vars(sm.sent[0])]
    result = observer.finish({"changed": True}, sm, current, {}, [])
    assert result["complete"] is False
    assert reason in result["unknown_effects"]


def test_custom_raw_omitted_definition_is_not_hidden_by_typed_model_pruning():
    observer = _observer()
    definitions = [{"networkName": "OLD", "networkTemplateName": "custom"}]
    current = [_row("OLD", "S1")]
    observer.observe_page("definitions", {"networks": definitions}, definitions, 0, 500, False)
    observer.observe_page("attachments", {"attachments": current}, current, 0, 500, False, ["OLD"])
    observer.record_payloads([{"networkName": "OLD", "switchId": "S1", "attach": False}])
    result = observer.finish({"changed": True}, _sm(before=("OLD",)), current, {}, [])
    assert result["complete"] is False
    assert "custom_network_template" in result["unknown_effects"]


def test_missing_switch_ip_or_deployment_attempt_requires_fallback():
    observer = _observer()
    _snapshot(observer, [])
    observer.record_payloads([{"networkName": "EDIT", "switchId": "UNKNOWN", "attach": True}])
    observer.deployment_attempts = 1
    result = observer.finish({"changed": True}, _sm(), [], {}, [])
    assert result["complete"] is False
    assert "affected_switch_management_ip_unproven" in result["unknown_effects"]
    assert result["deployment_attempts"] == 1


@pytest.mark.parametrize(
    "data,more",
    [
        ({"attachments": [], "metadata": {"counts": {"remaining": 1}}}, False),
        ({"attachments": [], "metadata": {"counts": {"remaining": 1}}}, True),
        ({"attachments": [], "metadata": {"counts": {"total": "invalid"}}}, False),
        ({}, False),
        ([], False),
    ],
)
def test_unproven_attachment_pagination_cannot_claim_complete(data, more):
    observer = _observer()
    _snapshot(observer, [])
    observer.observe_page("attachments", data, [], 0, 500, more, ["EDIT"])
    assert observer.finish({}, _sm(), [], {}, [])["complete"] is False


def test_current_native_snapshot_must_cover_all_definitions_not_just_nac_candidates():
    observer = _observer()
    _snapshot(observer, [], names=("EDIT",))
    result = observer.finish({}, _sm(before=("EDIT", "OUTSIDE")), [], {}, [])
    assert result["complete"] is False
    assert "global_native_snapshot_unproven" in result["unknown_effects"]


def test_observation_never_mutates_api_rows_or_request_payloads():
    observer = _observer()
    current = [_row("EDIT", "S1")]
    payloads = [{"networkName": "EDIT", "switchId": "S1", "attach": True, "interfaces": [{"interfaceRange": "Ethernet1/1", "mode": "trunk"}]}]
    before = deepcopy((current, payloads))
    _snapshot(observer, current)
    observer.record_payloads(payloads)
    observer.finish({"changed": True}, _sm(), current, {}, [])
    assert (current, payloads) == before
