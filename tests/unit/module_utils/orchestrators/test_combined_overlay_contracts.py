# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Canonical overlay inputs must retain staged observation and port intent."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import NetworkConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import NetworkBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import network_module_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_staging_effects import NetworkStagingEffects, network_staging_request_digest
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy


def _config(layer="layer3"):
    config = {
        "network_name": "BLUE",
        "network_id": 29991,
        "layer": layer,
        "deploy": False,
        "attach": [{"ip_address": "192.0.2.10", "interfaces": [{"mode": "trunk", "interface_range": "Ethernet1/35"}]}],
    }
    if layer != "layer2":
        config["vrf_name"] = "TENANT"
    return config


def _expanded(config):
    spec = {"config": {"type": "list", "elements": "dict", "options": network_module_argument_spec()}}
    result = ArgumentSpecValidator(spec).validate({"config": config})
    assert not result.error_messages
    return result.validated_parameters["config"]


def _strategy():
    return StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})


def _coordinator(config, state="staged"):
    params = {"fabric_name": "fab1", "state": state, "config": deepcopy(config)}
    return NetworkWorkflowCoordinator(SimpleNamespace(params=params, check_mode=False), strategy=_strategy())


@pytest.mark.parametrize("layer", ["layer2", "layer2WithVrf", "layer3"])
@pytest.mark.parametrize("netflow", [False, True])
def test_canonical_module_expansion_and_sparse_parsing_keep_original_request_binding(layer, netflow):
    raw = _config(layer)
    raw["netflow_enable"] = netflow
    if netflow:
        raw["vlan_netflow_monitor"] = "MONITOR_BLUE"
    config = [raw]
    before = deepcopy(config)
    expanded = _expanded(config)
    expected = network_staging_request_digest("fab1", "staged", config)
    assert network_staging_request_digest("fab1", "staged", expanded) == expected

    coordinator = _coordinator(expanded)
    parsed = coordinator._parse_config(expanded, NetworkConfigModel, "staged")
    assert coordinator._network_staging_request_sha256 == expected
    assert parsed[0]["layer"] == layer
    assert parsed[0]["netflow_enable"] is netflow
    assert ("vlan_netflow_monitor" in parsed[0]) is netflow
    assert "is_l2only" not in parsed[0]
    assert config == before


@pytest.mark.parametrize("removed", ["is_l2only", "vlan_nf_monitor", "rt_auto"])
def test_removed_native_aliases_are_not_restored_by_combined_request_support(removed):
    config = _config()
    config[removed] = True if removed != "vlan_nf_monitor" else "MONITOR_BLUE"
    spec = {"config": {"type": "list", "elements": "dict", "options": network_module_argument_spec()}}
    result = ArgumentSpecValidator(spec).validate({"config": [config]})
    assert result.error_messages
    assert removed in " ".join(result.error_messages)


@pytest.mark.parametrize("interfaces", [None, []])
def test_canonical_attachment_omission_and_empty_ports_reach_exact_replacement_distinctly(interfaces):
    raw = _config()
    attachment = raw["attach"][0]
    attachment.pop("interfaces")
    if interfaces is not None:
        attachment["interfaces"] = interfaces
    expanded = _expanded([raw])
    coordinator = _coordinator(expanded)
    parsed = coordinator._parse_config(expanded, NetworkConfigModel, "staged")
    manager = NetworkAttachmentManager(coordinator)
    with patch.object(manager, "resolve_switch_ids", return_value={"192.0.2.10": "TOR1"}):
        desired = manager.desired_attachment_map({"config": parsed}, coordinator.strategy)

    current = {
        ("BLUE", "TOR1"): {
            "networkName": "BLUE",
            "switchId": "TOR1",
            "attach": True,
            "interfaces": [{"mode": "trunk", "interfaceRange": "Ethernet1/35"}],
        }
    }
    payload = desired[("BLUE", "TOR1")]
    assert "vlanId" not in payload
    assert "vlanId" not in manager._validation_payload(payload)
    planned = manager.planned_detach_payloads("staged", parsed, current, desired)
    if interfaces is None:
        assert "interfaces" not in payload
        assert planned == []
    else:
        assert payload["interfaces"] == []
        assert planned == [{"networkName": "BLUE", "switchId": "TOR1", "attach": False}]
        after_detach = manager.attachment_map_after_detach(current, planned)
        assert manager.planned_attach_payloads(after_detach, desired) == [payload]

    omitted = _config()
    omitted["attach"][0].pop("interfaces")
    empty = deepcopy(omitted)
    empty["attach"][0]["interfaces"] = []
    assert network_staging_request_digest("fab1", "staged", [omitted]) != network_staging_request_digest("fab1", "staged", [empty])


@pytest.mark.parametrize("state", ["staged", "overridden"])
def test_authoritative_initial_query_observes_whole_scope_with_receipt_already_installed(state):
    config = _expanded([_config()])
    coordinator = _coordinator(config, state)
    original = deepcopy(coordinator.module.params)
    observer = NetworkStagingEffects(original, coordinator.strategy, False)
    coordinator._network_staging_effects = observer
    seen = []

    def initial_read(orchestrator, *_args, **_kwargs):
        assert orchestrator.staging_effects is observer
        assert orchestrator.rest_send.params["state"] == state
        assert orchestrator._query_scope_network_names() == []
        seen.append(orchestrator.staging_effects)
        return []

    with patch.object(NDNetworkOrchestrator, "query_all", autospec=True, side_effect=initial_read):
        state_machine, original_config, original_state = coordinator._new_state_machine(original, coordinator.strategy)
    try:
        assert seen == [observer]
        assert state_machine.model_orchestrator.staging_effects is observer
    finally:
        coordinator._restore_state_machine_params(original_config, original_state)
    assert coordinator.module.params == original


@pytest.mark.parametrize("role", ["normal", "primary", "community", "isolated"])
def test_canonical_pvlan_relationships_preserve_native_payload_but_decline_bounded_effect_receipt(role):
    config = {"network_name": "BLUE", "network_id": 29991, "vlan_id": 191, "layer": "layer2", "vlan_network_type": role}
    if role in ("community", "isolated"):
        config["primary_network_id"] = 29990
    canonical = NetworkConfigModel.from_config(_expanded([config])[0], context={"state": "staged"}).to_config(exclude_unset=True)
    coordinator = _coordinator([canonical])
    orchestrator, _results = coordinator._new_network_orchestrator(coordinator.module.params, coordinator.strategy)
    native = NetworkBaseModel.from_config(orchestrator.prepare_config_data([canonical])[0])
    payload = orchestrator._create_or_update_payload(native)
    if role in ("community", "isolated"):
        assert payload["primaryNetworkId"] == 29990
        assert payload["networkTemplateConfig"]["vlanId"] == "191"
        assert "vlanId" not in payload

    observer = NetworkStagingEffects({"config": [config]}, _strategy(), False)
    current = {"networkName": "BLUE", "switchId": "TOR1", "attach": True, "status": "inSync", "ipAddress": "192.0.2.10"}
    observer.observe_page("definitions", {"networks": [payload]}, [payload], 0, 500, False)
    observer.observe_page("attachments", {"attachments": [current]}, [current], 0, 500, False, ["BLUE"])
    state_machine = SimpleNamespace(before=[native], sent=[native])
    receipt = observer.finish({"changed": True}, state_machine, [current], {}, [])
    assert receipt["observed"] is True
    assert receipt["affected_switches"] == [{"switch_id": "TOR1", "management_ip": "192.0.2.10"}]
    assert receipt["deployment_attempts"] == 0
    if role == "normal":
        assert receipt["complete"] is True
        assert receipt["unknown_effects"] == []
    else:
        assert receipt["complete"] is False
        assert any("pvlan" in reason for reason in receipt["unknown_effects"])
