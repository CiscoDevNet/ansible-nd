# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""iBGP comparison of in-band-only telemetry sources without changing payloads."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import FabricAiIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import FabricIbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import ManageAiIbgpVxlanFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import ManageIbgpFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

FAMILIES = (
    pytest.param(FabricIbgpModel, ManageIbgpFabricOrchestrator, "vxlanIbgp", id="ibgp"),
    pytest.param(FabricAiIbgpVxlanModel, ManageAiIbgpVxlanFabricOrchestrator, "aimlVxlanIbgp", id="ai-ibgp"),
)
SOURCES = (
    ("telemetry_source_interface", "telemetrySourceInterface", "loopback99"),
    ("telemetry_source_vrf", "telemetrySourceVrf", "blue"),
)


def _config(**root):
    return {"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}, **root}


def _response(fabric_type, mode="outOfBand", interface="mgmt0", vrf="mgmt", **root):
    return {
        "name": "fabric1",
        "category": "fabric",
        "telemetryCollectionType": mode,
        "telemetrySourceInterface": interface,
        "telemetrySourceVrf": vrf,
        "management": {"type": fabric_type, "bgpAsn": "65001"},
        **root,
    }


def _rest(version, state):
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(()))
    rest = RestSend({"check_mode": False, "state": state})
    rest.sender, rest.response_handler, rest.unit_test = sender, ResponseHandler(), True
    rest.controller_product_version = version
    return rest


def _run(orchestrator, backend, config, state, version="4.3.1"):
    class RecordingOrchestrator(orchestrator):
        def query_all(self, **kwargs):
            return [deepcopy(backend["response"])]

        def update(self, model_instance, **kwargs):
            payload = model_instance.to_payload()
            backend["updates"].append(deepcopy(payload))
            backend["response"] = deepcopy(payload)
            if payload["telemetryCollectionType"] == "outOfBand":
                # Emulate the mgmt0/mgmt source echoes from targeted live diagnostics.
                backend["response"].update(telemetrySourceInterface="mgmt0", telemetrySourceVrf="mgmt")
            return {}

    module = MockAnsibleModule()
    module.no_log_values = set()
    module.params = {
        "state": state,
        "config": [deepcopy(config)],
        "output_level": "normal",
        "ignore_errors": False,
        "config_actions": {"save": False, "deploy": False},
    }
    machine = NDStateMachine(module=module, model_orchestrator=RecordingOrchestrator(rest_send=_rest(version, state)))
    machine.manage_state()
    return machine.output.format()["changed"]


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize("explicit_sources", (False, True))
def test_outofband_source_only_differences_are_ignored_even_when_explicit(model, orchestrator, fabric_type, state, explicit_sources):
    """Source controls have no comparison effect for effective out-of-band mode."""
    config = _config()
    if explicit_sources:
        config.update(telemetry_source_interface="loopback99", telemetry_source_vrf="blue")
    existing = model.from_response(_response(fabric_type))
    proposed = model.from_config(config)
    assert existing.get_diff(proposed, exclude_unset=state == "merged") is True


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("field,alias,value", SOURCES)
def test_merged_omitted_mode_uses_existing_inband_and_detects_each_source_change(model, orchestrator, fabric_type, field, alias, value):
    """The new out-of-band default cannot hide a source change to existing in-band."""
    existing = model.from_response(_response(fabric_type, mode="inBand", interface="loopback0", vrf="default"))
    proposed = model.from_config(_config(**{field: value}))
    assert proposed.telemetry_collection_type == "outOfBand"
    assert "telemetry_collection_type" not in proposed.model_fields_set
    assert existing.get_diff(proposed, exclude_unset=True) is False


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize("old_mode,new_mode", (("inBand", "outOfBand"), ("outOfBand", "inBand")))
def test_telemetry_mode_transitions_remain_changes(model, orchestrator, fabric_type, state, old_mode, new_mode):
    """Ignoring inactive source values never hides a mode transition."""
    existing = model.from_response(_response(fabric_type, mode=old_mode))
    proposed = model.from_config(_config(telemetry_collection_type=new_mode))
    assert existing.get_diff(proposed, exclude_unset=state == "merged") is False


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
def test_exact_omitted_mode_uses_outofband_default_while_merge_preserves_existing_inband(model, orchestrator, fabric_type):
    """Exact-state defaults and merged omission keep their distinct established roles."""
    existing = model.from_response(_response(fabric_type, mode="inBand", interface="loopback0", vrf="default"))
    proposed = model.from_config(_config())
    assert existing.get_diff(proposed, exclude_unset=True) is True
    assert existing.get_diff(proposed, exclude_unset=False) is False


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("exclude_unset", (False, True))
def test_outofband_still_detects_unrelated_management_changes(model, orchestrator, fabric_type, exclude_unset):
    """The comparison exception is confined to the two inactive telemetry sources."""
    existing = model.from_response(_response(fabric_type))
    config = _config()
    config["management"]["cdp"] = not existing.management.cdp
    assert existing.get_diff(model.from_config(config), exclude_unset=exclude_unset) is False


def _recursive_state(item):
    if isinstance(item, NDBaseModel):
        return (
            id(item),
            deepcopy(item.model_fields_set),
            deepcopy(item.__pydantic_private__),
            {name: _recursive_state(getattr(item, name)) for name in type(item).model_fields},
        )
    if isinstance(item, list):
        return [_recursive_state(value) for value in item]
    return deepcopy(item)


def _snapshot(item):
    return (item.to_payload(), item.to_config(), item.to_gathered_config(), item.to_diff_dict(), _recursive_state(item))


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("exclude_unset", (False, True))
def test_comparison_leaves_original_nested_models_field_sets_private_state_and_payloads_unchanged(model, orchestrator, fabric_type, exclude_unset):
    """Shallow root comparison views cannot mutate original or nested model state."""
    existing = model.from_response(_response(fabric_type, interface="loopback1", vrf="existing-vrf"))
    proposed = model.from_config(_config(telemetry_source_interface="loopback99", telemetry_source_vrf="blue"))
    orchestrator(rest_send=_rest("4.3.1", "merged" if exclude_unset else "replaced")).preflight([proposed])
    before_existing, before_proposed = _snapshot(existing), _snapshot(proposed)
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is True
    assert existing.get_diff(proposed, exclude_unset=exclude_unset) is True
    assert _snapshot(existing) == before_existing
    assert _snapshot(proposed) == before_proposed
    assert proposed.to_payload()["telemetrySourceInterface"] == "loopback99"
    assert proposed.to_payload()["telemetrySourceVrf"] == "blue"


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("exclude_unset", (False, True))
def test_comparison_type_errors_are_preserved(model, orchestrator, fabric_type, exclude_unset):
    """Cross-family and non-model arguments retain the established TypeError contract."""
    existing = model.from_response(_response(fabric_type))
    for other in (object(), FabricExternalConnectivityModel.from_config(_config())):
        with pytest.raises(TypeError, match="Cannot diff"):
            existing.get_diff(other, exclude_unset=exclude_unset)


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_state_machine_does_not_write_for_outofband_source_echoes(model, orchestrator, fabric_type, version, state):
    """The real state machine schedules no PUT for inactive-source differences."""
    backend = {"response": _response(fabric_type), "updates": []}
    config = _config(telemetry_source_interface="loopback99", telemetry_source_vrf="blue")
    assert _run(orchestrator, backend, config, state, version) is False
    assert backend["updates"] == []


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("field,alias,value", SOURCES)
def test_state_machine_merged_omitted_mode_updates_inband_sources_once(model, orchestrator, fabric_type, version, field, alias, value):
    """An existing in-band source change emits one PUT and then becomes idempotent."""
    backend = {"response": _response(fabric_type, mode="inBand", interface="loopback0", vrf="default"), "updates": []}
    config = _config(**{field: value})
    assert _run(orchestrator, backend, config, "merged", version) is True
    assert backend["updates"][0]["telemetryCollectionType"] == "inBand"
    assert backend["updates"][0][alias] == value
    assert _run(orchestrator, backend, config, "merged", version) is False
    assert len(backend["updates"]) == 1


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize("old_mode,new_mode", (("inBand", "outOfBand"), ("outOfBand", "inBand")))
def test_state_machine_mode_transition_updates_once_then_is_idempotent(model, orchestrator, fabric_type, version, state, old_mode, new_mode):
    """Both mode transitions still update and settle through the actual state machine."""
    backend = {"response": _response(fabric_type, mode=old_mode), "updates": []}
    config = _config(telemetry_collection_type=new_mode)
    assert _run(orchestrator, backend, config, state, version) is True
    assert backend["updates"][0]["telemetryCollectionType"] == new_mode
    assert _run(orchestrator, backend, config, state, version) is False
    assert len(backend["updates"]) == 1
