# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""iBGP fabric CRUD excludes settings owned by separate controller actions."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import FabricAiIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import FabricCampusIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import TelemetryEnergyManagementModel, TelemetrySettingsModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import FabricIbgpModel, IbgpTelemetrySettingsModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import ManageAiIbgpVxlanFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import ManageIbgpFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

FAMILIES = (
    pytest.param(FabricIbgpModel, ManageIbgpFabricOrchestrator, id="ibgp"),
    pytest.param(FabricAiIbgpVxlanModel, ManageAiIbgpVxlanFabricOrchestrator, id="ai-ibgp"),
)
OTHER_FAMILIES = (FabricEbgpModel, FabricAiEbgpVxlanModel, FabricExternalConnectivityModel, FabricCampusIbgpVxlanModel)


def _config(**root):
    return {"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}, **root}


def _validate_argspec(model, config):
    return ModuleArgumentSpecValidator(model.get_argument_spec()).validate({"state": "merged", "config": [deepcopy(config)]})


def _assert_unmanaged_absent(data, wire):
    assert ("alertSuspend" if wire else "alert_suspend") not in data
    telemetry = data.get("telemetrySettings" if wire else "telemetry_settings", {})
    assert ("energyManagement" if wire else "energy_management") not in telemetry


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
@pytest.mark.parametrize("patch", ({}, {"telemetry_collection": True}, {"telemetry_settings": {}}))
def test_removed_action_fields_have_no_public_options_defaults_or_serialized_state(model, orchestrator, patch):
    """Automatic and explicit telemetry creation cannot insert either removed default."""
    options = model.get_argument_spec()["config"]["options"]
    assert "alert_suspend" not in options
    assert "energy_management" not in options["telemetry_settings"]["options"]
    assert "alert_suspend" not in model.model_fields
    assert "alert_suspend" not in model.model_json_schema(by_alias=False)["properties"]
    assert "energy_management" not in IbgpTelemetrySettingsModel.model_fields
    assert "energy_management" not in IbgpTelemetrySettingsModel.model_json_schema(by_alias=False)["properties"]
    checked = _validate_argspec(model, _config(**patch))
    assert checked.error_messages == []
    configured = model.from_config(checked.validated_parameters["config"][0])
    assert configured.alert_suspend is None
    assert "alert_suspend" not in configured.model_fields_set
    if configured.telemetry_settings is not None:
        assert isinstance(configured.telemetry_settings, IbgpTelemetrySettingsModel)
        assert configured.telemetry_settings.energy_management is None
        assert "energy_management" not in configured.telemetry_settings.model_fields_set
    for data in (configured.to_payload(), configured.to_diff_dict(), configured.to_reverse_diff_dict()):
        _assert_unmanaged_absent(data, wire=True)
    for data in (configured.to_config(), configured.to_gathered_config()):
        _assert_unmanaged_absent(data, wire=False)


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
@pytest.mark.parametrize(
    "patch",
    (
        {"alert_suspend": "enabled"},
        {"alert_suspend": "disabled"},
        {"telemetry_settings": {"energy_management": {}}},
        {"telemetry_settings": {"energy_management": {"cost": 0.1}}},
        {"telemetry_settings": {"energy_management": {"cost": 1.3}}},
    ),
)
def test_argspec_and_direct_config_reject_removed_options(model, orchestrator, patch):
    """Neither generated Ansible input nor direct model input exposes writable action fields."""
    checked = _validate_argspec(model, _config(**patch))
    assert checked.unsupported_parameters
    with pytest.raises(ValidationError, match="not managed by the iBGP fabric module"):
        model.from_config(_config(**patch))


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
@pytest.mark.parametrize("patch", ({"alertSuspend": "enabled"}, {"telemetrySettings": {"energyManagement": {"cost": 1.3}}}))
def test_wire_spelling_does_not_bypass_writable_input_rejection(model, orchestrator, patch):
    """Response aliases cannot reintroduce either removed writable path."""
    with pytest.raises(ValidationError, match="not managed by the iBGP fabric module"):
        model.from_config(_config(**patch))


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
@pytest.mark.parametrize("alert,cost", (("enabled", 1.3), ("disabled", 0.1)))
def test_response_values_are_discarded_without_changing_raw_data_or_gathered_replay(model, orchestrator, alert, cost):
    """Observed action state stays in the raw response and never enters managed state."""
    proposed = model.from_config(_config(telemetry_collection=True))
    raw = proposed.to_payload()
    raw["alertSuspend"] = alert
    raw["telemetrySettings"]["energyManagement"] = {"cost": cost}
    snapshot = deepcopy(raw)
    existing = model.from_response(raw)
    assert raw == snapshot
    assert existing.alert_suspend is None
    assert existing.telemetry_settings.energy_management is None
    assert "alert_suspend" not in existing.model_fields_set
    assert "energy_management" not in existing.telemetry_settings.model_fields_set
    assert existing.get_diff(proposed, exclude_unset=False) is True
    assert existing.get_diff(proposed, exclude_unset=True) is True
    gathered = existing.to_gathered_config()
    _assert_unmanaged_absent(gathered, wire=False)
    checked = _validate_argspec(model, gathered)
    assert checked.error_messages == []
    replay = model.from_config(checked.validated_parameters["config"][0])
    assert existing.get_diff(replay, exclude_unset=False) is True
    _assert_unmanaged_absent(replay.to_payload(), wire=True)


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
def test_energy_only_response_container_does_not_materialize_managed_telemetry(model, orchestrator):
    """A response containing only removed action data cannot manufacture a CRUD diff."""
    proposed = model.from_config(_config())
    raw = proposed.to_payload()
    raw.update(alertSuspend="enabled", telemetrySettings={"energyManagement": {"cost": 1.3}})
    existing = model.from_response(raw)
    assert existing.telemetry_settings is None
    assert existing.get_diff(proposed, exclude_unset=False) is True
    assert "telemetrySettings" not in existing.to_payload()


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
def test_auto_created_shared_telemetry_and_opaque_replacement_keep_existing_fields_set_semantics(model, orchestrator):
    """The family subtype preserves automatic creation and opaque flow-mode replacement."""
    empty = model.from_config(_config())
    automatic = model.from_config(_config(telemetry_collection=True))
    assert "telemetry_settings" not in empty.model_fields_set
    assert "telemetry_settings" in automatic.model_fields_set
    assert automatic.telemetry_settings.model_fields_set == set()
    assert automatic.telemetry_settings.flow_collection.model_fields_set == set()
    raw = empty.to_payload()
    modes = {"netFlow": True, "sFlow": False}
    raw["telemetrySettings"] = {"energyManagement": {"cost": 1.3}, "flowCollection": {"flowCollectionModes": modes}}
    existing = model.from_response(raw)
    candidate = empty.prepare_for_replacement(existing)
    assert isinstance(candidate.telemetry_settings, IbgpTelemetrySettingsModel)
    assert candidate.to_payload()["telemetrySettings"]["flowCollection"]["flowCollectionModes"] == modes
    _assert_unmanaged_absent(candidate.to_payload(), wire=True)
    assert existing.get_diff(candidate, exclude_unset=False) is True


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
def test_explicit_shared_telemetry_object_cannot_bypass_energy_input_rejection(model, orchestrator):
    """Shared model instances with explicit action state remain unsupported input."""
    settings = TelemetrySettingsModel(energy_management=TelemetryEnergyManagementModel(cost=1.3))
    with pytest.raises(ValidationError, match="not managed by the iBGP fabric module"):
        model.from_config(_config(telemetry_settings=settings))


def _rest(version, state):
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(()))
    rest = RestSend({"check_mode": False, "state": state})
    rest.sender, rest.response_handler, rest.unit_test = sender, ResponseHandler(), True
    rest.controller_product_version = version
    return rest


def _run(orchestrator, backend, config, state, version):
    class RecordingOrchestrator(orchestrator):
        def query_all(self, **kwargs):
            return [deepcopy(backend["response"])] if backend["response"] is not None else []

        def create(self, model_instance, **kwargs):
            payload = model_instance.to_payload()
            _assert_unmanaged_absent(payload, wire=True)
            backend["creates"].append(deepcopy(payload))
            backend["response"] = deepcopy(payload)
            return {}

        def update(self, model_instance, **kwargs):
            payload = model_instance.to_payload()
            _assert_unmanaged_absent(payload, wire=True)
            backend["updates"].append(deepcopy(payload))
            alert = backend["response"]["alertSuspend"]
            energy = deepcopy(backend["response"]["telemetrySettings"]["energyManagement"])
            backend["response"] = deepcopy(payload)
            backend["response"]["alertSuspend"] = alert
            backend["response"]["telemetrySettings"]["energyManagement"] = energy
            return {}

    module = MockAnsibleModule()
    module.no_log_values = set()
    module.params = {"state": state, "config": [deepcopy(config)], "output_level": "normal", "ignore_errors": False}
    machine = NDStateMachine(module=module, model_orchestrator=RecordingOrchestrator(rest_send=_rest(version, state)))
    machine.manage_state()
    return machine.output.format()["changed"]


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_real_state_machine_create_omits_removed_defaults_and_reapply_is_unchanged(model, orchestrator, version, state):
    """The actual create callback receives neither disabled nor energy cost defaults."""
    backend = {"response": None, "creates": [], "updates": []}
    config = _config(telemetry_collection=True)
    assert _run(orchestrator, backend, config, state, version) is True
    assert len(backend["creates"]) == 1
    _assert_unmanaged_absent(backend["creates"][0], wire=True)
    assert _run(orchestrator, backend, config, state, version) is False
    assert backend["updates"] == []


@pytest.mark.parametrize("model,orchestrator", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_real_state_machine_ignores_action_values_and_preserves_them_during_unrelated_updates(model, orchestrator, version, state):
    """All write states send only managed settings and become idempotent after a CDP change."""
    config = _config(telemetry_collection=True)
    response = model.from_config(config).to_payload()
    response["alertSuspend"] = "enabled"
    response["telemetrySettings"]["energyManagement"] = {"cost": 1.3}
    backend = {"response": response, "updates": []}
    assert _run(orchestrator, backend, config, state, version) is False
    assert backend["updates"] == []
    config["management"]["cdp"] = not response["management"]["cdp"]
    assert _run(orchestrator, backend, config, state, version) is True
    assert backend["response"]["alertSuspend"] == "enabled"
    assert backend["response"]["telemetrySettings"]["energyManagement"]["cost"] == 1.3
    assert _run(orchestrator, backend, config, state, version) is False
    assert len(backend["updates"]) == 1


@pytest.mark.parametrize("model", OTHER_FAMILIES)
def test_other_fabric_families_keep_existing_alert_and_energy_defaults_and_input(model):
    """The iBGP-only exclusions do not change shared-base public contracts."""
    options = model.get_argument_spec()["config"]["options"]
    assert "alert_suspend" in options
    assert "energy_management" in options["telemetry_settings"]["options"]
    configured = model.from_config(_config(telemetry_settings={}))
    assert configured.to_payload()["alertSuspend"] == "disabled"
    assert configured.to_payload()["telemetrySettings"]["energyManagement"]["cost"] == 0.1
    explicit = model.from_config(_config(alert_suspend="enabled", telemetry_settings={"energy_management": {"cost": 1.3}}))
    assert explicit.to_payload()["alertSuspend"] == "enabled"
    assert explicit.to_payload()["telemetrySettings"]["energyManagement"]["cost"] == 1.3
