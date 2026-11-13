# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Required telemetry wire shape without changing public or comparison state."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    TelemetryFlowCollectionModel,
    TelemetryNasModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
)

FABRIC_MODELS = (
    pytest.param(FabricIbgpModel, id="ibgp"),
    pytest.param(FabricAiIbgpVxlanModel, id="ai-ibgp"),
    pytest.param(FabricEbgpModel, id="ebgp"),
    pytest.param(FabricAiEbgpVxlanModel, id="ai-ebgp"),
    pytest.param(FabricExternalConnectivityModel, id="external"),
    pytest.param(FabricCampusIbgpVxlanModel, id="campus"),
)


def _config(**patch) -> dict:
    return {
        "fabric_name": "fabric1",
        "management": {"bgp_asn": "65001"},
        **deepcopy(patch),
    }


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
def test_absent_telemetry_container_stays_absent(model_class):
    """An unrelated fabric operation must not materialize telemetry settings."""
    model = model_class.from_config(_config())
    assert model.telemetry_settings is None
    assert "telemetrySettings" not in model.to_payload()
    assert "telemetrySettings" not in model.to_diff_dict()
    assert "telemetry_settings" not in model.to_config()
    assert "telemetry_settings" not in model.to_gathered_config()


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
@pytest.mark.parametrize(
    "patch",
    (
        {"telemetry_settings": {}},
        {"telemetry_settings": {"flow_collection": {}}},
        {"telemetry_collection": True},
    ),
    ids=("provided-settings", "provided-flow", "auto-created-settings"),
)
def test_materialized_telemetry_supplies_required_object_only_on_payload(model_class, patch):
    """Provided or auto-created telemetry has the required API object and no public addition."""
    model = model_class.from_config(_config(**patch))
    flow = model.telemetry_settings.flow_collection
    original_extra = deepcopy(flow.model_extra)
    original_fields = set(flow.model_fields_set)

    payload = model.to_payload()
    flow_payload = payload["telemetrySettings"]["flowCollection"]
    assert flow_payload["flowCollectionModes"] == {}
    assert flow_payload["trafficAnalytics"] == "disabled"
    assert "flowCollectionModes" not in model.to_diff_dict()["telemetrySettings"]["flowCollection"]
    assert "flowCollectionModes" not in model.to_config()["telemetry_settings"]["flow_collection"]
    assert "flowCollectionModes" not in model.to_gathered_config()["telemetry_settings"]["flow_collection"]
    assert flow.model_extra == original_extra
    assert flow.model_fields_set == original_fields

    # A caller modifying an exported dictionary must not alter model state or
    # another export's independently supplied required object.
    flow_payload["flowCollectionModes"]["netFlow"] = True
    assert model.to_payload()["telemetrySettings"]["flowCollection"]["flowCollectionModes"] == {}
    options = model_class.get_argument_spec()["config"]["options"]["telemetry_settings"]["options"]["flow_collection"]["options"]
    assert "flow_collection_modes" not in options
    assert "flowCollectionModes" not in options


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
@pytest.mark.parametrize(
    "modes",
    (
        {},
        {"netFlow": True, "sFlow": False, "flowTelemetry": False},
        {"netFlow": False, "sFlow": True, "flowTelemetry": True},
    ),
    ids=("empty", "netflow", "mixed-flags"),
)
def test_replacement_preserves_existing_opaque_flow_modes(model_class, modes):
    """Required payload completion must not overwrite controller-returned mode choices."""
    response = model_class.from_config(_config()).to_payload()
    response["telemetrySettings"] = {
        "flowCollection": {
            "trafficAnalytics": "disabled",
            "flowCollectionModes": deepcopy(modes),
        }
    }
    original_response = deepcopy(response)
    existing = model_class.from_response(response)
    proposed = model_class.from_config(_config())
    candidate = proposed.prepare_for_replacement(existing)
    assert response == original_response
    assert candidate.to_payload()["telemetrySettings"]["flowCollection"]["flowCollectionModes"] == modes
    assert existing.to_payload()["telemetrySettings"]["flowCollection"]["flowCollectionModes"] == modes
    for exported in (candidate.to_config(), candidate.to_gathered_config()):
        assert "flowCollectionModes" not in exported["telemetry_settings"]["flow_collection"]
    # An explicitly preserved value is allowed to remain in diff data; the
    # serializer must never inject or change that comparison value.
    assert candidate.to_diff_dict()["telemetrySettings"]["flowCollection"]["flowCollectionModes"] == modes
    assert existing.get_diff(candidate, exclude_unset=False) is True


@pytest.mark.parametrize("mode", (None, "config", "diff", "payload"))
def test_flow_serializer_context_boundary(mode):
    """Only the actual payload context receives a synthetic required object."""
    flow = TelemetryFlowCollectionModel()
    data = flow.model_dump(by_alias=True, context={"mode": mode} if mode else None)
    assert ("flowCollectionModes" in data) is (mode == "payload")
    assert "flowCollectionModes" not in (flow.model_extra or {})


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
@pytest.mark.parametrize(
    "patch",
    (
        {"telemetry_settings": {}},
        {"telemetry_collection": True},
        {"telemetry_settings": {"flow_collection": {"traffic_analytics": "disabled"}}},
        {"telemetry_settings": {"nas": None}},
    ),
    ids=("provided-settings", "auto-settings", "flow-settings", "explicit-null"),
)
def test_unsupplied_nas_is_not_injected_into_other_telemetry_settings(model_class, patch):
    """Unconfigured optional NAS state must not become an empty server request."""
    model = model_class.from_config(_config(**patch))
    assert model.telemetry_settings is not None
    assert model.telemetry_settings.nas is None
    assert "nas" not in model.to_payload()["telemetrySettings"]
    assert "nas" not in model.to_diff_dict()["telemetrySettings"]
    assert "nas" not in model.to_config()["telemetry_settings"]
    assert "nas" not in model.to_gathered_config()["telemetry_settings"]


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
def test_explicit_nas_configuration_retains_its_public_name_and_payload(model_class):
    """Keep explicit NAS configuration shape without claiming a live provider exists."""
    supplied = {
        "server": "configured-storage-name",
        "export_settings": {"export_type": "base", "export_format": "json"},
    }
    model = model_class.from_config(_config(telemetry_settings={"nas": supplied}))
    assert isinstance(model.telemetry_settings.nas, TelemetryNasModel)
    assert model.to_payload()["telemetrySettings"]["nas"] == {
        "server": "configured-storage-name",
        "exportSettings": {"exportType": "base", "exportFormat": "json"},
    }
    assert model.to_config()["telemetry_settings"]["nas"] == supplied


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
def test_optional_nas_response_and_gathered_shape_round_trip(model_class):
    """Response parsing keeps omitted NAS absent and populated NAS typed/replayable."""
    response = model_class.from_config(_config()).to_payload()
    response["telemetrySettings"] = {"flowCollection": {"trafficAnalytics": "enabled"}}
    without_nas = model_class.from_response(deepcopy(response))
    assert without_nas.telemetry_settings.nas is None
    assert "nas" not in without_nas.to_payload()["telemetrySettings"]

    response["telemetrySettings"]["nas"] = {
        "server": "configured-storage-name",
        "exportSettings": {"exportType": "base", "exportFormat": "json"},
    }
    existing = model_class.from_response(deepcopy(response))
    assert isinstance(existing.telemetry_settings.nas, TelemetryNasModel)
    assert existing.telemetry_settings.nas.server == "configured-storage-name"
    gathered = existing.to_gathered_config()
    options = model_class.get_argument_spec()
    validation = ModuleArgumentSpecValidator(options).validate({"state": "merged", "config": [gathered]})
    assert validation.error_messages == []
    assert not validation.unsupported_parameters
    replay = model_class.from_config(gathered)
    assert replay.to_payload()["telemetrySettings"]["nas"] == response["telemetrySettings"]["nas"]
    nas_option = options["config"]["options"]["telemetry_settings"]["options"]["nas"]
    assert nas_option["type"] == "dict"
    assert not nas_option.get("required", False)
    assert "default" not in nas_option
    assert nas_option["options"]["server"]["type"] == "str"


def test_explicit_nas_object_retains_existing_child_defaults():
    """Changing the parent default does not invent new explicit-NAS validation rules."""
    model = FabricIbgpModel.from_config(_config(telemetry_settings={"nas": {}}))
    assert isinstance(model.telemetry_settings.nas, TelemetryNasModel)
    assert model.telemetry_settings.nas.server == ""
    assert model.to_payload()["telemetrySettings"]["nas"]["server"] == ""


@pytest.mark.parametrize("model_class", (FabricEbgpModel, FabricAiEbgpVxlanModel, FabricExternalConnectivityModel, FabricCampusIbgpVxlanModel))
@pytest.mark.parametrize(
    "patch",
    (
        {"telemetry_collection": True},
        {"telemetry_settings": {}},
        {"telemetry_settings": {"energy_management": {}}},
    ),
    ids=("auto-telemetry", "provided-telemetry", "provided-energy"),
)
def test_omitted_energy_cost_uses_formal_default_instead_of_api_example(model_class, patch):
    """The declared/live 0.1 default applies when telemetry materializes without a cost."""
    model = model_class.from_config(_config(**patch))
    assert model.telemetry_settings.energy_management.cost == 0.1
    assert model.to_payload()["telemetrySettings"]["energyManagement"]["cost"] == 0.1
    assert model.to_config()["telemetry_settings"]["energy_management"]["cost"] == 0.1
    assert model.to_gathered_config()["telemetry_settings"]["energy_management"]["cost"] == 0.1


@pytest.mark.parametrize("model_class", (FabricEbgpModel, FabricAiEbgpVxlanModel, FabricExternalConnectivityModel, FabricCampusIbgpVxlanModel))
@pytest.mark.parametrize("cost", (0.0, 1.2, 1.3))
def test_explicit_energy_cost_serialization_is_preserved(model_class, cost):
    """Default correction must not replace explicit values; live write acceptance is separate."""
    model = model_class.from_config(_config(telemetry_settings={"energy_management": {"cost": cost}}))
    assert model.to_payload()["telemetrySettings"]["energyManagement"]["cost"] == cost
    assert model.to_config()["telemetry_settings"]["energy_management"]["cost"] == cost
    assert model.to_gathered_config()["telemetry_settings"]["energy_management"]["cost"] == cost


@pytest.mark.parametrize("model_class", (FabricEbgpModel, FabricAiEbgpVxlanModel, FabricExternalConnectivityModel, FabricCampusIbgpVxlanModel))
def test_energy_default_echo_and_gathered_argument_spec_round_trip(model_class):
    """A 0.1 controller echo compares unchanged and omitted Ansible input stays unforced."""
    proposed = model_class.from_config(_config(telemetry_settings={}))
    response = proposed.to_payload()
    response["telemetrySettings"]["energyManagement"]["cost"] = 0.1
    existing = model_class.from_response(deepcopy(response))
    assert existing.get_diff(proposed, exclude_unset=False) is True
    gathered = existing.to_gathered_config()
    assert gathered["telemetry_settings"]["energy_management"]["cost"] == 0.1
    argspec = model_class.get_argument_spec()
    option = argspec["config"]["options"]["telemetry_settings"]["options"]["energy_management"]["options"]["cost"]
    assert option["type"] == "float"
    assert "default" not in option
    validated = ModuleArgumentSpecValidator(argspec).validate(
        {
            "state": "merged",
            "config": [_config(telemetry_settings={"energy_management": {}})],
        }
    )
    assert validated.error_messages == []
    assert validated.validated_parameters["config"][0]["telemetry_settings"]["energy_management"]["cost"] is None
    replay = model_class.from_config(validated.validated_parameters["config"][0])
    assert replay.telemetry_settings.energy_management.cost == 0.1
    assert "cost" not in replay.telemetry_settings.energy_management.model_fields_set


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
@pytest.mark.parametrize(
    "patch",
    (
        {"telemetry_collection": True},
        {"telemetry_settings": {}},
        {"telemetry_settings": {"flow_collection": {}}},
    ),
    ids=("auto-telemetry", "provided-telemetry", "provided-flow"),
)
def test_user_selected_flow_defaults_are_disabled(model_class, patch):
    """Apply the user's 2026-11-11 policy without inferring an API or UI default."""
    model = model_class.from_config(_config(**patch))
    flow = model.telemetry_settings.flow_collection
    assert flow.traffic_analytics == "disabled"
    assert flow.udp_categorization == "disabled"
    payload = model.to_payload()["telemetrySettings"]["flowCollection"]
    assert payload["trafficAnalytics"] == "disabled"
    assert payload["udpCategorization"] == "disabled"
    assert payload["flowCollectionModes"] == {}
    for data in (model.to_config(), model.to_gathered_config()):
        gathered_flow = data["telemetry_settings"]["flow_collection"]
        assert gathered_flow["traffic_analytics"] == "disabled"
        assert gathered_flow["udp_categorization"] == "disabled"


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
@pytest.mark.parametrize("traffic_analytics", ("enabled", "compatibility", "disabled"))
@pytest.mark.parametrize("udp_categorization", ("enabled", "disabled"))
def test_explicit_flow_states_remain_accepted_and_replayable(model_class, traffic_analytics, udp_categorization):
    """Default policy does not impose UI conditions or claim controller capabilities."""
    model = model_class.from_config(
        _config(
            telemetry_settings={
                "flow_collection": {
                    "traffic_analytics": traffic_analytics,
                    "udp_categorization": udp_categorization,
                }
            }
        )
    )
    payload = model.to_payload()
    flow_payload = payload["telemetrySettings"]["flowCollection"]
    assert flow_payload["trafficAnalytics"] == traffic_analytics
    assert flow_payload["udpCategorization"] == udp_categorization
    parsed = model_class.from_response(payload)
    for data in (
        model.to_config(),
        model.to_gathered_config(),
        parsed.to_gathered_config(),
    ):
        flow = data["telemetry_settings"]["flow_collection"]
        assert flow["traffic_analytics"] == traffic_analytics
        assert flow["udp_categorization"] == udp_categorization
    gathered = parsed.to_gathered_config()
    validation = ModuleArgumentSpecValidator(model_class.get_argument_spec()).validate({"state": "merged", "config": [gathered]})
    assert validation.error_messages == []
    replay = model_class.from_config(gathered)
    assert replay.to_payload()["telemetrySettings"]["flowCollection"] == flow_payload


@pytest.mark.parametrize("model_class", FABRIC_MODELS)
def test_flow_defaults_are_model_owned_and_keep_state_comparison_semantics(model_class):
    """Ansible omission remains unset; merge preserves and exact comparison detects a reset."""
    config = _config(telemetry_settings={"flow_collection": {}})
    argspec = model_class.get_argument_spec()
    options = argspec["config"]["options"]["telemetry_settings"]["options"]["flow_collection"]["options"]
    for name in ("traffic_analytics", "udp_categorization"):
        assert "default" not in options[name]
    validation = ModuleArgumentSpecValidator(argspec).validate({"state": "merged", "config": [config]})
    assert validation.error_messages == []
    raw_flow = validation.validated_parameters["config"][0]["telemetry_settings"]["flow_collection"]
    assert raw_flow["traffic_analytics"] is None
    assert raw_flow["udp_categorization"] is None
    proposed = model_class.from_config(validation.validated_parameters["config"][0])
    response = proposed.to_payload()
    response["telemetrySettings"]["flowCollection"].update({"trafficAnalytics": "enabled", "udpCategorization": "enabled"})
    existing = model_class.from_response(response)
    assert existing.get_diff(proposed, exclude_unset=True) is True
    assert existing.get_diff(proposed, exclude_unset=False) is False
