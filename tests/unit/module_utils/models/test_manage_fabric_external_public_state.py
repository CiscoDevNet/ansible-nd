# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""External public settings use ordinary management and product-release rules."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _config(**management):
    return {
        "fabric_name": "external_public_probe",
        "management": {"bgp_asn": "65001", **management},
    }


def _argspec(config):
    checked = ModuleArgumentSpecValidator(FabricExternalConnectivityModel.get_argument_spec()).validate({"state": "merged", "config": [deepcopy(config)]})
    assert checked.error_messages == []
    return checked.validated_parameters["config"][0]


def _orchestrator(version):
    rest = RestSend({"check_mode": False, "state": "merged"})
    rest.controller_product_version = version
    return ManageExternalFabricOrchestrator(rest_send=rest)


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
def test_external_samplers_are_public_on_both_supported_releases(version):
    """Both write schemas expose samplers; gathered values must replay through public input."""
    samplers = [{"sampler_name": "sampler-1", "num_samples": 10, "sampling_rate": 1000}]
    model = FabricExternalConnectivityModel.from_config(_argspec(_config(netflow_settings={"netflow_sampler_collection": samplers})))
    _orchestrator(version).preflight([model])
    wire = [{"samplerName": "sampler-1", "numSamples": 10, "samplingRate": 1000}]
    assert model.to_payload()["management"]["netflowSettings"]["netflowSamplerCollection"] == wire
    existing = FabricExternalConnectivityModel.from_response(model.to_payload())
    gathered = existing.to_gathered_config()
    assert gathered["management"]["netflow_settings"]["netflow_sampler_collection"] == samplers
    replay = FabricExternalConnectivityModel.from_config(_argspec(gathered))
    _orchestrator(version).preflight([replay])
    assert replay.to_payload()["management"]["netflowSettings"]["netflowSamplerCollection"] == wire
    assert existing.get_diff(replay, exclude_unset=False) is True


@pytest.mark.parametrize("supplied", (False, True))
def test_external_ai_monitoring_is_public_and_manageable_on_4_3(supplied):
    """An explicit AI monitoring value is ordinary managed state on its first API release."""
    model = FabricExternalConnectivityModel.from_config(_argspec(_config(ai_monitoring=supplied)))
    _orchestrator("4.3.1").preflight([model])
    assert model.to_payload()["management"]["aiMonitoring"] is supplied
    existing = FabricExternalConnectivityModel.from_response(model.to_payload())
    assert existing.to_gathered_config()["management"]["ai_monitoring"] is supplied
    assert existing.get_diff(model, exclude_unset=False) is True


@pytest.mark.parametrize("supplied", (False, True))
def test_external_ai_monitoring_explicit_values_are_rejected_on_4_2(supplied):
    """The 4.3-only API input is gated by presence, including a supplied false value."""
    model = FabricExternalConnectivityModel.from_config(_config(ai_monitoring=supplied))
    with pytest.raises(RuntimeError, match=r"management\.ai_monitoring.*requires ND 4\.3\.1"):
        _orchestrator("4.2.1").preflight([model])


def test_external_omitted_ai_monitoring_resets_to_public_model_default():
    """Exact replacement resets public AI monitoring instead of preserving it as opaque state."""
    existing = FabricExternalConnectivityModel.from_config(_config(ai_monitoring=True))
    proposed = FabricExternalConnectivityModel.from_config(_config())
    _orchestrator("4.3.1").preflight([proposed])
    candidate = proposed.prepare_for_replacement(existing)
    expected = type(candidate.management).model_fields["ai_monitoring"].default
    assert candidate.to_payload()["management"].get("aiMonitoring") is expected
    assert "ai_monitoring" not in candidate.management.model_fields_set
    assert existing.get_diff(candidate, exclude_unset=False) is False
