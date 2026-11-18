# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NX-API HTTP-only changes must reach the existing eBGP update callback."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import FabricAiEbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import ManageAiEbgpVxlanFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import ManageEbgpFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

FAMILIES = (
    pytest.param(FabricEbgpModel, ManageEbgpFabricOrchestrator, id="ebgp"),
    pytest.param(FabricAiEbgpVxlanModel, ManageAiEbgpVxlanFabricOrchestrator, id="ai-ebgp"),
)


def _config(enabled):
    return {"fabric_name": "nxapi_probe", "management": {"bgp_asn": "65001", "nxapi_http": enabled}}


def _rest(version, state):
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(()))
    rest = RestSend({"check_mode": False, "state": state})
    rest.sender, rest.response_handler, rest.unit_test = sender, ResponseHandler(), True
    rest.controller_product_version = version
    return rest


def _run(orchestrator, backend, version, state, desired):
    class RecordingOrchestrator(orchestrator):
        def query_all(self, **kwargs):
            return [deepcopy(backend["response"])]

        def update(self, model_instance, **kwargs):
            payload = model_instance.to_payload()
            backend["updates"].append(deepcopy(payload))
            backend["response"] = deepcopy(payload)
            return {}

    module = MockAnsibleModule()
    module.check_mode = False
    module.no_log_values = set()
    module.params = {
        "state": state,
        "config": [_config(desired)],
        "config_actions": {"save": False, "deploy": False},
        "output_level": "normal",
        "ignore_errors": False,
    }
    machine = NDStateMachine(module=module, model_orchestrator=RecordingOrchestrator(rest_send=_rest(version, state)))
    machine.manage_state()
    return machine.output.format()["changed"]


@pytest.mark.parametrize(("model_class", "orchestrator"), FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize(("existing_value", "desired_value"), ((True, False), (False, True)), ids=("disable", "enable"))
def test_ebgp_nxapi_only_change_updates_once_and_identical_repeat_makes_no_write(model_class, orchestrator, version, state, existing_value, desired_value):
    """Both boolean directions reach the real state-machine update plan without an unrelated change."""
    existing = model_class.from_config(_config(existing_value))
    orchestrator(rest_send=_rest(version, state)).preflight([existing])
    backend = {"response": existing.to_payload(), "updates": []}

    assert _run(orchestrator, backend, version, state, desired_value) is True
    assert len(backend["updates"]) == 1
    assert backend["updates"][0]["management"]["nxapiHttp"] is desired_value
    assert backend["response"]["management"]["nxapiHttp"] is desired_value

    assert _run(orchestrator, backend, version, state, desired_value) is False
    assert len(backend["updates"]) == 1
