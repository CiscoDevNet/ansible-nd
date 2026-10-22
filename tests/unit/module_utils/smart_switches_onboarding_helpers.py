# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Smart Switch transport and inventory builders shared across unit layers."""

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.smart_switches_onboarding import SmartSwitchOnboardingOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def response(data, code=200):
    return {"RETURN_CODE": code, "MESSAGE": "OK", "DATA": data}


def row(key, integration="", name=None, smart=True, alias="additionalData"):
    return {
        "switchId": key,
        "hostname": name or f"leaf-{key}",
        "fabricName": "fabric_1",
        alias: {"smartSwitch": smart, "hypershieldIntegrationName": integration},
    }


def page(rows, total=None, remaining=None):
    data = {"switches": rows}
    if total is not None:
        data["meta"] = {"counts": {"total": total, "remaining": remaining}}
    return response(data)


def orchestrator(responses, state="replaced", check=False):
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(responses))
    rest = RestSend({"check_mode": check, "state": state})
    rest.sender = sender
    rest.response_handler = ResponseHandler()
    rest.unit_test = True
    rest.timeout = 1
    results = Results()
    results.state = state
    results.check_mode = check
    return SmartSwitchOnboardingOrchestrator(rest_send=rest, results=results, fabric_name="fabric_1")
