# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Contract tests for the Switch config actions backend."""

from unittest.mock import Mock

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.config_actions_backend import SwitchConfigActionsBackend


@pytest.mark.parametrize(
    "action,utility_method,endpoint_name,arguments,expected_payload,operation",
    [
        ("save", "save_config", "ep_config_save", (), None, "config_save"),
        ("deploy_global", "deploy_config", "ep_config_deploy", (), None, "deploy_config"),
        ("deploy_switches", "deploy_switches", "ep_switch_deploy", (("S1", "S2"),), {"switchIds": ["S1", "S2"]}, "deploy_switches"),
    ],
)
@pytest.mark.parametrize("record_operations", [True, False])
def test_backend_forwards_actions_and_optionally_records_results(
    action, utility_method, endpoint_name, arguments, expected_payload, operation, record_operations
):
    """Each successful call returns its controller response and records its actual request if enabled."""
    fabric_utils = Mock()
    recorder = Mock() if record_operations else None
    response = {"RETURN_CODE": 202, "DATA": "accepted"}
    getattr(fabric_utils, utility_method).return_value = response
    backend = SwitchConfigActionsBackend(fabric_utils, recorder)
    context = ConfigActionsContext(fabric_names=("FAB1",), state="merged")

    assert getattr(backend, action)(context, "FAB1", *arguments) is response
    utility_args = (["S1", "S2"],) if action == "deploy_switches" else ()
    getattr(fabric_utils, utility_method).assert_called_once_with(*utility_args)
    if record_operations:
        recorder.assert_called_once_with(getattr(fabric_utils, endpoint_name), expected_payload, response, operation)


@pytest.mark.parametrize(
    "action,utility_method,arguments",
    [("save", "save_config", ()), ("deploy_global", "deploy_config", ()), ("deploy_switches", "deploy_switches", (("S1",),))],
)
def test_failed_action_does_not_record_a_completed_request(action, utility_method, arguments):
    """A utility exception propagates without recording a successful operation."""
    fabric_utils = Mock()
    recorder = Mock()
    getattr(fabric_utils, utility_method).side_effect = RuntimeError("controller rejected request")
    backend = SwitchConfigActionsBackend(fabric_utils, recorder)
    context = ConfigActionsContext(fabric_names=("FAB1",), state="merged")

    with pytest.raises(RuntimeError, match="controller rejected request"):
        getattr(backend, action)(context, "FAB1", *arguments)
    recorder.assert_not_called()


def test_backend_rejects_resource_deployment_without_contacting_controller():
    """Switch workflows cannot accidentally issue a resource-scoped deployment."""
    fabric_utils = Mock()
    recorder = Mock()
    backend = SwitchConfigActionsBackend(fabric_utils, recorder)
    context = ConfigActionsContext(fabric_names=("FAB1",), state="merged")

    with pytest.raises(NotImplementedError, match="Switch config actions do not support resource deploy"):
        backend.deploy_resources(context, "FAB1", ("VRF1",))
    assert not fabric_utils.mock_calls
    recorder.assert_not_called()
