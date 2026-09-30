# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import importlib

import pytest
import yaml
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    ConfigActionStepResult,
    ConfigActions,
    ConfigActionsResult,
)

CONFIG_ACTION_MODULES = (
    "nd_manage_fabric_ebgp_vxlan",
    "nd_manage_fabric_ibgp_vxlan",
    "nd_manage_fabric_ai_ebgp_vxlan",
    "nd_manage_fabric_ai_ibgp_vxlan",
    "nd_manage_fabric_external",
    "nd_manage_fabric_group_vxlan",
    "nd_manage_fabric_group_members",
    "nd_manage_tor",
)


def _config_actions_return(module_name: str) -> dict:
    """Load one module's documented config_actions return contract."""
    module = importlib.import_module(f"ansible_collections.cisco.nd.plugins.modules.{module_name}")
    return yaml.safe_load(module.RETURN)["config_actions"]


def _serialized_contract() -> dict:
    """Build a fully populated result so optional public fields are covered too."""
    actions = ConfigActions(
        save=True,
        deploy=True,
        type="switch",
        provided=True,
        explicit_options=frozenset({"save", "deploy", "type"}),
        resource_deploy_provided=False,
        resource_deploy_indexes=(),
    )
    deploy_response = {
        "submissions": [
            {
                "sequence": 1,
                "scope": "switch",
                "switch_ids": ["S1"],
                "response": {"status": "accepted"},
            }
        ],
        "verified_switch_ids": ["S1"],
    }
    step = ConfigActionStepResult(
        action="deploy",
        status="failed",
        scope="switch",
        target="FAB1",
        response=deploy_response,
        error="deploy failed",
        error_type="RuntimeError",
        http_status=500,
        request_payload={"switchIds": ["S1"]},
        response_payload={"message": "deploy failed"},
        raw={"RETURN_CODE": 500},
    )
    return ConfigActionsResult(
        requested=actions,
        effective=actions,
        status="failed",
        reason="action_failed",
        targets={"fabrics": ("FAB1",), "switches": ("S1",), "resources": ()},
        actions=(step,),
    ).to_result()


def test_config_actions_return_docs_are_identical_across_module_family() -> None:
    """All eight public modules expose one shared config action result contract."""
    expected = _config_actions_return(CONFIG_ACTION_MODULES[0])

    for module_name in CONFIG_ACTION_MODULES[1:]:
        assert _config_actions_return(module_name) == expected, module_name


@pytest.mark.parametrize("module_name", CONFIG_ACTION_MODULES)
def test_config_actions_return_docs_cover_serialized_contract(module_name: str) -> None:
    """Every serialized result field, including deploy submissions, is documented."""
    runtime = _serialized_contract()
    documented = _config_actions_return(module_name)["contains"]

    assert set(documented) == set(runtime)
    assert set(documented["requested"]["contains"]) == set(runtime["requested"])
    assert set(documented["effective"]["contains"]) == set(runtime["effective"])
    assert set(documented["targets"]["contains"]) == set(runtime["targets"])

    runtime_step = runtime["actions"][0]
    documented_step = documented["actions"]["contains"]
    assert set(documented_step) == set(runtime_step)

    runtime_response = runtime_step["response"]
    documented_response = documented_step["response"]["contains"]
    assert set(documented_response) == set(runtime_response)
    assert set(documented_response["submissions"]["contains"]) == set(runtime_response["submissions"][0])
