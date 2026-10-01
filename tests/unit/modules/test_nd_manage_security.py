"""Wrapper and public-contract tests for the ND Manage security modules."""

from __future__ import annotations

import pytest
import yaml

from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import (
    SecurityAssociationModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.contracts import (
    SecurityContractModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import (
    SecurityGroupModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.protocol_definitions import (
    SecurityProtocolDefinitionModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityAssociationOrchestrator,
    SecurityContractOrchestrator,
    SecurityGroupOrchestrator,
    SecurityProtocolDefinitionOrchestrator,
)
from ansible_collections.cisco.nd.plugins.modules import (
    nd_manage_security_associations,
    nd_manage_security_contracts,
    nd_manage_security_groups,
    nd_manage_security_protocol_definitions,
)

MODULE_CASES = (
    (
        nd_manage_security_protocol_definitions,
        SecurityProtocolDefinitionModel,
        SecurityProtocolDefinitionOrchestrator,
        "nd.nd_manage_security_protocol_definitions",
    ),
    (
        nd_manage_security_contracts,
        SecurityContractModel,
        SecurityContractOrchestrator,
        "nd.nd_manage_security_contracts",
    ),
    (
        nd_manage_security_groups,
        SecurityGroupModel,
        SecurityGroupOrchestrator,
        "nd.nd_manage_security_groups",
    ),
    (
        nd_manage_security_associations,
        SecurityAssociationModel,
        SecurityAssociationOrchestrator,
        "nd.nd_manage_security_associations",
    ),
)

EXPECTED_COMMON_RETURN_KEYS = {
    "changed",
    "output_level",
    "before",
    "after",
    "diff",
    "proposed",
    "gathered",
    "config_actions_result",
    "api_paths",
    "api_verbs",
    "logs",
    "msg",
}


@pytest.mark.parametrize("module,model_class,orchestrator_class,logger_name", MODULE_CASES)
def test_wrapper_delegates_to_shared_runner(
    monkeypatch: pytest.MonkeyPatch,
    module,
    model_class,
    orchestrator_class,
    logger_name: str,
) -> None:
    """Each thin wrapper passes its model, orchestrator, and logger to the shared runner."""
    calls: list[dict] = []

    def fake_run_security_module(**kwargs) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(module, "run_security_module", fake_run_security_module)

    module.main()

    assert calls == [
        {
            "model_class": model_class,
            "orchestrator_class": orchestrator_class,
            "logger_name": logger_name,
        }
    ]


@pytest.mark.parametrize("module,model_class,unused_orchestrator,unused_logger", MODULE_CASES)
def test_gathered_and_config_action_documentation_matches_argument_spec(
    module,
    model_class,
    unused_orchestrator,
    unused_logger: str,
) -> None:
    """The wrapper docs and argspec expose the same read-only gathered contract."""
    documentation = yaml.safe_load(module.DOCUMENTATION)
    argument_spec = model_class.get_argument_spec()

    assert argument_spec["config"].get("required", False) is False
    assert "gathered" in argument_spec["state"]["choices"]
    assert "gathered" in documentation["options"]["state"]["choices"]
    assert documentation["options"]["config"]["required"] is False

    for option in ("save", "deploy"):
        assert argument_spec["config_actions"]["options"][option]["default"] is False
        assert documentation["options"]["config_actions"]["suboptions"][option]["default"] is False

    assert "state: gathered" in module.EXAMPLES
    assert "CSV import and export" in module.DOCUMENTATION


@pytest.mark.parametrize("module,unused_model,unused_orchestrator,unused_logger", MODULE_CASES)
def test_return_documentation_covers_state_and_action_output(
    module,
    unused_model,
    unused_orchestrator,
    unused_logger: str,
) -> None:
    """Every wrapper documents the common state-machine and action result fields."""
    return_documentation = yaml.safe_load(module.RETURN)

    assert EXPECTED_COMMON_RETURN_KEYS <= return_documentation.keys()
    assert return_documentation["before"]["type"] == "list"
    assert return_documentation["after"]["type"] == "list"
    assert return_documentation["gathered"]["type"] == "list"
    assert return_documentation["config_actions_result"]["type"] == "dict"


def test_attach_return_documentation_matches_supported_module_families() -> None:
    """Only attach-capable wrappers document structured security action results."""
    for module in (
        nd_manage_security_protocol_definitions,
        nd_manage_security_contracts,
    ):
        assert "security_actions_result" not in yaml.safe_load(module.RETURN)

    expected_action_key = {
        nd_manage_security_groups: "securityGroupNames",
        nd_manage_security_associations: "securityAssociationNames",
    }
    for module, payload_key in expected_action_key.items():
        security_actions = yaml.safe_load(module.RETURN)["security_actions_result"]
        assert security_actions["type"] == "dict"
        assert set(security_actions["contains"]) == {"attach", "detach"}
        for action in ("attach", "detach"):
            assert security_actions["contains"][action]["type"] == "dict"
            assert payload_key in security_actions["contains"][action]["description"]


def test_version_specific_contracts_are_visible_in_examples_and_options() -> None:
    """Public docs retain the two active release contracts instead of advertising a synthetic union."""
    group_documentation = yaml.safe_load(nd_manage_security_groups.DOCUMENTATION)
    vm_options = group_documentation["options"]["config"]["suboptions"]["selectors"]["suboptions"]["vm_data"]["suboptions"]

    assert "Required when creating on ND 4.2.1" in nd_manage_security_groups.DOCUMENTATION
    assert "May be omitted when creating on ND 4.3.1" in nd_manage_security_groups.DOCUMENTATION
    assert {"vm_data_type", "v_center", "vm_uuid", "nic_mac"} <= vm_options.keys()
    assert "ack;syn" in nd_manage_security_protocol_definitions.EXAMPLES
    assert "C(est) must be used by itself" in nd_manage_security_protocol_definitions.DOCUMENTATION


def test_contract_direction_documentation_matches_release_behavior() -> None:
    """Contract docs describe the distinct ND 4.2 and schema direction policies."""
    documentation = yaml.safe_load(nd_manage_security_contracts.DOCUMENTATION)
    direction_description = " ".join(documentation["options"]["config"]["suboptions"]["direction"]["description"])

    assert "C(custom) for a default-tenant contract on ND 4.2.1" in direction_description
    assert "On ND 4.3.1, or when the controller version is unavailable" in direction_description
    assert "accepts only C(custom)" in direction_description
    assert "accepts C(bidirectional), C(unidirectional), or C(custom)" in direction_description
    assert "do not accept C(custom)" in direction_description
    assert "can be gathered and replayed unchanged" in direction_description
    assert "direction defaults to custom on ND 4.2.1" in nd_manage_security_contracts.EXAMPLES
    assert "bidirectional on ND 4.3.1" in nd_manage_security_contracts.EXAMPLES
