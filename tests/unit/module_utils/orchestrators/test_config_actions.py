# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for orchestrators/config_actions_mixin.py

Tests the ConfigActionsMixin class and FabricConfigActionsBackend focusing on:
- config_save calls _request with correct path/verb and no body
- _deploy_global calls _request with the fabric deploy endpoint and no body
- _deploy_switch_ids posts pre-filtered switchIds and is a no-op when empty
- _filter_switches_needing_deploy selects non-inSync switches
- FabricConfigActionsBackend delegates save/deploy to the orchestrator and rejects resource deploy
- build_config_actions_context skips switchless fabrics and pre-filters switch targets
- run_config_actions drives the shared controller end to end
- execute_config_actions_plan facade delegates to ConfigActionsController and warns on skips
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from typing import ClassVar, Literal, Optional

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.backend import ConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS, SWITCH_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    NOT_ISSUED,
    ConfigActionStepResult,
    ConfigActionsContext,
    ConfigActionsFailed,
    ConfigActionsResult,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.backends.fabric import FabricConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import ConfigActionsMixin, ConfigActionsPreconditionError
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import RecordingSender

# =============================================================================
# Test doubles: minimal concrete Endpoint and Model subclasses
# =============================================================================


class StubGetEndpoint(NDEndpointBaseModel):
    """Concrete GET endpoint for testing."""

    class_name: Literal["StubGetEndpoint"] = "StubGetEndpoint"

    @property
    def path(self) -> str:
        return "/api/v1/stub"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class StubPostEndpoint(NDEndpointBaseModel):
    """Concrete POST endpoint for testing."""

    class_name: Literal["StubPostEndpoint"] = "StubPostEndpoint"

    @property
    def path(self) -> str:
        return "/api/v1/stub"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class StubPutEndpoint(NDEndpointBaseModel):
    """Concrete PUT endpoint for testing."""

    class_name: Literal["StubPutEndpoint"] = "StubPutEndpoint"
    _path: str = "/api/v1/stub"

    @property
    def path(self) -> str:
        return self._path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT

    def set_identifiers(self, identifier=None) -> None:
        if identifier is not None:
            self._path = f"/api/v1/stub/{identifier}"


class StubDeleteEndpoint(NDEndpointBaseModel):
    """Concrete DELETE endpoint for testing."""

    class_name: Literal["StubDeleteEndpoint"] = "StubDeleteEndpoint"
    _path: str = "/api/v1/stub"

    @property
    def path(self) -> str:
        return self._path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE

    def set_identifiers(self, identifier=None) -> None:
        if identifier is not None:
            self._path = f"/api/v1/stub/{identifier}"


class StubModel(NDBaseModel):
    """Minimal concrete model for testing."""

    model_config = ConfigDict(populate_by_name=True)

    identifiers: ClassVar[list] = ["name"]
    identifier_strategy: ClassVar[str] = "single"

    name: str = "test_item"
    description: Optional[str] = None


class ConfigActionsOrchestrator(ConfigActionsMixin, NDBaseOrchestrator):
    """Concrete orchestrator with ConfigActionsMixin for testing."""

    model_class: ClassVar[type[NDBaseModel]] = StubModel


class FacadeBackend:
    """Backend test double for the controller facade path."""

    def __init__(self, owner=None) -> None:
        self.owner = owner
        self.calls = []

    def save(self, context, fabric_name):
        self.calls.append(("save", fabric_name, context.state))
        return {"saved": fabric_name}

    def deploy_global(self, context, fabric_name):
        self.calls.append(("deploy_global", fabric_name, context.state))
        return {"deployed": fabric_name}

    def deploy_switches(self, context, fabric_name, switch_ids):
        self.calls.append(("deploy_switches", fabric_name, switch_ids))
        return {"switch_ids": list(switch_ids)}

    def deploy_resources(self, context, fabric_name, resources):
        self.calls.append(("deploy_resources", fabric_name, resources))
        return {"resources": list(resources)}


class ConfiguredBackend(FacadeBackend):
    """Backend test double constructed from the mixin's class-level hook."""

    instances: ClassVar[list["ConfiguredBackend"]] = []

    def __init__(self, owner) -> None:
        super().__init__(owner)
        self.instances.append(self)


class ConfiguredBackendOrchestrator(ConfigActionsOrchestrator):
    """Concrete orchestrator that configures the backend hook at class level."""

    config_actions_backend_class: ClassVar[type[ConfigActionsBackend]] = ConfiguredBackend


class NoBackendOrchestrator(ConfigActionsOrchestrator):
    """Concrete orchestrator that disables the default backend hook."""

    config_actions_backend_class: ClassVar[type[ConfigActionsBackend] | None] = None


def _switches(statuses, method="GET"):
    """Build a switches GET response from a ``{switch_id: configSyncStatus}`` mapping."""
    return {
        "RETURN_CODE": 200,
        "METHOD": method,
        "REQUEST_PATH": "/api/v1/stub",
        "MESSAGE": "OK",
        "DATA": {"switches": [{"serialNumber": switch_id, "additionalData": {"configSyncStatus": status}} for switch_id, status in statuses.items()]},
    }


# =============================================================================
# Fixtures: RestSend wired with file-based Sender
# =============================================================================


def _make_rest_send(response_dicts):
    """
    Build a real RestSend instance backed by a file-based Sender
    that yields the given response dicts in order.
    """

    def responses():
        yield from response_dicts

    sender = RecordingSender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    rest_send = RestSend({"check_mode": False, "state": "merged"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    return rest_send


def _paths(rest_send):
    """Return the path of every request issued, in order."""
    return rest_send.sender.paths()


def _payload_for(rest_send, path_fragment):
    """Return the payload of the last request whose path contains `path_fragment`."""
    return rest_send.sender.payload_for(path_fragment)


def _success_response(data=None, method="POST", path="/api/v1/stub"):
    """Standard 200 OK response dict."""
    return {
        "RETURN_CODE": 200,
        "METHOD": method,
        "REQUEST_PATH": path,
        "MESSAGE": "OK",
        "DATA": data or {},
    }


def _error_response(method="POST", path="/api/v1/stub", message="Internal Server Error"):
    """Standard 500 failure response dict."""
    return {
        "RETURN_CODE": 500,
        "METHOD": method,
        "REQUEST_PATH": path,
        "MESSAGE": message,
        "DATA": {},
    }


def _make_orchestrator(rest_send, results=None, orchestrator_class=None):
    """Create a ConfigActionsOrchestrator with stub endpoints and the given RestSend."""
    return (orchestrator_class or ConfigActionsOrchestrator)(
        create_endpoint=StubPostEndpoint,
        update_endpoint=StubPutEndpoint,
        delete_endpoint=StubDeleteEndpoint,
        query_one_endpoint=StubGetEndpoint,
        query_all_endpoint=StubGetEndpoint,
        rest_send=rest_send,
        results=results,
    )


def _make_results():
    """Create a Results instance pre-configured for testing."""
    r = Results()
    r.state = "merged"
    r.check_mode = False
    return r


# =============================================================================
# Test: config_save
# =============================================================================


class TestConfigSave:
    """Tests for ConfigActionsMixin.config_save()."""

    def test_config_save_calls_correct_endpoint(self):
        """
        # Summary

        Verify config_save sends POST to /fabrics/{fabricName}/actions/configSave with no body.

        ## Test

        - _request is called with the configSave endpoint path
        - verb is POST
        - operation_type is UPDATE
        - No data payload is sent

        ## Classes and Methods

        - ConfigActionsMixin.config_save()
        """
        rest_send = _make_rest_send(
            [
                _success_response(data={"status": "Config save is completed"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.config_save("test-fabric")

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 2
        assert "configSave" in rest_send.path
        assert "test-fabric" in rest_send.path

    def test_config_save_registered_as_update_operation(self):
        """
        # Summary

        Verify config_save registers with Results as an UPDATE operation (verbosity 2).

        ## Test

        - Results captures the API call
        - Operation type is UPDATE (verbosity level 2)

        ## Classes and Methods

        - ConfigActionsMixin.config_save()
        - NDBaseOrchestrator._register_api_call()
        """
        rest_send = _make_rest_send(
            [
                _success_response(data={"status": "Config save is completed"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.config_save("my-fabric")

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 2


# =============================================================================
# Test: _deploy_global
# =============================================================================


class TestDeployGlobal:
    """Tests for ConfigActionsMixin.deploy_global()."""

    def test_deploy_global_calls_correct_endpoint(self):
        """Verify _deploy_global POSTs to the fabric deploy endpoint with no body."""
        rest_send = _make_rest_send(
            [
                _success_response(data={"status": "Configuration deployment completed"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.deploy_global("test-fabric")

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 2
        assert "actions/deploy" in rest_send.path
        assert "test-fabric" in rest_send.path
        assert "switchActions" not in rest_send.path
        # Base fabric deploy does not set the fabric-group global-switch flag.
        assert "inclAllFabricGroupsSwitches" not in rest_send.path


# =============================================================================
# Test: _deploy_switch_ids
# =============================================================================


class TestDeploySwitchIds:
    """Tests for ConfigActionsMixin.deploy_switch_ids()."""

    def test_deploy_switch_ids_posts_switch_endpoint(self):
        """Verify _deploy_switch_ids POSTs the pre-filtered switchIds."""
        rest_send = _make_rest_send(
            [
                _success_response(data={"switchIds": []}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.deploy_switch_ids("test-fabric", ["FOC111AAA", "FOC333CCC"])

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 2
        assert "switchActions/deploy" in rest_send.path
        assert rest_send.committed_payload == {"switchIds": ["FOC111AAA", "FOC333CCC"]}

    def test_deploy_switch_ids_empty_is_noop(self):
        """Verify _deploy_switch_ids signals not-issued and makes no API call when empty."""
        rest_send = _make_rest_send([])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        result = orch.deploy_switch_ids("test-fabric", [])

        assert result is NOT_ISSUED
        assert len(results._tasks) == 0


# =============================================================================
# Test: switch identifier resolution
# =============================================================================


class TestSwitchIdentifier:
    """Tests for switch identifier extraction (switchId preferred over serialNumber)."""

    @pytest.mark.parametrize(
        "switch, expected",
        [
            ({"switchId": "NODE-101", "serialNumber": "FOC111AAA"}, "NODE-101"),
            ({"serialNumber": "FOC111AAA"}, "FOC111AAA"),
            ({"switchId": "", "serialNumber": "FOC111AAA"}, "FOC111AAA"),
            ({"switchId": "NODE-101"}, "NODE-101"),
            ({}, ""),
        ],
    )
    def test_switch_identifier_prefers_switch_id(self, switch, expected):
        """Verify switchId wins, with serialNumber used only when it is absent or empty.

        ND documents switchId as required and, for ACI nodes, as a node ID rather
        than a serial number, so the two are not always interchangeable.
        """
        assert ConfigActionsMixin._switch_identifier(switch) == expected

    def test_extract_switch_ids_mixed_sources(self):
        """Verify _extract_switch_ids resolves each switch independently and drops unidentifiable ones."""
        switches = [
            {"switchId": "NODE-101", "serialNumber": "FOC111AAA"},
            {"serialNumber": "FOC222BBB"},
            {"switchId": "NODE-103"},
            {"hostname": "leaf9"},
        ]

        assert ConfigActionsMixin._extract_switch_ids(switches) == ["NODE-101", "FOC222BBB", "NODE-103"]

    def test_filter_switches_needing_deploy_uses_switch_id(self):
        """Verify out-of-sync switches are reported by switchId when present."""
        switches = [
            {"switchId": "NODE-101", "serialNumber": "FOC111AAA", "additionalData": {"configSyncStatus": "outOfSync"}},
            {"switchId": "NODE-102", "serialNumber": "FOC222BBB", "additionalData": {"configSyncStatus": "inSync"}},
            {"serialNumber": "FOC333CCC", "additionalData": {"configSyncStatus": "pending"}},
        ]

        assert ConfigActionsMixin._filter_switches_needing_deploy(switches) == ["NODE-101", "FOC333CCC"]


# =============================================================================
# Test: FabricConfigActionsBackend
# =============================================================================


class TestFabricConfigActionsBackend:
    """Tests for FabricConfigActionsBackend delegation to the orchestrator."""

    def test_save_delegates_to_config_save(self):
        rest_send = _make_rest_send([_success_response(data={"status": "saved"})])
        orch = _make_orchestrator(rest_send, _make_results())
        backend = FabricConfigActionsBackend(orch)

        backend.save(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1")

        assert "configSave" in rest_send.path
        assert "FAB1" in rest_send.path

    def test_deploy_global_delegates(self):
        rest_send = _make_rest_send(
            [
                _success_response(data={"status": "deployed"}),
                _switches({"FOC111AAA": "inSync"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        backend = FabricConfigActionsBackend(orch)

        backend.deploy_global(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1")

        assert any("actions/deploy" in path for path in _paths(rest_send))
        assert not any("switchActions" in path for path in _paths(rest_send))

    def test_deploy_switches_intersects_candidates_with_post_save_targets(self):
        """Verify deploy_switches re-resolves post-save and keeps only context candidates."""
        switches_response = {
            "switches": [
                {"serialNumber": "FOC111AAA", "additionalData": {"configSyncStatus": "outOfSync"}},
                {"serialNumber": "FOC222BBB", "additionalData": {"configSyncStatus": "outOfSync"}},
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"switchIds": []}),
                _switches({"FOC111AAA": "inSync", "FOC222BBB": "outOfSync"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        backend = FabricConfigActionsBackend(orch)

        backend.deploy_switches(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1", ("FOC111AAA",))

        assert any("switchActions/deploy" in path for path in _paths(rest_send))
        # FOC222BBB needs deploy but is not a candidate, so it is excluded.
        assert _payload_for(rest_send, "switchActions/deploy") == {"switchIds": ["FOC111AAA"]}

    def test_deploy_switches_skips_when_no_candidate_needs_deploy(self):
        """Verify no deploy POST is issued when the candidates are all in sync."""
        switches_response = {
            "switches": [
                {"serialNumber": "FOC111AAA", "additionalData": {"configSyncStatus": "outOfSync"}},
                {"serialNumber": "FOC222BBB", "additionalData": {"configSyncStatus": "inSync"}},
            ]
        }
        rest_send = _make_rest_send([_success_response(data=switches_response, method="GET")])
        orch = _make_orchestrator(rest_send, _make_results())
        backend = FabricConfigActionsBackend(orch)

        result = backend.deploy_switches(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1", ("FOC222BBB",))

        assert result is NOT_ISSUED
        assert "switchActions/deploy" not in rest_send.path

    def test_deploy_resources_not_supported(self):
        orch = _make_orchestrator(_make_rest_send([]))
        backend = FabricConfigActionsBackend(orch)

        with pytest.raises(ValueError, match="resource"):
            backend.deploy_resources(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1", ("R1",))


# =============================================================================
# Test: build_config_actions_context
# =============================================================================


class TestBuildConfigActionsContext:
    """Tests for ConfigActionsMixin.build_config_actions_context()."""

    def test_skips_switchless_fabric_and_seeds_membership(self):
        """Verify switchless fabrics are excluded and eligible fabrics are seeded with full membership."""
        switches_response = {
            "switches": [
                {
                    "serialNumber": "FOC111AAA",
                    "additionalData": {"configSyncStatus": "outOfSync"},
                },
                {
                    "serialNumber": "FOC222BBB",
                    "additionalData": {"configSyncStatus": "inSync"},
                },
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data={"switches": []}, method="GET"),
                _success_response(data=switches_response, method="GET"),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        context = orch.build_config_actions_context(
            ["switchless-fabric", "fabric-with-switches"],
            state="merged",
        )

        assert context.fabric_names == ("fabric-with-switches",)
        # Membership, not the pre-save out-of-sync filter; real targets resolve after save.
        assert context.switch_ids_by_fabric == {"fabric-with-switches": ("FOC111AAA", "FOC222BBB")}
        warnings = rest_send.sender.ansible_module.warnings
        assert any("switchless-fabric" in w and "no switches" in w for w in warnings)


# =============================================================================
# Test: run_config_actions
# =============================================================================


class TestRunConfigActions:
    """Tests for ConfigActionsMixin.run_config_actions()."""

    def test_noop_when_no_actions_requested(self):
        rest_send = _make_rest_send([])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        actions = parse_config_actions(
            params={"config_actions": {"save": False, "deploy": False}},
            raw_args={"config_actions": {"save": False, "deploy": False}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        assert result is None
        assert len(results._tasks) == 0

    def test_save_and_global_deploy(self):
        switches_response = {
            "switches": [
                {
                    "serialNumber": "FOC111AAA",
                    "additionalData": {"configSyncStatus": "outOfSync"},
                },
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
                _success_response(data={"status": "deployed"}),
                _switches({"FOC111AAA": "inSync"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        assert result.status == "completed"
        # membership query + save + deploy + post-deploy verification
        assert len(results._tasks) == 4
        assert any("actions/deploy" in path for path in _paths(rest_send))

    def test_save_and_switch_deploy(self):
        switches_response = {
            "switches": [
                {
                    "serialNumber": "FOC111AAA",
                    "additionalData": {"configSyncStatus": "outOfSync"},
                },
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"switchIds": []}),
                _switches({"FOC111AAA": "inSync"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        assert result.status == "completed"
        # membership query + save + post-save query + deploy + post-deploy verification
        assert len(results._tasks) == 5
        assert any("switchActions/deploy" in path for path in _paths(rest_send))
        assert _payload_for(rest_send, "switchActions/deploy") == {"switchIds": ["FOC111AAA"]}

    def test_switch_deploy_targets_switches_that_save_pushed_out_of_sync(self):
        """
        # Summary

        Regression for stale pre-save target selection: every switch is ``inSync``
        before ``configSave`` and ``outOfSync`` after it. Both must be deployed.

        ## Classes and Methods

        - ConfigActionsMixin.run_config_actions()
        - ConfigActionsMixin._resolve_switch_deploy_targets()
        - FabricConfigActionsBackend.deploy_switches()
        """
        pre_save_switches = {
            "switches": [
                {"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "inSync"}},
                {"serialNumber": "leaf2", "additionalData": {"configSyncStatus": "inSync"}},
            ]
        }
        post_save_switches = {
            "switches": [
                {"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}},
                {"serialNumber": "leaf2", "additionalData": {"configSyncStatus": "outOfSync"}},
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data=pre_save_switches, method="GET"),
                _success_response(data={"status": "Config save is completed"}),
                _success_response(data=post_save_switches, method="GET"),
                _success_response(data={"switchIds": []}),
                _switches({"leaf1": "inSync", "leaf2": "inSync"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        assert result.status == "completed"
        assert any("switchActions/deploy" in path for path in _paths(rest_send))
        assert _payload_for(rest_send, "switchActions/deploy") == {"switchIds": ["leaf1", "leaf2"]}

    def test_switch_deploy_skips_post_save_when_all_in_sync(self):
        """Verify no deploy POST is issued when nothing is out of sync after save."""
        switches_response = {
            "switches": [
                {"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "inSync"}},
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
                _success_response(data=switches_response, method="GET"),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        # membership query + save + post-save query, no deploy POST
        assert len(results._tasks) == 3
        assert "switchActions/deploy" not in rest_send.path
        # Observed live on ND 4.2.1: a deploy narrowed to nothing used to report `completed`.
        deploy_steps = [step for step in result.actions if step.action == "deploy"]
        assert [(step.status, step.error) for step in deploy_steps] == [("skipped", "no_targets")]
        assert any("no_targets" in warning for warning in rest_send.sender.ansible_module.warnings)

    def test_switchless_fabric_skips_actions(self):
        rest_send = _make_rest_send(
            [
                _success_response(data={"switches": []}, method="GET"),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["switchless-fabric"], state="merged")

        assert len(results._tasks) == 1
        assert result.status == "skipped"
        assert result.reason == "no_fabrics"


# =============================================================================
# Test: only_switch_ids scoping (enables the ToR refactor)
# =============================================================================


class TestOnlySwitchIdsScoping:
    """Tests for narrowing a switch-scoped deploy to specific serials.

    Callers that touch a known subset of a fabric (ToR associate/disassociate)
    pass `only_switch_ids` so the deploy does not fan out to every out-of-sync
    switch in the fabric.
    """

    @staticmethod
    def _switch_actions():
        return parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

    def test_deploy_is_limited_to_requested_serials(self):
        switches_response = {
            "switches": [
                {"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}},
                {"serialNumber": "leaf2", "additionalData": {"configSyncStatus": "outOfSync"}},
                {"serialNumber": "leaf3", "additionalData": {"configSyncStatus": "outOfSync"}},
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"switchIds": []}),
                _switches({"leaf1": "inSync", "leaf2": "outOfSync", "leaf3": "inSync"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        orch.run_config_actions(
            actions=self._switch_actions(),
            fabric_names=["FAB1"],
            state="merged",
            only_switch_ids={"leaf1", "leaf3"},
        )

        assert any("switchActions/deploy" in path for path in _paths(rest_send))
        assert _payload_for(rest_send, "switchActions/deploy") == {"switchIds": ["leaf1", "leaf3"]}

    def test_scoped_deploy_still_resolves_targets_after_save(self):
        """A requested serial that only goes out of sync during save is still deployed."""
        pre_save = {
            "switches": [
                {"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "inSync"}},
                {"serialNumber": "leaf2", "additionalData": {"configSyncStatus": "inSync"}},
            ]
        }
        post_save = {
            "switches": [
                {"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}},
                {"serialNumber": "leaf2", "additionalData": {"configSyncStatus": "outOfSync"}},
            ]
        }
        rest_send = _make_rest_send(
            [
                _success_response(data=pre_save, method="GET"),
                _success_response(data={"status": "saved"}),
                _success_response(data=post_save, method="GET"),
                _success_response(data={"switchIds": []}),
                _switches({"leaf1": "inSync", "leaf2": "outOfSync"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        orch.run_config_actions(
            actions=self._switch_actions(),
            fabric_names=["FAB1"],
            state="merged",
            only_switch_ids={"leaf1"},
        )

        assert _payload_for(rest_send, "switchActions/deploy") == {"switchIds": ["leaf1"]}

    def test_global_deploy_ignores_only_switch_ids(self):
        switches_response = {"switches": [{"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}}]}
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
                _success_response(data={"status": "deployed"}),
                _switches({"leaf1": "inSync"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        orch.run_config_actions(
            actions=actions,
            fabric_names=["FAB1"],
            state="merged",
            only_switch_ids={"does-not-exist"},
        )

        assert any("actions/deploy" in path for path in _paths(rest_send))
        assert "switchActions" not in rest_send.path

    def test_no_matching_serials_skips_deploy(self):
        switches_response = {"switches": [{"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}}]}
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        result = orch.run_config_actions(
            actions=self._switch_actions(),
            fabric_names=["FAB1"],
            state="merged",
            only_switch_ids={"not-in-this-fabric"},
        )

        assert "switchActions/deploy" not in rest_send.path
        assert any("no_targets" in w for w in rest_send.sender.ansible_module.warnings)
        assert result.status == "completed"


# =============================================================================
# Test: config action failure propagation
# =============================================================================


class TestConfigActionsFailurePropagation:
    """Tests that backend failures fail the task instead of reporting success.

    The shared controller records backend exceptions as a failed result rather
    than propagating them, so the mixin facade must re-raise. Otherwise a failed
    configSave or deploy would reach `module.exit_json()` and report success.
    """

    def test_save_failure_raises(self):
        switches_response = {"switches": [{"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}}]}
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _error_response(message="Config save failed"),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": False}},
            raw_args={"config_actions": {"save": True, "deploy": False}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        with pytest.raises(Exception, match=r"Config action 'save' failed for 'FAB1'"):
            orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

    def test_deploy_failure_raises(self):
        switches_response = {"switches": [{"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}}]}
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
                _error_response(message="Deploy failed"),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            raw_args={"config_actions": {"save": True, "deploy": True, "type": "global"}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        with pytest.raises(Exception, match=r"Config action 'deploy' \(global\) failed for 'FAB1'"):
            orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

    def test_second_fabric_is_not_saved_after_first_fabric_fails(self):
        switches_response = {"switches": [{"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}}]}
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data=switches_response, method="GET"),
                _error_response(message="Config save failed"),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": False}},
            raw_args={"config_actions": {"save": True, "deploy": False}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        with pytest.raises(Exception, match="Config action 'save' failed for 'FAB1'"):
            orch.run_config_actions(actions=actions, fabric_names=["FAB1", "FAB2"], state="merged")

        # Execution stopped on FAB1; FAB2 was never saved.
        assert "FAB1/actions/configSave" in rest_send.path

    def test_successful_run_does_not_raise(self):
        switches_response = {"switches": [{"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}}]}
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": False}},
            raw_args={"config_actions": {"save": True, "deploy": False}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        assert result.status == "completed"


# =============================================================================
# Test: config action mutations are never replayed
# =============================================================================


def _make_counting_rest_send(status_code, method="POST"):
    """Build a RestSend whose sender answers every request with `status_code`, counting attempts.

    Unlike `_make_rest_send`, the response stream is unbounded, so a retry is
    observable as an extra attempt instead of a StopIteration that masks it.
    """
    attempts = {"count": 0}

    def responses():
        while True:
            attempts["count"] += 1
            yield {
                "RETURN_CODE": status_code,
                "METHOD": method,
                "REQUEST_PATH": "/api/v1/stub",
                "MESSAGE": "Internal Server Error",
                "DATA": {},
            }

    sender = RecordingSender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    rest_send = RestSend({"check_mode": False, "state": "merged"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    return rest_send, attempts


class TestConfigActionMutationsAreNotReplayed:
    """A rejected config-action mutation must be issued exactly once.

    RestSend replays a retryable failure every `send_interval` seconds until
    `timeout` is spent, and a 5xx on a POST is retryable. configSave and both
    deploy endpoints document HTTP 500 and ND uses it for deterministic
    rejections, so the 300s default replayed one rejected save 60 times.
    """

    def test_config_save_is_issued_once_on_server_error(self):
        rest_send, attempts = _make_counting_rest_send(500)
        orch = _make_orchestrator(rest_send, _make_results())

        with pytest.raises(Exception, match="Request failed"):
            orch.config_save("FAB1")

        assert attempts["count"] == 1

    def test_deploy_global_is_issued_once_on_server_error(self):
        rest_send, attempts = _make_counting_rest_send(500)
        orch = _make_orchestrator(rest_send, _make_results())

        with pytest.raises(Exception, match="Request failed"):
            orch.deploy_global("FAB1")

        assert attempts["count"] == 1

    def test_switch_deploy_is_issued_once_on_server_error(self):
        rest_send, attempts = _make_counting_rest_send(500)
        orch = _make_orchestrator(rest_send, _make_results())

        with pytest.raises(Exception, match="Request failed"):
            orch.deploy_switch_ids("FAB1", ["leaf1"])

        assert attempts["count"] == 1

    def test_retry_window_is_restored_after_a_config_action(self):
        """The collapsed window is scoped to the mutation, not leaked to later requests."""
        rest_send = _make_counting_rest_send(500)[0]
        orch = _make_orchestrator(rest_send, _make_results())
        default_timeout = rest_send.timeout

        with pytest.raises(Exception, match="Request failed"):
            orch.config_save("FAB1")

        assert rest_send.timeout == default_timeout


class TestContentionIsRetried:
    """ND refuses a config action that collides with one already running.

    Live on ND 4.2.1 that is an HTTP 403: "This operation cannot be performed while
    recalculate and deploy is in progress. Please try again later." The refusal means
    nothing was applied, so replaying is safe, and the condition clears on its own.
    Neither the per-switch nor the fabric-level configSyncStatus reports it, so the
    message is the only available signal.
    """

    @staticmethod
    def _contention_response():
        return {
            "RETURN_CODE": 403,
            "METHOD": "POST",
            "REQUEST_PATH": "/api/v1/stub",
            "MESSAGE": "Error",
            "DATA": {"code": 403, "message": "This operation cannot be performed while recalculate and deploy is in progress. Please try again later."},
        }

    def test_contention_is_retried_until_it_clears(self):
        rest_send = _make_rest_send(
            [
                self._contention_response(),
                self._contention_response(),
                _success_response(data={"status": "Config save is completed"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        orch.config_save("FAB1")

        assert len(_paths(rest_send)) == 3
        assert sum("retrying" in warning for warning in rest_send.sender.ansible_module.warnings) == 2

    def test_contention_beyond_the_budget_fails(self):
        rest_send = _make_rest_send([self._contention_response()] * 5)
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        with pytest.raises(Exception, match="recalculate and deploy is in progress"):
            orch.config_save("FAB1")

        # Budget of 10s at 5s intervals allows the initial attempt plus two retries.
        assert len(_paths(rest_send)) == 3

    def test_a_plain_403_is_not_retried(self):
        """A real authorization failure must still fail immediately."""
        rest_send, attempts = _make_counting_rest_send(403)
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        with pytest.raises(Exception, match="Request failed"):
            orch.config_save("FAB1")

        assert attempts["count"] == 1


# =============================================================================
# Test: switch configSyncStatus classification
# =============================================================================


class TestSwitchSyncStatusClassification:
    """`_filter_switches_needing_deploy` against the documented `switchConfigSyncStatus` enum.

    ND documents deployed, deploymentInProgress, failed, inProgress, inSync, notApplicable,
    outOfSync, pending, previewInProgress and success, identically in 4.2.1 and 4.3.1.
    """

    @pytest.mark.parametrize("status", ["inSync", "deployed", "success", "notApplicable"])
    def test_settled_switches_are_not_deployed(self, status):
        assert ConfigActionsMixin._filter_switches_needing_deploy([{"switchId": "S1", "additionalData": {"configSyncStatus": status}}]) == []

    @pytest.mark.parametrize("status", ["inProgress", "deploymentInProgress", "previewInProgress"])
    def test_in_flight_switches_are_not_deployed(self, status):
        """Deploying into a running operation is what provokes the deterministic 500s."""
        assert ConfigActionsMixin._filter_switches_needing_deploy([{"switchId": "S1", "additionalData": {"configSyncStatus": status}}]) == []

    @pytest.mark.parametrize("status", ["outOfSync", "pending", "failed"])
    def test_switches_with_undeployed_config_are_deployed(self, status):
        """`pending` means configuration pending deployment, the usual state after configSave."""
        assert ConfigActionsMixin._filter_switches_needing_deploy([{"switchId": "S1", "additionalData": {"configSyncStatus": status}}]) == ["S1"]

    @pytest.mark.parametrize(
        "switch", [{"switchId": "S1"}, {"switchId": "S1", "additionalData": {}}, {"switchId": "S1", "additionalData": {"configSyncStatus": "somethingNew"}}]
    )
    def test_unknown_status_is_deployed(self, switch):
        """A status ND has not documented must not silently skip the switch."""
        assert ConfigActionsMixin._filter_switches_needing_deploy([switch]) == ["S1"]


# =============================================================================
# Test: pre-action convergence and post-deploy verification
# =============================================================================


class ImpatientOrchestrator(ConfigActionsOrchestrator):
    """Orchestrator with a two-retry budget, so exhaustion is cheap to test."""

    config_actions_retry_timeout: ClassVar[int] = 10
    config_actions_retry_interval: ClassVar[int] = 5
    config_actions_converge_stall: ClassVar[int] = 10
    config_actions_converge_interval: ClassVar[int] = 5


class NoCeilingOrchestrator(ConfigActionsOrchestrator):
    """Orchestrator whose convergence ceiling is already spent, to exercise that bailout."""

    config_actions_converge_stall: ClassVar[int] = 10_000
    config_actions_converge_max_wait: ClassVar[int] = 0
    config_actions_converge_interval: ClassVar[int] = 5


class ImpatientNoWaitOrchestrator(ConfigActionsOrchestrator):
    """Orchestrator with retrying disabled."""

    config_actions_retry_timeout: ClassVar[int] = 0


class TestReadFabricSwitches:
    """Tests for ConfigActionsMixin.read_fabric_switches().

    No convergence polling: measured on live ND 4.2.1, a full save/deploy moves switches
    pending -> outOfSync -> success -> inSync and never reports an `*InProgress` status,
    so there is nothing to wait out here. Real contention surfaces as an HTTP 403 on the
    mutation instead.
    """

    def test_returns_the_switch_list(self):
        rest_send = _make_rest_send([_switches({"S1": "outOfSync"})])
        orch = _make_orchestrator(rest_send, _make_results())

        switches = orch.read_fabric_switches("FAB1")

        assert len(_paths(rest_send)) == 1
        assert ConfigActionsMixin._filter_switches_needing_deploy(switches) == ["S1"]

    def test_an_in_flight_status_is_not_waited_out(self):
        """It is still excluded from deploy targeting, just not polled for."""
        rest_send = _make_rest_send([_switches({"S1": "deploymentInProgress"})])
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        switches = orch.read_fabric_switches("FAB1")

        assert len(_paths(rest_send)) == 1
        assert ConfigActionsMixin._filter_switches_needing_deploy(switches) == []

    def test_switch_read_is_issued_once_per_retry_on_server_error(self):
        """The read must not carry its own 300s RestSend window inside this loop.

        Two nested retry budgets would let one 5xx stall for five minutes inside a single
        iteration of a loop meant to give up after `ImpatientOrchestrator`'s ten seconds.
        """
        rest_send, attempts = _make_counting_rest_send(500, method="GET")
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        with pytest.raises(Exception, match="Request failed"):
            orch.read_fabric_switches("FAB1")

        # One read per retry: three tries spend the ten-second budget.
        assert attempts["count"] == 3

    def test_a_transient_read_failure_is_ridden_out(self):
        rest_send = _make_rest_send(
            [
                _error_response(method="GET", message="Failed to check fabric type"),
                _switches({"S1": "outOfSync"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        switches = orch.read_fabric_switches("FAB1")

        assert ConfigActionsMixin._filter_switches_needing_deploy(switches) == ["S1"]
        assert any("retrying" in warning for warning in rest_send.sender.ansible_module.warnings)

    def test_a_persistent_read_failure_surfaces_the_controller_error(self):
        rest_send = _make_rest_send([_error_response(method="GET", message="Failed to check fabric type")] * 3)
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        with pytest.raises(Exception, match="Failed to check fabric type"):
            orch.read_fabric_switches("FAB1")

    def test_a_failed_read_never_looks_like_a_switchless_fabric(self):
        """Degrading a failed read to an empty list would silently skip save/deploy."""
        rest_send = _make_rest_send([_error_response(method="GET", message="boom")])
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientNoWaitOrchestrator)

        with pytest.raises(Exception, match="Request failed"):
            orch.read_fabric_switches("FAB1")

        assert not rest_send.sender.ansible_module.warnings


class TestTruncatedSwitchList:
    """A paginated switches response must never be treated as the whole fabric.

    Live ND 4.2.1 returns `meta.counts.remaining`, and `?max=2` on a 14-switch fabric
    answers with `remaining: 12`. The default page size is undocumented, so the counter
    is the only reliable completeness signal.
    """

    @staticmethod
    def _paginated(returned, remaining):
        response = _switches({f"S{index}": "outOfSync" for index in range(returned)})
        response["DATA"]["meta"] = {"counts": {"remaining": remaining, "total": returned + remaining}}
        return response

    def test_truncated_response_is_rejected(self):
        rest_send = _make_rest_send([self._paginated(2, 12)])
        orch = _make_orchestrator(rest_send, _make_results())

        with pytest.raises(ConfigActionsPreconditionError, match="only 2 of 14 switches"):
            orch.read_fabric_switches("FAB1")

    def test_truncation_is_not_retried(self):
        """Re-reading cannot un-paginate a response, so it must not spend the retry budget."""
        rest_send = _make_rest_send([self._paginated(2, 12)] * 5)
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        with pytest.raises(ConfigActionsPreconditionError):
            orch.read_fabric_switches("FAB1")

        assert len(_paths(rest_send)) == 1

    def test_complete_response_is_accepted(self):
        rest_send = _make_rest_send([self._paginated(2, 0)])
        orch = _make_orchestrator(rest_send, _make_results())

        assert len(orch.read_fabric_switches("FAB1")) == 2

    def test_response_without_a_counter_is_taken_as_complete(self):
        rest_send = _make_rest_send([_switches({"S1": "outOfSync"})])
        orch = _make_orchestrator(rest_send, _make_results())

        assert len(orch.read_fabric_switches("FAB1")) == 1

    def test_config_actions_read_membership_before_touching_the_fabric(self):
        """The membership read that seeds the context happens before any mutation."""
        rest_send = _make_rest_send(
            [
                _switches({"S1": "outOfSync"}),
                _success_response(data={"status": "saved"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)
        actions = parse_config_actions(
            params={"config_actions": {"save": True, "deploy": False}},
            raw_args={"config_actions": {"save": True, "deploy": False}},
            policy=FABRIC_CONFIG_ACTIONS,
        )

        result = orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        assert result.status == "completed"
        assert _paths(rest_send)[-1].endswith("/actions/configSave")


class TestVerifyDeploy:
    """Tests for ConfigActionsMixin.verify_deploy().

    Polls because switch status moves after a deploy (`success` -> `inSync` in ~5s measured
    live), unlike during a save where it is frozen for the whole recalculation phase.
    """

    def test_raises_when_a_deployed_switch_reports_failed(self):
        rest_send = _make_rest_send([_switches({"S1": "failed", "S2": "inSync"})])
        orch = _make_orchestrator(rest_send, _make_results())

        with pytest.raises(Exception, match=r"Deploy failed on switch\(es\) S1 in fabric 'FAB1'"):
            orch.verify_deploy("FAB1", ["S1"])

    def test_ignores_switches_outside_the_deployed_scope(self):
        rest_send = _make_rest_send([_switches({"S1": "inSync", "S2": "failed"})])
        orch = _make_orchestrator(rest_send, _make_results())

        orch.verify_deploy("FAB1", ["S1"])

        assert not rest_send.sender.ansible_module.warnings

    def test_accepts_success_as_settled(self):
        """Live ND holds switches at `success` for ~5s before `inSync`."""
        rest_send = _make_rest_send([_switches({"S1": "success"})])
        orch = _make_orchestrator(rest_send, _make_results())

        orch.verify_deploy("FAB1", ["S1"])

        assert len(_paths(rest_send)) == 1

    def test_polls_until_the_switch_converges(self):
        rest_send = _make_rest_send(
            [
                _switches({"S1": "outOfSync"}),
                _switches({"S1": "success"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        orch.verify_deploy("FAB1", ["S1"])

        assert len(_paths(rest_send)) == 2

    def test_fails_when_a_switch_never_converges(self):
        rest_send = _make_rest_send([_switches({"S1": "outOfSync"})] * 5)
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        with pytest.raises(Exception, match=r"has come into sync for 10s; still waiting on S1 \(outOfSync\)"):
            orch.verify_deploy("FAB1", ["S1"])

    def test_progress_resets_the_stall_timer(self):
        """Switches settle incrementally, so a falling count must keep the wait alive."""
        rest_send = _make_rest_send(
            [
                _switches({"S1": "outOfSync", "S2": "outOfSync", "S3": "outOfSync"}),
                _switches({"S1": "outOfSync", "S2": "outOfSync", "S3": "inSync"}),
                _switches({"S1": "outOfSync", "S2": "inSync", "S3": "inSync"}),
                _switches({"S1": "inSync", "S2": "inSync", "S3": "inSync"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        orch.verify_deploy("FAB1", ["S1", "S2", "S3"])

        # Four polls, well past the 10s stall budget, because each one made progress.
        assert len(_paths(rest_send)) == 4

    def test_the_hard_ceiling_stops_a_drip_feed(self):
        """The stall timer alone is unbounded: one switch settling per expiry resets it forever."""
        rest_send = _make_rest_send([_switches({"S1": "outOfSync"})] * 5)
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=NoCeilingOrchestrator)

        with pytest.raises(Exception, match=r"did not come into sync within 0s"):
            orch.verify_deploy("FAB1", ["S1"])

        assert len(_paths(rest_send)) == 1

    def test_an_undocumented_status_keeps_waiting_and_is_named(self):
        rest_send = _make_rest_send([_switches({"S1": "someNewStatus"})] * 5)
        orch = _make_orchestrator(rest_send, _make_results(), orchestrator_class=ImpatientOrchestrator)

        with pytest.raises(Exception, match=r"still waiting on S1 \(someNewStatus\)"):
            orch.verify_deploy("FAB1", ["S1"])

    def test_pending_warns_rather_than_fails(self):
        """A deploy can legitimately stage fresh intent, so `pending` is not held against it."""
        rest_send = _make_rest_send([_switches({"S1": "pending"})])
        orch = _make_orchestrator(rest_send, _make_results())

        orch.verify_deploy("FAB1", ["S1"])

        assert any("configuration pending" in warning for warning in rest_send.sender.ansible_module.warnings)

    def test_a_deploy_that_reports_success_but_leaves_a_failed_switch_fails_the_task(self):
        """ND answers switchActions/deploy 207 and does not treat a per-item `notExecuted`
        as a failure, so the POST status alone can report success over a failed switch."""
        rest_send = _make_rest_send(
            [
                _switches({"S1": "outOfSync"}),
                _success_response(data={"switchIds": [{"switchId": "S1", "status": "notExecuted"}]}),
                _switches({"S1": "failed"}),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        backend = FabricConfigActionsBackend(orch)

        with pytest.raises(Exception, match=r"Deploy failed on switch\(es\) S1"):
            backend.deploy_switches(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1", ("S1",))


class TestSaveFailureBlocksDeploy:
    """A deploy must never be issued after a save that did not succeed.

    Enforced twice: `deploy_requires_save` rejects deploy-without-save at parse time, and the
    controller returns on the first failed step. The 500 below is the live ND 4.2.1 response to
    changing an underlay mask after deployment -- a permanent rejection, verified on hardware.
    """

    _SAVE_REJECTED = "Underlay Subnet IP Target Mask [31] cannot be changed to [30] after deployment "

    @staticmethod
    def _actions(deploy_type):
        spec = {"save": True, "deploy": True, "type": deploy_type}
        return parse_config_actions(params={"config_actions": spec}, raw_args={"config_actions": spec}, policy=FABRIC_CONFIG_ACTIONS)

    @pytest.mark.parametrize("deploy_type", ["switch", "global"])
    def test_a_rejected_save_stops_before_any_deploy(self, deploy_type):
        rest_send = _make_rest_send(
            [
                _switches({"S1": "pending"}),
                _error_response(message=self._SAVE_REJECTED),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        with pytest.raises(ConfigActionsFailed) as raised:
            orch.run_config_actions(actions=self._actions(deploy_type), fabric_names=["FAB1"], state="merged")

        assert not any("deploy" in path for path in _paths(rest_send))
        steps = [(step.action, step.status) for step in raised.value.result.actions]
        assert steps == [("save", "failed")]

    def test_deploy_without_save_is_rejected_before_any_request(self):
        with pytest.raises(ValueError, match="config_actions.deploy=true requires config_actions.save=true"):
            parse_config_actions(
                params={"config_actions": {"save": False, "deploy": True, "type": "switch"}},
                raw_args={"config_actions": {"save": False, "deploy": True, "type": "switch"}},
                policy=FABRIC_CONFIG_ACTIONS,
            )

    def test_the_failure_carries_the_result_so_a_completed_save_is_still_reported(self):
        """A save that landed before the deploy failed must not vanish from the report."""
        rest_send = _make_rest_send(
            [
                _switches({"S1": "outOfSync"}),
                _success_response(data={"status": "Config save is completed"}),
                _switches({"S1": "outOfSync"}),
                _error_response(message="Deploy rejected"),
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        with pytest.raises(ConfigActionsFailed) as raised:
            orch.run_config_actions(actions=self._actions("switch"), fabric_names=["FAB1"], state="merged")

        steps = [(step.action, step.status) for step in raised.value.result.actions]
        assert steps == [("save", "completed"), ("deploy", "failed")]
        assert raised.value.result.to_result()["status"] == "failed"


class TestConfigActionsControllerFacade:
    """Tests for ConfigActionsMixin.execute_config_actions_plan()."""

    def test_facade_uses_configured_classvar_backend(self):
        """
        # Summary

        Verify a Pydantic-backed orchestrator can configure the backend hook at class level.

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions_plan()
        """
        ConfiguredBackend.instances = []
        orch = ConfiguredBackendOrchestrator(
            create_endpoint=StubPostEndpoint,
            update_endpoint=StubPutEndpoint,
            delete_endpoint=StubDeleteEndpoint,
            query_one_endpoint=StubGetEndpoint,
            query_all_endpoint=StubGetEndpoint,
            rest_send=_make_rest_send([]),
        )
        actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
        context = ConfigActionsContext(fabric_names=("FAB1",), state="merged", switch_ids=("SER1",))

        result = orch.execute_config_actions_plan(actions=actions, context=context)

        assert "config_actions_policy" not in ConfiguredBackendOrchestrator.model_fields
        assert "config_actions_backend_class" not in ConfiguredBackendOrchestrator.model_fields
        assert len(ConfiguredBackend.instances) == 1
        assert ConfiguredBackend.instances[0].owner is orch
        assert ConfiguredBackend.instances[0].calls == [
            ("save", "FAB1", "merged"),
            ("deploy_switches", "FAB1", ("SER1",)),
        ]
        assert result.status == "completed"
        assert result.reason == "actions_executed"

    def test_facade_uses_supplied_backend_and_shared_controller(self):
        """
        # Summary

        Verify the mixin facade delegates normalized actions to ConfigActionsController.

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions_plan()
        """
        orch = _make_orchestrator(_make_rest_send([]))
        actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
        context = ConfigActionsContext(fabric_names=("FAB1",), state="merged", switch_ids=("SER1",))
        backend = FacadeBackend()

        result = orch.execute_config_actions_plan(actions=actions, context=context, backend=backend)

        assert backend.calls == [
            ("save", "FAB1", "merged"),
            ("deploy_switches", "FAB1", ("SER1",)),
        ]
        assert result.status == "completed"
        assert result.reason == "actions_executed"

    def test_facade_requires_backend_configuration(self):
        """
        # Summary

        Verify the mixin facade fails clearly when no backend is provided or configured.

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions_plan()
        """
        orch = NoBackendOrchestrator(
            create_endpoint=StubPostEndpoint,
            update_endpoint=StubPutEndpoint,
            delete_endpoint=StubDeleteEndpoint,
            query_one_endpoint=StubGetEndpoint,
            query_all_endpoint=StubGetEndpoint,
            rest_send=_make_rest_send([]),
        )
        actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
        context = ConfigActionsContext(fabric_names=("FAB1",), state="merged", switch_ids=("SER1",))

        with pytest.raises(ValueError, match="No config actions backend"):
            orch.execute_config_actions_plan(actions=actions, context=context)

    @pytest.mark.parametrize(
        ("actions_params", "actions_raw_args", "context", "expected_reason"),
        [
            ({}, {}, ConfigActionsContext(fabric_names=(), state="merged", switch_ids=("SER1",)), "no_fabrics"),
            ({}, {}, ConfigActionsContext(fabric_names=("FAB1",), state="merged", eligible=False, reason="switchless_fabric"), "switchless_fabric"),
            (
                {"config_actions": {"save": False, "deploy": False}},
                {"config_actions": {"save": False, "deploy": False}},
                ConfigActionsContext(fabric_names=("FAB1",), state="merged", switch_ids=("SER1",)),
                "actions_disabled",
            ),
        ],
    )
    def test_facade_warns_for_top_level_skipped_results(self, actions_params, actions_raw_args, context, expected_reason):
        """
        # Summary

        Verify top-level skipped controller results are surfaced through `rest_send.warn`.

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions_plan()
        """
        rest_send = _make_rest_send([])
        orch = _make_orchestrator(rest_send)
        actions = parse_config_actions(params=actions_params, raw_args=actions_raw_args, policy=SWITCH_CONFIG_ACTIONS)
        backend = FacadeBackend()

        result = orch.execute_config_actions_plan(actions=actions, context=context, backend=backend)

        assert result.status == "skipped"
        assert result.reason == expected_reason
        assert backend.calls == []
        warnings = rest_send.sender.ansible_module.warnings
        assert len(warnings) == 1
        assert expected_reason in warnings[0]

    def test_facade_warns_for_skipped_action_steps(self):
        """
        # Summary

        Verify skipped deploy steps from the controller are surfaced through `rest_send.warn`.

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions_plan()
        """
        rest_send = _make_rest_send([])
        orch = _make_orchestrator(rest_send)
        actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
        context = ConfigActionsContext(fabric_names=("FAB1",), state="merged", switch_ids=())
        backend = FacadeBackend()

        result = orch.execute_config_actions_plan(actions=actions, context=context, backend=backend)

        assert result.status == "completed"
        assert result.reason == "actions_executed_with_skips"
        assert backend.calls == [("save", "FAB1", "merged")]
        warnings = rest_send.sender.ansible_module.warnings
        assert len(warnings) == 1
        assert "deploy" in warnings[0]
        assert "switch" in warnings[0]
        assert "no_targets" in warnings[0]

    def test_facade_warns_once_when_all_action_steps_are_skipped(self):
        """
        # Summary

        Verify all-skipped controller results emit one top-level warning.

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions_plan()
        """
        rest_send = _make_rest_send([])
        orch = _make_orchestrator(rest_send)
        actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
        result = ConfigActionsResult(
            requested=actions,
            effective=actions,
            status="skipped",
            reason="no_targets",
            targets={"fabrics": ("FAB1",), "switches": (), "resources": ()},
            actions=(ConfigActionStepResult(action="deploy", status="skipped", scope="switch", target="FAB1", error="no_targets"),),
        )

        orch._warn_skipped_config_actions(result)

        warnings = rest_send.sender.ansible_module.warnings
        assert warnings == ["Skipping config actions for fabric(s) FAB1: no_targets."]
