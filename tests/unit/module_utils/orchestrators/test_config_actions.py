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
    ConfigActionStepResult,
    ConfigActionsContext,
    ConfigActionsExecutionError,
    ConfigActionsResult,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.backends.fabric import FabricConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.mixin import ConfigActionsMixin
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

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

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    rest_send = RestSend({"check_mode": False, "state": "merged"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    return rest_send


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


def _make_orchestrator(rest_send, results=None):
    """Create a ConfigActionsOrchestrator with stub endpoints and the given RestSend."""
    return ConfigActionsOrchestrator(
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
        """Verify _deploy_switch_ids returns None and makes no API call when empty."""
        rest_send = _make_rest_send([])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        result = orch.deploy_switch_ids("test-fabric", [])

        assert result is None
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
        rest_send = _make_rest_send([_success_response(data={"status": "deployed"})])
        orch = _make_orchestrator(rest_send, _make_results())
        backend = FabricConfigActionsBackend(orch)

        backend.deploy_global(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1")

        assert "actions/deploy" in rest_send.path
        assert "switchActions" not in rest_send.path

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
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())
        backend = FabricConfigActionsBackend(orch)

        backend.deploy_switches(ConfigActionsContext(fabric_names=("FAB1",), state="merged"), "FAB1", ("FOC111AAA",))

        assert "switchActions/deploy" in rest_send.path
        # FOC222BBB needs deploy but is not a candidate, so it is excluded.
        assert rest_send.committed_payload == {"switchIds": ["FOC111AAA"]}

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

        assert result is None
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

    def test_collects_all_paginated_switch_membership_when_later_metadata_is_omitted(self, monkeypatch):
        """Verify known counts continue switch collection across a metadata-free final page."""
        pages = [
            {
                "switches": [{"switchId": "NODE-101"}],
                "meta": {"counts": {"remaining": 1, "total": 2}},
            },
            {"switches": [{"switchId": "NODE-102"}]},
        ]
        rest_send = _make_rest_send([_success_response(data=page, method="GET") for page in pages])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        monkeypatch.setattr(ConfigActionsOrchestrator, "config_actions_switch_page_size", 1)

        context = orch.build_config_actions_context(["FAB1"], state="merged")

        assert context.switch_ids_by_fabric == {"FAB1": ("NODE-101", "NODE-102")}
        assert len(results._tasks) == 2
        assert "max=1" in results._tasks[0].path
        assert "offset=0" in results._tasks[0].path
        assert "max=1" in results._tasks[1].path
        assert "offset=1" in results._tasks[1].path

    def test_terminal_switch_counts_override_a_nonempty_next_link(self, monkeypatch):
        """Verify terminal counts stop pagination despite the templated next link in API examples."""
        page = {
            "switches": [{"switchId": "NODE-101"}],
            "meta": {
                "counts": {"remaining": 0, "total": 1},
                "links": {"next": "/switches?offset=1&max=1"},
            },
        }
        rest_send = _make_rest_send([_success_response(data=page, method="GET")])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        monkeypatch.setattr(ConfigActionsOrchestrator, "config_actions_switch_page_size", 1)

        context = orch.build_config_actions_context(["FAB1"], state="merged")

        assert context.switch_ids_by_fabric == {"FAB1": ("NODE-101",)}
        assert len(results._tasks) == 1


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
        assert len(results._tasks) == 3
        assert "actions/deploy" in rest_send.path

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
        # membership query + save + post-save query + deploy
        assert len(results._tasks) == 4
        assert "switchActions/deploy" in rest_send.path
        assert rest_send.committed_payload == {"switchIds": ["FOC111AAA"]}

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
        assert "switchActions/deploy" in rest_send.path
        assert rest_send.committed_payload == {"switchIds": ["leaf1", "leaf2"]}

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

        orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        # membership query + save + post-save query, no deploy POST
        assert len(results._tasks) == 3
        assert "switchActions/deploy" not in rest_send.path

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
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        orch.run_config_actions(
            actions=self._switch_actions(),
            fabric_names=["FAB1"],
            state="merged",
            only_switch_ids={"leaf1", "leaf3"},
        )

        assert "switchActions/deploy" in rest_send.path
        assert rest_send.committed_payload == {"switchIds": ["leaf1", "leaf3"]}

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
            ]
        )
        orch = _make_orchestrator(rest_send, _make_results())

        orch.run_config_actions(
            actions=self._switch_actions(),
            fabric_names=["FAB1"],
            state="merged",
            only_switch_ids={"leaf1"},
        )

        assert rest_send.committed_payload == {"switchIds": ["leaf1"]}

    def test_global_deploy_ignores_only_switch_ids(self):
        switches_response = {"switches": [{"serialNumber": "leaf1", "additionalData": {"configSyncStatus": "outOfSync"}}]}
        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data={"status": "saved"}),
                _success_response(data={"status": "deployed"}),
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

        assert "actions/deploy" in rest_send.path
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

        with pytest.raises(ConfigActionsExecutionError, match=r"Config action 'save' failed for 'FAB1'") as exc_info:
            orch.run_config_actions(actions=actions, fabric_names=["FAB1"], state="merged")

        assert exc_info.value.result.status == "failed"
        assert exc_info.value.result.actions[0].action == "save"

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
