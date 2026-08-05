# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for orchestrators/config_actions_mixin.py

Tests the ConfigActionsMixin class focusing on:
- config_save calls _request with correct path/verb and no body
- config_deploy with deploy_type="global" calls _request with correct path/verb and no body
- config_deploy with deploy_type="switch" queries switches, filters by configSyncStatus, deploys to out-of-sync switches
- config_deploy with deploy_type="switch" skips deploy when all switches are inSync
- config_deploy with invalid deploy_type raises ValueError
- execute_config_actions orchestrates save and deploy for multiple fabrics
- execute_config_actions raises ValueError when deploy=True and save=False
- execute_config_actions is a no-op when both save and deploy are False
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from typing import ClassVar, Literal, Optional

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import SWITCH_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions_mixin import ConfigActionsMixin
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

    def __init__(self) -> None:
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
# Test: config_deploy — global
# =============================================================================


class TestConfigDeployGlobal:
    """Tests for ConfigActionsMixin.config_deploy() with deploy_type='global'."""

    def test_deploy_global_calls_correct_endpoint(self):
        """
        # Summary

        Verify config_deploy with deploy_type='global' sends POST to
        /fabrics/{fabricName}/actions/deploy with no body.

        ## Test

        - _request is called with the fabric deploy endpoint path
        - verb is POST
        - No data payload is sent

        ## Classes and Methods

        - ConfigActionsMixin.config_deploy()
        - ConfigActionsMixin._deploy_global()
        """
        rest_send = _make_rest_send(
            [
                _success_response(data={"status": "Configuration deployment completed"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.config_deploy("test-fabric", deploy_type="global")

        assert len(results._tasks) == 1
        assert "actions/deploy" in rest_send.path
        assert "test-fabric" in rest_send.path
        # Should NOT contain switchActions
        assert "switchActions" not in rest_send.path

    def test_deploy_global_registered_as_update(self):
        """
        # Summary

        Verify global deploy registers as UPDATE operation.

        ## Test

        - Results captures the API call at verbosity level 2

        ## Classes and Methods

        - ConfigActionsMixin._deploy_global()
        """
        rest_send = _make_rest_send(
            [
                _success_response(data={"status": "Configuration deployment completed"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.config_deploy("test-fabric", deploy_type="global")

        assert results._tasks[0].verbosity_level == 2


# =============================================================================
# Test: config_deploy — switch
# =============================================================================


class TestConfigDeploySwitch:
    """Tests for ConfigActionsMixin.config_deploy() with deploy_type='switch'."""

    def test_deploy_switch_queries_switches_and_deploys_out_of_sync(self):
        """
        # Summary

        Verify config_deploy with deploy_type='switch' queries switches,
        filters by configSyncStatus, and deploys to out-of-sync switches.

        ## Test

        - First call is GET to /fabrics/{fabricName}/switches
        - Second call is POST to /fabrics/{fabricName}/switchActions/deploy
        - POST body contains switchIds of out-of-sync switches

        ## Classes and Methods

        - ConfigActionsMixin.config_deploy()
        - ConfigActionsMixin._deploy_switches()
        - ConfigActionsMixin._get_switches_needing_deploy()
        """
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
                {
                    "serialNumber": "FOC333CCC",
                    "additionalData": {"configSyncStatus": "pending"},
                },
            ]
        }
        deploy_response = {
            "switchIds": [
                {"switchId": "FOC111AAA", "status": "success"},
                {"switchId": "FOC333CCC", "status": "success"},
            ]
        }

        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data=deploy_response),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        result = orch.config_deploy("test-fabric", deploy_type="switch")

        # Two API calls: GET switches + POST switchActions/deploy
        assert len(results._tasks) == 2
        # First call is a QUERY (verbosity 3)
        assert results._tasks[0].verbosity_level == 3
        # Second call is UPDATE (verbosity 2)
        assert results._tasks[1].verbosity_level == 2
        # Deploy endpoint was called
        assert "switchActions/deploy" in rest_send.path
        # Payload contained the out-of-sync switch serial numbers
        assert rest_send.committed_payload == {"switchIds": ["FOC111AAA", "FOC333CCC"]}

    def test_deploy_switch_skips_when_all_in_sync(self):
        """
        # Summary

        Verify config_deploy with deploy_type='switch' returns None and does
        not call switchActions/deploy when all switches are inSync.

        ## Test

        - Only GET to /fabrics/{fabricName}/switches is called
        - No POST to switchActions/deploy
        - Returns None

        ## Classes and Methods

        - ConfigActionsMixin.config_deploy()
        - ConfigActionsMixin._deploy_switches()
        - ConfigActionsMixin._get_switches_needing_deploy()
        """
        switches_response = {
            "switches": [
                {
                    "serialNumber": "FOC111AAA",
                    "additionalData": {"configSyncStatus": "inSync"},
                },
                {
                    "serialNumber": "FOC222BBB",
                    "additionalData": {"configSyncStatus": "inSync"},
                },
            ]
        }

        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        result = orch.config_deploy("test-fabric", deploy_type="switch")

        # Only the switches query was made
        assert len(results._tasks) == 1
        assert result is None

    def test_deploy_switch_skips_when_no_switches(self):
        """
        # Summary

        Verify config_deploy with deploy_type='switch' returns None when
        no switches exist in the fabric.

        ## Test

        - GET returns empty switches list
        - No deploy call is made
        - Returns None

        ## Classes and Methods

        - ConfigActionsMixin._deploy_switches()
        - ConfigActionsMixin._get_switches_needing_deploy()
        """
        rest_send = _make_rest_send(
            [
                _success_response(data={"switches": []}, method="GET"),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        result = orch.config_deploy("test-fabric", deploy_type="switch")

        assert len(results._tasks) == 1
        assert result is None

    def test_deploy_switch_includes_empty_or_missing_status(self):
        """
        # Summary

        Verify config_deploy with deploy_type='switch' treats an empty or
        missing configSyncStatus as "not inSync" and includes those switches
        in the deploy set.

        ## Test

        - Switch with configSyncStatus="" is included
        - Switch with no configSyncStatus key is included
        - Switch with configSyncStatus="inSync" is excluded
        - POST body contains only the non-inSync switch serial numbers

        ## Classes and Methods

        - ConfigActionsMixin.config_deploy()
        - ConfigActionsMixin._deploy_switches()
        - ConfigActionsMixin._get_switches_needing_deploy()
        """
        switches_response = {
            "switches": [
                {
                    "serialNumber": "FOC111AAA",
                    "additionalData": {"configSyncStatus": ""},
                },
                {
                    "serialNumber": "FOC222BBB",
                    "additionalData": {},
                },
                {
                    "serialNumber": "FOC333CCC",
                    "additionalData": {"configSyncStatus": "inSync"},
                },
            ]
        }
        deploy_response = {
            "switchIds": [
                {"switchId": "FOC111AAA", "status": "success"},
                {"switchId": "FOC222BBB", "status": "success"},
            ]
        }

        rest_send = _make_rest_send(
            [
                _success_response(data=switches_response, method="GET"),
                _success_response(data=deploy_response),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.config_deploy("test-fabric", deploy_type="switch")

        # Two API calls: GET switches + POST switchActions/deploy
        assert len(results._tasks) == 2
        assert "switchActions/deploy" in rest_send.path
        # Empty and missing statuses are treated as needing deploy; inSync excluded
        assert rest_send.committed_payload == {"switchIds": ["FOC111AAA", "FOC222BBB"]}


# =============================================================================
# Test: config_deploy — invalid deploy_type
# =============================================================================


class TestConfigDeployInvalidType:
    """Tests for ConfigActionsMixin.config_deploy() with invalid deploy_type."""

    def test_deploy_invalid_type_raises_value_error(self):
        """
        # Summary

        Verify config_deploy raises ValueError for invalid deploy_type.

        ## Test

        - ValueError is raised with descriptive message
        - No API calls are made

        ## Classes and Methods

        - ConfigActionsMixin.config_deploy()
        """
        rest_send = _make_rest_send([])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        with pytest.raises(ValueError, match="Invalid deploy_type"):
            orch.config_deploy("test-fabric", deploy_type="invalid")

        assert len(results._tasks) == 0


# =============================================================================
# Test: execute_config_actions
# =============================================================================


class TestExecuteConfigActions:
    """Tests for ConfigActionsMixin.execute_config_actions()."""

    def test_execute_save_and_global_deploy(self):
        """
        # Summary

        Verify execute_config_actions with save=True, deploy=True, deploy_type='global'
        calls config_save then config_deploy for each fabric.

        ## Test

        - config_save is called (POST configSave)
        - config_deploy is called (POST actions/deploy)
        - Both fabrics are processed

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions()
        - ConfigActionsMixin.config_save()
        - ConfigActionsMixin.config_deploy()
        """
        rest_send = _make_rest_send(
            [
                # Fabric 1: save
                _success_response(data={"status": "Config save is completed"}),
                # Fabric 1: deploy
                _success_response(data={"status": "Configuration deployment completed"}),
                # Fabric 2: save
                _success_response(data={"status": "Config save is completed"}),
                # Fabric 2: deploy
                _success_response(data={"status": "Configuration deployment completed"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.execute_config_actions(
            fabric_names=["fabric-1", "fabric-2"],
            save=True,
            deploy=True,
            deploy_type="global",
        )

        # 4 API calls: save + deploy for each of 2 fabrics
        assert len(results._tasks) == 4

    def test_execute_save_only(self):
        """
        # Summary

        Verify execute_config_actions with save=True, deploy=False only calls config_save.

        ## Test

        - config_save is called for each fabric
        - config_deploy is NOT called

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions()
        - ConfigActionsMixin.config_save()
        """
        rest_send = _make_rest_send(
            [
                _success_response(data={"status": "Config save is completed"}),
                _success_response(data={"status": "Config save is completed"}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.execute_config_actions(
            fabric_names=["fabric-1", "fabric-2"],
            save=True,
            deploy=False,
        )

        # 2 API calls: save for each fabric
        assert len(results._tasks) == 2

    def test_execute_deploy_without_save_raises_value_error(self):
        """
        # Summary

        Verify execute_config_actions raises ValueError when deploy=True but save=False.

        ## Test

        - ValueError is raised with descriptive message
        - No API calls are made

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions()
        """
        rest_send = _make_rest_send([])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        with pytest.raises(ValueError, match="deploy=True requires save=True"):
            orch.execute_config_actions(
                fabric_names=["fabric-1"],
                save=False,
                deploy=True,
            )

        assert len(results._tasks) == 0

    def test_execute_both_false_is_noop(self):
        """
        # Summary

        Verify execute_config_actions is a no-op when both save and deploy are False.

        ## Test

        - No API calls are made
        - No exceptions raised

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions()
        """
        rest_send = _make_rest_send([])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.execute_config_actions(
            fabric_names=["fabric-1", "fabric-2"],
            save=False,
            deploy=False,
        )

        assert len(results._tasks) == 0

    def test_execute_save_and_switch_deploy(self):
        """
        # Summary

        Verify execute_config_actions with deploy_type='switch' queries switches
        and deploys to out-of-sync ones after saving.

        ## Test

        - config_save is called (POST configSave)
        - Switches are queried (GET switches)
        - switchActions/deploy is called with out-of-sync switchIds

        ## Classes and Methods

        - ConfigActionsMixin.execute_config_actions()
        - ConfigActionsMixin.config_save()
        - ConfigActionsMixin.config_deploy()
        - ConfigActionsMixin._deploy_switches()
        """
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
                # save
                _success_response(data={"status": "Config save is completed"}),
                # query switches
                _success_response(data=switches_response, method="GET"),
                # switch deploy
                _success_response(data={"switchIds": [{"switchId": "FOC111AAA", "status": "success"}]}),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.execute_config_actions(
            fabric_names=["test-fabric"],
            save=True,
            deploy=True,
            deploy_type="switch",
        )

        # 3 API calls: save + GET switches + POST switchActions/deploy
        assert len(results._tasks) == 3


# =============================================================================
# Test: validate_config_actions (side-effect-free input validation)
# =============================================================================


class TestValidateConfigActions:
    """Tests for ConfigActionsMixin.validate_config_actions().

    This validator is intended to be called *before* any resource mutation and
    without an orchestrator instance, so invalid input fails deterministically
    on every run (including idempotent no-drift runs) and never mutates ND.
    """

    def test_deploy_without_save_raises_value_error(self):
        """
        # Summary

        Verify validate_config_actions raises ValueError when deploy=True and save=False.

        ## Classes and Methods

        - ConfigActionsMixin.validate_config_actions()
        """
        with pytest.raises(ValueError, match="deploy=True requires save=True"):
            ConfigActionsMixin.validate_config_actions(save=False, deploy=True, deploy_type="switch")

    def test_invalid_deploy_type_raises_value_error(self):
        """
        # Summary

        Verify validate_config_actions raises ValueError for an invalid deploy_type.

        ## Classes and Methods

        - ConfigActionsMixin.validate_config_actions()
        """
        with pytest.raises(ValueError, match="invalid type"):
            ConfigActionsMixin.validate_config_actions(save=True, deploy=True, deploy_type="bogus")

    def test_save_and_deploy_valid(self):
        """
        # Summary

        Verify validate_config_actions accepts save=True with deploy=True.

        ## Classes and Methods

        - ConfigActionsMixin.validate_config_actions()
        """
        ConfigActionsMixin.validate_config_actions(save=True, deploy=True, deploy_type="switch")
        ConfigActionsMixin.validate_config_actions(save=True, deploy=True, deploy_type="global")

    def test_save_only_valid(self):
        """
        # Summary

        Verify validate_config_actions accepts save=True with deploy=False.

        ## Classes and Methods

        - ConfigActionsMixin.validate_config_actions()
        """
        ConfigActionsMixin.validate_config_actions(save=True, deploy=False, deploy_type="switch")

    def test_both_false_valid(self):
        """
        # Summary

        Verify validate_config_actions accepts both save and deploy as False (no action).

        ## Classes and Methods

        - ConfigActionsMixin.validate_config_actions()
        """
        ConfigActionsMixin.validate_config_actions(save=False, deploy=False, deploy_type="switch")
        # Defaults are also valid (no action, default type).
        ConfigActionsMixin.validate_config_actions()

    def test_callable_on_orchestrator_class_without_instance(self):
        """
        # Summary

        Verify validate_config_actions is reachable via the concrete orchestrator class
        without constructing an instance, mirroring how module main() calls it before
        creating the state machine.

        ## Classes and Methods

        - ConfigActionsMixin.validate_config_actions()
        """
        with pytest.raises(ValueError, match="deploy=True requires save=True"):
            ConfigActionsOrchestrator.validate_config_actions(save=False, deploy=True, deploy_type="switch")


class TestConfigActionsControllerFacade:
    """Tests for ConfigActionsMixin.execute_config_actions_plan()."""

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
        orch = _make_orchestrator(_make_rest_send([]))
        actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
        context = ConfigActionsContext(fabric_names=("FAB1",), state="merged", switch_ids=("SER1",))

        with pytest.raises(ValueError, match="No config actions backend"):
            orch.execute_config_actions_plan(actions=actions, context=context)
