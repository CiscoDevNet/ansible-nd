# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for ManageExtendedCommunityListOrchestrator."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.manage_extended_community_list import (
    ExtendedCommunityListModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_extended_community_list import (
    ManageExtendedCommunityListOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_manage_extended_community_list(key: str):
    """Load fixture data for manage extended community list orchestrator tests."""
    return load_fixture("test_manage_extended_community_list")[key]


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1") -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False, "fabric_name": fabric_name})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


class _FakeFabricContext:
    """Minimal `FabricContext` stand-in for query preflight."""

    def __init__(self) -> None:
        self.validated = False

    def validate_for_mutation(self) -> None:
        """Record that preflight validation was invoked."""
        self.validated = True


def _instance(gen_responses: ResponseGenerator) -> tuple[RestSend, ManageExtendedCommunityListOrchestrator, _FakeFabricContext]:
    """Build a `RestSend` and orchestrator with fake fabric preflight."""
    rest_send = _build_rest_send(gen_responses)
    instance = ManageExtendedCommunityListOrchestrator(rest_send=rest_send)
    fabric_context = _FakeFabricContext()
    instance._fabric_context = fabric_context
    return rest_send, instance, fabric_context


def _model(name: str = "ECL1") -> ExtendedCommunityListModel:
    """Build a standard extended community list model."""
    return ExtendedCommunityListModel.from_config(
        {
            "name": name,
            "type": "standard",
            "entries": [{"sequence_number": 10, "action": "permit", "route_target_collection": ["65000:100"]}],
        }
    )


def test_manage_extended_community_list_00010() -> None:
    """
    # Summary

    Verify orchestrator initialization and fabric_name lookup from RestSend params.

    ## Classes and Methods

    - ManageExtendedCommunityListOrchestrator.__init__()
    - ManageExtendedCommunityListOrchestrator.fabric_name
    """

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()), fabric_name="SITE1")

    with does_not_raise():
        instance = ManageExtendedCommunityListOrchestrator(rest_send=rest_send)

    assert instance.model_class is ExtendedCommunityListModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    assert instance.fabric_name == "SITE1"


def test_manage_extended_community_list_00030() -> None:
    """
    # Summary

    Verify query_all validates fabric prerequisites and extracts the response wrapper.

    ## Classes and Methods

    - ManageExtendedCommunityListOrchestrator.query_all()
    - ManageExtendedCommunityListOrchestrator.validate_prerequisites()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_extended_community_list(f"{method_name}a")

    unused_rest_send, instance, fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None

    result = instance.query_all()

    assert fabric_context.validated is True
    assert result[0]["name"] == "ECL1"


def test_manage_extended_community_list_00100() -> None:
    """
    # Summary

    Verify create_bulk sends the wrapped payload and accepts all-success 207 results.

    ## Classes and Methods

    - ManageExtendedCommunityListOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_extended_community_list(f"{method_name}a")

    rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_fabric_context is not None

    with does_not_raise():
        instance.create_bulk([_model()])

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/extendedCommunityLists"
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.committed_payload["extendedCommunityLists"][0]["name"] == "ECL1"


def test_manage_extended_community_list_00110() -> None:
    """
    # Summary

    Verify create_bulk raises when a 207 result item reports failure.

    ## Classes and Methods

    - ManageExtendedCommunityListOrchestrator.create_bulk()
    - ManageExtendedCommunityListOrchestrator._raise_on_207_action_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_extended_community_list(f"{method_name}a")

    unused_rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None
    assert unused_fabric_context is not None

    with pytest.raises(RuntimeError, match="duplicate name"):
        instance.create_bulk([_model()])


def test_manage_extended_community_list_00120() -> None:
    """
    # Summary

    Verify writes reject name-only models while still allowing them for delete models.

    ## Classes and Methods

    - ManageExtendedCommunityListOrchestrator.create()
    - ManageExtendedCommunityListOrchestrator._validate_write_model()
    """

    def responses():
        yield {}

    unused_rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None
    assert unused_fabric_context is not None

    with pytest.raises(RuntimeError, match="requires type, entries"):
        instance.create(ExtendedCommunityListModel.from_config({"name": "ECL1"}))


def test_manage_extended_community_list_00200() -> None:
    """
    # Summary

    Verify update sends a per-item PUT payload.

    ## Classes and Methods

    - ManageExtendedCommunityListOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_extended_community_list(f"{method_name}a")

    rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_fabric_context is not None

    instance.update(_model())

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/extendedCommunityLists/ECL1"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    assert rest_send.committed_payload["entries"][0]["routeTargetCollection"] == ["65000:100"]


def test_manage_extended_community_list_00300() -> None:
    """
    # Summary

    Verify delete_bulk only needs names and uses the action endpoint.

    ## Classes and Methods

    - ManageExtendedCommunityListOrchestrator.delete_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_extended_community_list(f"{method_name}a")

    rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_fabric_context is not None

    instance.delete_bulk([ExtendedCommunityListModel.from_config({"name": "ECL1"})])

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/extendedCommunityListActions/remove"
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.committed_payload == {"extendedCommunityListNames": ["ECL1"]}
