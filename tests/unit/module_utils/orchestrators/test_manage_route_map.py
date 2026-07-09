# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ManageRouteMapOrchestrator.

Verifies that route-map CRUD methods configure fabric-scoped endpoints, unwrap list responses,
wrap create/delete bulk payloads, and fail on per-item 207 bulk errors.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_route_map.manage_route_map import RouteMapModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_route_map import ManageRouteMapOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def _response(data: dict | None = None, return_code: int = 200, message: str = "OK") -> dict:
    return {
        "RETURN_CODE": return_code,
        "MESSAGE": message,
        "DATA": data or {},
    }


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "SITE1") -> RestSend:
    """Build a RestSend wired to file-style sender responses."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    rest_send = RestSend({"check_mode": False, "fabric_name": fabric_name, "state": "merged"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _route_map_model(name: str = "RM1", value: int = 100, tenant_name: str | None = None) -> RouteMapModel:
    """Build a minimal route map model."""
    config = {
        "name": name,
        "entries": [
            {
                "sequence_number": 10,
                "action": "permit",
                "rule_entries": [
                    {
                        "rule_type": "setLocalPreference",
                        "value": value,
                    }
                ],
            }
        ],
    }
    if tenant_name is not None:
        config["tenant_name"] = tenant_name
    return RouteMapModel.from_config(config)


class _FakeFabricContext:
    """FabricContext stand-in that records mutation validation."""

    def __init__(self) -> None:
        self.called = False

    def validate_for_mutation(self) -> None:
        self.called = True


def test_manage_route_map_orchestrator_00010() -> None:
    """
    # Summary

    Verify the orchestrator instantiates with current framework defaults.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.__init__()
    """

    def responses():
        yield _response()

    rest_send = _build_rest_send(ResponseGenerator(responses()))

    with does_not_raise():
        instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    assert instance.model_class is RouteMapModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    assert instance.fabric_name == "SITE1"


def test_manage_route_map_orchestrator_00020() -> None:
    """
    # Summary

    Verify preflight delegates to FabricContext validation when proposed config exists.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.preflight()
    """

    def responses():
        yield _response()

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)
    fake_context = _FakeFabricContext()
    instance._fabric_context = fake_context

    instance.preflight([_route_map_model()])

    assert fake_context.called is True


def test_manage_route_map_orchestrator_00100() -> None:
    """
    # Summary

    Verify query_all unwraps the routeMaps response list.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.query_all()
    """

    def responses():
        yield _response({"routeMaps": [_route_map_model().to_payload()]})

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == [_route_map_model().to_payload()]
    assert rest_send.path == "/api/v1/manage/fabrics/SITE1/routeMaps"
    assert rest_send.verb == HttpVerbEnum.GET


def test_manage_route_map_orchestrator_00110() -> None:
    """
    # Summary

    Verify query_one sets the route map identifier in the endpoint path.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.query_one()
    """
    model = _route_map_model("RM_ONE")

    def responses():
        yield _response(model.to_payload())

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_one(model)

    assert result == model.to_payload()
    assert rest_send.path == "/api/v1/manage/fabrics/SITE1/routeMaps/RM_ONE"
    assert rest_send.verb == HttpVerbEnum.GET


def test_manage_route_map_orchestrator_00200() -> None:
    """
    # Summary

    Verify create_bulk wraps route maps under the routeMaps payload key.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.create_bulk()
    """
    model = _route_map_model("RM_CREATE")

    def responses():
        yield _response({"results": [{"name": "RM_CREATE", "status": "success", "message": "created"}]}, return_code=207, message="Multi-Status")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.create_bulk([model])

    assert rest_send.path == "/api/v1/manage/fabrics/SITE1/routeMaps"
    assert rest_send.verb == HttpVerbEnum.POST
    assert rest_send.committed_payload == {"routeMaps": [model.to_payload()]}


def test_manage_route_map_orchestrator_00210() -> None:
    """
    # Summary

    Verify create delegates to create_bulk for single route maps.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.create()
    """
    model = _route_map_model("RM_CREATE_ONE")

    def responses():
        yield _response({"results": [{"name": "RM_CREATE_ONE", "status": "success", "message": "created"}]}, return_code=207, message="Multi-Status")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.create(model)

    assert rest_send.committed_payload == {"routeMaps": [model.to_payload()]}


def test_manage_route_map_orchestrator_00220() -> None:
    """
    # Summary

    Verify create_bulk raises on failed per-item 207 results.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.create_bulk()
    - ManageRouteMapOrchestrator._raise_on_bulk_errors()
    """
    model = _route_map_model("RM_EXISTS")

    def responses():
        yield _response(
            {"results": [{"name": "RM_EXISTS", "status": "failed", "message": "Route map already exists."}]}, return_code=207, message="Multi-Status"
        )

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with pytest.raises(Exception, match=r"Bulk create failed: Route map bulk create failed for RM_EXISTS: failed: Route map already exists\."):
        instance.create_bulk([model])


def test_manage_route_map_orchestrator_00300() -> None:
    """
    # Summary

    Verify update sends a per-route-map PUT with the model payload.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.update()
    """
    model = _route_map_model("RM_UPDATE", value=250)

    def responses():
        yield _response(return_code=204, message="No Content")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/SITE1/routeMaps/RM_UPDATE"
    assert rest_send.verb == HttpVerbEnum.PUT
    assert rest_send.committed_payload == model.to_payload()


def test_manage_route_map_orchestrator_00310() -> None:
    """
    # Summary

    Verify tenant-scoped updates use the fully qualified API path with a bare-name payload.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.update()
    """
    model = _route_map_model("RM_UPDATE", value=250, tenant_name="tenantSales")

    def responses():
        yield _response(return_code=204, message="No Content")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/fabrics/SITE1/routeMaps/tenantSales~RM_UPDATE"
    assert rest_send.verb == HttpVerbEnum.PUT
    assert rest_send.committed_payload == model.to_payload()
    assert rest_send.committed_payload["name"] == "RM_UPDATE"
    assert rest_send.committed_payload["tenantName"] == "tenantSales"


def test_manage_route_map_orchestrator_00400() -> None:
    """
    # Summary

    Verify delete_bulk wraps route map identifiers under routeMapNames.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.delete_bulk()
    """
    model = RouteMapModel.from_config({"name": "RM_DELETE"})

    def responses():
        yield _response({"results": [{"name": "RM_DELETE", "status": "success", "message": "removed"}]}, return_code=207, message="Multi-Status")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.delete_bulk([model])

    assert rest_send.path == "/api/v1/manage/fabrics/SITE1/routeMapActions/remove"
    assert rest_send.verb == HttpVerbEnum.POST
    assert rest_send.committed_payload == {"routeMapNames": ["RM_DELETE"]}


def test_manage_route_map_orchestrator_00405() -> None:
    """
    # Summary

    Verify tenant-scoped delete payloads use fully qualified API names.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.delete_bulk()
    """
    model = RouteMapModel.from_config({"name": "RM_DELETE", "tenant_name": "tenantSales"})

    def responses():
        yield _response({"results": [{"name": "tenantSales~RM_DELETE", "status": "success", "message": "removed"}]}, return_code=207, message="Multi-Status")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.delete_bulk([model])

    assert rest_send.path == "/api/v1/manage/fabrics/SITE1/routeMapActions/remove"
    assert rest_send.verb == HttpVerbEnum.POST
    assert rest_send.committed_payload == {"routeMapNames": ["tenantSales~RM_DELETE"]}


def test_manage_route_map_orchestrator_00410() -> None:
    """
    # Summary

    Verify delete delegates to delete_bulk for single route maps.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.delete()
    """
    model = RouteMapModel.from_config({"name": "RM_DELETE_ONE"})

    def responses():
        yield _response({"results": [{"name": "RM_DELETE_ONE", "status": "success", "message": "removed"}]}, return_code=207, message="Multi-Status")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with does_not_raise():
        instance.delete(model)

    assert rest_send.committed_payload == {"routeMapNames": ["RM_DELETE_ONE"]}


def test_manage_route_map_orchestrator_00420() -> None:
    """
    # Summary

    Verify delete_bulk raises on failed per-item 207 results.

    ## Classes and Methods

    - ManageRouteMapOrchestrator.delete_bulk()
    - ManageRouteMapOrchestrator._raise_on_bulk_errors()
    """
    model = RouteMapModel.from_config({"name": "RM_MISSING"})

    def responses():
        yield _response({"results": [{"name": "RM_MISSING", "status": "failed", "message": "Route map not found."}]}, return_code=207, message="Multi-Status")

    rest_send = _build_rest_send(ResponseGenerator(responses()))
    instance = ManageRouteMapOrchestrator(rest_send=rest_send)

    with pytest.raises(Exception, match=r"Bulk delete failed: Route map bulk delete failed for RM_MISSING: failed: Route map not found\."):
        instance.delete_bulk([model])
