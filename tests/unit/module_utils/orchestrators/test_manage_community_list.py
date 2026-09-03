# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for ManageCommunityListOrchestrator."""

from __future__ import annotations

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_community_list.manage_community_list import CommunityListModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_community_list import ManageCommunityListOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_manage_community_list(key: str):
    """Load fixture data for manage community list orchestrator tests."""
    return load_fixture("test_manage_community_list")[key]


def _build_rest_send(gen_responses: ResponseGenerator, fabric_name: str = "fabric_1", cluster_name: str | None = None) -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params = {"check_mode": False, "fabric_name": fabric_name}
    if cluster_name is not None:
        params["cluster_name"] = cluster_name
    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


class _FakeFabricContext:
    """Minimal `FabricContext` stand-in for mutation preflight."""

    def __init__(self) -> None:
        self.validated = False

    def validate_for_mutation(self) -> None:
        """Record that preflight validation was invoked."""
        self.validated = True


def _instance(gen_responses: ResponseGenerator) -> tuple[RestSend, ManageCommunityListOrchestrator, _FakeFabricContext]:
    """Build a `RestSend` and orchestrator with fake fabric preflight."""
    rest_send = _build_rest_send(gen_responses)
    instance = ManageCommunityListOrchestrator(rest_send=rest_send)
    fabric_context = _FakeFabricContext()
    instance._fabric_context = fabric_context
    return rest_send, instance, fabric_context


def _model(name: str = "CL1", tenant_name: str | None = None) -> CommunityListModel:
    """Build a standard community list model."""
    config = {
        "name": name,
        "type": "standard",
        "entries": [{"sequence_number": 10, "action": "permit", "community_numbers": ["100:200"]}],
    }
    if tenant_name is not None:
        config["tenant_name"] = tenant_name
    return CommunityListModel.from_config(config)


def test_manage_community_list_00010() -> None:
    """
    # Summary

    Verify orchestrator initialization and fabric_name lookup from RestSend params.

    ## Classes and Methods

    - ManageCommunityListOrchestrator.__init__()
    - ManageCommunityListOrchestrator.fabric_name
    """

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()), fabric_name="SITE1")

    with does_not_raise():
        instance = ManageCommunityListOrchestrator(rest_send=rest_send)

    assert instance.model_class is CommunityListModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    assert instance.fabric_name == "SITE1"


def test_manage_community_list_00030() -> None:
    """
    # Summary

    Verify query_all reads inventory without running mutation preflight.

    ## Classes and Methods

    - ManageCommunityListOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_community_list(f"{method_name}a")

    unused_rest_send, instance, fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None

    result = instance.query_all()

    assert fabric_context.validated is False
    assert result[0]["name"] == "CL1"


def test_manage_community_list_00020() -> None:
    """Verify mutation preflight delegates to FabricContext only when config exists."""

    def responses():
        yield {}

    unused_rest_send, instance, fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None

    instance.preflight([])
    assert fabric_context.validated is False
    instance.preflight([_model()])
    assert fabric_context.validated is True


def test_manage_community_list_00100() -> None:
    """
    # Summary

    Verify create_bulk sends the wrapped payload and accepts all-success 207 results.

    ## Classes and Methods

    - ManageCommunityListOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_community_list(f"{method_name}a")

    rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_fabric_context is not None

    with does_not_raise():
        instance.create_bulk([_model()])

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/communityLists"
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.committed_payload["communityLists"][0]["name"] == "CL1"


def test_manage_community_list_00110() -> None:
    """
    # Summary

    Verify create_bulk raises when a 207 result item reports failure.

    ## Classes and Methods

    - ManageCommunityListOrchestrator.create_bulk()
    - ManageCommunityListOrchestrator._raise_on_207_action_errors()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_community_list(f"{method_name}a")

    unused_rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None
    assert unused_fabric_context is not None

    with pytest.raises(RuntimeError, match="duplicate name"):
        instance.create_bulk([_model()])


def test_manage_community_list_00115() -> None:
    """Verify non-failure and missing 207 status tokens are tolerated."""
    result = {
        "results": [
            {"name": "CL1", "status": "accepted", "message": "queued"},
            {"name": "CL2", "status": "", "message": "no status"},
            {"name": "CL3", "message": "status omitted"},
        ]
    }

    with does_not_raise():
        ManageCommunityListOrchestrator._raise_on_207_action_errors(result)


def test_manage_community_list_00120() -> None:
    """
    # Summary

    Verify writes reject name-only models while still allowing them for delete models.

    ## Classes and Methods

    - ManageCommunityListOrchestrator.create()
    - ManageCommunityListOrchestrator._validate_write_model()
    """

    def responses():
        yield {}

    unused_rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None
    assert unused_fabric_context is not None

    with pytest.raises(RuntimeError, match="requires type, entries"):
        instance.create(CommunityListModel.from_config({"name": "CL1"}))


def test_manage_community_list_00200() -> None:
    """
    # Summary

    Verify update sends a per-item PUT payload.

    ## Classes and Methods

    - ManageCommunityListOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_community_list(f"{method_name}a")

    rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_fabric_context is not None

    instance.update(_model())

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/communityLists/CL1"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    assert rest_send.committed_payload["entries"][0]["communityNumbers"] == ["100:200"]


def test_manage_community_list_00300() -> None:
    """
    # Summary

    Verify delete_bulk only needs names and uses the action endpoint.

    ## Classes and Methods

    - ManageCommunityListOrchestrator.delete_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_manage_community_list(f"{method_name}a")

    rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_fabric_context is not None

    instance.delete_bulk([CommunityListModel.from_config({"name": "CL1"})])

    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/communityListActions/remove"
    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.committed_payload == {"communityListNames": ["CL1"]}


def test_manage_community_list_00310() -> None:
    """Verify tenant-scoped update paths and delete payloads use API names."""
    update_model = _model("CL1", tenant_name="tenantA")

    def responses():
        yield responses_manage_community_list("test_manage_community_list_00200a")
        yield responses_manage_community_list("test_manage_community_list_00300a")

    rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_fabric_context is not None

    instance.update(update_model)
    assert rest_send.path == "/api/v1/manage/fabrics/fabric_1/communityLists/tenantA~CL1"
    assert rest_send.committed_payload["name"] == "tenantA~CL1"

    instance.delete_bulk([CommunityListModel.from_config({"name": "CL1", "tenant_name": "tenantA"})])
    assert rest_send.committed_payload == {"communityListNames": ["tenantA~CL1"]}


def test_manage_community_list_00320(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify custom mutation paths record create, update, and delete operation types."""
    operation_types = []

    def fake_request(*args, **kwargs):
        operation_types.append(kwargs.get("operation_type"))
        return {"results": []}

    def responses():
        yield {}

    unused_rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None
    assert unused_fabric_context is not None
    monkeypatch.setattr(instance, "_request", fake_request)
    model = _model()

    instance.create_bulk([model])
    instance.update(model)
    instance.delete_bulk([model])

    assert operation_types == [OperationType.CREATE, OperationType.UPDATE, OperationType.DELETE]


def test_manage_community_list_00400(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify query_all walks and de-duplicates Lucene pages."""
    pages = [
        {"communityLists": [{"name": "CL1"}, {"name": "CL2"}]},
        {"communityLists": [{"name": "CL2"}, {"name": "CL3"}]},
        {"communityLists": []},
    ]
    paths = []

    def fake_request(*args, **kwargs):
        paths.append(kwargs["path"])
        return pages.pop(0)

    def responses():
        yield {}

    unused_rest_send, instance, unused_fabric_context = _instance(ResponseGenerator(responses()))
    assert unused_rest_send is not None
    assert unused_fabric_context is not None
    monkeypatch.setattr(ManageCommunityListOrchestrator, "query_all_page_size", 2)
    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all()

    assert [item["name"] for item in result] == ["CL1", "CL2", "CL3"]
    assert paths == [
        "/api/v1/manage/fabrics/fabric_1/communityLists?max=2&offset=0",
        "/api/v1/manage/fabrics/fabric_1/communityLists?max=2&offset=2",
        "/api/v1/manage/fabrics/fabric_1/communityLists?max=2&offset=4",
    ]


def test_manage_community_list_00410(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify cluster_name is forwarded to collection and item reads."""
    paths = []

    def fake_request(*args, **kwargs):
        paths.append(kwargs["path"])
        return {"communityLists": []}

    def responses():
        yield {}

    rest_send = _build_rest_send(ResponseGenerator(responses()), cluster_name="cluster-1")
    instance = ManageCommunityListOrchestrator(rest_send=rest_send)
    instance._fabric_context = _FakeFabricContext()
    monkeypatch.setattr(instance, "_request", fake_request)

    instance.query_all()
    instance.query_one(_model())

    assert paths == [
        "/api/v1/manage/fabrics/fabric_1/communityLists?clusterName=cluster-1&max=100&offset=0",
        "/api/v1/manage/fabrics/fabric_1/communityLists/CL1?clusterName=cluster-1",
    ]


# =============================================================================
# Test: Gathered state — orchestrator ClassVars and query routing
# =============================================================================


def test_manage_community_list_00500_gathered_server_filtering_classvars() -> None:
    """
    # Summary

    Verify ``supports_gathered_server_filtering`` is ``True`` and ``gathered_lucene_spec``
    has the correct base terms and field map.

    ## Test

    - supports_gathered_server_filtering is True
    - gathered_lucene_spec.base_terms is empty (no fixed policy type filter)
    - gathered_lucene_spec.field_map maps name to name and type to type

    ## Classes and Methods

    - ManageCommunityListOrchestrator.supports_gathered_server_filtering
    - ManageCommunityListOrchestrator.gathered_lucene_spec
    """
    assert ManageCommunityListOrchestrator.supports_gathered_server_filtering is True

    spec = ManageCommunityListOrchestrator.gathered_lucene_spec
    assert spec is not None
    assert spec.base_terms == ()
    assert spec.field_map == {("name",): "name", ("type",): "type"}


def test_manage_community_list_00510_query_all_routes_gathered(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``query_all(gathered_filters=...)`` routes through ``_query_all_for_gathered``
    and does not call ``_query_all_for_management_states``.

    ## Test

    - query_all with gathered_filters returns results from the gathered path
    - Management-state path is not invoked

    ## Classes and Methods

    - ManageCommunityListOrchestrator.query_all()
    - ManageCommunityListOrchestrator._query_all_for_gathered()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send, orchestrator, fake_ctx = _instance(gen_responses)

    gathered_called = {"value": False}
    mgmt_called = {"value": False}

    def fake_gathered(self, filters):
        gathered_called["value"] = True
        return [{"name": "CL1", "type": "standard"}]

    def fake_mgmt(self):
        mgmt_called["value"] = True
        return []

    monkeypatch.setattr(ManageCommunityListOrchestrator, "_query_all_for_gathered", fake_gathered)
    monkeypatch.setattr(ManageCommunityListOrchestrator, "_query_all_for_management_states", fake_mgmt)

    result = orchestrator.query_all(gathered_filters=[{"name": "CL1"}])
    assert gathered_called["value"] is True
    assert mgmt_called["value"] is False
    assert len(result) == 1


def test_manage_community_list_00520_query_all_routes_management(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``query_all()`` without ``gathered_filters`` routes through
    ``_query_all_for_management_states``.

    ## Test

    - query_all without gathered_filters calls management path
    - Gathered path is not invoked

    ## Classes and Methods

    - ManageCommunityListOrchestrator.query_all()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send, orchestrator, fake_ctx = _instance(gen_responses)

    gathered_called = {"value": False}
    mgmt_called = {"value": False}

    def fake_gathered(self, filters):
        gathered_called["value"] = True
        return []

    def fake_mgmt(self):
        mgmt_called["value"] = True
        return [{"name": "CL1", "type": "standard"}]

    monkeypatch.setattr(ManageCommunityListOrchestrator, "_query_all_for_gathered", fake_gathered)
    monkeypatch.setattr(ManageCommunityListOrchestrator, "_query_all_for_management_states", fake_mgmt)

    result = orchestrator.query_all()
    assert mgmt_called["value"] is True
    assert gathered_called["value"] is False
    assert len(result) == 1
