# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for complete and ownership-safe fabric inventory queries."""

from __future__ import annotations

from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    FabricGroupVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric.collection_query import (
    ManageFabricCollectionQueryMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_campus_ibgp_vxlan import (
    ManageCampusIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import (
    ManageEbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_vxlan import (
    ManageFabricGroupVxlanOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)

FABRIC_ORCHESTRATOR_CASES = (
    (ManageIbgpFabricOrchestrator, "fabric", "vxlanIbgp"),
    (ManageEbgpFabricOrchestrator, "fabric", "vxlanEbgp"),
    (ManageExternalFabricOrchestrator, "fabric", "externalConnectivity"),
    (ManageCampusIbgpVxlanFabricOrchestrator, "fabric", "vxlanCampus"),
    (ManageAiIbgpVxlanFabricOrchestrator, "fabric", "aimlVxlanIbgp"),
    (ManageAiEbgpVxlanFabricOrchestrator, "fabric", "aimlVxlanEbgp"),
    (ManageFabricGroupVxlanOrchestrator, "fabricGroup", "vxlan"),
)


def _fabric(
    name: str,
    management_type: str = "vxlanIbgp",
    category: str = "fabric",
    **extra,
) -> dict:
    return {
        "name": name,
        "category": category,
        "management": {"type": management_type},
        **extra,
    }


def _orchestrator(config=None, state: str = "merged") -> ManageIbgpFabricOrchestrator:
    params = {"check_mode": False, "state": state}
    if config is not None:
        params["config"] = config
    return ManageIbgpFabricOrchestrator(rest_send=RestSend(params))


@pytest.mark.parametrize("orchestrator_class,category,management_type", FABRIC_ORCHESTRATOR_CASES)
def test_fabric_inventory_query_00010(orchestrator_class, category, management_type) -> None:
    """All seven fabric modules declare their shared inventory ownership."""
    assert issubclass(orchestrator_class, ManageFabricCollectionQueryMixin)
    assert orchestrator_class.fabric_inventory_category == category
    assert orchestrator_class.fabric_inventory_management_type == management_type


@pytest.mark.parametrize("state", ("gathered", "overridden"))
def test_fabric_inventory_query_00020(monkeypatch, state: str) -> None:
    """Gathered and overridden both retain an owned row found only on page two."""
    instance = _orchestrator(state=state)
    monkeypatch.setattr(ManageIbgpFabricOrchestrator, "fabric_inventory_page_size", 2)
    responses = iter(
        (
            {
                "fabrics": [
                    _fabric("ebgp", "vxlanEbgp"),
                    _fabric("external", "externalConnectivity"),
                ],
                "meta": {"total": 3, "remaining": 1},
            },
            {
                "fabrics": [_fabric("wanted")],
                "meta": {"total": 3, "remaining": 0},
            },
        )
    )
    paths: list[str] = []

    def fake_request(**kwargs):
        paths.append(kwargs["path"])
        return next(responses)

    monkeypatch.setattr(instance, "_request", fake_request)

    assert instance.query_all() == [_fabric("wanted")]
    queries = [parse_qs(urlsplit(path).query) for path in paths]
    assert queries == [
        {"category": ["fabric"], "max": ["2"], "offset": ["0"], "sort": ["name"]},
        {"category": ["fabric"], "max": ["2"], "offset": ["2"], "sort": ["name"]},
    ]


def test_fabric_inventory_query_00030(monkeypatch) -> None:
    """Missing metadata falls back to full-page detection and short-page termination."""
    instance = _orchestrator()
    monkeypatch.setattr(ManageIbgpFabricOrchestrator, "fabric_inventory_page_size", 2)
    responses = iter(
        (
            {"fabrics": [_fabric("one"), _fabric("two")]},
            {"fabrics": [_fabric("three")]},
        )
    )
    paths: list[str] = []

    def fake_request(**kwargs):
        paths.append(kwargs["path"])
        return next(responses)

    monkeypatch.setattr(instance, "_request", fake_request)

    assert [item["name"] for item in instance.query_all()] == ["one", "two", "three"]
    assert [parse_qs(urlsplit(path).query)["offset"] for path in paths] == [
        ["0"],
        ["2"],
    ]


@pytest.mark.parametrize(
    "meta",
    (
        {"remaining": 1},
        {"counts": {"remaining": 1}},
    ),
)
def test_fabric_inventory_query_00040(monkeypatch, meta) -> None:
    """Repeated/no-progress pages fail closed for both supported metadata shapes."""
    instance = _orchestrator()
    monkeypatch.setattr(ManageIbgpFabricOrchestrator, "fabric_inventory_page_size", 2)
    repeated = [_fabric("one"), _fabric("two")]
    responses = iter(
        (
            {"fabrics": repeated, "meta": meta},
            {"fabrics": repeated, "meta": {"remaining": 0}},
        )
    )
    monkeypatch.setattr(instance, "_request", lambda **kwargs: next(responses))

    with pytest.raises(
        Exception,
        match=r"^Query all failed: Fabric inventory pagination made no progress",
    ):
        instance.query_all()


def test_fabric_inventory_query_00050(monkeypatch) -> None:
    """The hard page bound stops a controller that continually advertises more data."""
    instance = _orchestrator()
    monkeypatch.setattr(ManageIbgpFabricOrchestrator, "fabric_inventory_page_size", 1)
    monkeypatch.setattr(ManageIbgpFabricOrchestrator, "fabric_inventory_max_pages", 1)
    monkeypatch.setattr(
        instance,
        "_request",
        lambda **kwargs: {"fabrics": [_fabric("one")], "meta": {"remaining": 1}},
    )

    with pytest.raises(
        Exception,
        match=r"^Query all failed: Fabric inventory pagination exceeded the 1-page safety limit",
    ):
        instance.query_all()


def test_fabric_inventory_query_00060(monkeypatch) -> None:
    """List rows are filtered by both ownership dimensions and de-duplicated by name."""
    instance = _orchestrator()
    first = _fabric("owned", generation="first")
    response = {
        "fabrics": [
            first,
            _fabric("owned", generation="duplicate"),
            _fabric("wrong-type", "vxlanEbgp"),
            _fabric("wrong-category", category="fabricGroup"),
        ]
    }
    monkeypatch.setattr(instance, "_request", lambda **kwargs: response)

    assert instance.query_all() == [first]


def test_fabric_inventory_query_00070(monkeypatch) -> None:
    """A configured name omitted by the list is recovered by its authoritative GET."""
    instance = _orchestrator(config=[{"fabric_name": "wanted"}])
    calls: list[str] = []

    def fake_request(**kwargs):
        calls.append(kwargs["path"])
        return {"fabrics": []} if urlsplit(kwargs["path"]).query else _fabric("wanted", generation="current")

    monkeypatch.setattr(instance, "_request", fake_request)

    assert instance.query_all() == [_fabric("wanted", generation="current")]
    assert len(calls) == 2
    assert urlsplit(calls[1]).path.endswith("/fabrics/wanted")


def test_fabric_inventory_query_00080(monkeypatch) -> None:
    """A configured name's targeted response replaces a stale list representation."""
    instance = _orchestrator(config=[{"fabric_name": "wanted"}])

    def fake_request(**kwargs):
        if urlsplit(kwargs["path"]).query:
            return {"fabrics": [_fabric("wanted", generation="stale")]}
        return _fabric("wanted", generation="current")

    monkeypatch.setattr(instance, "_request", fake_request)

    assert instance.query_all() == [_fabric("wanted", generation="current")]


@pytest.mark.parametrize("listed", (True, False))
def test_fabric_inventory_query_00090(monkeypatch, listed: bool) -> None:
    """A targeted 404 removes a stale list row or leaves an absent name creatable."""
    instance = _orchestrator(config=[{"fabric_name": "wanted"}])

    def fake_request(**kwargs):
        if urlsplit(kwargs["path"]).query:
            return {"fabrics": [_fabric("wanted")] if listed else []}
        return {}

    monkeypatch.setattr(instance, "_request", fake_request)

    assert instance.query_all() == []


@pytest.mark.parametrize(
    "target",
    (
        _fabric("wanted", management_type="vxlanEbgp"),
        _fabric("wanted", category="fabricGroup"),
    ),
)
def test_fabric_inventory_query_00100(monkeypatch, target) -> None:
    """A configured name owned by another category/type fails before mutation."""
    instance = _orchestrator(config=[{"fabric_name": "wanted"}])

    def fake_request(**kwargs):
        return {"fabrics": []} if urlsplit(kwargs["path"]).query else target

    monkeypatch.setattr(instance, "_request", fake_request)

    with pytest.raises(Exception, match=r"^Query all failed: Fabric name collision for 'wanted'"):
        instance.query_all()


def test_fabric_inventory_query_00110(monkeypatch) -> None:
    """Duplicate configured identifiers cause only one authoritative lookup."""
    instance = _orchestrator(config=[{"fabric_name": "wanted"}, {"fabric_name": "wanted"}])
    targeted_calls = 0

    def fake_request(**kwargs):
        nonlocal targeted_calls
        if urlsplit(kwargs["path"]).query:
            return {"fabrics": []}
        targeted_calls += 1
        return _fabric("wanted")

    monkeypatch.setattr(instance, "_request", fake_request)

    assert instance.query_all() == [_fabric("wanted")]
    assert targeted_calls == 1


def test_fabric_inventory_query_00120(monkeypatch) -> None:
    """Gathered state with empty config performs no per-name reads."""
    instance = _orchestrator(state="gathered")
    calls: list[str] = []

    def fake_request(**kwargs):
        calls.append(kwargs["path"])
        return {"fabrics": [_fabric("one")]}

    monkeypatch.setattr(instance, "_request", fake_request)

    assert instance.query_all() == [_fabric("one")]
    assert len(calls) == 1


def test_fabric_inventory_query_00130() -> None:
    """A group recovered by targeted GET is classified as existing, never created."""
    config = [{"fabric_name": "group-one"}]
    existing = FabricGroupVxlanModel.from_config(config[0]).to_payload()

    class FabricGroupTargetedGetSpy(ManageFabricGroupVxlanOrchestrator):
        def model_post_init(self, __context) -> None:
            super().model_post_init(__context)
            self._created: list = []

        def _request(self, path, verb, **kwargs) -> ResponseType:
            del verb, kwargs
            return {"fabrics": []} if urlsplit(path).query else deepcopy(existing)

        def create(self, model_instance, **kwargs) -> ResponseType:
            del kwargs
            self._created.append(model_instance)
            return {}

    module = MockAnsibleModule()
    module.check_mode = False
    module.no_log_values = set()
    module.params = {
        "state": "merged",
        "config": config,
        "output_level": "normal",
        "ignore_errors": False,
    }
    rest_send = RestSend({"check_mode": False, **module.params})
    spy = FabricGroupTargetedGetSpy(rest_send=rest_send)

    state_machine = NDStateMachine(module=module, model_orchestrator=spy)
    state_machine.manage_state()

    assert spy._created == []
    assert state_machine.output.format()["changed"] is False
