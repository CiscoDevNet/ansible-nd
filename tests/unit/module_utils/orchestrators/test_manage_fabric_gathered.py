# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Deeksha Pandey (@deekpand)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for gathered queries shared by the manage-fabric family."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

from urllib.parse import unquote

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import (
    ManageEbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


@pytest.mark.parametrize(
    ("orchestrator_class", "fabric_type"),
    [
        (ManageExternalFabricOrchestrator, "externalConnectivity"),
        (ManageEbgpFabricOrchestrator, "vxlanEbgp"),
        (ManageIbgpFabricOrchestrator, "vxlanIbgp"),
        (ManageAiEbgpVxlanFabricOrchestrator, "aimlVxlanEbgp"),
        (ManageAiIbgpVxlanFabricOrchestrator, "aimlVxlanIbgp"),
    ],
    ids=[
        "external",
        "ebgp",
        "ibgp",
        "ai_ebgp",
        "ai_ibgp",
    ],
)
def test_empty_gathered_filters_use_type_only_lucene_query(
    monkeypatch,
    orchestrator_class,
    fabric_type,
) -> None:
    """Verify an explicit empty filter list narrows the request by fabric type."""
    instance = orchestrator_class(
        rest_send=RestSend(
            {
                "check_mode": False,
                "state": "gathered",
            }
        )
    )
    requested_paths = []
    expected_fabric = {
        "name": "matching-fabric",
        "management": {"type": fabric_type},
    }

    def fake_request(*args, **kwargs):
        requested_paths.append(unquote(kwargs["path"]))
        return {
            "fabrics": [
                expected_fabric,
                {
                    "name": "wrong-type-fabric",
                    "management": {"type": "wrongType"},
                },
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(gathered_filters=[])

    assert requested_paths == [
        f"/api/v1/manage/fabrics?filter=type:{fabric_type}&max=500&offset=0",
    ]
    assert result == [expected_fabric]


@pytest.mark.parametrize(
    ("orchestrator_class", "fabric_type"),
    [
        (ManageEbgpFabricOrchestrator, "vxlanEbgp"),
        (ManageIbgpFabricOrchestrator, "vxlanIbgp"),
    ],
    ids=["ebgp", "ibgp"],
)
def test_pagination_collects_multiple_pages(
    monkeypatch,
    orchestrator_class,
    fabric_type,
) -> None:
    """Verify _fetch_fabrics_paginated fetches until a short page signals the end."""
    instance = orchestrator_class(rest_send=RestSend({"check_mode": False, "state": "gathered"}))
    page_size = 500
    call_count = 0

    def fake_request(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"fabrics": [{"name": f"fabric-{i}", "management": {"type": fabric_type}} for i in range(page_size)]}
        return {
            "fabrics": [
                {"name": "fabric-last", "management": {"type": fabric_type}},
            ]
        }

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance._fetch_fabrics_paginated(f"type:{fabric_type}")

    assert call_count == 2
    assert len(result) == page_size + 1
    assert result[-1]["name"] == "fabric-last"


@pytest.mark.parametrize(
    ("orchestrator_class", "fabric_type"),
    [
        (ManageEbgpFabricOrchestrator, "vxlanEbgp"),
        (ManageIbgpFabricOrchestrator, "vxlanIbgp"),
        (ManageExternalFabricOrchestrator, "externalConnectivity"),
        (ManageAiEbgpVxlanFabricOrchestrator, "aimlVxlanEbgp"),
        (ManageAiIbgpVxlanFabricOrchestrator, "aimlVxlanIbgp"),
    ],
    ids=["ebgp", "ibgp", "external", "ai_ebgp", "ai_ibgp"],
)
def test_fabric_name_only_uses_exact_endpoint(
    monkeypatch,
    orchestrator_class,
    fabric_type,
) -> None:
    """Verify fabric_name-only filters use GET /fabrics/{name} instead of Lucene."""
    instance = orchestrator_class(rest_send=RestSend({"check_mode": False, "state": "gathered"}))
    requested_paths = []
    expected_fabric = {"name": "my-fabric", "management": {"type": fabric_type}}

    def fake_request(*args, **kwargs):
        requested_paths.append(unquote(kwargs["path"]))
        if "/fabrics/my-fabric" in kwargs["path"]:
            return expected_fabric
        return {"fabrics": []}

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(gathered_filters=[{"fabric_name": "my-fabric"}])

    assert len(requested_paths) == 1
    assert "/fabrics/my-fabric" in requested_paths[0]
    assert "filter=" not in requested_paths[0]
    assert result == [expected_fabric]


@pytest.mark.parametrize(
    ("orchestrator_class", "fabric_type"),
    [
        (ManageEbgpFabricOrchestrator, "vxlanEbgp"),
        (ManageExternalFabricOrchestrator, "externalConnectivity"),
    ],
    ids=["ebgp", "external"],
)
def test_nonexistent_fabric_name_returns_empty(
    monkeypatch,
    orchestrator_class,
    fabric_type,
) -> None:
    """Verify a non-existent fabric_name returns empty without error."""
    instance = orchestrator_class(rest_send=RestSend({"check_mode": False, "state": "gathered"}))

    def fake_request(*args, **kwargs):
        return {}

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(gathered_filters=[{"fabric_name": "does-not-exist"}])

    assert result == []


@pytest.mark.parametrize(
    ("orchestrator_class", "fabric_type"),
    [
        (ManageEbgpFabricOrchestrator, "vxlanEbgp"),
        (ManageIbgpFabricOrchestrator, "vxlanIbgp"),
    ],
    ids=["ebgp", "ibgp"],
)
def test_exact_endpoint_rejects_wrong_fabric_type(
    monkeypatch,
    orchestrator_class,
    fabric_type,
) -> None:
    """Verify _query_one_by_name filters out fabrics of the wrong type."""
    instance = orchestrator_class(rest_send=RestSend({"check_mode": False, "state": "gathered"}))

    def fake_request(*args, **kwargs):
        return {"name": "some-fabric", "management": {"type": "wrongType"}}

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(gathered_filters=[{"fabric_name": "some-fabric"}])

    assert result == []


@pytest.mark.parametrize(
    ("orchestrator_class", "fabric_type"),
    [
        (ManageEbgpFabricOrchestrator, "vxlanEbgp"),
    ],
    ids=["ebgp"],
)
def test_mixed_exact_and_lucene_filters(
    monkeypatch,
    orchestrator_class,
    fabric_type,
) -> None:
    """Verify OR filters with fabric_name-only and property filters use both paths."""
    instance = orchestrator_class(rest_send=RestSend({"check_mode": False, "state": "gathered"}))
    requested_paths = []
    exact_fabric = {"name": "exact-hit", "management": {"type": fabric_type}}
    lucene_fabric = {"name": "lucene-hit", "management": {"type": fabric_type}}

    def fake_request(*args, **kwargs):
        path = unquote(kwargs["path"])
        requested_paths.append(path)
        if "/fabrics/exact-hit" in path:
            return exact_fabric
        return {"fabrics": [lucene_fabric]}

    monkeypatch.setattr(instance, "_request", fake_request)

    result = instance.query_all(
        gathered_filters=[
            {"fabric_name": "exact-hit"},
            {"license_tier": "premier"},
        ]
    )

    assert len(requested_paths) == 2
    assert "/fabrics/exact-hit" in requested_paths[0]
    assert "filter=" in requested_paths[1]
    assert len(result) == 2
    assert exact_fabric in result
    assert lucene_fabric in result
