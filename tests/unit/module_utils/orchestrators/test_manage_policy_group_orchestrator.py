# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``PolicyGroupOrchestrator``.

Verifies that the orchestrator drives ``RestSend`` correctly for policy-group
CRUD/deploy operations: the ``_raw_cache`` query cache, source-artifact
filtering, identifier deduplication, the bulk POST body shape, the markDelete-
then-direct-DELETE fallback in ``delete_bulk``, the switch-level deploy union,
and the ``deploy_unchanged_user_mentioned`` re-deploy of user-mentioned but
unchanged groups.

Scope: methods defined in ``orchestrators/manage_policy_group.py`` only.
The shared infrastructure inherited from ``NDBaseOrchestrator`` (``_request``,
``_register_api_call``, verbosity tagging) is covered separately by
``test_base_orchestrator.py`` and is not re-exercised here.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_group_actions import (
    EpManagePolicyGroupActionsMarkDeletePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_groups import (
    EpManagePolicyGroupsDelete,
    EpManagePolicyGroupsGet,
    EpManagePolicyGroupsPost,
    EpManagePolicyGroupsPut,
    EpManagePolicySummaryGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
    PolicyGroupCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_policy_group import (
    PolicyGroupOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

# =============================================================================
# Test harness
# =============================================================================


def _build_rest_send(response_dicts: list[dict]) -> RestSend:
    """Build a real ``RestSend`` wired to a file-based ``Sender`` and a
    ``ResponseHandler`` that yields ``response_dicts`` in order.

    Each entry in ``response_dicts`` is a controller response of the shape
    ``{"RETURN_CODE", "METHOD", "REQUEST_PATH", "MESSAGE", "DATA"}``.  The
    helper ``_resp`` below builds these compactly.
    """

    def responses():
        yield from response_dicts

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False, "fabric_name": "fab1"})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _resp(
    data: Any = None,
    *,
    return_code: int = 200,
    method: str = "GET",
    path: str = "/api/v1",
    message: str = "OK",
) -> dict:
    """Build one controller response dict for the ``Sender`` generator."""
    return {
        "RETURN_CODE": return_code,
        "METHOD": method,
        "REQUEST_PATH": path,
        "MESSAGE": message,
        "DATA": data if data is not None else {},
    }


def _make_results() -> Results:
    """Build a ``Results`` instance pre-wired for orchestrator call capture."""
    r = Results()
    r.state = "merged"
    r.check_mode = False
    return r


def _make_orchestrator(
    rest_send: RestSend,
    *,
    fabric_name: str = "fab1",
    deploy: bool = True,
    results: Results | None = None,
    ticket_id: str | None = None,
    cluster_name: str | None = None,
) -> PolicyGroupOrchestrator:
    """Construct a ``PolicyGroupOrchestrator`` with the given wiring.

    ``ticket_id`` and ``cluster_name`` default to ``None`` (omitted from the
    constructor entirely) so the bulk of the existing test suite continues
    to exercise the no-query-param path and emit unchanged request paths.
    """
    kwargs: dict[str, Any] = {
        "rest_send": rest_send,
        "fabric_name": fabric_name,
        "deploy": deploy,
        "results": results,
    }
    if ticket_id is not None:
        kwargs["ticket_id"] = ticket_id
    if cluster_name is not None:
        kwargs["cluster_name"] = cluster_name
    return PolicyGroupOrchestrator(**kwargs)


def _build_pg_model(
    *,
    template_name: str = "feature_enable",
    description: str = "test pg",
    switch_ids: list[str] | None = None,
    template_inputs: dict | None = None,
    policy_id: str | None = None,
    priority: int | None = 500,
    entity_type: str = "switch",
    entity_name: str = "SWITCH",
) -> PolicyGroupCreate:
    """Build a minimal valid ``PolicyGroupCreate`` instance for tests.

    Defaults reflect a single-switch ``feature_enable`` policy group with no
    template inputs, which is the cheapest payload that satisfies the model's
    invariants while still being routable to every orchestrator method.
    """
    kwargs: dict[str, Any] = {
        "template_name": template_name,
        "description": description,
        "switch_ids": switch_ids if switch_ids is not None else ["SN1"],
        "entity_type": entity_type,
        "entity_name": entity_name,
    }
    if priority is not None:
        kwargs["priority"] = priority
    if template_inputs is not None:
        kwargs["template_inputs"] = template_inputs
    if policy_id is not None:
        kwargs["policy_id"] = policy_id
    return PolicyGroupCreate(**kwargs)


def _build_pg_raw(
    *,
    policy_id: str = "P1",
    template_name: str = "feature_enable",
    description: str = "test pg",
    switch_ids: list[str] | None = None,
    template_inputs: dict | None = None,
    priority: int = 500,
    entity_type: str = "switch",
    entity_name: str = "SWITCH",
    source: str = "",
) -> dict:
    """Build a controller-shaped policy-group response for update tests."""
    raw = {
        "policyId": policy_id,
        "templateName": template_name,
        "description": description,
        "switchIds": switch_ids if switch_ids is not None else ["SN1"],
        "priority": priority,
        "entityType": entity_type,
        "entityName": entity_name,
        "source": source,
    }
    if template_inputs is not None:
        raw["templateInputs"] = template_inputs
    return raw


def _build_summary_row(group: dict) -> dict:
    """Convert a policy-group-shaped fixture into a policySummary row."""
    row = dict(group)
    row.setdefault("policyType", "group")
    switch_ids = row.pop("switchIds", [])
    priority = row.get("priority", 500)
    mark_deleted = bool(row.pop("markDeleted", False))
    if "switches" not in row:
        row["switches"] = [
            {
                "switchId": switch_id,
                "switchIp": "1.1.1.1",
                "switchName": switch_id,
                "priority": priority,
                "markDeleted": mark_deleted,
            }
            for switch_id in switch_ids
        ]
    if mark_deleted and not row["switches"]:
        row["markDeleted"] = True
    return row


def _summary_payload(groups: list[dict]) -> dict:
    """Build a policySummary response body from policy-group fixtures."""
    return {"policies": [_build_summary_row(group) for group in groups]}


# =============================================================================
# Test: initialisation / ClassVars
# =============================================================================


def test_manage_policy_group_orchestrator_00010() -> None:
    """
    # Summary

    ``PolicyGroupOrchestrator`` instantiates cleanly and exposes the documented
    ClassVars and endpoint assignments.

    ## Test

    - ``model_class`` is ``PolicyGroupCreate``
    - Bulk flags are both True
    - All endpoint slots resolve to the expected ND endpoint classes
    - ``fabric_name`` and ``deploy`` flow through from the constructor

    ## Classes and Methods

    - PolicyGroupOrchestrator.__init__
    """
    rest_send = _build_rest_send([])
    with does_not_raise():
        instance = _make_orchestrator(rest_send)

    assert instance.model_class is PolicyGroupCreate
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    assert instance.create_endpoint is EpManagePolicyGroupsPost
    assert instance.update_endpoint is EpManagePolicyGroupsPut
    assert instance.delete_endpoint is EpManagePolicyGroupsDelete
    assert instance.query_one_endpoint is EpManagePolicyGroupsGet
    assert instance.query_all_endpoint is EpManagePolicyGroupsGet
    assert instance.policy_summary_endpoint is EpManagePolicySummaryGet
    assert instance.create_bulk_endpoint is EpManagePolicyGroupsPost
    assert instance.delete_bulk_endpoint is EpManagePolicyGroupsDelete
    assert instance.mark_delete_endpoint is EpManagePolicyGroupActionsMarkDeletePost
    assert instance.switch_deploy_endpoint is EpManageSwitchActionsDeployPost
    assert instance.fabric_name == "fab1"
    assert instance.deploy is True
    # Change-Control / multi-cluster query params default to None so existing
    # request paths are unchanged when callers do not set them.
    assert instance.ticket_id is None
    assert instance.cluster_name is None
    assert instance._raw_cache is None
    assert instance._policy_summary_cache is None


def test_manage_policy_group_orchestrator_00020() -> None:
    """
    # Summary

    ``_invalidate_cache`` resets ``_raw_cache`` to ``None``.

    ## Classes and Methods

    - PolicyGroupOrchestrator._invalidate_cache
    """
    rest_send = _build_rest_send([])
    instance = _make_orchestrator(rest_send)
    instance._raw_cache = [{"policyId": "p1", "description": "x", "templateName": "t"}]
    assert instance._raw_cache is not None

    with does_not_raise():
        instance._invalidate_cache()

    assert instance._raw_cache is None


# =============================================================================
# Test: query_all
# =============================================================================


def test_manage_policy_group_orchestrator_00100() -> None:
    """
    # Summary

    First ``query_all`` call hits the API, populates ``_raw_cache``, and
    returns the deduplicated, description-bearing groups.

    ## Test

    - ``_raw_cache`` is ``None`` going in
    - One GET is issued against ``/policySummary``
    - Returned list contains the single matching policy group
    - After the call, ``_raw_cache`` holds the active source/markDeleted-filtered list

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    groups = [
        {"policyId": "P1", "description": "desc1", "templateName": "t1"},
    ]
    rest_send = _build_rest_send([_resp(_summary_payload(groups))])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)
    assert instance._raw_cache is None

    with does_not_raise():
        result = instance.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["policyId"] == "P1"
    assert [g["policyId"] for g in instance._raw_cache] == ["P1"]
    assert len(results._tasks) == 1
    assert "/policySummary" in results._tasks[0].path
    assert "filter=policyId:*POLICY-GROUP-*" in results._tasks[0].path
    assert "max=10000" in results._tasks[0].path
    assert "%2A" not in results._tasks[0].path
    assert results._tasks[0].verb == "GET"


def test_manage_policy_group_orchestrator_00110() -> None:
    """
    # Summary

    Subsequent ``query_all`` calls reuse ``_raw_cache`` without firing
    another HTTP GET.

    ## Test

    - Pre-populate ``_raw_cache`` with two groups
    - No responses queued in ``RestSend`` -- a real GET would StopIteration
    - ``query_all`` returns the cached list filtered by description

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    cached = [
        {"policyId": "P1", "description": "desc1", "templateName": "t1"},
        {"policyId": "P2", "description": "desc2", "templateName": "t2"},
    ]
    rest_send = _build_rest_send([])  # no responses -> would explode if used
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)
    instance._raw_cache = cached

    with does_not_raise():
        result = instance.query_all()

    assert {g["policyId"] for g in result} == {"P1", "P2"}
    assert results._tasks == []  # no API call made


def test_manage_policy_group_orchestrator_00120() -> None:
    """
    # Summary

    ``query_all`` strips internal controller artifacts and pending-delete
    records from the cached raw list.

    ## Test

    - Three groups in API response, one with a non-empty ``source``
    - One group with ``markDeleted=true``
    - Both non-active records are excluded from the return value and cache

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    api_groups = [
        {"policyId": "P1", "description": "user", "templateName": "t1", "source": ""},
        {"policyId": "P2", "description": "user", "templateName": "t2"},
        {
            "policyId": "P3",
            "description": "artifact",
            "templateName": "switch_freeform",
            "source": "P1",
        },
        {
            "policyId": "P4",
            "description": "pending",
            "templateName": "feature_enable",
            "markDeleted": True,
        },
    ]
    rest_send = _build_rest_send([_resp(_summary_payload(api_groups))])
    instance = _make_orchestrator(rest_send)

    result = instance.query_all()

    pids = {g["policyId"] for g in result}
    assert "P3" not in pids
    assert "P4" not in pids
    assert instance._raw_cache is not None
    assert all(not g.get("source") for g in instance._raw_cache)
    assert all(not g.get("markDeleted", False) for g in instance._raw_cache)


def test_manage_policy_group_orchestrator_00130() -> None:
    """
    # Summary

    ``include_no_description=False`` (the default) hides groups whose
    description is missing / empty / null; ``True`` preserves them.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    cached = [
        {"policyId": "P1", "description": "real", "templateName": "t"},
        {"policyId": "P2", "description": "", "templateName": "t"},
        {"policyId": "P3", "description": None, "templateName": "t"},
        {"policyId": "P4", "templateName": "t"},  # description absent
    ]
    rest_send = _build_rest_send([])
    instance = _make_orchestrator(rest_send)
    instance._raw_cache = cached

    default_view = instance.query_all()
    full_view = instance.query_all(include_no_description=True, deduplicate=False)

    assert {g["policyId"] for g in default_view} == {"P1"}
    assert {g["policyId"] for g in full_view} == {"P1", "P2", "P3", "P4"}


def test_manage_policy_group_orchestrator_00135() -> None:
    """
    # Summary

    A policySummary row with mixed per-switch markDeleted state remains active
    and exposes only the non-deleted switches in the normalized ``switchIds``.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    summary_row = {
        "policyId": "POLICY-GROUP-MIXED",
        "policyType": "group",
        "description": "mixed",
        "templateName": "feature_enable",
        "switches": [
            {
                "switchId": "SN_ACTIVE",
                "switchIp": "1.1.1.1",
                "switchName": "active",
                "priority": 500,
                "markDeleted": False,
            },
            {
                "switchId": "SN_DELETED",
                "switchIp": "1.1.1.2",
                "switchName": "deleted",
                "priority": 500,
                "markDeleted": True,
            },
        ],
    }
    rest_send = _build_rest_send([_resp({"policies": [summary_row]})])
    instance = _make_orchestrator(rest_send)

    result = instance.query_all()

    assert len(result) == 1
    assert result[0]["policyId"] == "POLICY-GROUP-MIXED"
    assert result[0]["switchIds"] == ["SN_ACTIVE"]
    assert result[0]["markDeleted"] is False


def test_manage_policy_group_orchestrator_00140() -> None:
    """
    # Summary

    ``deduplicate=False`` returns every cached entry including duplicates,
    even when the (description, templateName) composite identifier repeats.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    cached = [
        {
            "policyId": "P1",
            "description": "same",
            "templateName": "t",
            "updateTimestamp": 100,
        },
        {
            "policyId": "P2",
            "description": "same",
            "templateName": "t",
            "updateTimestamp": 200,
        },
    ]
    rest_send = _build_rest_send([])
    instance = _make_orchestrator(rest_send)
    instance._raw_cache = cached

    with_dedup = instance.query_all()
    without_dedup = instance.query_all(deduplicate=False)

    assert len(with_dedup) == 1
    assert with_dedup[0]["policyId"] == "P2"  # latest timestamp wins
    assert len(without_dedup) == 2


def test_manage_policy_group_orchestrator_00150() -> None:
    """
    # Summary

    ``query_all`` wraps low-level exceptions in a self-describing
    ``Exception`` that mentions the operation.

    ## Test

    - Controller returns HTTP 500 on the GET
    - ``_request`` raises; wrapper re-raises with a friendly prefix

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    rest_send = _build_rest_send([_resp({}, return_code=500, message="boom")])
    instance = _make_orchestrator(rest_send)

    with pytest.raises(Exception, match="Query all policy groups failed"):
        instance.query_all()


def test_manage_policy_group_orchestrator_00160() -> None:
    """
    # Summary

    An empty ``policyGroups`` payload yields an empty list and an empty
    cache (not ``None``), so subsequent calls still skip the network.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    """
    rest_send = _build_rest_send([_resp({"policies": []})])
    instance = _make_orchestrator(rest_send)

    result = instance.query_all()

    assert result == []
    assert instance._raw_cache == []
    # Second call should not need a response (cache is populated).
    second = instance.query_all()
    assert second == []


# =============================================================================
# Test: _deduplicate_groups
# =============================================================================


def test_manage_policy_group_orchestrator_00200() -> None:
    """
    # Summary

    Groups with distinct (description, templateName) identifiers pass through
    unchanged.

    ## Classes and Methods

    - PolicyGroupOrchestrator._deduplicate_groups
    """
    groups = [
        {"policyId": "P1", "description": "a", "templateName": "t1"},
        {"policyId": "P2", "description": "b", "templateName": "t2"},
    ]
    result = PolicyGroupOrchestrator._deduplicate_groups(groups)
    assert {g["policyId"] for g in result} == {"P1", "P2"}


def test_manage_policy_group_orchestrator_00210() -> None:
    """
    # Summary

    When duplicates share an identifier, the entry with the higher
    ``updateTimestamp`` wins.

    ## Classes and Methods

    - PolicyGroupOrchestrator._deduplicate_groups
    """
    groups = [
        {
            "policyId": "old",
            "description": "x",
            "templateName": "t",
            "updateTimestamp": 100,
        },
        {
            "policyId": "new",
            "description": "x",
            "templateName": "t",
            "updateTimestamp": 200,
        },
        {
            "policyId": "mid",
            "description": "x",
            "templateName": "t",
            "updateTimestamp": 150,
        },
    ]
    result = PolicyGroupOrchestrator._deduplicate_groups(groups)
    assert len(result) == 1
    assert result[0]["policyId"] == "new"


def test_manage_policy_group_orchestrator_00220() -> None:
    """
    # Summary

    Falls back to ``createTimestamp`` when ``updateTimestamp`` is missing
    on either side.

    ## Classes and Methods

    - PolicyGroupOrchestrator._deduplicate_groups
    """
    groups = [
        {
            "policyId": "old",
            "description": "x",
            "templateName": "t",
            "createTimestamp": 50,
        },
        {
            "policyId": "new",
            "description": "x",
            "templateName": "t",
            "createTimestamp": 75,
        },
    ]
    result = PolicyGroupOrchestrator._deduplicate_groups(groups)
    assert len(result) == 1
    assert result[0]["policyId"] == "new"


def test_manage_policy_group_orchestrator_00230() -> None:
    """
    # Summary

    With no timestamps on either entry, the first-seen group is kept
    (since ``0 > 0`` is False the second cannot beat it).

    ## Classes and Methods

    - PolicyGroupOrchestrator._deduplicate_groups
    """
    groups = [
        {"policyId": "first", "description": "x", "templateName": "t"},
        {"policyId": "second", "description": "x", "templateName": "t"},
    ]
    result = PolicyGroupOrchestrator._deduplicate_groups(groups)
    assert len(result) == 1
    assert result[0]["policyId"] == "first"


# =============================================================================
# Test: query_by_id
# =============================================================================


def test_manage_policy_group_orchestrator_00300() -> None:
    """
    # Summary

    A 200 response carrying ``policyId`` is returned as the dict body.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_by_id
    """
    rest_send = _build_rest_send(
        [_resp(_summary_payload([{"policyId": "P1", "description": "x"}]))]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    result = instance.query_by_id("P1")

    assert isinstance(result, dict)
    assert result["policyId"] == "P1"
    assert "/policySummary" in results._tasks[0].path
    assert results._tasks[0].verb == "GET"


def test_manage_policy_group_orchestrator_00310() -> None:
    """
    # Summary

    A 404 / empty / non-dict response yields ``None``, signaling "not found"
    to the caller.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_by_id
    """
    rest_send = _build_rest_send([_resp({}, return_code=404, message="Not Found")])
    instance = _make_orchestrator(rest_send)

    result = instance.query_by_id("missing")

    assert result is None


def test_manage_policy_group_orchestrator_00320() -> None:
    """
    # Summary

    A success response *without* a ``policyId`` key is treated as "not
    found" (a defensive guard against malformed controller bodies).

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_by_id
    """
    rest_send = _build_rest_send([_resp({"description": "x"})])
    instance = _make_orchestrator(rest_send)

    result = instance.query_by_id("P1")
    assert result is None


def test_manage_policy_group_orchestrator_00330() -> None:
    """
    # Summary

    HTTP 500 from the controller is wrapped in a "Query policy group by ID
    failed" exception.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_by_id
    """
    rest_send = _build_rest_send([_resp({}, return_code=500)])
    instance = _make_orchestrator(rest_send)

    with pytest.raises(Exception, match="Query policy group by ID failed"):
        instance.query_by_id("P1")


# =============================================================================
# Test: query_filtered
# =============================================================================


def test_manage_policy_group_orchestrator_00400() -> None:
    """
    # Summary

    When ``_raw_cache`` is populated, ``query_filtered`` filters in memory and
    never touches the network.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_filtered
    """
    cached = [
        {"policyId": "P1", "description": "alpha", "templateName": "feat_a"},
        {"policyId": "P2", "description": "beta", "templateName": "feat_b"},
        {"policyId": "P3", "description": "alpha", "templateName": "feat_b"},
    ]
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)
    instance._raw_cache = cached

    by_template = instance.query_filtered(template_name="feat_b")
    by_description = instance.query_filtered(description="alpha")
    by_both = instance.query_filtered(template_name="feat_b", description="alpha")

    assert {g["policyId"] for g in by_template} == {"P2", "P3"}
    assert {g["policyId"] for g in by_description} == {"P1", "P3"}
    assert {g["policyId"] for g in by_both} == {"P3"}
    assert results._tasks == []


def test_manage_policy_group_orchestrator_00410() -> None:
    """
    # Summary

    Cache-miss path builds a Lucene ``AND`` filter on both ``templateName``
    and ``description`` then strips non-active records.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_filtered
    """
    api_groups = [
        {"policyId": "P1", "description": "d", "templateName": "t1"},
        {"policyId": "P2", "description": "d", "templateName": "t1", "source": "PX"},
        {
            "policyId": "P3",
            "description": "d",
            "templateName": "t1",
            "markDeleted": True,
        },
    ]
    rest_send = _build_rest_send([_resp(_summary_payload(api_groups))])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    result = instance.query_filtered(template_name="t1", description="d")

    assert {g["policyId"] for g in result} == {"P1"}
    # The request is reduced to policy-group IDs, then template/description
    # filters are applied exactly in Python.
    assert "filter=policyId:*POLICY-GROUP-*" in results._tasks[0].path
    assert "max=10000" in results._tasks[0].path
    assert "%2A" not in results._tasks[0].path


def test_manage_policy_group_orchestrator_00420() -> None:
    """
    # Summary

    With no filters the cache-miss path still strips non-active records and
    deduplicates the returned list.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_filtered
    """
    api_groups = [
        {
            "policyId": "P1",
            "description": "d",
            "templateName": "t",
            "updateTimestamp": 100,
        },
        {
            "policyId": "P2",
            "description": "d",
            "templateName": "t",
            "updateTimestamp": 200,
        },
        {"policyId": "P3", "description": "other", "templateName": "t", "source": "PX"},
        {
            "policyId": "P4",
            "description": "pending",
            "templateName": "t",
            "markDeleted": True,
        },
    ]
    rest_send = _build_rest_send([_resp(_summary_payload(api_groups))])
    instance = _make_orchestrator(rest_send)

    result = instance.query_filtered()
    pids = {g["policyId"] for g in result}

    assert "P3" not in pids  # source-artifact stripped
    assert "P4" not in pids  # markDeleted record stripped
    assert pids == {"P2"}  # P1 collapsed into P2 (later timestamp)


def test_manage_policy_group_orchestrator_00430() -> None:
    """
    # Summary

    ``deduplicate=False`` preserves duplicate (description, templateName)
    groups so ``state: gathered`` sees every distinct ``policyId``.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_filtered
    """
    cached = [
        {"policyId": "P1", "description": "d", "templateName": "t"},
        {"policyId": "P2", "description": "d", "templateName": "t"},
    ]
    rest_send = _build_rest_send([])
    instance = _make_orchestrator(rest_send)
    instance._raw_cache = cached

    result = instance.query_filtered(template_name="t", deduplicate=False)

    assert {g["policyId"] for g in result} == {"P1", "P2"}


def test_manage_policy_group_orchestrator_00440() -> None:
    """
    # Summary

    Controller errors are wrapped with the "Query filtered policy groups
    failed" prefix.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_filtered
    """
    rest_send = _build_rest_send([_resp({}, return_code=500)])
    instance = _make_orchestrator(rest_send)

    with pytest.raises(Exception, match="Query filtered policy groups failed"):
        instance.query_filtered(template_name="t")


# =============================================================================
# Test: policySummary pending-delete cleanup
# =============================================================================


def test_manage_policy_group_orchestrator_00450() -> None:
    """
    # Summary

    Pending-delete cleanup for an active-cache miss first proves a hidden
    ``markDeleted`` row through policySummary, then deploys the matched
    switch IDs.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_pending_deleted_cleanup
    """
    deploy_body = {"switchIds": [{"switchId": "SN1", "status": "success"}]}

    rest_send = _build_rest_send(
        [
            _resp(
                _summary_payload(
                    [
                        {
                            "policyId": "POLICY-GROUP-20020",
                            "description": "pending",
                            "switchIds": ["SN1"],
                            "markDeleted": True,
                        }
                    ]
                )
            ),
            _resp(deploy_body, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    summary = instance.deploy_pending_deleted_cleanup(
        [{"policy_id": "POLICY-GROUP-20020", "switch_ids": ["SN1"]}]
    )

    assert summary["changed"] is True
    assert summary["switch_ids"] == ["SN1"]
    assert summary["matched_policy_ids"] == ["POLICY-GROUP-20020"]
    assert summary["validation"] == "policy_summary_markDeleted"
    assert len(results._tasks) == 2
    assert "policySummary" in results._tasks[0].path
    assert "switchActions/deploy" in results._tasks[1].path
    assert results._tasks[1].payload == {"switchIds": ["SN1"]}


def test_manage_policy_group_orchestrator_00455() -> None:
    """
    # Summary

    Pending-delete cleanup is skipped when policySummary has no matching
    ``markDeleted`` row.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_pending_deleted_cleanup
    """
    rest_send = _build_rest_send([_resp({"policies": []})])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    summary = instance.deploy_pending_deleted_cleanup(
        [{"policy_id": "POLICY-GROUP-FAKE998"}]
    )

    assert summary["changed"] is False
    assert summary["switch_ids"] == []
    assert summary["skipped"][0]["reason"] == "no matching markDeleted policySummary row"
    assert len(results._tasks) == 1
    assert "policySummary" in results._tasks[0].path


def test_manage_policy_group_orchestrator_00456() -> None:
    """
    # Summary

    A generated pending-delete child row can be matched by the original policy
    group ID through its ``source`` field.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_pending_deleted_cleanup
    """
    rest_send = _build_rest_send(
        [
            _resp(
                _summary_payload(
                    [
                        {
                            "policyId": "POLICY-GROUP-CHILD",
                            "source": "POLICY-GROUP-ORIGINAL",
                            "description": "source child",
                            "switchIds": ["SN9"],
                            "markDeleted": True,
                        }
                    ]
                )
            ),
            _resp({"switchIds": [{"switchId": "SN9", "status": "success"}]}, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    summary = instance.deploy_pending_deleted_cleanup(
        [{"policy_id": "POLICY-GROUP-ORIGINAL"}]
    )

    assert summary["changed"] is True
    assert summary["switch_ids"] == ["SN9"]
    assert summary["matched_policy_ids"] == ["POLICY-GROUP-CHILD"]
    assert results._tasks[1].payload == {"switchIds": ["SN9"]}


def test_manage_policy_group_orchestrator_00457() -> None:
    """
    # Summary

    Description-only pending cleanup does not deploy when policySummary has
    multiple matching ``markDeleted`` rows. The user must provide an ID.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_pending_deleted_cleanup
    """
    rest_send = _build_rest_send(
        [
            _resp(
                _summary_payload(
                    [
                        {
                            "policyId": "POLICY-GROUP-A",
                            "description": "same",
                            "switchIds": ["SN1"],
                            "markDeleted": True,
                        },
                        {
                            "policyId": "POLICY-GROUP-B",
                            "description": "same",
                            "switchIds": ["SN2"],
                            "markDeleted": True,
                        },
                    ]
                )
            )
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    summary = instance.deploy_pending_deleted_cleanup(
        [{"name": "feature_enable", "description": "same"}]
    )

    assert summary["changed"] is False
    assert summary["switch_ids"] == []
    assert summary["skipped"][0]["reason"] == (
        "ambiguous pending-delete description; use policy group ID"
    )
    assert len(results._tasks) == 1


def test_manage_policy_group_orchestrator_00460() -> None:
    """
    # Summary

    Queued policySummary pending-delete cleanup switches are unioned into the
    normal delete_bulk consolidated switch deploy.

    ## Classes and Methods

    - PolicyGroupOrchestrator.schedule_pending_deleted_cleanup
    - PolicyGroupOrchestrator.delete_bulk
    """
    deploy_body = {
        "switchIds": [
            {"switchId": "SN1", "status": "success"},
            {"switchId": "SN2", "status": "success"},
        ]
    }
    rest_send = _build_rest_send(
        [
            _resp(
                _summary_payload(
                    [
                        {
                            "policyId": "POLICY-GROUP-PENDING",
                            "description": "pending",
                            "switchIds": ["SN2"],
                            "markDeleted": True,
                        }
                    ]
                )
            ),
            _resp({"policyGroups": [{"policyId": "P1", "status": "success"}]}, method="POST"),
            _resp(deploy_body, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)
    instance.schedule_pending_deleted_cleanup(
        [{"policy_id": "POLICY-GROUP-PENDING"}]
    )

    result = instance.delete_bulk(
        [_build_pg_model(policy_id="P1", description="active", switch_ids=["SN1"])]
    )

    assert result["pendingDeletedCleanupSwitchIds"] == ["SN2"]
    assert len(results._tasks) == 3
    assert results._tasks[2].payload == {"switchIds": ["SN1", "SN2"]}


def test_manage_policy_group_orchestrator_00470() -> None:
    """
    # Summary

    If there are no active policy group IDs to delete, a queued policySummary
    pending cleanup can still deploy its matched switches through delete_bulk
    without a markDelete call.

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete_bulk
    """
    rest_send = _build_rest_send(
        [
            _resp(
                _summary_payload(
                    [
                        {
                            "policyId": "POLICY-GROUP-PENDING",
                            "description": "pending",
                            "switchIds": ["SN1"],
                            "markDeleted": True,
                        }
                    ]
                )
            ),
            _resp({"switchIds": [{"switchId": "SN1", "status": "success"}]}, method="POST")
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)
    instance.schedule_pending_deleted_cleanup(
        [{"policy_id": "POLICY-GROUP-PENDING"}]
    )

    result = instance.delete_bulk([])

    assert result["policyIds"] == []
    assert result["pendingDeletedCleanupSwitchIds"] == ["SN1"]
    assert len(results._tasks) == 2
    assert "switchActions/deploy" in results._tasks[1].path


# =============================================================================
# Test: create / create_bulk
# =============================================================================


def test_manage_policy_group_orchestrator_00500() -> None:
    """
    # Summary

    ``create`` delegates to ``create_bulk`` with a single-element list and
    returns the same response.

    ## Classes and Methods

    - PolicyGroupOrchestrator.create
    """
    response_body = {"policyGroups": [{"policyId": "NEW", "status": "success"}]}
    rest_send = _build_rest_send([_resp(response_body, method="POST")])
    instance = _make_orchestrator(rest_send, deploy=False)
    model = _build_pg_model()

    result = instance.create(model)

    assert result == response_body
    assert model.policy_id == "NEW"  # populated by create_bulk


def test_manage_policy_group_orchestrator_00510() -> None:
    """
    # Summary

    ``create_bulk`` posts a ``{"policyGroups": [...]}`` envelope, propagates
    server-generated ``policyId`` values onto the model instances, and
    invalidates the cache.

    ## Test

    - Two models posted in one call
    - Response carries two ``policyGroups`` entries with distinct ``policyId``
    - Each model receives its ``policy_id`` (positional match)
    - ``_raw_cache`` reset to ``None`` afterwards

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    """
    response_body = {
        "policyGroups": [
            {"policyId": "P1", "status": "success", "templateName": "feature_enable"},
            {"policyId": "P2", "status": "success", "templateName": "feature_enable"},
        ]
    }
    rest_send = _build_rest_send([_resp(response_body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = ["stale"]  # to confirm invalidation
    models = [_build_pg_model(description="one"), _build_pg_model(description="two")]

    result = instance.create_bulk(models)

    assert result == response_body
    assert models[0].policy_id == "P1"
    assert models[1].policy_id == "P2"
    assert instance._raw_cache is None
    # Single POST issued; payload uses the policyGroups envelope.
    assert len(results._tasks) == 1
    assert results._tasks[0].verb == "POST"
    assert results._tasks[0].payload == {
        "policyGroups": [m.to_payload() for m in models]
    }


def test_manage_policy_group_orchestrator_00515() -> None:
    """
    # Summary

    ``create_bulk`` materializes the create-time priority default when the
    user omitted priority.

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    """
    response_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    rest_send = _build_rest_send([_resp(response_body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    model = _build_pg_model(priority=None)

    instance.create_bulk([model])

    assert model.to_payload().get("priority") is None
    assert results._tasks[0].payload["policyGroups"][0]["priority"] == 500


def test_manage_policy_group_orchestrator_00520() -> None:
    """
    # Summary

    With ``deploy=True`` and switches assigned, ``create_bulk`` follows the
    POST with a single ``switchActions/deploy`` against the union of all
    referenced switches.

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    """
    create_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    deploy_body = {
        "switchIds": [
            {"switchId": "SN1", "status": "success", "message": "ok"},
            {"switchId": "SN2", "status": "success", "message": "ok"},
        ]
    }
    rest_send = _build_rest_send(
        [
            _resp(create_body, method="POST"),
            _resp(deploy_body, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    model = _build_pg_model(switch_ids=["SN2", "SN1"])

    instance.create_bulk([model])

    assert len(results._tasks) == 2
    deploy_task = results._tasks[1]
    assert "switchActions/deploy" in deploy_task.path
    assert deploy_task.payload == {"switchIds": ["SN1", "SN2"]}  # sorted


def test_manage_policy_group_orchestrator_00530() -> None:
    """
    # Summary

    With ``deploy=False`` no ``switchActions/deploy`` request follows the
    create POST.

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    """
    create_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    rest_send = _build_rest_send([_resp(create_body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    model = _build_pg_model(switch_ids=["SN1"])

    instance.create_bulk([model])

    assert len(results._tasks) == 1


def test_manage_policy_group_orchestrator_00540() -> None:
    """
    # Summary

    A 207 response carrying a ``status: failed`` entry raises an
    ``Exception`` describing the failed item(s).

    ## Test

    - Two models posted; second item fails with a server message
    - Wrapped error names the failed template + description and includes the
      server message
    - ``_raw_cache`` is *not* invalidated when the bulk-create flow fails

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    """
    response_body = {
        "policyGroups": [
            {"policyId": "P1", "status": "success"},
            {"policyId": "", "status": "failed", "message": "boom"},
        ]
    }
    rest_send = _build_rest_send([_resp(response_body, method="POST")])
    instance = _make_orchestrator(rest_send, deploy=False)
    instance._raw_cache = ["preserved-on-error"]
    models = [
        _build_pg_model(description="one"),
        _build_pg_model(description="bad"),
    ]

    with pytest.raises(Exception, match="Bulk create policy groups failed.*bad.*boom"):
        instance.create_bulk(models)
    assert instance._raw_cache == ["preserved-on-error"]


def test_manage_policy_group_orchestrator_00550() -> None:
    """
    # Summary

    When no models supply ``switch_ids`` and ``deploy=True``, the orchestrator
    skips the ``switchActions/deploy`` call (nothing to deploy).

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    """
    create_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    rest_send = _build_rest_send([_resp(create_body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    model = _build_pg_model(switch_ids=[])

    instance.create_bulk([model])

    # Only the create POST was issued -- no deploy follow-up.
    assert len(results._tasks) == 1


# =============================================================================
# Test: update
# =============================================================================


def test_manage_policy_group_orchestrator_00600() -> None:
    """
    # Summary

    Happy-path ``update`` issues a ``PUT /policyGroups/{policy_id}`` carrying
    the model's payload and invalidates the cache.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [{"policyId": "P1", "switchIds": ["SN1"]}]
    update_body = {"policyId": "P1"}
    rest_send = _build_rest_send([_resp(update_body, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = cached_raw  # provides current switch_ids -> no extra GET
    model = _build_pg_model(policy_id="P1", switch_ids=["SN1"])

    result = instance.update(model)

    assert result == update_body
    assert instance._raw_cache is None  # invalidated by the mutation
    assert len(results._tasks) == 1
    assert results._tasks[0].path.endswith("/policyGroups/P1")
    assert results._tasks[0].verb == "PUT"
    assert results._tasks[0].payload == model.to_payload()


def test_manage_policy_group_orchestrator_00605() -> None:
    """
    # Summary

    ``update`` preserves the current priority when the user omitted priority.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [_build_pg_raw(policy_id="P1", switch_ids=["SN1"], priority=725)]
    update_body = {"policyId": "P1"}
    rest_send = _build_rest_send([_resp(update_body, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = cached_raw
    model = _build_pg_model(policy_id="P1", switch_ids=["SN1"], priority=None)

    instance.update(model)

    assert model.to_payload().get("priority") is None
    assert results._tasks[0].payload["priority"] == 725


def test_manage_policy_group_orchestrator_00610() -> None:
    """
    # Summary

    Missing ``policy_id`` raises a wrapped ``Exception`` whose message names
    the offending description.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    rest_send = _build_rest_send([])
    instance = _make_orchestrator(rest_send, deploy=False)
    model = _build_pg_model(policy_id=None, description="needs id")

    with pytest.raises(
        Exception, match="Update policy group failed.*needs id.*no policy_id"
    ):
        instance.update(model)


def test_manage_policy_group_orchestrator_00620() -> None:
    """
    # Summary

    When ``deploy=True`` and switches are *removed* from the group, the
    follow-up ``switchActions/deploy`` covers the union of new + removed
    switches so the controller pushes the negative config.

    ## Test

    - Old switch_ids (from cache): {SN1, SN2}
    - New switch_ids (in model): {SN2, SN3}
    - Expected deploy union (sorted): [SN1, SN2, SN3]

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [{"policyId": "P1", "switchIds": ["SN1", "SN2"]}]
    deploy_body = {
        "switchIds": [
            {"switchId": sn, "status": "success"} for sn in ["SN1", "SN2", "SN3"]
        ]
    }
    rest_send = _build_rest_send(
        [
            _resp({"policyId": "P1"}, method="PUT"),
            _resp(deploy_body, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    instance._raw_cache = cached_raw
    model = _build_pg_model(policy_id="P1", switch_ids=["SN2", "SN3"])

    instance.update(model)

    assert len(results._tasks) == 2
    deploy_task = results._tasks[1]
    assert "switchActions/deploy" in deploy_task.path
    assert deploy_task.payload == {"switchIds": ["SN1", "SN2", "SN3"]}


def test_manage_policy_group_orchestrator_00630() -> None:
    """
    # Summary

    With ``deploy=False`` no deploy request follows the ``PUT`` even when
    switches change.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [{"policyId": "P1", "switchIds": ["SN1"]}]
    rest_send = _build_rest_send([_resp({"policyId": "P1"}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = cached_raw
    model = _build_pg_model(policy_id="P1", switch_ids=["SN2"])

    instance.update(model)

    assert len(results._tasks) == 1  # PUT only


def test_manage_policy_group_orchestrator_00640() -> None:
    """
    # Summary

    When ``deploy=True`` and the switches are unchanged (new == old), the
    deploy call still fires on that switch set (so the existing intended
    config is re-pushed).

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [{"policyId": "P1", "switchIds": ["SN1"]}]
    deploy_body = {"switchIds": [{"switchId": "SN1", "status": "success"}]}
    rest_send = _build_rest_send(
        [
            _resp({"policyId": "P1"}, method="PUT"),
            _resp(deploy_body, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    instance._raw_cache = cached_raw
    model = _build_pg_model(policy_id="P1", switch_ids=["SN1"])

    instance.update(model)

    assert len(results._tasks) == 2
    assert results._tasks[1].payload == {"switchIds": ["SN1"]}


def test_manage_policy_group_orchestrator_00650() -> None:
    """
    # Summary

    A mixed update that changes both membership and policy intent is split into
    two independent ``PUT`` calls, followed by a single consolidated deploy.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [
        _build_pg_raw(
            policy_id="P1",
            switch_ids=["SN1"],
            template_inputs={"featureName": "lacp"},
            priority=500,
        )
    ]
    rest_send = _build_rest_send(
        [
            _resp({"policyId": "P1", "step": "membership"}, method="PUT"),
            _resp({"policyId": "P1", "step": "intent"}, method="PUT"),
            _resp(
                {
                    "switchIds": [
                        {"switchId": "SN1", "status": "success"},
                        {"switchId": "SN2", "status": "success"},
                    ]
                },
                method="POST",
            ),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    instance._raw_cache = cached_raw
    model = _build_pg_model(
        policy_id="P1",
        switch_ids=["SN1", "SN2"],
        template_inputs={"featureName": "lldp"},
    )

    instance.update(model)

    membership_payload = {
        "switchIds": ["SN1", "SN2"],
        "templateName": "feature_enable",
        "entityType": "switch",
        "entityName": "SWITCH",
        "description": "test pg",
        "priority": 500,
        "source": "",
        "templateInputs": {"featureName": "lacp"},
    }

    assert len(results._tasks) == 3
    assert results._tasks[0].verb == "PUT"
    assert results._tasks[0].metadata["action"] == "update"
    assert results._tasks[0].payload == membership_payload
    assert results._tasks[1].verb == "PUT"
    assert results._tasks[1].metadata["action"] == "update"
    assert results._tasks[1].payload == model.to_payload()
    assert "switchActions/deploy" in results._tasks[2].path
    assert results._tasks[2].payload == {"switchIds": ["SN1", "SN2"]}


def test_manage_policy_group_orchestrator_00660() -> None:
    """
    # Summary

    The same mixed update split happens when ``deploy=False``, but no
    ``switchActions/deploy`` call is issued.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [
        _build_pg_raw(
            policy_id="P1",
            switch_ids=["SN1"],
            template_inputs={"featureName": "lacp"},
            priority=500,
        )
    ]
    rest_send = _build_rest_send(
        [
            _resp({"policyId": "P1", "step": "membership"}, method="PUT"),
            _resp({"policyId": "P1", "step": "intent"}, method="PUT"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = cached_raw
    model = _build_pg_model(
        policy_id="P1",
        switch_ids=["SN1", "SN2"],
        template_inputs={"featureName": "lldp"},
    )

    instance.update(model)

    assert len(results._tasks) == 2
    assert [task.verb for task in results._tasks] == ["PUT", "PUT"]
    assert [task.metadata["action"] for task in results._tasks] == ["update", "update"]


def test_manage_policy_group_orchestrator_00670() -> None:
    """
    # Summary

    A membership-only update remains a single ``PUT``.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    cached_raw = [
        _build_pg_raw(
            policy_id="P1",
            switch_ids=["SN1"],
            template_inputs={"featureName": "lacp"},
            priority=500,
        )
    ]
    rest_send = _build_rest_send([_resp({"policyId": "P1"}, method="PUT")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    instance._raw_cache = cached_raw
    model = _build_pg_model(
        policy_id="P1",
        switch_ids=["SN1", "SN2"],
        template_inputs={"featureName": "lacp"},
    )

    instance.update(model)

    assert len(results._tasks) == 1
    assert results._tasks[0].verb == "PUT"
    assert results._tasks[0].payload == {
        "switchIds": ["SN1", "SN2"],
        "templateName": "feature_enable",
        "entityType": "switch",
        "entityName": "SWITCH",
        "description": "test pg",
        "priority": 500,
        "source": "",
        "templateInputs": {"featureName": "lacp"},
    }


# =============================================================================
# Test: delete / delete_bulk
# =============================================================================


def test_manage_policy_group_orchestrator_00700() -> None:
    """
    # Summary

    ``delete`` delegates to ``delete_bulk`` with a single-element list.

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete
    """
    mark_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    rest_send = _build_rest_send([_resp(mark_body, method="POST")])
    instance = _make_orchestrator(rest_send, deploy=False)
    model = _build_pg_model(policy_id="P1", switch_ids=["SN1"])

    result = instance.delete(model)

    assert result == {"policyIds": ["P1"], "status": "success"}


def test_manage_policy_group_orchestrator_00710() -> None:
    """
    # Summary

    Happy-path ``delete_bulk`` issues one ``markDelete`` and one
    ``switchActions/deploy`` against the union of affected switches; the
    cache is invalidated.

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete_bulk
    """
    mark_body = {
        "policyGroups": [
            {"policyId": "P1", "status": "success"},
            {"policyId": "P2", "status": "success"},
        ]
    }
    deploy_body = {
        "switchIds": [
            {"switchId": sn, "status": "success"} for sn in ("SN1", "SN2", "SN3")
        ]
    }
    rest_send = _build_rest_send(
        [
            _resp(mark_body, method="POST"),
            _resp(deploy_body, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    instance._raw_cache = ["stale"]
    models = [
        _build_pg_model(policy_id="P1", description="one", switch_ids=["SN1", "SN2"]),
        _build_pg_model(policy_id="P2", description="two", switch_ids=["SN2", "SN3"]),
    ]

    result = instance.delete_bulk(models)

    assert result == {"policyIds": ["P1", "P2"], "status": "success"}
    assert instance._raw_cache is None
    assert len(results._tasks) == 2
    assert results._tasks[0].path.endswith("/policyGroups/actions/markDelete")
    assert results._tasks[0].payload == {"policyIds": ["P1", "P2"]}
    assert "switchActions/deploy" in results._tasks[1].path
    assert set(results._tasks[1].payload["switchIds"]) == {"SN1", "SN2", "SN3"}


def test_manage_policy_group_orchestrator_00720() -> None:
    """
    # Summary

    When ``markDelete`` reports a per-policy failure the orchestrator falls
    back to a direct ``DELETE /policyGroups/{id}`` for the failed IDs, then
    deploys against the union of switches from *both* succeeded and
    direct-deleted groups.

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete_bulk
    """
    mark_body = {
        "policyGroups": [
            {"policyId": "P1", "status": "success"},
            {"policyId": "P2", "status": "failed", "message": "switch_freeform"},
        ]
    }
    rest_send = _build_rest_send(
        [
            _resp(mark_body, method="POST"),
            _resp({}, method="DELETE"),  # direct DELETE for P2
            _resp(
                {
                    "switchIds": [
                        {"switchId": "SN1", "status": "success"},
                        {"switchId": "SN2", "status": "success"},
                    ]
                },
                method="POST",
            ),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    models = [
        _build_pg_model(policy_id="P1", description="one", switch_ids=["SN1"]),
        _build_pg_model(policy_id="P2", description="two", switch_ids=["SN2"]),
    ]

    result = instance.delete_bulk(models)

    assert result == {"policyIds": ["P1", "P2"], "status": "success"}
    assert len(results._tasks) == 3
    assert results._tasks[1].path.endswith("/policyGroups/P2")
    assert results._tasks[1].verb == "DELETE"
    assert set(results._tasks[2].payload["switchIds"]) == {"SN1", "SN2"}


def test_manage_policy_group_orchestrator_00730() -> None:
    """
    # Summary

    With ``deploy=False`` ``delete_bulk`` performs ``markDelete`` (and any
    direct ``DELETE`` fallbacks) but skips the trailing
    ``switchActions/deploy``.

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete_bulk
    """
    mark_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    rest_send = _build_rest_send([_resp(mark_body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    models = [_build_pg_model(policy_id="P1", switch_ids=["SN1"])]

    instance.delete_bulk(models)

    assert len(results._tasks) == 1  # markDelete only


def test_manage_policy_group_orchestrator_00740() -> None:
    """
    # Summary

    A models list containing no ``policy_id`` values short-circuits to an
    empty dict without issuing any HTTP call.

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete_bulk
    """
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)
    models = [_build_pg_model(policy_id=None)]

    result = instance.delete_bulk(models)

    assert result == {}
    assert results._tasks == []


def test_manage_policy_group_orchestrator_00750() -> None:
    """
    # Summary

    When ``markDelete`` returns an empty ``policyGroups`` list the
    orchestrator treats every requested ID as succeeded (ambiguous response
    is interpreted permissively).

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete_bulk
    """
    mark_body = {"policyGroups": []}
    rest_send = _build_rest_send([_resp(mark_body, method="POST")])
    instance = _make_orchestrator(rest_send, deploy=False)
    models = [_build_pg_model(policy_id="P1", switch_ids=["SN1"])]

    result = instance.delete_bulk(models)

    assert result == {"policyIds": ["P1"], "status": "success"}


# =============================================================================
# Test: _switch_deploy
# =============================================================================


def test_manage_policy_group_orchestrator_00800() -> None:
    """
    # Summary

    ``_switch_deploy`` posts the ``{"switchIds": [...]}`` body to the deploy
    endpoint and accepts an all-success response without raising.

    ## Classes and Methods

    - PolicyGroupOrchestrator._switch_deploy
    """
    body = {"switchIds": [{"switchId": "SN1", "status": "success", "message": "ok"}]}
    rest_send = _build_rest_send([_resp(body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    with does_not_raise():
        instance._switch_deploy(["SN1"])

    assert results._tasks[0].path.endswith("switchActions/deploy")
    assert results._tasks[0].payload == {"switchIds": ["SN1"]}


def test_manage_policy_group_orchestrator_00810() -> None:
    """
    # Summary

    ``notExecuted`` per-switch entries are logged but do *not* raise -- the
    controller considers those switches already in-sync.

    ## Classes and Methods

    - PolicyGroupOrchestrator._switch_deploy
    """
    body = {
        "switchIds": [
            {"switchId": "SN1", "status": "success", "message": "ok"},
            {
                "switchId": "SN2",
                "status": "notExecuted",
                "message": "No Commands to execute",
            },
        ]
    }
    rest_send = _build_rest_send([_resp(body, method="POST")])
    instance = _make_orchestrator(rest_send)

    with does_not_raise():
        instance._switch_deploy(["SN1", "SN2"])


def test_manage_policy_group_orchestrator_00820() -> None:
    """
    # Summary

    Any per-switch ``failed`` status escalates to an ``Exception`` enumerating
    the failed switches and their messages.

    ## Classes and Methods

    - PolicyGroupOrchestrator._switch_deploy
    """
    body = {
        "switchIds": [
            {"switchId": "SN1", "status": "success"},
            {"switchId": "SN2", "status": "failed", "message": "deploy timeout"},
        ]
    }
    rest_send = _build_rest_send([_resp(body, method="POST")])
    instance = _make_orchestrator(rest_send)

    with pytest.raises(
        Exception,
        match="switchActions/deploy reported 1 failed switch.*SN2.*deploy timeout",
    ):
        instance._switch_deploy(["SN1", "SN2"])


def test_manage_policy_group_orchestrator_00830() -> None:
    """
    # Summary

    A response shaped as a list (older / variant controllers) is still
    parsed for per-switch status and a failure inside still raises.

    ## Classes and Methods

    - PolicyGroupOrchestrator._switch_deploy
    """
    list_body = [
        {"switchId": "SN1", "status": "failed", "message": "x"},
    ]
    rest_send = _build_rest_send([_resp(list_body, method="POST")])
    instance = _make_orchestrator(rest_send)

    with pytest.raises(
        Exception, match="switchActions/deploy reported 1 failed switch.*SN1"
    ):
        instance._switch_deploy(["SN1"])


# =============================================================================
# Test: deploy_unchanged_user_mentioned
# =============================================================================


class _FakeStateMachine:
    """Minimal duck-typed ``NDStateMachine`` substitute exposing only the
    three collections ``deploy_unchanged_user_mentioned`` reads."""

    def __init__(self, *, sent=None, proposed=None, existing=None) -> None:
        self.sent = sent or []
        self.proposed = proposed or []
        self.existing = existing or []


def test_manage_policy_group_orchestrator_00900() -> None:
    """
    # Summary

    With ``deploy=False`` the helper is a true no-op even when there are
    candidates to push.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_unchanged_user_mentioned
    """
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)
    pg = _build_pg_model(policy_id="P1", switch_ids=["SN1"])
    sm = _FakeStateMachine(proposed=[pg], existing=[pg])

    with does_not_raise():
        instance.deploy_unchanged_user_mentioned(sm)

    assert results._tasks == []


def test_manage_policy_group_orchestrator_00910() -> None:
    """
    # Summary

    When every user-mentioned policy was actually ``sent`` in this run, no
    re-deploy is needed.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_unchanged_user_mentioned
    """
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    pg = _build_pg_model(policy_id="P1", switch_ids=["SN1"])
    sm = _FakeStateMachine(sent=[pg], proposed=[pg], existing=[pg])

    with does_not_raise():
        instance.deploy_unchanged_user_mentioned(sm)

    assert results._tasks == []


def test_manage_policy_group_orchestrator_00920() -> None:
    """
    # Summary

    A user-mentioned policy whose desired state matches the controller
    (proposed AND existing AND NOT sent) triggers a ``switchActions/deploy`` over
    that policy's switches.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_unchanged_user_mentioned
    """
    body = {
        "switchIds": [
            {"switchId": "SN1", "status": "success"},
            {"switchId": "SN2", "status": "success"},
        ]
    }
    rest_send = _build_rest_send([_resp(body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    pg = _build_pg_model(policy_id="P1", switch_ids=["SN1", "SN2"])
    sm = _FakeStateMachine(proposed=[pg], existing=[pg])  # not in sent

    instance.deploy_unchanged_user_mentioned(sm)

    assert len(results._tasks) == 1
    assert set(results._tasks[0].payload["switchIds"]) == {"SN1", "SN2"}


def test_manage_policy_group_orchestrator_00930() -> None:
    """
    # Summary

    Existing policies *not* mentioned by the user (i.e. absent from
    ``proposed``) are ignored -- the helper never touches unrelated fabric
    policies.

    ## Classes and Methods

    - PolicyGroupOrchestrator.deploy_unchanged_user_mentioned
    """
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=True, results=results)
    pg_unrelated = _build_pg_model(
        policy_id="P_OTHER", description="unrelated", switch_ids=["SN9"]
    )
    sm = _FakeStateMachine(proposed=[], existing=[pg_unrelated])

    with does_not_raise():
        instance.deploy_unchanged_user_mentioned(sm)

    assert results._tasks == []


# =============================================================================
# Test: _get_current_switch_ids
# =============================================================================


def test_manage_policy_group_orchestrator_01000() -> None:
    """
    # Summary

    Cache hit returns the cached ``switchIds`` set without a network call.

    ## Classes and Methods

    - PolicyGroupOrchestrator._get_current_switch_ids
    """
    rest_send = _build_rest_send([])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)
    instance._raw_cache = [{"policyId": "P1", "switchIds": ["SN1", "SN2"]}]

    result = instance._get_current_switch_ids("P1")

    assert result == {"SN1", "SN2"}
    assert results._tasks == []


def test_manage_policy_group_orchestrator_01010() -> None:
    """
    # Summary

    Cache populated but ID not found returns the empty set (group was likely
    just created in this run).

    ## Classes and Methods

    - PolicyGroupOrchestrator._get_current_switch_ids
    """
    rest_send = _build_rest_send([])
    instance = _make_orchestrator(rest_send)
    instance._raw_cache = [{"policyId": "P2", "switchIds": ["SN1"]}]

    result = instance._get_current_switch_ids("P1")

    assert result == set()


def test_manage_policy_group_orchestrator_01020() -> None:
    """
    # Summary

    Cache miss falls back to policySummary and parses normalized ``switchIds``.

    ## Classes and Methods

    - PolicyGroupOrchestrator._get_current_switch_ids
    """
    body = _summary_payload([{"policyId": "P1", "switchIds": ["SN1", "SN2"]}])
    rest_send = _build_rest_send([_resp(body)])
    results = _make_results()
    instance = _make_orchestrator(rest_send, results=results)

    result = instance._get_current_switch_ids("P1")

    assert result == {"SN1", "SN2"}
    assert "policySummary" in results._tasks[0].path


def test_manage_policy_group_orchestrator_01030() -> None:
    """
    # Summary

    A 404 from the GET (with ``not_found_ok=True``) is silently treated as
    "no prior switches".

    ## Classes and Methods

    - PolicyGroupOrchestrator._get_current_switch_ids
    """
    rest_send = _build_rest_send([_resp({}, return_code=404, message="Not Found")])
    instance = _make_orchestrator(rest_send)

    result = instance._get_current_switch_ids("missing")

    assert result == set()


def test_manage_policy_group_orchestrator_01040() -> None:
    """
    # Summary

    Any non-404 GET exception is caught, logged, and treated as "no prior
    switches" so the removal-deploy is simply skipped -- never escalates.

    ## Classes and Methods

    - PolicyGroupOrchestrator._get_current_switch_ids
    """
    rest_send = _build_rest_send([_resp({}, return_code=500, message="boom")])
    instance = _make_orchestrator(rest_send)

    with does_not_raise():
        result = instance._get_current_switch_ids("P1")

    assert result == set()


# =============================================================================
# Test: _populate_policy_ids
# =============================================================================


def test_manage_policy_group_orchestrator_01100() -> None:
    """
    # Summary

    An empty ``response_groups`` argument is a no-op (no models touched).

    ## Classes and Methods

    - PolicyGroupOrchestrator._populate_policy_ids
    """
    models = [_build_pg_model(policy_id=None), _build_pg_model(policy_id=None)]

    PolicyGroupOrchestrator._populate_policy_ids(models, [])

    assert all(m.policy_id is None for m in models)


def test_manage_policy_group_orchestrator_01110() -> None:
    """
    # Summary

    Successful response items propagate their ``policyId`` onto the
    positionally-corresponding model.

    ## Classes and Methods

    - PolicyGroupOrchestrator._populate_policy_ids
    """
    models = [_build_pg_model(description="a"), _build_pg_model(description="b")]
    response_groups = [
        {"policyId": "P1", "status": "success"},
        {"policyId": "P2", "status": "success"},
    ]

    PolicyGroupOrchestrator._populate_policy_ids(models, response_groups)

    assert models[0].policy_id == "P1"
    assert models[1].policy_id == "P2"


def test_manage_policy_group_orchestrator_01120() -> None:
    """
    # Summary

    Failed response items are skipped -- the corresponding model retains its
    pre-existing ``policy_id`` (or stays ``None``).

    ## Classes and Methods

    - PolicyGroupOrchestrator._populate_policy_ids
    """
    models = [_build_pg_model(description="ok"), _build_pg_model(description="bad")]
    response_groups = [
        {"policyId": "P1", "status": "success"},
        {"policyId": "", "status": "failed", "message": "boom"},
    ]

    PolicyGroupOrchestrator._populate_policy_ids(models, response_groups)

    assert models[0].policy_id == "P1"
    assert models[1].policy_id is None


def test_manage_policy_group_orchestrator_01130() -> None:
    """
    # Summary

    When the top-level ``policyId`` is missing the helper falls back to
    ``templateInputs.POLICY_ID`` (some templates embed the assigned ID
    there).

    ## Classes and Methods

    - PolicyGroupOrchestrator._populate_policy_ids
    """
    models = [_build_pg_model()]
    response_groups = [{"status": "success", "templateInputs": {"POLICY_ID": "P_TI"}}]

    PolicyGroupOrchestrator._populate_policy_ids(models, response_groups)

    assert models[0].policy_id == "P_TI"


def test_manage_policy_group_orchestrator_01140() -> None:
    """
    # Summary

    When ``response_groups`` is longer than ``model_instances`` the helper
    only consumes up to ``len(model_instances)`` (no IndexError).

    ## Classes and Methods

    - PolicyGroupOrchestrator._populate_policy_ids
    """
    models = [_build_pg_model()]
    response_groups = [
        {"policyId": "P1", "status": "success"},
        {"policyId": "P2", "status": "success"},
    ]

    with does_not_raise():
        PolicyGroupOrchestrator._populate_policy_ids(models, response_groups)

    assert models[0].policy_id == "P1"


def test_manage_policy_group_orchestrator_01150() -> None:
    """
    # Summary

    When ``response_groups`` is shorter than ``model_instances`` the helper
    stops at the response length without raising; trailing models keep
    their existing ``policy_id``.

    ## Classes and Methods

    - PolicyGroupOrchestrator._populate_policy_ids
    """
    models = [_build_pg_model(description="a"), _build_pg_model(description="b")]
    response_groups = [{"policyId": "P1", "status": "success"}]

    with does_not_raise():
        PolicyGroupOrchestrator._populate_policy_ids(models, response_groups)

    assert models[0].policy_id == "P1"
    assert models[1].policy_id is None


# =============================================================================
# Change Control / multi-cluster: ticket_id + cluster_name forwarding
# =============================================================================
#
# These tests verify that ``ticket_id`` and ``cluster_name`` set on the
# orchestrator are forwarded as ``ticketId`` / ``clusterName`` query
# parameters on every endpoint that accepts them.  ``ticket_id`` is
# suppressed on read endpoints and on ``switchActions/deploy`` because
# their endpoint models do not expose it.
#
# Per-endpoint coverage matrix:
#
#   Endpoint                                            cluster_name  ticket_id
#   ----------------------------------------------------------------------------
#   GET    /policyGroups                                     YES          NO
#   GET    /policyGroups/{id}                                YES          NO
#   POST   /policyGroups                                     YES          YES
#   PUT    /policyGroups/{id}                                YES          YES
#   DELETE /policyGroups/{id}                                YES          YES
#   POST   /policyGroups/actions/markDelete                  YES          YES
#   POST   /switchActions/deploy                             YES          NO
#
# The query string is built by Pydantic and is opaque to the orchestrator;
# each test asserts on the recorded ``rest_send.path`` via the ``Results``
# task log, so the assertions are tolerant to parameter ordering.


def test_manage_policy_group_orchestrator_01200() -> None:
    """
    # Summary

    ``query_all`` forwards ``cluster_name`` as ``clusterName`` and does NOT
    forward ``ticket_id`` (the GET endpoint's ``EndpointParams`` model does
    not expose ``ticket_id``).

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_all
    - PolicyGroupOrchestrator._apply_endpoint_params
    """
    rest_send = _build_rest_send([_resp({"policies": []})])
    results = _make_results()
    instance = _make_orchestrator(
        rest_send,
        results=results,
        ticket_id="MyTicket1234",
        cluster_name="cluster1",
    )

    instance.query_all()

    path = results._tasks[0].path
    assert "clusterName=cluster1" in path
    assert "ticketId=" not in path  # GET does not accept ticketId


def test_manage_policy_group_orchestrator_01210() -> None:
    """
    # Summary

    ``query_by_id`` forwards ``cluster_name`` and not ``ticket_id``.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_by_id
    """
    rest_send = _build_rest_send(
        [_resp(_summary_payload([{"policyId": "POLICY-GROUP-1", "templateName": "t"}]))]
    )
    results = _make_results()
    instance = _make_orchestrator(
        rest_send,
        results=results,
        ticket_id="MyTicket1234",
        cluster_name="cluster1",
    )

    instance.query_by_id("POLICY-GROUP-1")

    path = results._tasks[0].path
    assert "clusterName=cluster1" in path
    assert "ticketId=" not in path


def test_manage_policy_group_orchestrator_01220() -> None:
    """
    # Summary

    ``query_filtered`` (cache-miss path) forwards ``cluster_name`` alongside
    the Lucene filter parameters and does not forward ``ticket_id``.

    ## Classes and Methods

    - PolicyGroupOrchestrator.query_filtered
    """
    rest_send = _build_rest_send([_resp({"policies": []})])
    results = _make_results()
    instance = _make_orchestrator(
        rest_send,
        results=results,
        ticket_id="MyTicket1234",
        cluster_name="cluster1",
    )

    instance.query_filtered(template_name="feature_enable")

    path = results._tasks[0].path
    assert "clusterName=cluster1" in path
    assert "ticketId=" not in path


def test_manage_policy_group_orchestrator_01230() -> None:
    """
    # Summary

    ``create_bulk`` forwards both ``clusterName`` and ``ticketId`` on the
    POST request.

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    """
    response_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    rest_send = _build_rest_send([_resp(response_body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(
        rest_send,
        deploy=False,
        results=results,
        ticket_id="MyTicket1234",
        cluster_name="cluster1",
    )

    instance.create_bulk([_build_pg_model()])

    path = results._tasks[0].path
    assert "clusterName=cluster1" in path
    assert "ticketId=MyTicket1234" in path


def test_manage_policy_group_orchestrator_01240() -> None:
    """
    # Summary

    ``update`` forwards both ``clusterName`` and ``ticketId`` on the PUT
    request.

    ## Classes and Methods

    - PolicyGroupOrchestrator.update
    """
    # Two responses: (1) cached GET miss for _get_current_policy_group, then
    # (2) the actual PUT.  Order matters because _get_current_policy_group
    # runs before the PUT inside update().
    rest_send = _build_rest_send(
        [
            _resp(
                _summary_payload(
                    [{"policyId": "POLICY-GROUP-1", "switchIds": ["SN1"]}]
                ),
                method="GET",
            ),
            _resp({"policyId": "POLICY-GROUP-1"}, method="PUT"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(
        rest_send,
        deploy=False,
        results=results,
        ticket_id="MyTicket1234",
        cluster_name="cluster1",
    )
    model = _build_pg_model(policy_id="POLICY-GROUP-1")

    instance.update(model)

    # Two tasks recorded: GET (cluster-only) then PUT (both).
    get_path = results._tasks[0].path
    put_path = results._tasks[1].path
    assert "clusterName=cluster1" in get_path
    assert "ticketId=" not in get_path  # GET does not accept ticketId
    assert "clusterName=cluster1" in put_path
    assert "ticketId=MyTicket1234" in put_path


def test_manage_policy_group_orchestrator_01250() -> None:
    """
    # Summary

    ``delete_bulk`` forwards both ``clusterName`` and ``ticketId`` on the
    markDelete POST. When markDelete fails and the direct-DELETE fallback
    fires, the DELETE also carries both query parameters.

    ## Classes and Methods

    - PolicyGroupOrchestrator.delete_bulk
    - PolicyGroupOrchestrator._mark_delete
    """
    # markDelete reports the policy id as failed → triggers direct DELETE.
    mark_response = {
        "policyGroups": [
            {
                "policyId": "POLICY-GROUP-1",
                "status": "failed",
                "message": "PYTHON content-type",
            }
        ]
    }
    rest_send = _build_rest_send(
        [
            _resp(mark_response, method="POST"),  # markDelete
            _resp({}, return_code=204, method="DELETE"),  # direct DELETE fallback
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(
        rest_send,
        deploy=False,
        results=results,
        ticket_id="MyTicket1234",
        cluster_name="cluster1",
    )
    model = _build_pg_model(policy_id="POLICY-GROUP-1")

    instance.delete_bulk([model])

    mark_path = results._tasks[0].path
    delete_path = results._tasks[1].path
    assert "clusterName=cluster1" in mark_path
    assert "ticketId=MyTicket1234" in mark_path
    assert "clusterName=cluster1" in delete_path
    assert "ticketId=MyTicket1234" in delete_path


def test_manage_policy_group_orchestrator_01260() -> None:
    """
    # Summary

    ``_switch_deploy`` forwards ``clusterName`` only.  ``POST
    /switchActions/deploy`` accepts ``forceShowRun`` and ``clusterName``
    but its endpoint model does not expose ``ticket_id``; the orchestrator
    must suppress the ``ticket_id`` assignment for this endpoint to avoid
    silently doing nothing or failing on a stricter ``extra='forbid'``
    model.

    ## Classes and Methods

    - PolicyGroupOrchestrator._switch_deploy
    - PolicyGroupOrchestrator._apply_endpoint_params (with_ticket=False)
    """
    # create_bulk → POST then trailing switchActions/deploy when deploy=True.
    create_response = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    deploy_response = {
        "switchIds": [
            {"switchId": "SN1", "status": "success", "message": "Deployed Successfully"}
        ]
    }
    rest_send = _build_rest_send(
        [
            _resp(create_response, method="POST"),
            _resp(deploy_response, method="POST"),
        ]
    )
    results = _make_results()
    instance = _make_orchestrator(
        rest_send,
        deploy=True,
        results=results,
        ticket_id="MyTicket1234",
        cluster_name="cluster1",
    )

    instance.create_bulk([_build_pg_model()])

    deploy_path = results._tasks[1].path
    assert "switchActions/deploy" in deploy_path
    assert "clusterName=cluster1" in deploy_path
    assert "ticketId=" not in deploy_path  # not allowed on this endpoint


def test_manage_policy_group_orchestrator_01270() -> None:
    """
    # Summary

    When neither ``ticket_id`` nor ``cluster_name`` is set on the orchestrator
    (the default, matching pre-existing behaviour), the request path emitted
    for a mutation is completely free of these query parameters.  This
    guarantees the new code is purely additive and does not alter cassettes
    or recorded fixtures for callers who never set the params.

    ## Classes and Methods

    - PolicyGroupOrchestrator.create_bulk
    - PolicyGroupOrchestrator._apply_endpoint_params (no-op path)
    """
    response_body = {"policyGroups": [{"policyId": "P1", "status": "success"}]}
    rest_send = _build_rest_send([_resp(response_body, method="POST")])
    results = _make_results()
    instance = _make_orchestrator(rest_send, deploy=False, results=results)

    instance.create_bulk([_build_pg_model()])

    path = results._tasks[0].path
    assert "clusterName=" not in path
    assert "ticketId=" not in path
